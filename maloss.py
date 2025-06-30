#!/usr/bin/env python3
"""
Package Security Vulnerability Scanner

This script parses package.json, package-lock.json, pyproject.toml, and requirements.txt 
files to extract package names and versions, then checks for known vulnerabilities using 
OSV and GitHub Security Advisory APIs.
"""

import json
import re
import requests
import argparse
import sys
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from urllib.parse import quote, urlparse
from bs4 import BeautifulSoup
import tempfile
import os
from datetime import datetime

# Try to import tomllib for Python 3.11+, fallback to tomli for older versions
try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None

class RemoteFileDownloader:
    """Handles downloading package manifest files from remote URLs."""
    
    @staticmethod
    def github_url_to_raw(github_url: str) -> str:
        """Convert GitHub web URL to raw content URL."""
        # Handle various GitHub URL formats
        if 'github.com' not in github_url:
            raise ValueError("URL must be from github.com")
        
        # Convert web URL to raw URL
        if '/blob/' in github_url:
            # https://github.com/user/repo/blob/main/package.json
            raw_url = github_url.replace('github.com', 'raw.githubusercontent.com')
            raw_url = raw_url.replace('/blob/', '/')
            return raw_url
        elif 'raw.githubusercontent.com' in github_url:
            # Already a raw URL
            return github_url
        else:
            raise ValueError("URL must be a valid GitHub file URL (with /blob/)")
    
    @staticmethod
    def download_file(url: str, target_filename: str = None) -> str:
        """Download file from URL and return local path."""
        try:
            # Convert GitHub URL to raw format if needed
            if 'github.com' in url:
                raw_url = RemoteFileDownloader.github_url_to_raw(url)
            else:
                raw_url = url
            
            # Download the file
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = requests.get(raw_url, headers=headers, timeout=30)
            response.raise_for_status()
            
            # Determine filename
            if not target_filename:
                # Extract filename from URL
                parsed_url = urlparse(raw_url)
                target_filename = os.path.basename(parsed_url.path)
                if not target_filename:
                    target_filename = "downloaded_manifest"
            
            # Create maloss directory in /tmp/
            maloss_dir = "/tmp/maloss"
            os.makedirs(maloss_dir, exist_ok=True)
            
            # Create full file path
            temp_file_path = os.path.join(maloss_dir, target_filename)
            
            # Write content to file
            with open(temp_file_path, 'w', encoding='utf-8') as f:
                f.write(response.text)
            
            return temp_file_path
            
        except requests.RequestException as e:
            raise Exception(f"Failed to download file from {url}: {e}")
        except Exception as e:
            raise Exception(f"Error processing remote file: {e}")
    
    @staticmethod
    def cleanup_temp_file(file_path: str):
        """Clean up temporary downloaded file."""
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
        except Exception:
            pass  # Ignore cleanup errors

# ANSI color codes for terminal output
class Colors:
    RED = '\033[91m'
    BRIGHT_RED = '\033[1;91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'  # Reset to default color

    @staticmethod
    def strip_colors(text: str) -> str:
        """Remove ANSI color codes from text."""
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        return ansi_escape.sub('', text)

@dataclass
class Package:
    """Represents a package with name and version."""
    name: str
    version: str
    file_source: str

@dataclass
class Vulnerability:
    """Represents a security vulnerability."""
    id: str
    summary: str
    severity: str
    package_name: str
    affected_versions: List[str]
    source: str  # 'OSV' or 'GitHub'
    url: Optional[str] = None  # Source URL

class PackageParser:
    """Handles parsing of different package file formats."""
    
    @staticmethod
    def parse_package_json(file_path: str) -> List[Package]:
        """Parse package.json file and extract dependencies."""
        packages = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Parse dependencies and devDependencies
            for dep_type in ['dependencies', 'devDependencies', 'peerDependencies']:
                if dep_type in data:
                    for name, version in data[dep_type].items():
                        # Clean version string (remove ^, ~, >=, etc.)
                        clean_version = re.sub(r'^[^0-9]*', '', version)
                        packages.append(Package(name, clean_version, file_path))
        
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"Error parsing {file_path}: {e}")
        
        return packages
    
    @staticmethod
    def parse_package_lock_json(file_path: str) -> List[Package]:
        """Parse package-lock.json file and extract all installed packages."""
        packages = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Parse packages from lockfile v2/v3 format
            if 'packages' in data:
                for package_path, package_info in data['packages'].items():
                    if package_path == "":  # Skip root package
                        continue
                    
                    # Extract package name from path (remove node_modules/ prefix)
                    name = package_path.replace('node_modules/', '')
                    version = package_info.get('version', 'unknown')
                    
                    if name and version:
                        packages.append(Package(name, version, file_path))
            
            # Fallback: Parse dependencies from lockfile v1 format
            elif 'dependencies' in data:
                def extract_deps(deps_dict, prefix=""):
                    for name, info in deps_dict.items():
                        version = info.get('version', 'unknown')
                        packages.append(Package(name, version, file_path))
                        
                        # Recursively parse nested dependencies
                        if 'dependencies' in info:
                            extract_deps(info['dependencies'], f"{prefix}{name}/")
                
                extract_deps(data['dependencies'])
        
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"Error parsing {file_path}: {e}")
        
        return packages
    
    @staticmethod
    def parse_pyproject_toml(file_path: str) -> List[Package]:
        """Parse pyproject.toml file and extract dependencies."""
        packages = []
        
        if tomllib is None:
            print(f"Error: tomllib/tomli not available. Install with: pip install tomli")
            return packages
        
        try:
            with open(file_path, 'rb') as f:
                data = tomllib.load(f)
            
            # Parse different dependency sections
            dependency_sections = [
                ['project', 'dependencies'],
                ['project', 'optional-dependencies'],
                ['tool', 'poetry', 'dependencies'],
                ['tool', 'poetry', 'dev-dependencies'],
                ['build-system', 'requires']
            ]
            
            for section_path in dependency_sections:
                current = data
                
                # Navigate to the section
                try:
                    for key in section_path:
                        current = current[key]
                except KeyError:
                    continue
                
                # Parse dependencies based on format
                if isinstance(current, list):
                    # Handle build-system.requires format (list of strings)
                    for dep in current:
                        match = re.match(r'^([a-zA-Z0-9_.-]+)', dep)
                        if match:
                            name = match.group(1)
                            # Extract version if present
                            version_match = re.search(r'[><=!]+([0-9.]+)', dep)
                            version = version_match.group(1) if version_match else 'latest'
                            packages.append(Package(name, version, file_path))
                
                elif isinstance(current, dict):
                    if section_path[-1] == 'optional-dependencies':
                        # Handle optional-dependencies (nested dict)
                        for group_name, deps in current.items():
                            for dep in deps:
                                match = re.match(r'^([a-zA-Z0-9_.-]+)', dep)
                                if match:
                                    name = match.group(1)
                                    version_match = re.search(r'[><=!]+([0-9.]+)', dep)
                                    version = version_match.group(1) if version_match else 'latest'
                                    packages.append(Package(name, version, file_path))
                    else:
                        # Handle poetry-style dependencies (dict format)
                        for name, version_spec in current.items():
                            if name == 'python':  # Skip python version specification
                                continue
                            
                            if isinstance(version_spec, str):
                                # Simple version string
                                clean_version = re.sub(r'^[^0-9]*', '', version_spec)
                                packages.append(Package(name, clean_version or 'latest', file_path))
                            elif isinstance(version_spec, dict):
                                # Complex version specification
                                version = version_spec.get('version', 'latest')
                                clean_version = re.sub(r'^[^0-9]*', '', str(version))
                                packages.append(Package(name, clean_version or 'latest', file_path))
        
        except (FileNotFoundError, Exception) as e:
            print(f"Error parsing {file_path}: {e}")
        
        return packages
    
    @staticmethod
    def parse_requirements_txt(file_path: str) -> List[Package]:
        """Parse requirements.txt file and extract dependencies."""
        packages = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            for line in lines:
                line = line.strip()
                # Skip comments and empty lines
                if not line or line.startswith('#'):
                    continue
                
                # Parse package==version or package>=version format
                match = re.match(r'^([a-zA-Z0-9_.-]+)[><=!]+([0-9.]+)', line)
                if match:
                    name, version = match.groups()
                    packages.append(Package(name, version, file_path))
                else:
                    # Handle packages without version specifiers
                    clean_name = re.match(r'^([a-zA-Z0-9_.-]+)', line)
                    if clean_name:
                        packages.append(Package(clean_name.group(1), 'latest', file_path))
        
        except FileNotFoundError as e:
            print(f"Error parsing {file_path}: {e}")
        
        return packages

class VulnerabilityChecker:
    """Handles vulnerability checking using OSV and GitHub APIs."""
    
    def __init__(self, json_mode=False):
        self.osv_url = "https://api.osv.dev/v1/query"
        self.github_malware_urls = {
            "npm": "https://github.com/advisories?query=type%3Amalware+ecosystem%3Anpm",
            "pip": "https://github.com/advisories?query=type%3Amalware+ecosystem%3Apip"
        }
        self.github_malware_cache = {
            "npm": None,
            "pip": None
        }
        self.json_mode = json_mode
    
    def fetch_github_malware_advisories(self, ecosystem: str) -> List[Dict]:
        """Fetch malware advisories from GitHub web interface for given ecosystem."""
        if self.github_malware_cache[ecosystem] is not None:
            return self.github_malware_cache[ecosystem]
        
        advisories = []
        url = self.github_malware_urls[ecosystem]
        
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = requests.get(url, headers=headers, timeout=15)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                
                # Find advisory cards
                advisory_cards = soup.find_all('div', class_='Box-row')
                
                for card in advisory_cards:
                    try:
                        # Extract advisory ID
                        id_elem = card.find('a', href=re.compile(r'/advisories/GHSA-'))
                        if not id_elem:
                            continue
                        
                        advisory_id = id_elem.get('href', '').split('/')[-1]
                        
                        # Extract title/summary
                        title_elem = card.find('a', href=re.compile(r'/advisories/GHSA-'))
                        title = title_elem.get_text(strip=True) if title_elem else "No title available"
                        
                        # Extract severity
                        severity_elem = card.find('span', class_='Label')
                        severity = severity_elem.get_text(strip=True) if severity_elem else "Unknown"
                        
                        # Extract affected packages from the description
                        description_elem = card.find('p')
                        description = description_elem.get_text(strip=True) if description_elem else ""
                        
                        # Try to extract package names from the title or description
                        package_names = []
                        
                        # Common patterns for package names in malware advisories
                        if ecosystem == "npm":
                            # Look for npm package patterns
                            npm_patterns = [
                                r'`([a-z0-9_.-]+)`',  # Backticked package names
                                r'"([a-z0-9_.-]+)"',  # Quoted package names
                            ]
                            for pattern in npm_patterns:
                                matches = re.findall(pattern, title + " " + description, re.IGNORECASE)
                                package_names.extend(matches)
                        
                        elif ecosystem == "pip":
                            # Look for PyPI package patterns
                            pip_patterns = [
                                r'`([a-zA-Z0-9_.-]+)`',  # Backticked package names
                                r'"([a-zA-Z0-9_.-]+)"',  # Quoted package names
                            ]
                            for pattern in pip_patterns:
                                matches = re.findall(pattern, title + " " + description, re.IGNORECASE)
                                package_names.extend(matches)
                        
                        # Remove duplicates and filter valid package names
                        package_names = list(set([name.lower() for name in package_names if len(name) > 1]))
                        
                        # Construct the full URL for this advisory
                        advisory_url = f"https://github.com/advisories/{advisory_id}"
                        
                        advisories.append({
                            'id': advisory_id,
                            'title': title,
                            'severity': severity,
                            'description': description,
                            'packages': package_names,
                            'url': advisory_url
                        })
                    
                    except Exception as e:
                        print(f"Error parsing advisory card: {e}")
                        continue
            
            else:
                if not self.json_mode:
                    print(f"Failed to fetch GitHub malware advisories for {ecosystem}: {response.status_code}")
        
        except requests.RequestException as e:
            if not self.json_mode:
                print(f"Error fetching GitHub malware advisories for {ecosystem}: {e}")
        
        # Cache the results
        self.github_malware_cache[ecosystem] = advisories
        return advisories
    
    def check_osv_vulnerability(self, package: Package) -> List[Vulnerability]:
        """Check package against OSV database, filtering for MAL- prefixed advisories only."""
        vulnerabilities = []
        
        # Determine ecosystem based on file source
        file_name = Path(package.file_source).name.lower()
        if file_name in ['package.json', 'package-lock.json']:
            ecosystem = "npm"
        elif file_name in ['requirements.txt', 'pyproject.toml']:
            ecosystem = "PyPI"
        else:
            ecosystem = "npm"  # Default fallback
        
        query = {
            "package": {
                "name": package.name,
                "ecosystem": ecosystem
            }
        }
        
        # Add version if not 'latest'
        if package.version != 'latest':
            query["version"] = package.version
        
        try:
            response = requests.post(self.osv_url, json=query, timeout=10)
            if response.status_code == 200:
                data = response.json()
                
                for vuln in data.get('vulns', []):
                    vuln_id = vuln.get('id', 'Unknown')
                    
                    # Filter: only include advisories that start with "MAL-"
                    # Skip PYSEC-, GHSA-, CVE-, and other prefixes
                    if not vuln_id.startswith('MAL-'):
                        continue
                    
                    affected_versions = []
                    for affected in vuln.get('affected', []):
                        if 'versions' in affected:
                            affected_versions.extend(affected['versions'])
                    
                    vulnerabilities.append(Vulnerability(
                        id=vuln_id,
                        summary=vuln.get('summary', 'No summary available'),
                        severity='Malware',  # Override severity for MAL- advisories
                        package_name=package.name,
                        affected_versions=affected_versions,
                        source='OSV',
                        url=f"https://osv.dev/vulnerability/{vuln_id}"
                    ))
        
        except requests.RequestException as e:
            if not self.json_mode:
                print(f"Error checking OSV for {package.name}: {e}")
        
        return vulnerabilities
    
    def check_github_advisory(self, package: Package) -> List[Vulnerability]:
        """Check package against GitHub Security Advisory malware database."""
        vulnerabilities = []
        
        # Determine ecosystem based on file source
        file_name = Path(package.file_source).name.lower()
        if file_name in ['package.json', 'package-lock.json']:
            ecosystem = "npm"
        elif file_name in ['requirements.txt', 'pyproject.toml']:
            ecosystem = "pip"
        else:
            ecosystem = "npm"  # Default fallback
        
        try:
            # Fetch malware advisories for this ecosystem
            advisories = self.fetch_github_malware_advisories(ecosystem)
            
            # Check if our package is mentioned in any advisory with strict matching
            for advisory in advisories:
                package_name_lower = package.name.lower()
                
                # Primary check: exact match in the extracted packages list
                if package_name_lower in advisory['packages']:
                    vulnerabilities.append(Vulnerability(
                        id=advisory['id'],
                        summary=advisory['title'],
                        severity=advisory['severity'],
                        package_name=package.name,
                        affected_versions=['All versions'],  # Malware typically affects all versions
                        source='GitHub',
                        url=advisory['url']
                    ))
                    continue  # Skip the fallback check if we found an exact match
                
                # Fallback check: strict word boundary matching in title and description
                # Only match if the package name appears as a complete word
                text_to_search = (advisory['title'] + " " + advisory['description']).lower()
                
                # Use word boundaries to ensure exact package name matches
                word_boundary_pattern = r'\b' + re.escape(package_name_lower) + r'\b'
                
                if re.search(word_boundary_pattern, text_to_search):
                    # Additional validation: make sure it's not a substring of a longer package name
                    # Check for common package name patterns around the match
                    context_pattern = r'(?:^|[\s`"\'\(])'+ re.escape(package_name_lower) + r'(?:[\s`"\'\)]|$)'
                    
                    if re.search(context_pattern, text_to_search):
                        vulnerabilities.append(Vulnerability(
                            id=advisory['id'],
                            summary=advisory['title'],
                            severity=advisory['severity'],
                            package_name=package.name,
                            affected_versions=['All versions'],
                            source='GitHub',
                            url=advisory['url']
                        ))
        
        except Exception as e:
            if not self.json_mode:
                print(f"Error checking GitHub Advisory for {package.name}: {e}")
        
        return vulnerabilities

class SecurityScanner:
    """Main scanner class that orchestrates the scanning process."""
    
    def __init__(self, json_mode=False, no_color=False):
        self.parser = PackageParser()
        self.checker = VulnerabilityChecker(json_mode)
        self.json_mode = json_mode
        self.no_color = no_color
        self.remote_url = None  # Store remote URL for reporting
    
    def set_remote_url(self, url: str):
        """Set the remote URL being scanned for reporting purposes."""
        self.remote_url = url
    
    def scan_file(self, file_path: str) -> Tuple[List[Package], List[Vulnerability]]:
        """Scan a single file for vulnerabilities."""
        packages = []
        vulnerabilities = []
        
        file_path_obj = Path(file_path)
        file_name = file_path_obj.name.lower()
        
        # Determine parser based on filename
        if file_name == 'package.json':
            packages = self.parser.parse_package_json(file_path)
        elif file_name == 'package-lock.json':
            packages = self.parser.parse_package_lock_json(file_path)
        elif file_name == 'pyproject.toml':
            packages = self.parser.parse_pyproject_toml(file_path)
        elif file_name == 'requirements.txt':
            packages = self.parser.parse_requirements_txt(file_path)
        else:
            if not self.json_mode:
                print(f"Unsupported file type: {file_path}")
                print("Supported files: package.json, package-lock.json, pyproject.toml, requirements.txt")
            return packages, vulnerabilities
        
        if not self.json_mode:
            print(f"Found {len(packages)} packages in {file_path}")
        
        # Check each package for vulnerabilities
        for i, package in enumerate(packages, 1):
            if not self.json_mode:
                print(f"Checking {i}/{len(packages)}: {package.name}")
            
            # Check OSV
            osv_vulns = self.checker.check_osv_vulnerability(package)
            vulnerabilities.extend(osv_vulns)
            
            # Check GitHub Advisory
            github_vulns = self.checker.check_github_advisory(package)
            vulnerabilities.extend(github_vulns)
        
        return packages, vulnerabilities
    
    def generate_report(self, packages: List[Package], vulnerabilities: List[Vulnerability], json_mode=False, no_color=False, output_file=None) -> str:
        """Generate a security report and return the content."""
        
        if not vulnerabilities:
            if json_mode:
                # Output empty JSON array in json mode
                if output_file:
                    # Create JSON with metadata when writing to file (no findings case)
                    timestamp = datetime.now().isoformat()
                    json_output = {
                        "analyzed_by": f"MALOSS at {timestamp}",
                        "total_packages_scanned": len(packages),
                        "malicious_packages_found": 0,
                        "remote_source": self.remote_url if self.remote_url else None,
                        "findings": []
                    }
                    json_content = json.dumps(json_output, indent=2)
                    
                    with open(output_file, 'w', encoding='utf-8') as f:
                        f.write(json_content)
                    print(f"JSON report written to: {output_file}")
                    return json_content
                else:
                    # Console output: just empty array
                    json_content = "[]"
                    print(json_content)
                    return json_content
            else:
                # Human readable format
                if not output_file:
                    print("\n" + "="*74)
                    print("MALOSS - MALICIOUS PACKAGE REPORT")
                    print("="*74)
                    print(f"\nTotal packages scanned: {len(packages)}")
                    print(f"Malicious packages found: {len(vulnerabilities)}")
                    print("\n✅ No known malicious packages found!")
                
                # Also write to file if requested
                if output_file:
                    report_content = "\n" + "="*74 + "\n"
                    report_content += "MALOSS - MALICIOUS PACKAGE REPORT\n"
                    report_content += "="*74 + "\n"
                    
                    # Add remote URL info if scanning remote file
                    if self.remote_url:
                        report_content += f"\nRemote source: {self.remote_url}\n"
                    
                    report_content += f"\nTotal packages scanned: {len(packages)}\n"
                    report_content += f"Malicious packages found: {len(vulnerabilities)}\n"
                    report_content += "\nNo known malicious packages found!\n"
                    
                    with open(output_file, 'w', encoding='utf-8') as f:
                        f.write(report_content)
                    print(f"Report written to: {output_file}")
                    return report_content
                
                return ""
        
        if json_mode:
            # Output vulnerabilities as JSON in json mode
            vuln_data = []
            for vuln in vulnerabilities:
                vuln_dict = {
                    "package_name": vuln.package_name,
                    "id": vuln.id,
                    "severity": vuln.severity,
                    "source": vuln.source,
                    "summary": vuln.summary,
                    "affected_versions": vuln.affected_versions,
                    "url": vuln.url
                }
                vuln_data.append(vuln_dict)
            
            if output_file:
                # Create JSON with metadata when writing to file
                timestamp = datetime.now().isoformat()
                json_output = {
                    "analyzed_by": f"MALOSS at {timestamp}",
                    "total_packages_scanned": len(packages),
                    "malicious_packages_found": len(vulnerabilities),
                    "remote_source": self.remote_url if self.remote_url else None,
                    "findings": vuln_data
                }
                json_content = json.dumps(json_output, indent=2)
                
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(json_content)
                print(f"JSON report written to: {output_file}")
            else:
                # Console output: just the findings array for easy parsing
                json_content = json.dumps(vuln_data, indent=2)
                print(json_content)
            
            return json_content if not output_file else json.dumps(json_output, indent=2)
        
        # Non-json mode: show detailed human-readable format
        report_content = ""
        
        # Build file content
        if output_file:
            report_content += "\n" + "="*74 + "\n"
            report_content += "MALOSS MALICIOUS PACKAGE REPORT\n"
            report_content += "="*74 + "\n"
            
            # Add remote URL info if scanning remote file
            if self.remote_url:
                report_content += f"\nRemote source: {self.remote_url}\n"
            
            report_content += f"\nTotal packages scanned: {len(packages)}\n"
            report_content += f"Malicious packages found: {len(vulnerabilities)}\n"
        
        # Print to console (if not writing to file only)
        if not output_file:
            print("\n" + "="*74)
            print("MALOSS - MALICIOUS PACKAGE REPORT")
            print("="*74)
            print(f"\nTotal packages scanned: {len(packages)}")
            print(f"Malicious packages found: {len(vulnerabilities)}")
        
        # Group vulnerabilities by severity
        severity_counts = {}
        for vuln in vulnerabilities:
            severity = vuln.severity
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Add severity info to both console and file content
        file_severity_text = f"\nFindings by severity:\n"
        for severity, count in severity_counts.items():
            file_severity_text += f"  {severity}: {count}\n"
        
        if output_file:
            report_content += file_severity_text
        
        if not output_file:
            print(f"\nFindings by severity:")
            for severity, count in severity_counts.items():
                print(f"  {severity}: {count}")
        
        # Add detailed vulnerabilities header
        file_detailed_header = f"\nDetailed findings:\n" + "-" * 74 + "\n"
        if output_file:
            report_content += file_detailed_header
            
        if not output_file:
            print(f"\nDetailed findings:")
            print("-" * 74)
        
        # Show detailed vulnerabilities
        for vuln in vulnerabilities:
            # File output: clean format without emojis
            file_package_line = f"Package: {vuln.package_name}"
            # Console output: with emojis and "Malicious Package" label
            console_package_line = f"📦 Malicious Package: {vuln.package_name}"
            
            # Add to file content (clean format without emojis)
            if output_file:
                report_content += f"\n{file_package_line}\n"
            
            # Print to console (with colors and emojis if enabled)
            if not output_file:
                if no_color:
                    print(f"\n{console_package_line}")
                else:
                    colored_package_line = f"{Colors.BRIGHT_RED}{console_package_line}{Colors.END}"
                    print(f"\n{colored_package_line}")
            
            # Build other lines - different formats for file vs console
            if vuln.url:
                file_id_line = f"ID: {vuln.id} ({vuln.url})"
                console_id_line = f"🆔 ID: {vuln.id} ({vuln.url})"
            else:
                file_id_line = f"ID: {vuln.id}"
                console_id_line = f"🆔 ID: {vuln.id}"
            
            file_severity_line = f"Severity: {vuln.severity}"
            console_severity_line = f"⚠️  Severity: {vuln.severity}"
            
            file_source_line = f"Source: {vuln.source}"
            console_source_line = f"🔍 Source: {vuln.source}"
            
            file_summary_line = f"Summary: {vuln.summary}"
            console_summary_line = f"📝 Summary: {vuln.summary}"
            
            # Add to file content (clean format)
            if output_file:
                report_content += f"{file_id_line}\n"
                report_content += f"{file_severity_line}\n"
                report_content += f"{file_source_line}\n"
                report_content += f"{file_summary_line}\n"
            
            # Print to console (with emojis)
            if not output_file:
                print(f"{console_id_line}")
                print(f"{console_severity_line}")
                print(f"{console_source_line}")
                print(f"{console_summary_line}")
            
            if vuln.affected_versions:
                file_versions_text = f"Affected versions: {', '.join(vuln.affected_versions[:5])}"
                console_versions_text = f"🎯 Affected versions: {', '.join(vuln.affected_versions[:5])}"
                
                if len(vuln.affected_versions) > 5:
                    file_extra_text = f"\n   ... and {len(vuln.affected_versions) - 5} more"
                    console_extra_text = f"\n   ... and {len(vuln.affected_versions) - 5} more"
                    file_versions_text += file_extra_text
                    console_versions_text += console_extra_text
                
                if output_file:
                    report_content += f"{file_versions_text}\n"
                
                if not output_file:
                    print(f"{console_versions_text}")
                    if len(vuln.affected_versions) > 5:
                        print(f"   ... and {len(vuln.affected_versions) - 5} more")
        
        # Write to file if output_file is specified
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(report_content)
            print(f"Report written to: {output_file}")
        
        return report_content

def print_banner():
    """Print ASCII banner."""
    print("""==========================================================================
|   __  __            _       ____    _____  _____   |                   |
|  |  \/  |    /\    | |     / __ \  / ____|/ ____|  |                   |
|  | \  / |   /  \   | |    | |  | || (___ | (___    |                   |
|  | |\/| |  / /\ \  | |    | |  | | \___ \ \___ \   |                   |
|  | |  | | / ____ \ | |____| |__| | ____) |____) |  |                   |
|  |_|  |_|/_/    \_\|______|\____/ |_____/|_____/   |  Created by 6mile |
|                                                    |                   |
|     "Hunt for malicious open source software"      |  Copyright 2025   |
==========================================================================""")

def main():
    """Main function."""
    parser = argparse.ArgumentParser(
        description="Maloss scans package manifest files and checks OSV and GHSA to see if any of the packages you are using are malicious."
    )
    parser.add_argument(
        "files",
        nargs="*",  # Changed from "+" to "*" to allow no files when using --remote
        help="Path to package manifest files (package.json, package-lock.json, pyproject.toml, requirements.txt)"
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Output file for the report (optional)"
    )
    parser.add_argument(
        "--json",
        "-j",
        action="store_true",
        help="JSON mode: suppress all output except vulnerability details in JSON format (useful for CI/CD)"
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output (useful for logs or unsupported terminals)"
    )
    parser.add_argument(
        "--remote",
        "-r",
        help="Download and scan a package manifest file from a GitHub URL"
    )
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.remote and not args.files:
        parser.error("Must provide either files to scan or use --remote flag")
    
    # Handle remote file download
    remote_file_path = None
    if args.remote:
        if not args.json:
            print(f"Downloading remote file: {args.remote}")
        try:
            remote_file_path = RemoteFileDownloader.download_file(args.remote)
            if not args.json:
                print(f"Downloaded to: {remote_file_path}")
        except Exception as e:
            if not args.json:
                print(f"Error downloading remote file: {e}")
            else:
                print("[]")  # Empty JSON for error in JSON mode
            sys.exit(1)
    
    # Only display banner and info in non-json mode
    if not args.json:
        print_banner()
        #print("Required dependencies: pip install beautifulsoup4 tomli")
        #print("This script checks for malicious packages using OSV (MAL- advisories) and GitHub malware advisories.")
        #print("Supported files: package.json, package-lock.json, pyproject.toml, requirements.txt\n")
    
    scanner = SecurityScanner(json_mode=args.json, no_color=args.no_color)
    all_packages = []
    all_vulnerabilities = []
    
    # Set remote URL for reporting if scanning remote file
    if args.remote:
        scanner.set_remote_url(args.remote)
    
    # Determine files to scan
    files_to_scan = []
    if args.remote:
        files_to_scan = [remote_file_path]
    else:
        files_to_scan = args.files
    
    # Scan files
    for file_path in files_to_scan:
        if not Path(file_path).exists():
            if not args.json:
                print(f"File not found: {file_path}")
            continue
        
        if not args.json:
            if args.remote:
                print(f"\nScanning remote file: {args.remote}")
            else:
                print(f"\nScanning {file_path}...")
        packages, vulnerabilities = scanner.scan_file(file_path)
        all_packages.extend(packages)
        all_vulnerabilities.extend(vulnerabilities)
    
    # Generate report
    scanner.generate_report(all_packages, all_vulnerabilities, json_mode=args.json, no_color=args.no_color, output_file=args.output)
    
    # Clean up temporary file if used
    if remote_file_path:
        RemoteFileDownloader.cleanup_temp_file(remote_file_path)
    
    # Exit with error code if vulnerabilities found
    if all_vulnerabilities:
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == "__main__":
    main()
