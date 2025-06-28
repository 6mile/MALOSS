#!/usr/bin/env python3
"""
MALOSS - Identify malicious packages

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
from urllib.parse import quote
from bs4 import BeautifulSoup

# Try to import tomllib for Python 3.11+, fallback to tomli for older versions
try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None

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
        import re
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
            # Only print error if not in json mode
            if hasattr(sys.modules[__name__], '_json_mode') and not _json_mode:
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
                    
                    severity = 'Unknown'
                    if 'severity' in vuln:
                        if isinstance(vuln['severity'], list) and vuln['severity']:
                            severity = vuln['severity'][0].get('score', 'Unknown')
                    
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
            
            # Check if our package is mentioned in any advisory
            for advisory in advisories:
                # Check if package name matches any of the packages mentioned in the advisory
                package_name_lower = package.name.lower()
                
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
                
                # Also check if package name appears in title or description as fallback
                elif (package_name_lower in advisory['title'].lower() or 
                      package_name_lower in advisory['description'].lower()):
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
                json_content = "[]"
                if output_file:
                    with open(output_file, 'w', encoding='utf-8') as f:
                        f.write(json_content)
                    print(f"JSON report written to: {output_file}")
                else:
                    print(json_content)
                return json_content
            else:
                # Human readable format
                if not output_file:
                    print("\n" + "="*70)
                    print("MALOSS - MALICIOUS PACKAGE REPORT")
                    print("="*70)
                    print(f"\nTotal packages scanned: {len(packages)}")
                    print(f"Total findings: {len(vulnerabilities)}")
                    print("\n✅ No malicious packages found!")
                
                # Also write to file if requested
                if output_file:
                    report_content = "\n" + "="*70 + "\n"
                    report_content += "MALOSS MALICIOUS PACKAGE REPORT\n"
                    report_content += "="*70 + "\n"
                    report_content += f"\nTotal packages scanned: {len(packages)}\n"
                    report_content += f"Total findings: {len(vulnerabilities)}\n"
                    report_content += "\nNo known findings found!\n"
                    
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
            
            json_content = json.dumps(vuln_data, indent=2)
            if output_file:
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(json_content)
                print(f"JSON report written to: {output_file}")
            else:
                print(json_content)
            return json_content
        
        # Non-json mode: show detailed human-readable format
        report_content = ""
        
        # Build file content
        if output_file:
            report_content += "\n" + "="*70 + "\n"
            report_content += "MALOSS - MALICIOUS PACKAGE REPORT\n"
            report_content += "="*70 + "\n"
            report_content += f"\nTotal packages scanned: {len(packages)}\n"
            report_content += f"Total findings: {len(vulnerabilities)}\n"
        
        # Print to console (if not writing to file only)
        if not output_file:
            print("\n" + "="*70)
            print("MALOSS - MALICIOUS PACKAGE REPORT")
            print("="*70)
            print(f"\nTotal packages scanned: {len(packages)}")
            print(f"Total findings: {len(vulnerabilities)}")
        
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
        file_detailed_header = f"\nDetailed findings:\n" + "-" * 70 + "\n"
        if output_file:
            report_content += file_detailed_header
            
        if not output_file:
            print(f"\nDetailed findings:")
            print("-" * 70)
        
        # Show detailed vulnerabilities
        for vuln in vulnerabilities:
            # File output: clean format without emojis
            file_package_line = f"Malicious Package: {vuln.package_name}"
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
    print("""
========================================================================
|    __  __    _    _     ___  ____ ____    |                          |
|   |  \/  |  / \  | |   / _ \/ ___/ ___|   |                          |
|   | |\/| | / _ \ | |  | | | \___ \___ \   |                          |
|   | |  | |/ ___ \| |__| |_| |___) |__) |  |                          |
|   |_|  |_/_/   \_\_____\___/|____/____/   | Created by 6mile         |
|   "Identify malicious packages quickly"   | Email 6mile at linux.com |
========================================================================
""")

def main():
    parser = argparse.ArgumentParser(
        description="Maloss scans package manifest files and checks OSV and GHSA to see if any of the packages you are using are malicious."
    )
    parser.add_argument(
        "files",
        nargs="+",
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
    
    args = parser.parse_args()
    
    # Only display banner and info in non-json mode
    if not args.json:
        print_banner()
        #print('Maloss (pronounced "malice"), scans your package manifest files, and checks OSV')
        #print('and GHSA to see if any of the libraries and packages you are using are malicious.')
        #print('Maloss supports these package manifest files:')
        #print("package.json, package-lock.json, pyproject.toml, requirements.txt\n")
    
    scanner = SecurityScanner(json_mode=args.json, no_color=args.no_color)
    all_packages = []
    all_vulnerabilities = []
    
    for file_path in args.files:
        if not Path(file_path).exists():
            if not args.json:
                print(f"File not found: {file_path}")
            continue
        
        if not args.json:
            print(f"\nScanning {file_path}...")
        packages, vulnerabilities = scanner.scan_file(file_path)
        all_packages.extend(packages)
        all_vulnerabilities.extend(vulnerabilities)
    
    # Generate report
    scanner.generate_report(all_packages, all_vulnerabilities, json_mode=args.json, no_color=args.no_color, output_file=args.output)
    
    # Exit with error code if vulnerabilities found
    if all_vulnerabilities:
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == "__main__":
    main()
