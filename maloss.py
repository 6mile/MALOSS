import json
import requests
import os
import time
import sys
import re # Import the re module for regular expressions
import argparse 

def parse_dependencies_file(file_path):
    """
    Parses a dependency file (package.json or requirements.txt) to extract packages and their versions.

    Args:
        file_path (str): The path to the dependency file.

    Returns:
        tuple: A tuple containing (dict: packages, str: ecosystem).
               Packages dictionary contains name and version. Ecosystem is 'npm' or 'PyPI'.
               Returns ({}, None) if the file cannot be parsed or found.
    """
    packages = {}
    ecosystem = None

    file_name = os.path.basename(file_path).lower()

    try:
        if file_name == 'package.json':
            ecosystem = 'npm'
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

                if 'dependencies' in data:
                    for pkg, version in data['dependencies'].items():
                        packages[pkg] = version

                if 'devDependencies' in data:
                    for pkg, version in data['devDependencies'].items():
                        packages[pkg] = version

        elif file_name == 'requirements.txt':
            ecosystem = 'PyPI'
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue # Skip empty lines and comments

                    # Regex to match package names and various version specifiers
                    # Examples: package==1.0, package>=1.0, package~=1.0, package
                    match = re.match(r'^([a-zA-Z0-9._-]+)\s*(?:[<=>!~=]+\s*([\d.]+.*))?$', line)
                    if match:
                        pkg_name = match.group(1)
                        # For requirements.txt, if no version is specified, it might be the latest.
                        # For OSV API, it's better to get a specific version.
                        # If a version is provided with a specifier, we take the direct version part.
                        pkg_version = match.group(2) if match.group(2) else "unknown"
                        packages[pkg_name] = pkg_version
                    else:
                        print(f"Warning: Could not parse line in requirements.txt: '{line}'")

        else:
            print(f"Error: Unsupported dependency file type: '{file_name}'. Supported: package.json, requirements.txt.")
            return {}, None

    except FileNotFoundError:
        print(f"Error: Dependency file not found at '{file_path}'")
        return {}, None
    except json.JSONDecodeError:
        print(f"Error: Could not decode JSON from '{file_path}'. Make sure it's a valid JSON file.")
        return {}, None
    except Exception as e:
        print(f"An unexpected error occurred while parsing '{file_path}': {e}")
        return {}, None

    return packages, ecosystem

def check_github_advisory(package_name):
    """
    Attempts to check the GitHub Advisories page for "malware" type advisories
    related to a given package name.

    Note: This is a basic web scraping approach and is highly sensitive to
    changes in GitHub's website structure. It does not use a direct API.

    Args:
        package_name (str): The name of the package (e.g., 'lodash').

    Returns:
        bool: True if the package name appears to be linked to a malicious
              advisory on the GitHub page, False otherwise.
    """
    # Construct the search URL for GitHub Advisories with the "malware" type filter
    # and the package name as a search query.
    GITHUB_ADVISORIES_URL = f"https://github.com/advisories?query={package_name}+type%3Amalware"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }

    try:
        response = requests.get(GITHUB_ADVISORIES_URL, headers=headers, timeout=15)
        response.raise_for_status() # Raise an HTTPError for bad responses (4xx or 5xx)

        # A very basic check: see if the package name is present in the response text.
        # This is a rudimentary check and might yield false positives/negatives.
        # A more robust solution would involve proper HTML parsing (e.g., with BeautifulSoup)
        # to look for specific advisory elements, but this exceeds the scope for a simple example.
        if package_name.lower() in response.text.lower():
            # Check for common indicators of advisories on the page (e.g., "advisory", "vulnerability")
            # This makes the check slightly less naive than just looking for the package name.
            if "advisory" in response.text.lower() or "vulnerability" in response.text.lower():
                return True
        return False
    except requests.exceptions.RequestException as e:
        print(f"Error checking GitHub Advisories for {package_name}: {e}")
        return False

def check_osv_vulnerability(package_name, package_version, ecosystem):
    """
    Checks the OSV.dev API for vulnerabilities in a given package.
    Only reports vulnerability IDs that start with 'MAL-'.

    Args:
        package_name (str): The name of the package (e.g., 'lodash').
        package_version (str): The version of the package (e.g., '4.17.21').
        ecosystem (str): The ecosystem of the package (e.g., 'npm', 'PyPI', 'Go').

    Returns:
        list: A list of vulnerability IDs (filtered for 'MAL-') if found, otherwise an empty list.
    """
    # OSV API requires a specific version. If 'unknown' (from requirements.txt without exact version),
    # we might not get precise results, but the API might still return broad advisories.
    if package_version == "unknown":
        print(f"Warning: Exact version for {package_name} is unknown. OSV results may be less precise.")

    OSV_API_URL = "https://api.osv.dev/v1/query"
    payload = {
        "version": package_version,
        "package": {
            "name": package_name,
            "ecosystem": ecosystem
        }
    }
    headers = {"Content-Type": "application/json"}

    try:
        response = requests.post(OSV_API_URL, headers=headers, json=payload, timeout=10)
        response.raise_for_status() # Raise an HTTPError for bad responses (4xx or 5xx)
        data = response.json()

        mal_vulnerabilities = []
        if 'vulns' in data and data['vulns']:
            # Filter vulnerability IDs to only include those that start with 'MAL-'
            for vuln in data['vulns']:
                if 'id' in vuln and vuln['id'].startswith('MAL-'):
                    mal_vulnerabilities.append(vuln['id'])
        return mal_vulnerabilities
    except requests.exceptions.RequestException as e:
        print(f"Error querying OSV API for {package_name}@{package_version} in ecosystem {ecosystem}: {e}")
        return []
    except json.JSONDecodeError:
        print(f"Error: Could not decode JSON response from OSV API for {package_name}@{package_version}.")
        return []


def main():

    # pauledits
    # Set up argument parser
    parser = argparse.ArgumentParser(
        description="Detect Malicious Packages in NPM or PyPI dependency files.",
        formatter_class=argparse.RawTextHelpFormatter # For better formatting of multiline descriptions
    )
    parser.add_argument(
        'dependency_file',
        nargs='?', # Makes the argument optional
        help="Path to the dependency file (e.g., package.json or requirements.txt).\n"
             "If not provided, the script will prompt you for it."
    )

    args = parser.parse_args()
    # pauledits

    """
    Main function to run the package maliciousness and vulnerability checks.
    """
    print("--- Combined Package Security Checker ---")
    print("This script checks packages in your dependency file against both:")
    print("1. GitHub's public advisories for 'malware' type issues (via basic web scraping).")
    print("2. The OSV.dev database for known vulnerabilities (filtered for 'MAL-' IDs).")
    print("Supported file types: package.json (npm), requirements.txt (PyPI).")
    print("WARNING: The GitHub check involves basic web scraping and is less reliable than using dedicated APIs.")

    # Check if a file path is provided as a command-line argument
    if len(sys.argv) > 1:
        dependency_file_path = sys.argv[1]
    else:
        # If not provided, prompt the user for it (fallback)
        dependency_file_path = input("Enter the path to your dependency file (e.g., package.json or requirements.txt): ").strip()

    if not dependency_file_path:
        print("No path entered. Exiting.")
        return

    # Check if the file exists before proceeding
    if not os.path.exists(dependency_file_path):
        print(f"Error: The file '{dependency_file_path}' does not exist. Please provide a valid path.")
        return

    packages_to_check, ecosystem = parse_dependencies_file(dependency_file_path)

    if not packages_to_check or ecosystem is None:
        print("No packages found to check or an error occurred during parsing, or an unsupported file type was provided.")
        return

    print(f"\nFound {len(packages_to_check)} packages from {os.path.basename(dependency_file_path)} (Ecosystem: {ecosystem}). Checking for security issues...\n")

    github_malicious_packages = []
    osv_vulnerable_packages = {}

    for pkg_name, pkg_version in packages_to_check.items():
        print(f"Checking {pkg_name}@{pkg_version}...")

        # Check GitHub Advisories for malware (ecosystem independent)
        is_malicious_github = check_github_advisory(pkg_name)
        if is_malicious_github:
            github_malicious_packages.append(pkg_name)

        # Check OSV.dev for general vulnerabilities
        vuln_ids_osv = check_osv_vulnerability(pkg_name, pkg_version, ecosystem)
        if vuln_ids_osv:
            osv_vulnerable_packages[pkg_name] = {'version': pkg_version, 'vulnerabilities': vuln_ids_osv, 'ecosystem': ecosystem}

        time.sleep(1) # Add a small delay to avoid hitting rate limits or being too aggressive

    print("\n--- Scan Complete ---")

    # Report GitHub Advisories findings
    if github_malicious_packages:
        print("\n--- GitHub Advisories (Potential Malware) ---")
        print("The following packages might be linked to malicious advisories on GitHub:")
        for pkg in github_malicious_packages:
            print(f"- {pkg} (Please visit https://github.com/advisories?query={pkg}+type%3Amalware for details)")
        print("Please review these findings carefully on GitHub Advisories.")
    else:
        print("\n--- GitHub Advisories (Potential Malware) ---")
        print("No apparent malicious advisories found for the packages listed in your dependency file on GitHub.")

    # Report OSV.dev findings
    if osv_vulnerable_packages:
        print("\n--- OSV.dev (Known Vulnerabilities) ---")
        print("The following packages have known vulnerabilities (filtered for 'MAL-' IDs) listed on OSV.dev:")
        for pkg, details in osv_vulnerable_packages.items():
            print(f"- {pkg} (version: {details['version']}, ecosystem: {details['ecosystem']})")
            for vuln_id in details['vulnerabilities']:
                print(f"  - Vulnerability ID: {vuln_id} (Details: https://osv.dev/{vuln_id})")
        print("Please review these vulnerabilities and consider updating or replacing the packages.")
    else:
        print("\n--- OSV.dev (Known Vulnerabilities) ---")
        print("No known vulnerabilities (filtered for 'MAL-' IDs) found for the packages listed in your dependency file on OSV.dev.")

    print("\nNote: The accuracy of these checks depends on the respective databases and methods used.")


if __name__ == "__main__":
    main()

