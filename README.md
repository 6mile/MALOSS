# MALOSS - Identify Malicious Open-Source Software Packages

![MALOSS](images/MALOSS-square-image.jpeg)

MALOSS (pronounced "malice"), scans package manifest files to see if any of the libraries and packages are malicious. It does this by analyzing local package manifest files, or remote package files, and checking both [OSV](https://osv.dev) and [GitHub Security Advisory (GHSA)}(https://github.com/advisories) for known malicious packages.  

Maloss supports these package manifest files:
package.json, package-lock.json, pyproject.toml, requirements.txt

## Installation

```bash
git clone https://github.com/6mile/MALOSS.git
cd ./MALOSS/
pip install beautifulsoup4 tomli requests
```

## Usage Examples

### Write Human-Readable Report

```bash
python maloss.py package.json --output security-report.txt
```

Creates `security-report.txt`:
```
================================================================================
SECURITY VULNERABILITY REPORT
================================================================================

Total packages scanned: 25
Total vulnerabilities found: 2

Vulnerabilities by severity:
  CRITICAL: 1
  HIGH: 1

Detailed vulnerabilities:
--------------------------------------------------------------------------------

📦 Package: malicious-package
🆔 ID: MAL-2024-1234 (https://osv.dev/vulnerability/MAL-2024-1234)
⚠️  Severity: CRITICAL
🔍 Source: OSV
📝 Summary: Malicious package containing credential harvesting code
🎯 Affected versions: 1.0.0, 1.0.1
```

### Write JSON Report

```bash
python maloss.py package.json --json --output vulnerabilities.json
```

Creates `vulnerabilities.json`:
```json
[
  {
    "package_name": "malicious-package",
    "id": "MAL-2024-1234",
    "severity": "CRITICAL",
    "source": "OSV",
    "summary": "Malicious package containing credential harvesting code",
    "affected_versions": ["1.0.0", "1.0.1"],
    "url": "https://osv.dev/vulnerability/MAL-2024-1234"
  }
]
```

### No Vulnerabilities Found

```bash
python maloss.py clean-package.json --output clean-report.txt
```

Creates `clean-report.txt`:
```
================================================================================
SECURITY VULNERABILITY REPORT
================================================================================

Total packages scanned: 15
Total vulnerabilities found: 0

✅ No known vulnerabilities found!
```

## CI/CD Integration Examples

### Generate Reports for Artifacts

```bash
# Generate human-readable report for review
python maloss.py package.json --output security-scan-report.txt

# Generate JSON for automated processing
python maloss.py package.json --json --output security-scan.json
```

### GitHub Actions Integration

```yaml
- name: Scan for malicious packages
  run: |
    python maloss.py package.json --json --output vulnerabilities.json
    
- name: Upload security report
  uses: actions/upload-artifact@v3
  with:
    name: security-scan-results
    path: vulnerabilities.json
    
- name: Process results
  run: |
    if [ "$(cat vulnerabilities.json)" != "[]" ]; then
      echo "::error::Security vulnerabilities found!"
      cat vulnerabilities.json | jq -r '.[] | "::error::Malicious package: \(.package_name) - \(.summary)"'
      exit 1
    fi
```

### Archive Reports

```bash
# Generate timestamped reports
DATE=$(date +%Y%m%d-%H%M%S)
python maloss.py package.json --output "security-scan-$DATE.txt"
python maloss.py package.json --json --output "security-scan-$DATE.json"
```

## Command Line Options

- `--json`, `-j`: JSON mode - outputs structured JSON data instead of human-readable format
- `--output`, `-o`: Write report to specified file instead of console output
- `--no-color`: Disable colored output (useful for logs or unsupported terminals)

## Supported File Types

- `package.json` - Node.js dependencies
- `package-lock.json` - Node.js lockfile with exact versions
- `pyproject.toml` - Python project dependencies (PEP 621, Poetry, etc.)
- `requirements.txt` - Python requirements file

## Exit Codes

- `0`: No vulnerabilities found
- `1`: Vulnerabilities detected (useful for CI/CD pipeline failures)

## Features

- 🔍 Scans for malicious packages using OSV (MAL- advisories) and GitHub Security Advisory
- 📄 Supports multiple package manifest formats
- 🎨 Colored terminal output with bright red highlighting for malicious packages
- 📊 JSON output mode for CI/CD integration
- 💾 File output for reports and archiving
- 🚀 Perfect for automated security scanning in development workflows
