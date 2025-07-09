# MALOSS - Identify Malicious Open-Source Software

![MALOSS](images/MALOSS-square-image-smaller.jpeg)

MALOSS (pronounced "malice"), scans package manifest files to see if any of the libraries and packages are malicious. It does this by analyzing local package manifest files, or remote package files, and checking both [OSV](https://osv.dev) and [GitHub Security Advisory (GHSA)](https://github.com/advisories) for known malicious packages.  

Incredibly, SCA tools don't help you identify malicious packages.  I know, this is crazy, but its true.  MALOSS is the missing piece to the SCA puzzle that I needed but couldn't find.  You can use MALOSS manually at the command line, but you can also use it in you CI/CD pipelines and to scan GitHub, GitLab and other repos directly.

## Installation

```bash
git clone https://github.com/6mile/MALOSS.git
cd ./MALOSS/
pip install beautifulsoup4 tomli requests
```

## How to use MALOSS

### Scan local package.json file
 
```bash
python3 maloss.py package.json
```

## Command Line Options

- `--remote`, `-r`: Remote mode - scan remote files via URLs
- `--json`, `-j`: JSON mode - outputs structured JSON data instead of human-readable format
- `--output`, `-o`: Write report to specified file instead of console output
- `--no-color`: Disable colored output (useful for logs or unsupported terminals)

## Supported File Types

- `package.json` - Node.js dependencies
- `package-lock.json` - Node.js lockfile with exact versions
- `pyproject.toml` - Python project dependencies (PEP 621, Poetry, etc.)
- `requirements.txt` - Python requirements file

## More detailed usage examples

### Scan local requirements.txt

```bash
python3 maloss.py requirements.txt
```

### Scan remote package file

```bash
python3 maloss.py -r https://github.com/oven-sh/bun/blob/main/package.json
```

### Write Human-Readable Report

```bash
python maloss.py package.json --output report.txt
```

Creates `report.txt`:
```
Scanning ./tests/malicious/package.json...
Found 3 packages in ./tests/malicious/package.json
Checking 1/3: validate-rb
Checking 2/3: express-exp
Checking 3/3: prettier

==========================================================================
MALOSS - MALICIOUS PACKAGE REPORT
==========================================================================

Total packages scanned: 3
Malicious packages found: 2

Findings by severity:
  Malware: 2

Detailed findings:
--------------------------------------------------------------------------

📦 Malicious Package: validate-rb
🆔 ID: MAL-2025-5294 (https://osv.dev/vulnerability/MAL-2025-5294)
⚠️  Severity: Malware
🔍 Source: OSV
📝 Summary: Malicious code in validate-rb (npm)
🎯 Affected versions: 1.0.0

📦 Malicious Package: express-exp
🆔 ID: MAL-2025-3238 (https://osv.dev/vulnerability/MAL-2025-3238)
⚠️  Severity: Malware
🔍 Source: OSV
📝 Summary: Malicious code in express-exp (npm)
🎯 Affected versions: 1.0.1
```

### Create JSON Report

```bash
python maloss.py package.json --json --output report.json
```

Creates `report.json`:
```json
{
  "analyzed_by": "MALOSS at 2025-06-30T10:05:01.590757",
  "total_packages_scanned": 3,
  "malicious_packages_found": 2,
  "remote_source": null,
  "findings": [
    {
      "package_name": "validate-rb",
      "id": "MAL-2025-5294",
      "severity": "Malware",
      "source": "OSV",
      "summary": "Malicious code in validate-rb (npm)",
      "affected_versions": [
        "1.0.0"
      ],
      "url": "https://osv.dev/vulnerability/MAL-2025-5294"
    },
    {
      "package_name": "express-exp",
      "id": "MAL-2025-3238",
      "severity": "Malware",
      "source": "OSV",
      "summary": "Malicious code in express-exp (npm)",
      "affected_versions": [
        "1.0.1"
      ],
      "url": "https://osv.dev/vulnerability/MAL-2025-3238"
    }
  ]
}
```

### No Vulnerabilities Found

```bash
python maloss.py package.json --output report.txt
```

Creates `report.txt`:
```
==========================================================================
MALOSS - MALICIOUS PACKAGE REPORT
==========================================================================

Total packages scanned: 3
Malicious packages found: 0

✅ No known malicious packages found!
```

## CI/CD Integration Examples

### Generate Reports for Artifacts

```bash
# Generate human-readable report for review
python maloss.py package.json --output report.txt

# Generate JSON for automated processing
python maloss.py package.json --json --output security-scan.json
```

### GitHub Actions Integration

```yaml
- name: Scan for malicious packages
  run: |
    python maloss.py package.json --json --output report.json
    
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
python maloss.py package.json --output "report-$DATE.txt"
python maloss.py package.json --json --output "report-$DATE.json"
```

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
