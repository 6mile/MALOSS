#!/usr/bin/env node

/**
 * Package Security Vulnerability Scanner
 * 
 * This script parses package.json, package-lock.json, pyproject.toml, and requirements.txt 
 * files to extract package names and versions, then checks for known vulnerabilities using 
 * OSV and GitHub Security Advisory APIs.
 */

const fs = require('fs').promises;
const path = require('path');
const https = require('https');
const http = require('http');
const { URL } = require('url');
const { promisify } = require('util');

// colours
const red = '\\x1b[31m';
const green = '\\x1b[32m';
const reset = '\\x1b[0m';

class RemoteFileDownloader {
    /**
     * Convert GitHub web URL to raw content URL
     */
    static githubUrlToRaw(githubUrl) {
        if (!githubUrl.includes('github.com')) {
            throw new Error('URL must be from github.com');
        }
        
        if (githubUrl.includes('/blob/')) {
            // https://github.com/user/repo/blob/main/package.json
            let rawUrl = githubUrl.replace('github.com', 'raw.githubusercontent.com');
            rawUrl = rawUrl.replace('/blob/', '/');
            return rawUrl;
        } else if (githubUrl.includes('raw.githubusercontent.com')) {
            // Already a raw URL
            return githubUrl;
        } else {
            throw new Error('URL must be a valid GitHub file URL (with /blob/)');
        }
    }

    /**
     * Convert GitLab web URL to raw content URL
     */
    static gitlabUrlToRaw(gitlabUrl) {
        if (!gitlabUrl.includes('gitlab.com') && !gitlabUrl.includes('gitlab.')) {
            throw new Error('URL must be from GitLab');
        }

        if (gitlabUrl.includes('/-/blob/')) {
            // https://gitlab.com/user/repo/-/blob/main/package.json
            return gitlabUrl.replace('/-/blob/', '/-/raw/');
        } else if (gitlabUrl.includes('/blob/')) {
            // https://gitlab.com/user/repo/blob/main/package.json
            return gitlabUrl.replace('/blob/', '/-/raw/');
        } else if (gitlabUrl.includes('/-/raw/')) {
            // Already a raw URL
            return gitlabUrl;
        } else {
            throw new Error('URL must be a valid GitLab file URL (with /blob/ or /-/blob/)');
        }
    }

    /**
     * Download file from URL and return local path
     */
    static async downloadFile(url, targetFilename = null) {
        try {
            let rawUrl = url;

            // Convert to raw format based on platform
            if (url.includes('github.com')) {
                rawUrl = RemoteFileDownloader.githubUrlToRaw(url);
            } else if (url.includes('gitlab.com') || url.includes('gitlab.')) {
                rawUrl = RemoteFileDownloader.gitlabUrlToRaw(url);
            }

            // Download the file
            const content = await this.httpGet(rawUrl);
            
            // Determine filename
            if (!targetFilename) {
                const parsedUrl = new URL(rawUrl);
                targetFilename = path.basename(parsedUrl.pathname) || 'downloaded_manifest';
            }
            
            // Create maloss directory in /tmp/
            const malossDir = '/tmp/maloss';
            await fs.mkdir(malossDir, { recursive: true });
            
            // Create full file path
            const tempFilePath = path.join(malossDir, targetFilename);
            
            // Write content to file
            await fs.writeFile(tempFilePath, content, 'utf8');
            
            return tempFilePath;
            
        } catch (error) {
            throw new Error(`Failed to download file from ${url}: ${error.message}`);
        }
    }

    /**
     * HTTP GET request helper
     */
    static httpGet(url) {
        return new Promise((resolve, reject) => {
            const client = url.startsWith('https:') ? https : http;
            const options = {
                headers: {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }
            };

            const req = client.get(url, options, (res) => {
                if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
                    // Handle redirects
                    return this.httpGet(res.headers.location).then(resolve).catch(reject);
                }
                
                if (res.statusCode !== 200) {
                    reject(new Error(`HTTP ${res.statusCode}: ${res.statusMessage}`));
                    return;
                }

                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => resolve(data));
            });

            req.on('error', reject);
            req.setTimeout(30000, () => {
                req.destroy();
                reject(new Error('Request timeout'));
            });
        });
    }

    /**
     * Clean up temporary downloaded file
     */
    static async cleanupTempFile(filePath) {
        try {
            await fs.unlink(filePath);
        } catch (error) {
            // Ignore cleanup errors
        }
    }
}

// ANSI color codes for terminal output
class Colors {
    static RED = '\x1b[91m';
    static BRIGHT_RED = '\x1b[1;91m';
    static GREEN = '\x1b[92m';
    static YELLOW = '\x1b[93m';
    static BLUE = '\x1b[94m';
    static MAGENTA = '\x1b[95m';
    static CYAN = '\x1b[96m';
    static WHITE = '\x1b[97m';
    static BOLD = '\x1b[1m';
    static UNDERLINE = '\x1b[4m';
    static END = '\x1b[0m';

    /**
     * Remove ANSI color codes from text
     */
    static stripColors(text) {
        return text.replace(/\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])/g, '');
    }
}

class Package {
    constructor(name, version, fileSource) {
        this.name = name;
        this.version = version;
        this.fileSource = fileSource;
    }
}

class Vulnerability {
    constructor(id, summary, severity, packageName, affectedVersions, source, url = null) {
        this.id = id;
        this.summary = summary;
        this.severity = severity;
        this.packageName = packageName;
        this.affectedVersions = affectedVersions;
        this.source = source;
        this.url = url;
    }
}

class PackageParser {
    /**
     * Parse package.json file and extract dependencies
     */
    static async parsePackageJson(filePath) {
        const packages = [];
        
        try {
            const content = await fs.readFile(filePath, 'utf8');
            const data = JSON.parse(content);
            
            // Parse dependencies and devDependencies
            const depTypes = ['dependencies', 'devDependencies', 'peerDependencies'];
            for (const depType of depTypes) {
                if (data[depType]) {
                    for (const [name, version] of Object.entries(data[depType])) {
                        // Clean version string (remove ^, ~, >=, etc.)
                        const cleanVersion = version.replace(/^[^0-9]*/, '');
                        packages.push(new Package(name, cleanVersion, filePath));
                    }
                }
            }
        } catch (error) {
            console.error(`Error parsing ${filePath}: ${error.message}`);
        }
        
        return packages;
    }

    /**
     * Parse package-lock.json file and extract all installed packages
     */
    static async parsePackageLockJson(filePath) {
        const packages = [];
        
        try {
            const content = await fs.readFile(filePath, 'utf8');
            const data = JSON.parse(content);
            
            // Parse packages from lockfile v2/v3 format
            if (data.packages) {
                for (const [packagePath, packageInfo] of Object.entries(data.packages)) {
                    if (packagePath === "") continue; // Skip root package
                    
                    // Extract package name from path (remove node_modules/ prefix)
                    const name = packagePath.replace('node_modules/', '');
                    const version = packageInfo.version || 'unknown';
                    
                    if (name && version) {
                        packages.push(new Package(name, version, filePath));
                    }
                }
            }
            // Fallback: Parse dependencies from lockfile v1 format
            else if (data.dependencies) {
                const extractDeps = (depsDict, prefix = "") => {
                    for (const [name, info] of Object.entries(depsDict)) {
                        const version = info.version || 'unknown';
                        packages.push(new Package(name, version, filePath));
                        
                        // Recursively parse nested dependencies
                        if (info.dependencies) {
                            extractDeps(info.dependencies, `${prefix}${name}/`);
                        }
                    }
                };
                
                extractDeps(data.dependencies);
            }
        } catch (error) {
            console.error(`Error parsing ${filePath}: ${error.message}`);
        }
        
        return packages;
    }

    /**
     * Parse pyproject.toml file and extract dependencies
     */
    static async parsePyprojectToml(filePath) {
        const packages = [];
        
        try {
            const content = await fs.readFile(filePath, 'utf8');
            // Basic TOML parsing (simplified - you might want to use a proper TOML library)
            const data = this.parseToml(content);
            
            // Parse different dependency sections
            const dependencySections = [
                ['project', 'dependencies'],
                ['project', 'optional-dependencies'],
                ['tool', 'poetry', 'dependencies'],
                ['tool', 'poetry', 'dev-dependencies'],
                ['build-system', 'requires']
            ];
            
            for (const sectionPath of dependencySections) {
                let current = data;
                
                // Navigate to the section
                try {
                    for (const key of sectionPath) {
                        current = current[key];
                    }
                } catch (error) {
                    continue;
                }
                
                // Parse dependencies based on format
                if (Array.isArray(current)) {
                    // Handle build-system.requires format (list of strings)
                    for (const dep of current) {
                        const match = dep.match(/^([a-zA-Z0-9_.-]+)/);
                        if (match) {
                            const name = match[1];
                            // Extract version if present
                            const versionMatch = dep.match(/[><=!]+([0-9.]+)/);
                            const version = versionMatch ? versionMatch[1] : 'latest';
                            packages.push(new Package(name, version, filePath));
                        }
                    }
                } else if (typeof current === 'object' && current !== null) {
                    if (sectionPath[sectionPath.length - 1] === 'optional-dependencies') {
                        // Handle optional-dependencies (nested dict)
                        for (const [groupName, deps] of Object.entries(current)) {
                            if (Array.isArray(deps)) {
                                for (const dep of deps) {
                                    const match = dep.match(/^([a-zA-Z0-9_.-]+)/);
                                    if (match) {
                                        const name = match[1];
                                        const versionMatch = dep.match(/[><=!]+([0-9.]+)/);
                                        const version = versionMatch ? versionMatch[1] : 'latest';
                                        packages.push(new Package(name, version, filePath));
                                    }
                                }
                            }
                        }
                    } else {
                        // Handle poetry-style dependencies (dict format)
                        for (const [name, versionSpec] of Object.entries(current)) {
                            if (name === 'python') continue; // Skip python version specification
                            
                            if (typeof versionSpec === 'string') {
                                // Simple version string
                                const cleanVersion = versionSpec.replace(/^[^0-9]*/, '') || 'latest';
                                packages.push(new Package(name, cleanVersion, filePath));
                            } else if (typeof versionSpec === 'object' && versionSpec !== null) {
                                // Complex version specification
                                const version = versionSpec.version || 'latest';
                                const cleanVersion = String(version).replace(/^[^0-9]*/, '') || 'latest';
                                packages.push(new Package(name, cleanVersion, filePath));
                            }
                        }
                    }
                }
            }
        } catch (error) {
            console.error(`Error parsing ${filePath}: ${error.message}`);
        }
        
        return packages;
    }

    /**
     * Basic TOML parser (simplified)
     */
    static parseToml(content) {
        const result = {};
        const lines = content.split('\n');
        let currentSection = result;
        let currentPath = [];
        
        for (const line of lines) {
            const trimmed = line.trim();
            if (!trimmed || trimmed.startsWith('#')) continue;
            
            // Handle section headers [section.subsection]
            if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
                const sectionName = trimmed.slice(1, -1);
                const parts = sectionName.split('.');
                currentPath = parts;
                currentSection = result;
                
                for (const part of parts) {
                    if (!currentSection[part]) {
                        currentSection[part] = {};
                    }
                    currentSection = currentSection[part];
                }
                continue;
            }
            
            // Handle key-value pairs
            const equalIndex = trimmed.indexOf('=');
            if (equalIndex > 0) {
                const key = trimmed.slice(0, equalIndex).trim();
                let value = trimmed.slice(equalIndex + 1).trim();
                
                // Remove quotes
                if ((value.startsWith('"') && value.endsWith('"')) || 
                    (value.startsWith("'") && value.endsWith("'"))) {
                    value = value.slice(1, -1);
                }
                
                // Handle arrays (simplified)
                if (value.startsWith('[') && value.endsWith(']')) {
                    const items = value.slice(1, -1).split(',').map(item => {
                        item = item.trim();
                        if ((item.startsWith('"') && item.endsWith('"')) || 
                            (item.startsWith("'") && item.endsWith("'"))) {
                            return item.slice(1, -1);
                        }
                        return item;
                    });
                    currentSection[key] = items;
                } else {
                    currentSection[key] = value;
                }
            }
        }
        
        return result;
    }

    /**
     * Parse requirements.txt file and extract dependencies
     */
    static async parseRequirementsTxt(filePath) {
        const packages = [];
        
        try {
            const content = await fs.readFile(filePath, 'utf8');
            const lines = content.split('\n');
            
            for (const line of lines) {
                const trimmed = line.trim();
                // Skip comments and empty lines
                if (!trimmed || trimmed.startsWith('#')) continue;
                
                // Parse package==version or package>=version format
                const match = trimmed.match(/^([a-zA-Z0-9_.-]+)[><=!]+([0-9.]+)/);
                if (match) {
                    const [, name, version] = match;
                    packages.push(new Package(name, version, filePath));
                } else {
                    // Handle packages without version specifiers
                    const cleanMatch = trimmed.match(/^([a-zA-Z0-9_.-]+)/);
                    if (cleanMatch) {
                        packages.push(new Package(cleanMatch[1], 'latest', filePath));
                    }
                }
            }
        } catch (error) {
            console.error(`Error parsing ${filePath}: ${error.message}`);
        }
        
        return packages;
    }
}

class VulnerabilityChecker {
    constructor(jsonMode = false) {
        this.osvUrl = "https://api.osv.dev/v1/query";
        this.githubMalwareUrls = {
            npm: "https://github.com/advisories?query=type%3Amalware+ecosystem%3Anpm",
            pip: "https://github.com/advisories?query=type%3Amalware+ecosystem%3Apip"
        };
        this.githubMalwareCache = {
            npm: null,
            pip: null
        };
        this.jsonMode = jsonMode;
    }

    /**
     * Check package against OSV database, filtering for MAL- prefixed advisories only
     */
    async checkOsvVulnerability(pkg) {
        const vulnerabilities = [];
        
        // Determine ecosystem based on file source
        const fileName = path.basename(pkg.fileSource).toLowerCase();
        let ecosystem;
        if (['package.json', 'package-lock.json'].includes(fileName)) {
            ecosystem = "npm";
        } else if (['requirements.txt', 'pyproject.toml'].includes(fileName)) {
            ecosystem = "PyPI";
        } else {
            ecosystem = "npm"; // Default fallback
        }
        
        const query = {
            package: {
                name: pkg.name,
                ecosystem: ecosystem
            }
        };
        
        // Add version if not 'latest'
        if (pkg.version !== 'latest') {
            query.version = pkg.version;
        }
        
        try {
            const response = await this.httpPost(this.osvUrl, query);
            const data = JSON.parse(response);
            
            for (const vuln of data.vulns || []) {
                const vulnId = vuln.id || 'Unknown';
                
                // Filter: only include advisories that start with "MAL-"
                if (!vulnId.startsWith('MAL-')) {
                    continue;
                }
                
                const affectedVersions = [];
                for (const affected of vuln.affected || []) {
                    if (affected.versions) {
                        affectedVersions.push(...affected.versions);
                    }
                }
                
                vulnerabilities.push(new Vulnerability(
                    vulnId,
                    vuln.summary || 'No summary available',
                    'Malware', // Override severity for MAL- advisories
                    pkg.name,
                    affectedVersions,
                    'OSV',
                    `https://osv.dev/vulnerability/${vulnId}`
                ));
            }
        } catch (error) {
            if (!this.jsonMode) {
                console.error(`Error checking OSV for ${pkg.name}: ${error.message}`);
            }
        }
        
        return vulnerabilities;
    }

    /**
     * Check package against GitHub Security Advisory malware database
     */
    async checkGithubAdvisory(pkg) {
        const vulnerabilities = [];
        
        // Determine ecosystem based on file source
        const fileName = path.basename(pkg.fileSource).toLowerCase();
        let ecosystem;
        if (['package.json', 'package-lock.json'].includes(fileName)) {
            ecosystem = "npm";
        } else if (['requirements.txt', 'pyproject.toml'].includes(fileName)) {
            ecosystem = "pip";
        } else {
            ecosystem = "npm"; // Default fallback
        }
        
        try {
            // Fetch malware advisories for this ecosystem
            const advisories = await this.fetchGithubMalwareAdvisories(ecosystem);
            
            // Check if our package is mentioned in any advisory with strict matching
            for (const advisory of advisories) {
                const packageNameLower = pkg.name.toLowerCase();
                
                // Primary check: exact match in the extracted packages list
                if (advisory.packages.includes(packageNameLower)) {
                    vulnerabilities.push(new Vulnerability(
                        advisory.id,
                        advisory.title,
                        advisory.severity,
                        pkg.name,
                        ['All versions'], // Malware typically affects all versions
                        'GitHub',
                        advisory.url
                    ));
                    continue; // Skip the fallback check if we found an exact match
                }
                
                // Fallback check: strict word boundary matching in title and description
                const textToSearch = (advisory.title + " " + advisory.description).toLowerCase();
                
                // Use word boundaries to ensure exact package name matches
                const escapedName = packageNameLower.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
                const wordBoundaryPattern = '\\b' + escapedName + '\\b';
                const wordBoundaryRegex = new RegExp(wordBoundaryPattern);
                
                if (wordBoundaryRegex.test(textToSearch)) {
                    // Additional validation: make sure it's not a substring of a longer package name
                    const contextPattern = '(?:^|[\\s`"\'\\(])' + escapedName + '(?:[\\s`"\'\\)]|$)';
                    const contextRegex = new RegExp(contextPattern);
                    
                    if (contextRegex.test(textToSearch)) {
                        vulnerabilities.push(new Vulnerability(
                            advisory.id,
                            advisory.title,
                            advisory.severity,
                            pkg.name,
                            ['All versions'],
                            'GitHub',
                            advisory.url
                        ));
                    }
                }
            }
        } catch (error) {
            if (!this.jsonMode) {
                console.error(`Error checking GitHub Advisory for ${pkg.name}: ${error.message}`);
            }
        }
        
        return vulnerabilities;
    }

    /**
     * Fetch malware advisories from GitHub web interface for given ecosystem
     */
    async fetchGithubMalwareAdvisories(ecosystem) {
        if (this.githubMalwareCache[ecosystem] !== null) {
            return this.githubMalwareCache[ecosystem];
        }
        
        const advisories = [];
        const url = this.githubMalwareUrls[ecosystem];
        
        try {
            const response = await RemoteFileDownloader.httpGet(url);
            
            // Basic HTML parsing (simplified - you might want to use a proper HTML parser)
            const advisoryMatches = response.match(/<div[^>]*class="[^"]*Box-row[^"]*"[^>]*>[\s\S]*?<\/div>/g);
            
            if (advisoryMatches) {
                for (const cardHtml of advisoryMatches) {
                    try {
                        // Extract advisory ID
                        const idMatch = cardHtml.match(/href="[^"]*\/advisories\/(GHSA-[^"]+)"/);
                        if (!idMatch) continue;
                        
                        const advisoryId = idMatch[1];
                        
                        // Extract title/summary
                        const titleMatch = cardHtml.match(/>([^<]+(?:malware|malicious)[^<]*)</i);
                        const title = titleMatch ? titleMatch[1].trim() : "No title available";
                        
                        // Extract severity
                        const severityMatch = cardHtml.match(/class="[^"]*Label[^"]*"[^>]*>([^<]+)</);
                        const severity = severityMatch ? severityMatch[1].trim() : "Unknown";
                        
                        // Extract description (simplified)
                        const descMatch = cardHtml.match(/<p[^>]*>([^<]+)</);
                        const description = descMatch ? descMatch[1].trim() : "";
                        
                        // Try to extract package names from the title or description
                        const packageNames = [];
                        
                        // Common patterns for package names in malware advisories
                        const patterns = ecosystem === "npm" ? 
                            [/`([a-z0-9_.-]+)`/gi, /"([a-z0-9_.-]+)"/gi] :
                            [/`([a-zA-Z0-9_.-]+)`/gi, /"([a-zA-Z0-9_.-]+)"/gi];
                        
                        for (const pattern of patterns) {
                            const matches = [...(title + " " + description).matchAll(pattern)];
                            packageNames.push(...matches.map(match => match[1].toLowerCase()));
                        }
                        
                        // Remove duplicates and filter valid package names
                        const uniquePackageNames = [...new Set(packageNames.filter(name => name.length > 1))];
                        
                        // Construct the full URL for this advisory
                        const advisoryUrl = `https://github.com/advisories/${advisoryId}`;
                        
                        advisories.push({
                            id: advisoryId,
                            title: title,
                            severity: severity,
                            description: description,
                            packages: uniquePackageNames,
                            url: advisoryUrl
                        });
                    } catch (error) {
                        console.error(`Error parsing advisory card: ${error.message}`);
                        continue;
                    }
                }
            }
        } catch (error) {
            if (!this.jsonMode) {
                console.error(`Error fetching GitHub malware advisories for ${ecosystem}: ${error.message}`);
            }
        }
        
        // Cache the results
        this.githubMalwareCache[ecosystem] = advisories;
        return advisories;
    }

    /**
     * HTTP POST request helper
     */
    async httpPost(url, data) {
        return new Promise((resolve, reject) => {
            const postData = JSON.stringify(data);
            const urlObj = new URL(url);
            
            const options = {
                hostname: urlObj.hostname,
                port: urlObj.port,
                path: urlObj.pathname,
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Content-Length': Buffer.byteLength(postData),
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }
            };

            const req = https.request(options, (res) => {
                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => resolve(data));
            });

            req.on('error', reject);
            req.setTimeout(10000, () => {
                req.destroy();
                reject(new Error('Request timeout'));
            });
            
            req.write(postData);
            req.end();
        });
    }
}

class SecurityScanner {
    constructor(jsonMode = false, noColor = false) {
        this.checker = new VulnerabilityChecker(jsonMode);
        this.jsonMode = jsonMode;
        this.noColor = noColor;
        this.remoteUrl = null; // Store remote URL for reporting
    }

    /**
     * Set the remote URL being scanned for reporting purposes
     */
    setRemoteUrl(url) {
        this.remoteUrl = url;
    }

    /**
     * Scan a single file for vulnerabilities
     */
    async scanFile(filePath) {
        let packages = [];
        const vulnerabilities = [];
        
        const fileName = path.basename(filePath).toLowerCase();
        
        // Determine parser based on filename
        if (fileName === 'package.json') {
            packages = await PackageParser.parsePackageJson(filePath);
        } else if (fileName === 'package-lock.json') {
            packages = await PackageParser.parsePackageLockJson(filePath);
        } else if (fileName === 'pyproject.toml') {
            packages = await PackageParser.parsePyprojectToml(filePath);
        } else if (fileName === 'requirements.txt') {
            packages = await PackageParser.parseRequirementsTxt(filePath);
        } else {
            if (!this.jsonMode) {
                console.error(`Unsupported file type: ${filePath}`);
                console.error("Supported files: package.json, package-lock.json, pyproject.toml, requirements.txt");
            }
            return [packages, vulnerabilities];
        }
        
        if (!this.jsonMode) {
            console.log(`Found ${packages.length} packages in ${filePath}`);
        }
        
        // Check each package for vulnerabilities
        for (let i = 0; i < packages.length; i++) {
            const pkg = packages[i];
            if (!this.jsonMode) {
                console.log(`Checking ${i + 1}/${packages.length}: ${pkg.name}`);
            }
            
            // Check OSV
            const osvVulns = await this.checker.checkOsvVulnerability(pkg);
            vulnerabilities.push(...osvVulns);
            
            // Check GitHub Advisory
            const githubVulns = await this.checker.checkGithubAdvisory(pkg);
            vulnerabilities.push(...githubVulns);
        }
        
        return [packages, vulnerabilities];
    }

    /**
     * Generate a security report and return the content
     */
    async generateReport(packages, vulnerabilities, outputFile = null) {
        if (!vulnerabilities.length) {
            if (this.jsonMode) {
                // Output empty JSON array in json mode
                if (outputFile) {
                    // Create JSON with metadata when writing to file (no findings case)
                    const timestamp = new Date().toISOString();
                    const jsonOutput = {
                        analyzed_by: `MALOSS at ${timestamp}`,
                        total_packages_scanned: packages.length,
                        malicious_packages_found: 0,
                        remote_source: this.remoteUrl || null,
                        findings: []
                    };
                    const jsonContent = JSON.stringify(jsonOutput, null, 2);
                    
                    await fs.writeFile(outputFile, jsonContent);
                    console.log(`JSON report written to: ${outputFile}`);
                    return jsonContent;
                } else {
                    // Console output: just empty array
                    const jsonContent = "[]";
                    console.log(jsonContent);
                    return jsonContent;
                }
            } else {
                // Human readable format
                if (!outputFile) {
                    console.log("\n" + "=".repeat(74));
                    console.log("MALOSS - MALICIOUS PACKAGE REPORT");
                    console.log("=".repeat(74));
                    console.log(`\nTotal packages scanned: ${packages.length}`);
                    console.log(`Malicious packages found: ${vulnerabilities.length}`);
                    console.log("\n✅ No known malicious packages found!");
                }
                
                // Also write to file if requested
                if (outputFile) {
                    let reportContent = "\n" + "=".repeat(74) + "\n";
                    reportContent += "MALOSS - MALICIOUS PACKAGE REPORT\n";
                    reportContent += "=".repeat(74) + "\n";
                    
                    // Add remote URL info if scanning remote file
                    if (this.remoteUrl) {
                        reportContent += `\nRemote source: ${this.remoteUrl}\n`;
                    }
                    
                    reportContent += `\nTotal packages scanned: ${packages.length}\n`;
                    reportContent += `Malicious packages found: ${vulnerabilities.length}\n`;
                    reportContent += "\nNo known malicious packages found!\n";
                    
                    await fs.writeFile(outputFile, reportContent);
                    console.log(`Report written to: ${outputFile}`);
                    return reportContent;
                }
                
                return "";
            }
        }

        if (this.jsonMode) {
            // Output vulnerabilities as JSON in json mode
            const vulnData = vulnerabilities.map(vuln => ({
                package_name: vuln.packageName,
                id: vuln.id,
                severity: vuln.severity,
                source: vuln.source,
                summary: vuln.summary,
                affected_versions: vuln.affectedVersions,
                url: vuln.url
            }));
            
            if (outputFile) {
                // Create JSON with metadata when writing to file
                const timestamp = new Date().toISOString();
                const jsonOutput = {
                    analyzed_by: `MALOSS at ${timestamp}`,
                    total_packages_scanned: packages.length,
                    malicious_packages_found: vulnerabilities.length,
                    remote_source: this.remoteUrl || null,
                    findings: vulnData
                };
                const jsonContent = JSON.stringify(jsonOutput, null, 2);
                
                await fs.writeFile(outputFile, jsonContent);
                console.log(`JSON report written to: ${outputFile}`);
                return jsonContent;
            } else {
                // Console output: just the findings array for easy parsing
                const jsonContent = JSON.stringify(vulnData, null, 2);
                console.log(jsonContent);
                return jsonContent;
            }
        }

        // Non-json mode: show detailed human-readable format
        let reportContent = "";
        
        // Build file content
        if (outputFile) {
            reportContent += "\n" + "=".repeat(74) + "\n";
            reportContent += "MALOSS MALICIOUS PACKAGE REPORT\n";
            reportContent += "=".repeat(74) + "\n";
            
            // Add remote URL info if scanning remote file
            if (this.remoteUrl) {
                reportContent += `\nRemote source: ${this.remoteUrl}\n`;
            }
            
            reportContent += `\nTotal packages scanned: ${packages.length}\n`;
            reportContent += `Malicious packages found: ${vulnerabilities.length}\n`;
        }
        
        // Print to console (if not writing to file only)
        if (!outputFile) {
            console.log("\n" + "=".repeat(74));
            console.log("MALOSS - MALICIOUS PACKAGE REPORT");
            console.log("=".repeat(74));
            console.log(`\nTotal packages scanned: ${packages.length}`);
            console.log(`Malicious packages found: ${vulnerabilities.length}`);
        }
        
        // Group vulnerabilities by severity
        const severityCounts = {};
        for (const vuln of vulnerabilities) {
            const severity = vuln.severity;
            severityCounts[severity] = (severityCounts[severity] || 0) + 1;
        }
        
        // Add severity info to both console and file content
        const fileSeverityText = `\nFindings by severity:\n` + 
            Object.entries(severityCounts).map(([severity, count]) => `  ${severity}: ${count}`).join('\n') + '\n';
        
        if (outputFile) {
            reportContent += fileSeverityText;
        }
        
        if (!outputFile) {
            console.log(`\nFindings by severity:`);
            for (const [severity, count] of Object.entries(severityCounts)) {
                console.log(`  ${severity}: ${count}`);
            }
        }
        
        // Add detailed vulnerabilities header
        const fileDetailedHeader = `\nDetailed findings:\n` + "-".repeat(74) + "\n";
        if (outputFile) {
            reportContent += fileDetailedHeader;
        }
            
        if (!outputFile) {
            console.log(`\nDetailed findings:`);
            console.log("-".repeat(74));
        }
        
        // Show detailed vulnerabilities
        for (const vuln of vulnerabilities) {
            // File output: clean format without emojis
            const filePackageLine = `Package: ${vuln.packageName}`;
            // Console output: with emojis and "Malicious Package" label
            const consolePackageLine = `📦 Malicious Package: ${vuln.packageName}`;
            
            // Add to file content (clean format without emojis)
            if (outputFile) {
                reportContent += `\n${filePackageLine}\n`;
            }
            
            // Print to console (with colors and emojis if enabled)
            if (!outputFile) {
                if (this.noColor) {
                    console.log(`\n${consolePackageLine}`);
                } else {
                    const coloredPackageLine = `${Colors.BRIGHT_RED}${consolePackageLine}${Colors.END}`;
                    console.log(`\n${coloredPackageLine}`);
                }
            }
            
            // Build other lines - different formats for file vs console
            const fileIdLine = vuln.url ? `ID: ${vuln.id} (${vuln.url})` : `ID: ${vuln.id}`;
            const consoleIdLine = vuln.url ? `🆔 ID: ${vuln.id} (${vuln.url})` : `🆔 ID: ${vuln.id}`;
            
            const fileSeverityLine = `Severity: ${vuln.severity}`;
            const consoleSeverityLine = `⚠️  Severity: ${vuln.severity}`;
            
            const fileSourceLine = `Source: ${vuln.source}`;
            const consoleSourceLine = `🔍 Source: ${vuln.source}`;
            
            const fileSummaryLine = `Summary: ${vuln.summary}`;
            const consoleSummaryLine = `📝 Summary: ${vuln.summary}`;
            
            // Add to file content (clean format)
            if (outputFile) {
                reportContent += `${fileIdLine}\n`;
                reportContent += `${fileSeverityLine}\n`;
                reportContent += `${fileSourceLine}\n`;
                reportContent += `${fileSummaryLine}\n`;
            }
            
            // Print to console (with emojis)
            if (!outputFile) {
                console.log(`${consoleIdLine}`);
                console.log(`${consoleSeverityLine}`);
                console.log(`${consoleSourceLine}`);
                console.log(`${consoleSummaryLine}`);
            }
            
            if (vuln.affectedVersions.length > 0) {
                const displayVersions = vuln.affectedVersions.slice(0, 5);
                let fileVersionsText = `Affected versions: ${displayVersions.join(', ')}`;
                let consoleVersionsText = `🎯 Affected versions: ${displayVersions.join(', ')}`;
                
                if (vuln.affectedVersions.length > 5) {
                    const remaining = vuln.affectedVersions.length - 5;
                    fileVersionsText += `\n   ... and ${remaining} more`;
                    consoleVersionsText += `\n   ... and ${remaining} more`;
                }
                
                if (outputFile) {
                    reportContent += `${fileVersionsText}\n`;
                }
                
                if (!outputFile) {
                    console.log(`${consoleVersionsText}`);
                }
            }
        }
        
        // Write to file if output_file is specified
        if (outputFile) {
            await fs.writeFile(outputFile, reportContent);
            console.log(`Report written to: ${outputFile}`);
        }
        
        return reportContent;
    }
}

function printBanner() {
    console.log(`==========================================================================
|   __  __            _       ____    _____  _____   |                   |
|  |  \\/  |    /\\    | |     / __ \\  / ____|/ ____|  |                   |
|  | \\  / |   /  \\   | |    | |  | || (___ | (___    |                   |
|  | |\\/| |  / /\\ \\  | |    | |  | | \\___ \\ \\___ \\   |                   |
|  | |  | | / ____ \\ | |____| |__| | ____) |____) |  |                   |
|  |_|  |_|/_/    \\_\\|______|\\____/ |_____/|_____/   |    Copyright 2025 |
|                                                    |            ${Colors.GREEN}v0.2.3${Colors.END} |
|     ${Colors.BRIGHT_RED}"Hunt for malicious open source software"${Colors.END}      |  ${Colors.GREEN}Created by 6mile${Colors.END} |
==========================================================================`);
}

async function main() {
    const args = process.argv.slice(2);
    const options = {
        files: [],
        output: null,
        json: false,
        noColor: false,
        remote: null
    };

    // Parse command line arguments
    for (let i = 0; i < args.length; i++) {
        const arg = args[i];
        if (arg === '--output' || arg === '-o') {
            options.output = args[++i];
        } else if (arg === '--json' || arg === '-j') {
            options.json = true;
        } else if (arg === '--no-color') {
            options.noColor = true;
        } else if (arg === '--remote' || arg === '-r') {
            options.remote = args[++i];
        } else if (arg === '--help' || arg === '-h') {
            console.log(`Usage: maloss [-h] [--output OUTPUT] [--json] [--no-color] [--remote REMOTE] [files ...]

Maloss scans package manifest files and checks OSV and GHSA to see if any of the packages you are using are malicious.

Arguments:
  files                    Path to package manifest files (package.json, package-lock.json, pyproject.toml, requirements.txt)

Options:
  --output, -o <file>      Output file for the report (optional)
  --json, -j               JSON mode: suppress all output except vulnerability details in JSON format (useful for CI/CD)
  --no-color               Disable colored output (useful for logs or unsupported terminals)  
  --remote, -r <url>       Download and scan a package manifest file from a GitHub or a GitLab URL
  --help, -h               Show this help message`);
            process.exit(0);
        } else if (!arg.startsWith('-')) {
            options.files.push(arg);
        }
    }

    // Validate arguments
    if (!options.remote && options.files.length === 0) {
        console.error("Error: Must provide either files to scan or use --remote flag (or use --help)");
        process.exit(1);
    }

    // Handle remote file download
    let remoteFilePath = null;
    if (options.remote) {
        if (!options.json) {
            console.log(`Downloading remote file: ${options.remote}`);
        }
        try {
            remoteFilePath = await RemoteFileDownloader.downloadFile(options.remote);
            if (!options.json) {
                console.log(`Downloaded to: ${remoteFilePath}`);
            }
        } catch (error) {
            if (!options.json) {
                console.error(`Error downloading remote file: ${error.message}`);
            } else {
                console.log("[]"); // Empty JSON for error in JSON mode
            }
            process.exit(1);
        }
    }

    // Only display banner and info in non-json mode
    if (!options.json) {
        printBanner();
    }

    const scanner = new SecurityScanner(options.json, options.noColor);
    const allPackages = [];
    const allVulnerabilities = [];

    // Set remote URL for reporting if scanning remote file
    if (options.remote) {
        scanner.setRemoteUrl(options.remote);
    }

    // Determine files to scan
    const filesToScan = options.remote ? [remoteFilePath] : options.files;

    // Scan files
    for (const filePath of filesToScan) {
        try {
            await fs.access(filePath);
        } catch (error) {
            if (!options.json) {
                console.error(`File not found: ${filePath}`);
            }
            continue;
        }

        if (!options.json) {
            if (options.remote) {
                console.log(`\nScanning remote file: ${options.remote}`);
            } else {
                console.log(`\nScanning ${filePath}...`);
            }
        }
        
        const [packages, vulnerabilities] = await scanner.scanFile(filePath);
        allPackages.push(...packages);
        allVulnerabilities.push(...vulnerabilities);
    }

    // Generate report
    await scanner.generateReport(allPackages, allVulnerabilities, options.output);

    // Clean up temporary file if used
    if (remoteFilePath) {
        await RemoteFileDownloader.cleanupTempFile(remoteFilePath);
    }

    // Exit with error code if vulnerabilities found
    process.exit(allVulnerabilities.length > 0 ? 1 : 0);
}

// Run the main function if this file is executed directly
if (require.main === module) {
    main().catch(error => {
        console.error(`Fatal error: ${error.message}`);
        process.exit(1);
    });
}

module.exports = {
    RemoteFileDownloader,
    Colors,
    Package,
    Vulnerability,
    PackageParser,
    VulnerabilityChecker,
    SecurityScanner,
    printBanner,
    main
};
