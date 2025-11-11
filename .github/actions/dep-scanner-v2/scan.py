"""
MISS Framework - Dependency Confusion Scanner (scan.py)
VERSION 2.0 - Auto-Discovery

This script automatically scans an entire repository for package files
(package.json, requirements.txt, Gemfile), parses them, and checks
for potential Dependency Confusion vulnerabilities.

It uses a config file to understand what defines an "internal" package
(e.g., a scope like '@acme' or a prefix like 'acme-').

It only flags packages that appear to be internal but are *unscoped*
and *exist* on the public registry.
"""

import os
import re
import requests
import json
import argparse
import time
from urllib.parse import urlparse

# API endpoints for public registries
REGISTRIES = {
    "npm": "https://registry.npmjs.org/{}",
    "pypi": "https://pypi.org/pypi/{}/json",
    "ruby": "https://rubygems.org/api/v1/gems/{}.json"
}

REQUEST_HEADERS = {
    'User-Agent': 'MISS-Framework-Dep-Scanner/2.0'
}

# --- Package Discovery Functions ---

def find_manifest_files(root_dir):
    """Finds all package manifest files in the repository."""
    manifests = {"npm": [], "pypi": [], "ruby": []}
    for root, _, files in os.walk(root_dir):
        if 'node_modules' in root or '.git' in root:
            continue

        if 'package.json' in files:
            manifests["npm"].append(os.path.join(root, 'package.json'))
        if 'requirements.txt' in files:
            manifests["pypi"].append(os.path.join(root, 'requirements.txt'))
        if 'Gemfile' in files:
            manifests["ruby"].append(os.path.join(root, 'Gemfile'))
    return manifests

def parse_npm(filepath):
    """Extracts all dependencies from a package.json file."""
    packages = set()
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
            for key in ('dependencies', 'devDependencies', 'peerDependencies'):
                if key in data:
                    packages.update(data[key].keys())
    except Exception as e:
        print(f"Warning: Could not parse {filepath}: {e}")
    return packages

def parse_pypi(filepath):
    """Extracts all dependencies from a requirements.txt file."""
    packages = set()
    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    # Get the package name, stripping versions, comments, etc.
                    pkg = re.split(r'[=<>~#\s]', line)[0]
                    if pkg:
                        packages.add(pkg)
    except Exception as e:
        print(f"Warning: Could not parse {filepath}: {e}")
    return packages

def parse_ruby(filepath):
    """Extracts all dependencies from a Gemfile."""
    packages = set()
    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith('gem '):
                    # Simple regex to get the gem name
                    match = re.search(r"gem\s+['\"]([^'\"]+)['\"]", line)
                    if match:
                        packages.add(match.group(1))
    except Exception as e:
        print(f"Warning: Could not parse {filepath}: {e}")
    return packages

# --- Vulnerability Checking ---

def check_public_registry(package_name, registry_type):
    """Checks if a package exists on a specific public registry."""
    if registry_type not in REGISTRIES:
        return False

    url = REGISTRIES[registry_type].format(package_name)
    try:
        response = requests.get(url, timeout=5, headers=REQUEST_HEADERS)
        if response.status_code == 200:
            return True # VULNERABLE: Package exists
        return False
    except requests.exceptions.RequestException:
        return False

def main():
    parser = argparse.ArgumentParser(description="MISS Framework Dependency Confusion Scanner (v2)")
    parser.add_argument("--root-dir", required=True, help="Root directory of the repository to scan")
    parser.add_argument("--config", required=True, help="Path to the internal package config JSON file")
    parser.add_argument("--output", default="dependency_report.json", help="Output JSON report file")
    args = parser.parse_args()

    print(f"Starting Automated Dependency Confusion Scan...")
    print(f"Loading internal package rules from: {args.config}")

    try:
        with open(args.config, 'r') as f:
            config = json.load(f)
        internal_rules = config.get("internal_package_rules", {})
        internal_scopes = internal_rules.get("scopes", [])
        internal_prefixes = internal_rules.get("prefixes", [])

        if not internal_scopes and not internal_prefixes:
            print("CRITICAL ERROR: Config file missing 'scopes' or 'prefixes'. Cannot determine internal packages.")
            exit(1)

    except Exception as e:
        print(f"CRITICAL ERROR: Could not read or parse config file {args.config}. {e}")
        exit(1)

    print(f"Scanning {args.root_dir} for manifest files...")
    manifest_files = find_manifest_files(args.root_dir)

    vulnerabilities = []
    packages_found = {} # To track where we found each package

    # --- 1. Auto-Discovery Phase ---
    print("Parsing manifest files...")
    all_packages = {"npm": set(), "pypi": set(), "ruby": set()}

    for filepath in manifest_files["npm"]:
        print(f"  -> Parsing npm: {filepath}")
        for pkg in parse_npm(filepath):
            all_packages["npm"].add(pkg)
            packages_found.setdefault(pkg, []).append(filepath)

    for filepath in manifest_files["pypi"]:
        print(f"  -> Parsing pypi: {filepath}")
        for pkg in parse_pypi(filepath):
            all_packages["pypi"].add(pkg)
            packages_found.setdefault(pkg, []).append(filepath)

    for filepath in manifest_files["ruby"]:
        print(f"  -> Parsing ruby: {filepath}")
        for pkg in parse_ruby(filepath):
            all_packages["ruby"].add(pkg)
            packages_found.setdefault(pkg, []).append(filepath)

    # --- 2. Analysis Phase ---
    print("\nAnalyzing packages against internal rules...")
    total_checked = 0

    for ecosystem, packages in all_packages.items():
        if not packages:
            continue

        print(f"\nChecking {len(packages)} unique packages for '{ecosystem}'...")

        for package_name in packages:
            total_checked += 1
            is_internal = False
            is_scoped = False

            # Check if it matches an internal scope (e.g., @acme/tool)
            if any(package_name.startswith(scope) for scope in internal_scopes):
                is_internal = True
                is_scoped = True

            # Check if it matches an internal prefix (e.g., acme-tool)
            elif any(package_name.startswith(prefix) for prefix in internal_prefixes):
                is_internal = True
                is_scoped = False

            # This is a public package (e.g., 'react', 'django')
            if not is_internal:
                print(f"  -> Skipping Public Package: '{package_name}'")
                continue

            # This is an internal, *scoped* package (e.g., '@acme/tool')
            # This is the "safe" way to do internal packages.
            if is_scoped:
                print(f"  -> Skipping Internal Scoped Package: '{package_name}'")
                continue

            # --- DANGER ZONE ---
            # This is an internal, *un-scoped* package (e.g., 'acme-tool')
            # We must check if it exists on the public registry.
            print(f"  -> Checking Unscoped Internal Package: '{package_name}'...")

            if check_public_registry(package_name, ecosystem):
                print(f"  -> CRITICAL: Found public package for '{package_name}' on {ecosystem}!")
                vuln = {
                    "package_name": package_name,
                    "ecosystem": ecosystem,
                    "vulnerability_type": f"CRITICAL: An internal package name is 'squatted' on the public '{ecosystem}' registry.",
                    "fix": f"Rename this internal package to be unique, or scope it (e.g., '@your-scope/{package_name}').",
                    "found_in_files": list(set(packages_found.get(package_name, [])))
                }
                vulnerabilities.append(vuln)

            time.sleep(0.1) # Be nice to the APIs

    # --- 3. Reporting Phase ---
    report_data = {
        "summary": {
            "total_packages_analyzed": total_checked,
            "vulnerabilities_found": len(vulnerabilities),
            "internal_rules": {
                "scopes": internal_scopes,
                "prefixes": internal_prefixes
            }
        },
        "vulnerabilities": vulnerabilities
    }

    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(report_data, f, indent=2)

    print(f"\nScan complete. Report saved to {args.output}")

    if vulnerabilities:
        print(f"\nCRITICAL: Found {len(vulnerabilities)} dependency confusion vulnerabilities!")
        exit(1) # Fail the build
    else:
        print("\nSUCCESS: No dependency confusion vulnerabilities found.")
        exit(0) # Pass the build

if __name__ == "__main__":
    main()
