#!/usr/bin/env python3
"""
LiteLLM Security Incident Diagnostic Tool
==========================================

A diagnostic script to check if your system was affected by the LiteLLM 
supply chain incident on March 24, 2026 (versions 1.82.7 and 1.82.8).

IMPORTANT DISCLAIMER:
- This is an UNOFFICIAL community resource, not affiliated with LiteLLM/BerriAI
- This script is 100% OPEN SOURCE - please review before running
- This script is READ-ONLY - it only checks and reports, makes no changes
- No warranty or liability is provided - use at your own risk
- For official guidance, see: https://github.com/BerriAI/litellm/issues/24518

To review this script before running:
    cat litellm-security-check.py

Usage:
    python litellm-security-check.py
    
    # With verbose output
    python litellm-security-check.py --verbose
    
    # Output JSON report
    python litellm-security-check.py --json

Exit codes:
    0 - No issues found
    1 - Potentially affected (check report)
    2 - Confirmed affected (immediate action required)
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

__version__ = "1.0.0"

# Affected versions
AFFECTED_VERSIONS = {"1.82.7", "1.82.8"}
SAFE_VERSION_THRESHOLD = "1.82.6"

# Colors for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

    @classmethod
    def disable(cls):
        cls.RED = cls.GREEN = cls.YELLOW = cls.BLUE = ''
        cls.MAGENTA = cls.CYAN = cls.WHITE = cls.BOLD = cls.END = ''


def print_banner():
    """Print the tool banner."""
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════╗
║           LiteLLM Security Incident Diagnostic Tool              ║
║                                                                  ║
║  Checks for affected versions, malicious artifacts, and          ║
║  persistence mechanisms from the March 24, 2026 incident         ║
╚══════════════════════════════════════════════════════════════════╝
{Colors.END}
    """
    print(banner)
    
    disclaimer = f"""{Colors.WHITE}
  This is an UNOFFICIAL community resource for informational purposes.
  Please review this script's source code before running. No liability assumed.
  For official guidance: https://github.com/BerriAI/litellm/issues/24518
{Colors.END}
    """
    print(disclaimer)


def print_section(title: str):
    """Print a section header."""
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'─' * 60}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}  {title}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'─' * 60}{Colors.END}\n")


def print_result(status: str, message: str, details: str = ""):
    """Print a result line with appropriate color."""
    if status == "OK":
        symbol = f"{Colors.GREEN}✓{Colors.END}"
        color = Colors.GREEN
    elif status == "WARNING":
        symbol = f"{Colors.YELLOW}⚠{Colors.END}"
        color = Colors.YELLOW
    elif status == "CRITICAL":
        symbol = f"{Colors.RED}✗{Colors.END}"
        color = Colors.RED
    elif status == "INFO":
        symbol = f"{Colors.CYAN}ℹ{Colors.END}"
        color = Colors.CYAN
    else:
        symbol = "•"
        color = Colors.WHITE
    
    print(f"  {symbol} {color}{message}{Colors.END}")
    if details:
        print(f"    {Colors.WHITE}{details}{Colors.END}")


def run_command(cmd: List[str], capture_output: bool = True) -> Tuple[int, str, str]:
    """Run a shell command and return exit code, stdout, stderr."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=capture_output,
            text=True,
            timeout=30
        )
        return result.returncode, result.stdout, result.stderr
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
        return -1, "", str(e)


def find_python_environments(home_dir: Path) -> List[Path]:
    """Find all Python environments on the system."""
    environments = []
    
    # Common virtual environment patterns
    patterns = [
        "**/bin/python",
        "**/Scripts/python.exe",
        "**/.venv/bin/python",
        "**/venv/bin/python",
        "**/env/bin/python",
        "**/.env/bin/python",
    ]
    
    for pattern in patterns:
        try:
            for path in home_dir.rglob(pattern):
                if path.is_file() and os.access(path, os.X_OK):
                    env_path = path.parent.parent if "Scripts" not in str(path) else path.parent.parent
                    if env_path not in environments:
                        environments.append(env_path)
        except (PermissionError, OSError):
            continue
    
    return environments


def check_litellm_version_pip(python_path: Path) -> Optional[Tuple[str, str]]:
    """Check LiteLLM version using pip."""
    pip_cmd = python_path.parent / "pip"
    if not pip_cmd.exists():
        pip_cmd = python_path.parent / "pip3"
    
    if not pip_cmd.exists():
        # Try using python -m pip
        cmd = [str(python_path), "-m", "pip", "show", "litellm"]
    else:
        cmd = [str(pip_cmd), "show", "litellm"]
    
    exit_code, stdout, stderr = run_command(cmd)
    
    if exit_code == 0 and stdout:
        version = None
        location = None
        for line in stdout.split('\n'):
            if line.startswith('Version:'):
                version = line.split(':', 1)[1].strip()
            elif line.startswith('Location:'):
                location = line.split(':', 1)[1].strip()
        
        if version:
            return (version, location or str(python_path))
    
    return None


def find_site_packages_litellm(home_dir: Path) -> List[Tuple[str, Path]]:
    """Find LiteLLM in all site-packages directories."""
    findings = []
    
    try:
        for site_packages in home_dir.rglob("site-packages"):
            if not site_packages.is_dir():
                continue
            
            litellm_dir = site_packages / "litellm"
            if litellm_dir.exists() and litellm_dir.is_dir():
                # Try to find version from dist-info
                for dist_info in site_packages.glob("litellm-*.dist-info"):
                    metadata_file = dist_info / "METADATA"
                    if metadata_file.exists():
                        try:
                            content = metadata_file.read_text()
                            for line in content.split('\n'):
                                if line.startswith('Version:'):
                                    version = line.split(':', 1)[1].strip()
                                    findings.append((version, site_packages))
                                    break
                        except Exception:
                            pass
                        break
                else:
                    # No version found, mark as unknown
                    findings.append(("unknown", site_packages))
    except (PermissionError, OSError):
        pass
    
    return findings


def check_for_pth_files(home_dir: Path) -> List[Path]:
    """Check for malicious .pth files."""
    malicious_pth_files = []
    
    try:
        for pth_file in home_dir.rglob("*.pth"):
            if "litellm" in pth_file.name.lower():
                malicious_pth_files.append(pth_file)
    except (PermissionError, OSError):
        pass
    
    return malicious_pth_files


def check_persistence_artifacts() -> Dict[str, List[Path]]:
    """Check for persistence artifacts."""
    artifacts = {
        "sysmon_service": [],
        "sysmon_files": [],
        "tmp_files": [],
    }
    
    home = Path.home()
    
    # Check for sysmon systemd service
    systemd_paths = [
        Path("/etc/systemd/system/sysmon.service"),
        home / ".config/systemd/user/sysmon.service",
        Path("/usr/lib/systemd/system/sysmon.service"),
    ]
    
    for path in systemd_paths:
        if path.exists():
            artifacts["sysmon_service"].append(path)
    
    # Check for sysmon files
    sysmon_paths = [
        home / ".config/sysmon/sysmon.py",
        home / ".local/share/sysmon/sysmon.py",
        Path("/opt/sysmon/sysmon.py"),
    ]
    
    for path in sysmon_paths:
        if path.exists():
            artifacts["sysmon_files"].append(path)
    
    # Check for suspicious tmp files
    tmp_paths = [
        Path("/tmp/pglog"),
        Path("/tmp/.pg_state"),
        Path("/tmp/tpcp.tar.gz"),
    ]
    
    for path in tmp_paths:
        if path.exists():
            artifacts["tmp_files"].append(path)
    
    return artifacts


def check_package_caches() -> Dict[str, List[str]]:
    """Check package caches for affected versions."""
    cache_findings = {
        "pip": [],
        "uv": [],
        "poetry": [],
    }
    
    home = Path.home()
    
    # Check pip cache
    exit_code, stdout, _ = run_command(["pip", "cache", "list"])
    if exit_code == 0 and stdout:
        for line in stdout.split('\n'):
            if 'litellm' in line.lower():
                cache_findings["pip"].append(line.strip())
    
    # Check pip wheel cache directories
    pip_cache_paths = [
        home / "Library/Caches/pip/wheels",  # macOS
        home / ".cache/pip/wheels",  # Linux
        home / "AppData/Local/pip/Cache/wheels",  # Windows
    ]
    
    for cache_dir in pip_cache_paths:
        if cache_dir.exists():
            try:
                for wheel in cache_dir.rglob("litellm*"):
                    version = wheel.name.split("-")[1] if "-" in wheel.name else "unknown"
                    cache_findings["pip"].append(f"{wheel}: {version}")
            except (PermissionError, OSError):
                pass
    
    # Check UV cache
    uv_cache = home / ".cache/uv"
    if uv_cache.exists():
        try:
            for wheel in uv_cache.rglob("litellm*"):
                cache_findings["uv"].append(str(wheel))
        except (PermissionError, OSError):
            pass
    
    # Check Poetry cache
    poetry_cache_paths = [
        home / "Library/Caches/pypoetry",  # macOS
        home / ".cache/pypoetry",  # Linux
    ]
    
    for cache_dir in poetry_cache_paths:
        if cache_dir.exists():
            try:
                for artifact in cache_dir.rglob("litellm*"):
                    cache_findings["poetry"].append(str(artifact))
            except (PermissionError, OSError):
                pass
    
    return cache_findings


def check_kubernetes() -> Optional[Dict]:
    """Check Kubernetes for suspicious pods if kubectl is available."""
    kubectl_check = run_command(["kubectl", "version", "--client"])
    
    if kubectl_check[0] != 0:
        return None  # kubectl not available
    
    findings = {
        "suspicious_pods": [],
        "accessible": True
    }
    
    # Check for suspicious pods
    exit_code, stdout, _ = run_command([
        "kubectl", "get", "pods", "--all-namespaces", 
        "--no-headers"
    ])
    
    if exit_code == 0 and stdout:
        for line in stdout.split('\n'):
            if 'node-setup-' in line.lower():
                findings["suspicious_pods"].append(line.strip())
    
    return findings


def check_current_shell_env() -> Optional[str]:
    """Check if litellm is in current shell environment."""
    try:
        import litellm
        return getattr(litellm, "__version__", "unknown")
    except ImportError:
        return None


def generate_report(findings: Dict, args) -> str:
    """Generate a formatted text report."""
    lines = []
    
    lines.append("=" * 70)
    lines.append("LiteLLM Security Incident Diagnostic Report")
    lines.append(f"Generated: {datetime.now().isoformat()}")
    lines.append("=" * 70)
    lines.append("")
    
    # Summary
    lines.append("SUMMARY")
    lines.append("-" * 70)
    
    if findings["is_affected"]:
        lines.append("STATUS: ⚠️  AFFECTED - Immediate action recommended")
    elif findings["needs_attention"]:
        lines.append("STATUS: ⚠️  NEEDS ATTENTION - Review findings below")
    else:
        lines.append("STATUS: ✓  NO ISSUES FOUND")
    
    lines.append("")
    
    # Current environment
    if findings["current_env"]:
        lines.append(f"Current Python Environment: {findings['current_env']}")
        lines.append("")
    
    # Installed versions
    if findings["installed_versions"]:
        lines.append("INSTALLED LITELLM VERSIONS FOUND:")
        lines.append("-" * 70)
        for version, location in findings["installed_versions"]:
            status = "⚠️  AFFECTED" if version in AFFECTED_VERSIONS else "✓ OK"
            lines.append(f"  {status} - Version {version}")
            lines.append(f"           Location: {location}")
        lines.append("")
    
    # .pth files
    if findings["pth_files"]:
        lines.append("MALICIOUS .PTH FILES FOUND:")
        lines.append("-" * 70)
        for pth in findings["pth_files"]:
            lines.append(f"  ⚠️  {pth}")
        lines.append("")
    
    # Persistence artifacts
    if findings["persistence"]["found"]:
        lines.append("PERSISTENCE ARTIFACTS FOUND:")
        lines.append("-" * 70)
        for category, paths in findings["persistence"]["artifacts"].items():
            if paths:
                lines.append(f"  {category}:")
                for path in paths:
                    lines.append(f"    - {path}")
        lines.append("")
    
    # Cache findings
    if any(findings["caches"].values()):
        lines.append("PACKAGE CACHE FINDINGS:")
        lines.append("-" * 70)
        for cache_type, items in findings["caches"].items():
            if items:
                lines.append(f"  {cache_type}:")
                for item in items:
                    lines.append(f"    - {item}")
        lines.append("")
    
    # Kubernetes
    if findings["kubernetes"]:
        lines.append("KUBERNETES FINDINGS:")
        lines.append("-" * 70)
        if findings["kubernetes"]["suspicious_pods"]:
            lines.append("  ⚠️  Suspicious pods found:")
            for pod in findings["kubernetes"]["suspicious_pods"]:
                lines.append(f"      {pod}")
        else:
            lines.append("  ✓ No suspicious pods found")
        lines.append("")
    
    # Recommendations
    lines.append("RECOMMENDATIONS")
    lines.append("-" * 70)
    if findings["is_affected"]:
        lines.append("1. Immediately rotate ALL credentials from affected systems:")
        lines.append("   - SSH keys")
        lines.append("   - Cloud provider credentials (AWS, GCP, Azure)")
        lines.append("   - AI API keys (OpenAI, Anthropic, etc.)")
        lines.append("   - Database passwords")
        lines.append("   - Kubernetes tokens")
        lines.append("")
        lines.append("2. Remove persistence artifacts if found")
        lines.append("3. Clear package caches: pip cache purge")
        lines.append("4. Consider rebuilding affected systems from clean state")
    elif findings["needs_attention"]:
        lines.append("1. Review the findings above")
        lines.append("2. Clear package caches as a precaution")
        lines.append("3. Monitor for any suspicious activity")
    else:
        lines.append("No immediate action required.")
        lines.append("Consider clearing package caches as a precaution.")
    
    lines.append("")
    lines.append("For more information: https://github.com/BerriAI/litellm/issues/24518")
    lines.append("=" * 70)
    
    return "\n".join(lines)


def perform_check(args) -> Dict:
    """Perform all security checks."""
    findings = {
        "is_affected": False,
        "needs_attention": False,
        "installed_versions": [],
        "pth_files": [],
        "persistence": {"found": False, "artifacts": {}},
        "caches": {},
        "kubernetes": None,
        "current_env": None,
    }
    
    print_banner()
    
    home_dir = Path.home()
    
    # Check 1: Current shell environment
    print_section("Checking Current Python Environment")
    current_version = check_current_shell_env()
    if current_version:
        findings["current_env"] = current_version
        if current_version in AFFECTED_VERSIONS:
            print_result("CRITICAL", f"LiteLLM {current_version} is LOADED in current environment", "This is an affected version!")
            findings["is_affected"] = True
        else:
            print_result("OK", f"LiteLLM {current_version} loaded - not an affected version")
    else:
        print_result("INFO", "LiteLLM not loaded in current Python environment")
    
    # Check 2: All site-packages installations
    print_section("Scanning Python Installations")
    print("  Scanning for LiteLLM in all Python environments...")
    
    site_packages_findings = find_site_packages_litellm(home_dir)
    
    if site_packages_findings:
        for version, location in site_packages_findings:
            findings["installed_versions"].append((version, str(location)))
            if version in AFFECTED_VERSIONS:
                print_result("CRITICAL", f"Affected version {version} found", location)
                findings["is_affected"] = True
            elif version == "unknown":
                print_result("WARNING", f"LiteLLM found (version unknown)", location)
                findings["needs_attention"] = True
            else:
                print_result("OK", f"Version {version} found - not affected", location)
    else:
        print_result("OK", "No LiteLLM installations found in site-packages")
    
    # Check 3: Virtual environments via pip
    print("\n  Checking virtual environments...")
    
    # Find Python executables
    python_paths = []
    for pattern in ["python", "python3", "bin/python", "bin/python3"]:
        try:
            result = subprocess.run(
                ["which", "-a", pattern],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line and line not in python_paths:
                        python_paths.append(Path(line))
        except Exception:
            pass
    
    checked_paths = set()
    for python_path in python_paths:
        if str(python_path) in checked_paths:
            continue
        checked_paths.add(str(python_path))
        
        result = check_litellm_version_pip(python_path)
        if result:
            version, location = result
            if (version, location) not in findings["installed_versions"]:
                findings["installed_versions"].append((version, location))
                if version in AFFECTED_VERSIONS:
                    print_result("CRITICAL", f"Affected version {version} in {python_path}")
                    findings["is_affected"] = True
    
    # Check 4: .pth files
    print_section("Checking for Malicious .pth Files")
    pth_files = check_for_pth_files(home_dir)
    
    if pth_files:
        findings["pth_files"] = pth_files
        for pth in pth_files:
            print_result("CRITICAL", f"Suspicious .pth file found: {pth}")
        findings["is_affected"] = True
    else:
        print_result("OK", "No malicious .pth files found")
    
    # Check 5: Persistence artifacts
    print_section("Checking for Persistence Artifacts")
    persistence = check_persistence_artifacts()
    
    has_persistence = any(persistence.values())
    findings["persistence"] = {"found": has_persistence, "artifacts": persistence}
    
    if has_persistence:
        print_result("CRITICAL", "Persistence artifacts found!")
        for category, paths in persistence.items():
            if paths:
                print(f"    {category}:")
                for path in paths:
                    print(f"      - {path}")
        findings["is_affected"] = True
    else:
        print_result("OK", "No persistence artifacts found")
    
    # Check 6: Package caches
    if args.check_caches:
        print_section("Checking Package Caches")
        caches = check_package_caches()
        findings["caches"] = caches
        
        found_in_cache = False
        for cache_type, items in caches.items():
            if items:
                found_in_cache = True
                print_result("WARNING", f"Found in {cache_type} cache:")
                for item in items[:5]:  # Limit output
                    print(f"      - {item}")
                if len(items) > 5:
                    print(f"      ... and {len(items) - 5} more")
        
        if not found_in_cache:
            print_result("OK", "No LiteLLM found in package caches")
    
    # Check 7: Kubernetes
    if args.check_kubernetes:
        print_section("Checking Kubernetes (if available)")
        k8s_findings = check_kubernetes()
        
        if k8s_findings is None:
            print_result("INFO", "kubectl not available or not configured")
        else:
            findings["kubernetes"] = k8s_findings
            if k8s_findings["suspicious_pods"]:
                print_result("CRITICAL", f"Found {len(k8s_findings['suspicious_pods'])} suspicious pod(s)")
                findings["is_affected"] = True
            else:
                print_result("OK", "No suspicious Kubernetes pods found")
    
    return findings


def main():
    parser = argparse.ArgumentParser(
        description="LiteLLM Security Incident Diagnostic Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python litellm-security-check.py              # Run all checks
  python litellm-security-check.py --verbose    # Detailed output
  python litellm-security-check.py --json       # JSON output
  python litellm-security-check.py --no-color   # Disable colors
        """
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    parser.add_argument(
        "--json", "-j",
        action="store_true",
        help="Output results as JSON"
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output"
    )
    parser.add_argument(
        "--check-caches",
        action="store_true",
        default=True,
        help="Check package caches (default: True)"
    )
    parser.add_argument(
        "--check-kubernetes", "-k",
        action="store_true",
        help="Check Kubernetes if available"
    )
    parser.add_argument(
        "--output", "-o",
        metavar="FILE",
        help="Save report to file"
    )
    
    args = parser.parse_args()
    
    if args.no_color:
        Colors.disable()
    
    try:
        findings = perform_check(args)
        
        # Generate report
        if args.json:
            report = json.dumps(findings, indent=2, default=str)
        else:
            report = generate_report(findings, args)
        
        # Output report
        print("\n" + "=" * 70)
        print(report)
        
        # Save to file if requested
        if args.output:
            with open(args.output, 'w') as f:
                f.write(report)
            print(f"\nReport saved to: {args.output}")
        
        # Exit with appropriate code
        if findings["is_affected"]:
            print(f"\n{Colors.RED}{Colors.BOLD}⚠️  AFFECTED: Immediate action required!{Colors.END}")
            sys.exit(2)
        elif findings["needs_attention"]:
            print(f"\n{Colors.YELLOW}{Colors.BOLD}⚠️  Review recommended{Colors.END}")
            sys.exit(1)
        else:
            print(f"\n{Colors.GREEN}{Colors.BOLD}✓ No issues found{Colors.END}")
            sys.exit(0)
            
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}Scan interrupted by user{Colors.END}")
        sys.exit(130)
    except Exception as e:
        print(f"\n{Colors.RED}Error: {e}{Colors.END}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(3)


if __name__ == "__main__":
    main()
