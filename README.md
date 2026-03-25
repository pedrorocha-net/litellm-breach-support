# LiteLLM Security Incident Advisory

A one-page informational resource and diagnostic tool for the LiteLLM supply chain incident on March 24, 2026.

🌐 **Live Site**: https://pedrorocha-net.github.io/litellm-breach-support/

---

## What This Is

On March 24, 2026, LiteLLM versions 1.82.7 and 1.82.8 were compromised in a supply chain attack. This repository provides:

- 📖 **Interactive Advisory Page** - Comprehensive guide with incident details, risk assessment, and response steps
- 🚀 **Python Diagnostic Script** - Automated tool to check all your Python environments

---

## Quick Start: Diagnostic Tool

The fastest way to check if you're affected is to run our diagnostic script:

```bash
# Download the script
curl -O https://pedrorocha-net.github.io/litellm-breach-support/litellm-security-check.py

# Run it
python litellm-security-check.py
```

### What the Script Checks

- ✅ All Python installations and virtual environments
- ✅ Site-packages directories across your system
- ✅ Package caches (pip, uv, poetry)
- ✅ Malicious .pth files
- ✅ Persistence artifacts (systemd services, suspicious files)
- ✅ Kubernetes pods (optional)

### Script Options

```bash
# Output results as JSON
python litellm-security-check.py --json

# Save report to file
python litellm-security-check.py --output report.txt

# Include Kubernetes check
python litellm-security-check.py --check-kubernetes

# Disable colors (for CI/CD)
python litellm-security-check.py --no-color
```

### Exit Codes

- `0` - No issues found
- `1` - Review recommended
- `2` - Affected (immediate action required)

---

## Manual Quick Check

If you prefer to check manually:

```bash
# Check current environment
pip show litellm | grep Version

# Check for malicious .pth files
find ~ -name "litellm_init.pth" 2>/dev/null
```

---

## Setting Up GitHub Pages

To publish this site:

1. Go to your repository on GitHub
2. Click **Settings** → **Pages** (in the left sidebar)
3. Under **Source**, select **Deploy from a branch**
4. Select the `main` branch and `/ (root)` folder
5. Click **Save**

Your site will be available at: `https://pedrorocha-net.github.io/litellm-breach-support/`

---

## Key Facts

| | |
|---|---|
| **Affected Versions** | `1.82.7`, `1.82.8` |
| **Safe Versions** | `≤ 1.82.6` |
| **Exposure Window** | ~3 hours (March 24, 2026) |
| **Daily Downloads** | ~3.6 million |
| **Attacker** | TeamPCP |

---

## Files in This Repository

| File | Description |
|------|-------------|
| `index.html` | Main advisory page with full incident details |
| `litellm-security-check.py` | Python diagnostic script |
| `README.md` | This file |

---

## References

- [Official LiteLLM Security Advisory](https://github.com/BerriAI/litellm/issues/24518)
- [LiteLLM Security Update Blog](https://docs.litellm.ai/blog/security-update-march-2026)
- [Snyk Technical Analysis](https://snyk.io/articles/poisoned-security-scanner-backdooring-litellm/)

---

## About This Project

This is an **unofficial community resource** created to help organizations understand and respond to the LiteLLM security incident. It is not affiliated with, endorsed by, or connected to the LiteLLM project or BerriAI.

### The Diagnostic Script

The Python diagnostic script (`litellm-security-check.py`) is:
- **100% open source** - Review the code before running
- **Read-only** - It only checks and reports; it makes no changes to your system
- **Community-maintained** - Created to help the community respond to this incident

**You can (and should) review the script before running it:**
```bash
# Download and review
curl -O https://pedrorocha-net.github.io/litellm-breach-support/litellm-security-check.py
# Read the code
cat litellm-security-check.py
# Then run if you're comfortable
python litellm-security-check.py
```

### Important Notice

- This website and script are provided as-is for informational purposes only
- Always refer to the **official LiteLLM communications** for authoritative information
- The creators assume **no liability** for any damages arising from use of this resource
- You are responsible for reviewing and understanding any code before running it on your systems
- This is not professional security advice; consult with your security team for your specific situation
