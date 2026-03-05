# UBEL ( Unified Bill / Enforced Law ) – Multi‑Ecosystem Security & Policy Enforcement CLI

Ubel is a fast, cross‑ecosystem security engine that resolves dependencies, generates PURLs, scans them through OSV.dev, and enforces security policies during installation to prevent supply-chain attacks. It works with:

- **PyPI** (via `ubel-pip`)
- **npm** (via `ubel-npm`)
- **Linux distributions** (Ubuntu-based, Debian-based, RHEL, AlmaLinux)

Ubel runs in **CLI**, **automation scripts**, and **CI/CD pipelines**, producing clean **JSON** and **PDF** reports.

---

## ✨ Features
- Full dependency resolution across ecosystems
- OSV.dev vulnerability scanning (batch API)
- Policy engine (block/allow by severity & infection)
- Checking linux-package or node/python dependency or entire project (`check` mode)
- Install‑time enforcement (`install` mode)
- Project‑level/Host-level/kernal-level scanning (`health` mode)
- Catches Non-CVEs
- It is a supply-chain protection tool
- Automatic report generation (JSON + PDF)
- Extremely fast (seconds per scan)

---

## 📦 Installation
```bash
pip install ubel
```

If you are on Linux, you need to:
- setup a virtual envirenment
- run enable the virtual envirenment
- then run: `pip install ubel`

Ubel exposes three binaries:

- `ubel` (Linux package scanning and OS-level operations: Ubuntu-based , Debian-based, Red Hat, Almalinux )
- `ubel-pip` (Python ecosystem)
- `ubel-npm` (Node.js ecosystem)

---

# 🚀 Usage Overview

## Main CLI
```
usage: ubel [-h] {check,install,health,init,allow,block} [extra_args ...]
```

## PyPI CLI
```
usage: ubel-pip [-h] {check,install,health,init,allow,block} [extra_args ...]
```

## npm CLI
```
usage: ubel-npm [-h] {check,install,health,init,allow,block} [extra_args ...]
```

---

# 🧠 Commands Explained

### **check**
Resolve dependencies/linux-packages → generate report → exit.

#### Python example:
```bash
ubel-pip check
```
If no extra arguments are passed, Ubel will:
- Detect `requirements.txt`
- Resolve all packages
- Scan them
- Output PDF + JSON

#### npm example:
```bash
ubel-npm check flask==3.1.0
```
If no args are passed, it will detect `package.json` automatically.

---

### **install**
Same as `check`, but enforces policies and either **blocks or allows** installation.

#### Python example:
```bash
ubel-pip install flask==3.1.0
```
Or auto-detect project requirements:
```bash
ubel-pip install
```

#### npm example:
```bash
ubel-npm install express@5.0.0
```
Or simply:
```bash
ubel-npm install
```
(uses `package.json` automatically)

---

### **health**
Scan the **entire machine** or **running project**, including:
- Installed PyPI packages
- Installed npm global packages
- OS-level packages (Ubuntu-based/Debian-based/RHEL/AlmaLinux)

Example:
( for linux )
```bash
ubel health
```
or ( for node.js app )
```bash
ubel-npm health
```
or ( for python app )
```bash
ubel-pip health
```

This mode produces large, detailed inventories and vulnerability matrices.

---

### **init**
Initialize a policy file for the project or system.

Example:
```bash
ubel init
```
Creates default policy:
```yaml
infections: block
severity:
  critical: block
  high: block
  medium: allow
  low: allow
  unknown: allow
```

---

### **allow / block**
Override Ubel's decision from CI/CD or scripted pipelines.

The arguments can be: "low", "medium", "high", "critical".

Example:
```bash
ubel block high critical
```
---

# 📁 Automatic Project Detection

For **npm** and **PyPI**, when running:
- `install`
- `check`

without arguments:

### Ubel automatically loads:
- `package.json` (for npm)
- `requirements.txt` (for pip)

This makes it ideal for CI/CD workflows.

---

# 📤 Output
Ubel generates:

### **1. JSON report**
Machine‑readable, includes:
- dependency list
- purls
- vulnerabilities
- severity
- infection state
- policy decision
- Generate complete SBOM-like machine inventory

### **2. PDF report**
Human‑readable, includes:
- summary statistics
- per‑dependency vulnerability details
- fix recommendations
- tables
- OSV reference links
- Generate complete SBOM-like machine inventory


---

# 🧩 Ecosystem Tools
- `ubel` → system packages, Linux distros
- `ubel-pip` → PyPI projects, virtual environments\
- `ubel-npm` → Node.js, npm, package.json projects


---
Ubel – Secure every dependency, before it reaches production.

