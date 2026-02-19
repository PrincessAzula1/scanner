# scanner
🎮 Usage Quick Start Launch as Administrator - Right-click → Run as Administrator Check Dashboard - Review system health score and BSOD risk Run Diagnostics - Select affected component and run tests Apply Fixes - Follow recommendations and apply automatic repairs Restart - Reboot when prompted to complete repairs

# BSOD Rescue Pro 🛠️

A comprehensive Windows diagnostic and repair suite designed to troubleshoot and resolve Blue Screen of Death (BSOD) errors, system crashes, and hardware failures.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![PyQt6](https://img.shields.io/badge/PyQt6-6.0+-green.svg)

## 🚨 What This Tool Fixes

BSOD Rescue Pro diagnoses and repairs the most common causes of Windows system crashes:

| Component | Issues Detected | Repairs Applied |
|-----------|----------------|-----------------|
| **Storage (SSD/HDD)** | Bad sectors, SMART failures, file system corruption | CHKDSK, sector remapping, health monitoring |
| **Memory (RAM)** | Faulty modules, bit errors, timing issues | Pattern testing, stress tests, module isolation |
| **Drivers** | Corrupted, outdated, conflicting drivers | Driver reset, conflict detection, update checks |
| **System Files** | Corrupted Windows files, component store damage | SFC, DISM, automatic repair |
| **Software Conflicts** | Incompatible programs, malware, bloatware | Clean boot config, removal assistance |
| **Power Management** | Fast Startup issues, sleep/hibernation crashes | Power plan optimization, Fast Startup control |

## ✨ Features

### 🔧 Diagnostic Modules

- **System Dashboard** - Real-time health monitoring with BSOD risk assessment
- **Storage Diagnostic** - Deep SMART analysis, bad sector scanning, file recovery
- **Driver Manager** - Complete driver inventory with corruption detection
- **Memory Test** - Pattern testing, stress tests, hardware validation
- **System Repair** - Automated SFC, DISM, and component store repair
- **Conflict Resolver** - Software conflict detection and resolution
- **Power Management** - Fast Startup control and power optimization
- **Event Analyzer** - BSOD history, minidump analysis, crash forensics

### 🎯 Key Capabilities

- **Automatic BSOD Detection** - Parses Event Logs and minidumps to identify crash causes
- **One-Click Repairs** - Automated fixes for common issues
- **Hardware Monitoring** - Real-time temperature, usage, and health tracking
- **Data Safety** - Creates restore points before repairs
- **Detailed Reporting** - Export comprehensive diagnostic reports

## 📋 Requirements

- **OS:** Windows 10/11 (64-bit)
- **Python:** 3.8 or higher
- **Privileges:** Administrator (for system repairs)
- **RAM:** 4GB minimum (8GB recommended for stress testing)
- **Disk:** 100MB free space

## 🚀 Installation

### Option 1: Run from Source

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/bsod-rescue-pro.git
cd bsod-rescue-pro

# Install dependencies
pip install -r requirements.txt

# Run the application (will request admin rights)
python main.py
