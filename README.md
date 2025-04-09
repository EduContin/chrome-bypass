# Chrome Cookie Extractor

[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![Windows](https://img.shields.io/badge/platform-windows-lightgrey.svg)](https://www.microsoft.com/windows)

A proof of concept demonstrating the extraction of cookies from Chrome and Chromium-based browsers, including those protected by app-bound encryption (v10/v11/v20).

## Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Technical Details](#technical-details)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)
- [Disclaimer](#disclaimer)

## Overview
Modern browsers have implemented app-bound encryption to protect sensitive data like cookies and passwords. This tool demonstrates how to extract cookies using both direct database access and Chrome's remote debugging protocol as a bypass method.

## Features
- Extracts cookies from all Chrome profiles
- Handles app-bound encrypted cookies (v10, v11, v20)
- Uses multiple extraction techniques:
  - Direct database access with decryption
  - Chrome remote debugging protocol as fallback
- Cross-profile support (Default and all user profiles)
- JSON output format for easy parsing

## Requirements
- Windows OS
- Python 3.7+
- Google Chrome or Chromium-based browser
- Administrator privileges (for database access)

## Installation
1. Clone this repository or download the source files
2. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage
1. Close all running Chrome instances (recommended)
2. Run the script:
   ```bash
   python chrome_cookie_extractor.py
   ```
3. The extracted cookies will be saved to `extracted_cookies.json` in the current directory

Example output format:
```json
{
  "Default": [
    {
      "host_key": ".example.com",
      "name": "session",
      "path": "/",
      "value": "abcdef123456",
      "expires_utc": 1777983785,
      "is_secure": true,
      "is_httponly": true,
      "creation_utc": 1743423553645002,
      "last_access_utc": 1743895419325000,
      "has_expires": true,
      "is_persistent": true,
      "priority": "medium",
      "samesite": "Lax",
      "source_scheme": "Secure",
      "source_port": 0
    },
    ...
  ],
  "Profile 1": [
    ...
  ]
}
```

## Technical Details

### Chrome Encryption Methods
Chrome uses multiple encryption methods to protect sensitive data:

1. **DPAPI (Data Protection API)** - Used on Windows for older versions
2. **AES-GCM with app-bound keys** - Used in newer Chrome versions (v10/v11)

### Extraction Methods

#### Database Extraction
1. Retrieves the master encryption key from Chrome's `Local State` file
2. Decrypts the master key using Windows DPAPI
3. Creates a temporary copy of the Cookies database to avoid lock issues
4. Reads and decrypts cookie values using the appropriate algorithm based on prefix

#### Remote Debugging Protocol Bypass
1. Launches Chrome with debugging enabled on port 9222
2. Connects to the WebSocket debugging endpoint
3. Uses the `Network.getAllCookies` API command to extract all cookies
4. This method bypasses the need for decryption as Chrome provides already-decrypted values

## Security Considerations
- This tool can extract sensitive information including authenticated session cookies
- Chrome's app-bound encryption provides protection against simple database copying but can be bypassed using the debugging protocol
- Site isolation and domain-specific cookies help mitigate the risk of cookie theft

## Troubleshooting
- **Error: Local State file not found** - Verify Chrome is installed and the user data directory is accessible
- **Database locked errors** - Close all Chrome instances before running
- **Decryption failures** - May indicate a new encryption method or incorrect master key extraction
- **Debug port connection failures** - Check if another process is using port 9222 or if Chrome is blocked by security software

## Disclaimer
This tool is for educational and research purposes only. Use responsibly and only on systems you own or have explicit permission to test. Unauthorized access to browser data may violate privacy laws and terms of service agreements.
