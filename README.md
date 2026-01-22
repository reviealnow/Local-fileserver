# Local-fileserver
A hardened HTTPS file server for local networks with authentication, audit logging, and image preview UI.
# 🔐 LAN File Server

> A hardened HTTPS file server for local networks with authentication, audit logging, and image preview UI.

![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![Security](https://img.shields.io/badge/security-hardened-green)
![HTTPS](https://img.shields.io/badge/https-enabled-brightgreen)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

---

## ✨ Features

- ✅ HTTPS (auto-generated self-signed certificates)
- ✅ User authentication (hashed passwords)
- ✅ Image preview UI
- ✅ Upload / Download / Delete
- ✅ Audit logging (who accessed what and when)
- ✅ Path traversal protection
- ✅ File type whitelist
- ✅ LAN-friendly deployment
- ✅ Zero external dependencies (Flask only)

---

## 📸 Screenshot

> Example UI running on a local network.

![UI Preview](docs/screenshot.png)

---

## 🚀 Quick Start (macOS / Linux)

```bash
git clone https://github.com/<YOUR_GITHUB>/<REPO_NAME>.git
cd <REPO_NAME>

python3 -m venv .venv
source .venv/bin/activate
pip install flask werkzeug

mkdir data
cp users.json.example users.json
