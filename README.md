# MiniDAV - Minimal WebDAV Server

**Author:** Philippe TEMESI  
**Website:** https://www.tems.be  
**Version:** 1.0  
**Year:** 2026

## Description

MiniDAV is a minimalistic WebDAV server written in Rust, lightweight and secure. It allows file sharing via the WebDAV protocol with HTTP Basic authentication and brute-force attack protection.

## Features

### Core WebDAV
- ✅ HTTP methods support: GET, PUT, DELETE, HEAD, OPTIONS
- ✅ WebDAV support: PROPFIND (directory listing), MKCOL (directory creation)
- ✅ Directory browsing via simple HTML interface
- ✅ File upload and download
- ✅ File and directory creation/deletion

### Security
- 🔐 Multi-user HTTP Basic authentication
- 🛡️ Brute-force protection (temporary blocking after X failures)
- 📁 Per-user isolation (lightweight chroot: each user sees their own root folder)
- 🚫 Path traversal detection (prevents `../` escape attempts)

### Logging
- 📝 Detailed access logs (IP, user, method, path, status, size)
- 📊 Error and warning logs
- 🐛 Debug mode for development
- 📁 Log file support

### Daemon Mode
- 🚀 Detach from terminal with `-d`
- 📦 systemd compatible (forking type)
- 🔧 Runs in background

## Usage

# Run in foreground
minidav --auth-file users.txt -p 8080

# Run in daemon mode
minidav --auth-file users.txt -p 8080 -d --log /var/log/minidav.log

# With custom brute-force protection
minidav --auth-file users.txt --max-attempts 3 --block-time 600
