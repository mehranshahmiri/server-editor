# Server Editor

A **secure, single-file PHP file manager and code editor** for Linux servers.  
Edit, upload, and manage files directly from your browser — **no SSH, no nano, no dependencies**.

Drop in. Use. Delete.

www.mehranshahmiri.com

---

## ✨ Features

- Single PHP file (no assets, no frameworks)
- Password-protected access
- Directory browsing (locked to a base path)
- Text file editor (binary-safe)
- Upload & download files
- Create, rename, delete files & folders
- View file size, permissions, modified time
- CSRF protection for write actions
- Mobile-friendly, clean UI
- Light / Dark mode (CSS only)

---

## 🔐 Security by Design

- Hard `BASE_PATH` restriction (no directory traversal)
- Escaped output to prevent XSS
- No shell execution, `eval`, or system calls
- Login rate limiting
- Optional IP allowlist
- Read-only detection for unsafe files

> ⚠️ Recommended: delete the file after use.

---

## 🚀 Installation

1. Upload `server-editor.php` to your server
2. Open it in your browser : https://yourdomain[dot]com/server-editor.php
3. Set a strong password inside the file
4. Use responsibly

---

## 🛠 Requirements

- PHP 7.4+
- Linux server (shared hosting / VPS)
- Standard file permissions

---

## ❌ What This Tool Will Never Do

- Execute shell commands
- Modify system users
- Access files outside `BASE_PATH`
- Act as a backdoor

This is a **utility**, not a control panel.

---

## 📦 Use Cases

- Emergency server edits
- Quick production hotfixes
- Mobile server access
- Shared hosting without SSH
- Teaching & demos

---

## 🧹 Cleanup

After finishing your work:
- Download changes
- **Delete `server-editor.php`**
- Clear browser cache/session

---

## 📜 License

MIT License — free to use, modify, and distribute.

---

## ❤️ Philosophy

Simple tools. Minimal surface area.  
Power without permanence.
