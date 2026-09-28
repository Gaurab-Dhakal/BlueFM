# BlueFM - Blue File Manager

<p align="center">
  <img src="https://raw.githubusercontent.com/username/bluefm/main/screenshots/bluefm-banner.png" alt="BlueFM Banner" width="100%" onerror="this.style.display='none'"/>
</p>

<p align="center">
  <strong>A modern, lightweight, single-file PHP web-based file manager engineered for shared cPanel hosting, strict PHP limits, and Imunify360 / ModSecurity WAF environments.</strong>
</p>

<p align="center">
  <a href="#features"><img src="https://img.shields.io/badge/Version-1.0-blue.svg" alt="Version 1.0"></a>
  <a href="#requirements"><img src="https://img.shields.io/badge/PHP-7.4%20|%208.0%20|%208.1%20|%208.2%20|%208.3+-indigo.svg" alt="PHP 7.4 - 8.3+"></a>
  <a href="#security"><img src="https://img.shields.io/badge/Imunify360-Hardened-emerald.svg" alt="Imunify360 Ready"></a>
  <a href="#zero-dependencies"><img src="https://img.shields.io/badge/Dependencies-Zero%20(Pure%20Vanilla)-success.svg" alt="Zero Dependencies"></a>
  <a href="#license"><img src="https://img.shields.io/badge/License-MIT-lightgrey.svg" alt="License MIT"></a>
</p>

---

## 💡 Why BlueFM?

Standard web file uploaders and managers frequently fail on shared cPanel hosting due to tight resource restrictions:
* **`upload_max_filesize`** and **`post_max_size`** limits (often capped at 2MB – 8MB).
* **`max_execution_time`** timeouts (30s) during large file transfers.
* **`memory_limit`** exhaustion when buffering large streams into PHP RAM.
* **Imunify360 / ModSecurity WAF false-positive triggers** (blocking requests with parameters like `cmd=`, `exec=`, `eval=`, or path traversal sequences `../`).

**BlueFM solves all of these problems.** It slices files into **2MB chunks** in the browser, uploads them sequentially via AJAX with automatic exponential retry, and reassembles them using zero-memory PHP stream pipes. It delivers a full cPanel & TinyFileManager experience in a **single `index.php` file** with **zero external dependencies**.

---

## ✨ Features

### 🚀 2MB Vanilla JS Chunked File Uploader
* **Bypass Hosting Limits**: Upload files of any size (even 5GB+) regardless of `upload_max_filesize` or `post_max_size`.
* **Automatic Exponential Retry**: If a chunk upload experiences a network hiccup or temporary server timeout, the client automatically pauses and retries up to **3 times** (`1s`, `2s`, `4s` delays).
* **Live Progress Widget**: Real-time progress bar, percentage counter, transfer speed (MB/s), and Estimated Time of Arrival (ETA).
* **Instant Close / Dismiss**: Floating upload drawer with immediate close button (`X`) and automatic graceful fadeout upon queue completion.
* **Batch Upload Queue**: Select or drag-and-drop multiple files at once.

### 🎨 Clean, Human-Friendly Light UI
* **Thoughtful Aesthetics**: Built with an approachable, clean light design system (soft slate canvas `#f8fafc`, crisp white elevated cards, friendly royal indigo accents `#4f46e5`, and warm amber folder iconography).
* **Zero External CDNs**: Pure HTML5, Vanilla CSS, and inline vector SVGs. No jQuery, no Bootstrap, no Tailwind, and no external Google Fonts required.
* **Fully Responsive**: Optimized for desktop, tablets, and smartphones.

### 🛠️ File Management & Productivity (TinyFileManager Power)
* **In-Browser Code & Text Editor**:
  * Edit scripts, configs, and text files (`.php`, `.html`, `.css`, `.js`, `.json`, `.sql`, `.env`, `.htaccess`, `.ini`, `.sh`, `.yml`, `.txt`).
  * Monospace font, line wrapping, tab-key indentation support.
  * **Keyboard Shortcut**: Press `Ctrl + S` (or `Cmd + S` on macOS) to save instantly without closing the editor.
* **Media & File Lightbox Previewer**:
  * **Images**: High-resolution preview for PNG, JPG, JPEG, GIF, WebP, SVG, BMP, ICO.
  * **Video**: HTML5 inline video player (`.mp4`, `.webm`).
  * **Audio**: HTML5 inline audio player (`.mp3`, `.wav`, `.ogg`).
  * **PDF**: Embedded browser PDF viewer.
* **ZIP Archive Compression & Extraction**:
  * **Unzip / Extract**: One-click extraction of `.zip` archives directly into the current folder.
  * **Create Zip**: Select one or multiple files/folders and archive them into `.zip`.
  * **Zip Slip Hardened**: Rejects any archive containing path traversal characters (`..`) to safeguard system files.
* **File Permissions (`chmod`)**: View octal permissions (`0644`, `0755`) and change permissions via a dedicated dialog.
* **Multi-Select Batch Actions**: Checkboxes with "Select All" to batch delete or batch zip multiple items simultaneously.
* **Create New Files & Folders**: Quick creation buttons in toolbar.
* **Duplicate / Copy**: Duplicate any file or folder with automated name incrementing (`filename_copy.php`).
* **Rename & Move**: Rename files/folders or relocate them within your storage directory.
* **Streaming Downloads**: Stream downloads in 64KB chunks to prevent PHP memory spikes on large files.
* **Real-time Filter**: Instant search/filter box as you type.
* **Interactive Breadcrumbs**: One-click navigation to ancestor directories.

### 📲 Progressive Web App (PWA) Standalone Installation
* **Direct Desktop & Mobile App**: Install BlueFM as a standalone application on Windows, macOS, Linux, ChromeOS, Android, and iOS.
* **Launch Without Browser**: Run directly from your Desktop, Taskbar, Start Menu, or Home Screen in its own dedicated, chromeless window without browser tabs or address bar.
* **1-Click Install Button**: Intuitive "Install App" button in both the header and sign-in screen using the native `beforeinstallprompt` API.
* **iOS Safari Guided Modal**: Interactive step-by-step instructions for iPhone and iPad users ("Add to Home Screen").
* **Service Worker Caching**: Ultra-fast app shell caching with full pass-through for file uploads, chunk streams, and server actions.

---

## 🔒 Security Hardening

* **Directory Traversal Protection**: Uses canonical `realpath()` resolution and strict prefix checking (`str_starts_with()`). Escaping the root storage folder via `../`, null bytes `\0`, or symlinks is impossible.
* **Imunify360 & ModSecurity Friendly**: All actions use clean, standard REST-style parameters (`upload_chunk`, `assemble_file`, `list`, `mkdir`, `save_file`). Avoids suspicious parameter names like `cmd`, `exec`, or `eval`.
* **Isolated Temporary Storage**: Uploaded chunks are isolated in `.fm_tmp/` with an auto-generated `.htaccess` file enforcing `Deny from all` and disabling the PHP engine (`php_flag engine off`).
* **Cryptographic CSRF Protection**: Every mutating request requires a unique session-bound token (`X-CSRF-Token`).
* **Bcrypt Credential Storage**: Custom credentials are encrypted using PHP `password_hash(..., PASSWORD_BCRYPT)` and saved to `.fm_auth.json` with restricted `0600` file permissions.
* **Dual-Layer Login Reliability**: Supports both asynchronous AJAX login and native browser form POST with server-side `302` redirects.

---

## 📋 Requirements

* **PHP**: 7.4 or higher (fully compatible with PHP 8.0, 8.1, 8.2, 8.3+)
* **PHP Extensions**: `session`, `json`, `mbstring`, `fileinfo` (standard on all cPanel hosts)
* **Zip Extension** (optional): `zip` (for Zip archive creation and extraction)
* **Web Server**: Apache, LiteSpeed, Nginx, or built-in PHP development server

---

## ⚡ Quick Start

### 1. Installation
Download `index.php` and upload it to any directory on your web server:

```bash
# Example: clone or copy index.php to your web directory
mkdir -p /home/user/public_html/filemanager
cp index.php /home/user/public_html/filemanager/index.php
```

### 2. Permissions
Ensure PHP has write permissions to create the `storage/` directory:
```bash
chmod 755 /home/user/public_html/filemanager
chmod 644 /home/user/public_html/filemanager/index.php
```

### 3. Log In
Open your browser and navigate to the uploaded URL:
```
https://yourdomain.com/filemanager/
```

Default credentials:
* **Username:** `admin`
* **Password:** `admin123`

### 4. Change Password
Once logged in, click your username badge (**admin**) in the top right header to change both your username and password.

---

## ⚙️ Configuration

All configuration constants are located at the top of [index.php](index.php) (lines 28–46):

```php
// Application title and version
define('FM_VERSION', '1.0');
define('FM_APP_TITLE', 'BlueFM');

// Base storage directory (relative or absolute path)
define('FM_BASE_DIR', __DIR__ . DIRECTORY_SEPARATOR . 'storage');

// Temporary folder for 2MB chunked uploads
define('FM_TMP_DIR', FM_BASE_DIR . DIRECTORY_SEPARATOR . '.fm_tmp');

// Upload chunk size in bytes (2MB default)
define('FM_CHUNK_SIZE', 2 * 1024 * 1024);

// Default fallback credentials (used before custom credentials are saved)
define('FM_DEFAULT_USER', 'admin');
define('FM_DEFAULT_PASS', 'admin123');
```

---

## 📱 Desktop & Mobile App Installation (PWA)

BlueFM includes full **Progressive Web App (PWA)** support. You can install BlueFM directly onto your operating system or mobile device, allowing you to access and manage your files without needing to open a web browser first.

### 🖥️ Installing on Desktop (Windows, macOS, Linux, ChromeOS)
1. Open your BlueFM URL in Google Chrome, Microsoft Edge, Brave, or any Chromium-based browser over **HTTPS** (or `localhost`).
2. Click the **"Install App"** button in the top navigation bar, or click the **Install icon** (monitor with a down arrow) on the right side of your browser's address bar.
3. In the confirmation dialog, click **Install**.
4. BlueFM will be installed as a native desktop application and added to your **Desktop**, **Taskbar / Dock**, and **Start Menu / Applications Launcher**.
5. When launched, BlueFM opens in its own standalone, clean window without browser tabs or an address bar.

### 📱 Installing on Android
1. Open BlueFM in **Chrome** or **Samsung Internet**.
2. Tap the **"Install App"** button on the page or tap the browser menu (⋮) and select **"Install app"** (or **"Add to Home screen"**).
3. The BlueFM icon will appear on your Home Screen and in your App Drawer, launching full-screen just like a native Android app.

### 🍏 Installing on iOS (iPhone & iPad)
1. Open BlueFM in **Safari**.
2. Tap the **"Install App"** button to view instructions, or tap the **Share** button (box with an arrow pointing up) in Safari's bottom toolbar.
3. Scroll down and tap **"Add to Home Screen"**.
4. Tap **"Add"** in the top-right corner.
5. The BlueFM icon will be placed on your iOS Home Screen and opens in full-screen standalone mode.

### 🎨 Customizing PWA Name, Colors & Icons
* **App Name & Title**: Update `FM_APP_TITLE` in [index.php](index.php) (line 29) and `"name"` / `"short_name"` in [manifest.json](manifest.json).
* **Theme & Accent Colors**: Modify `--primary` in [index.php](index.php) and `"theme_color"` / `"background_color"` in [manifest.json](manifest.json).
* **Custom App Icons**: Replace `icon-192.png`, `icon-512.png`, `apple-touch-icon.png`, and `favicon.ico` with your custom brand logos.

---

## 📁 File Structure

BlueFM is engineered with minimal overhead and self-contained structure:

```text
filemanager/
├── index.php             # The complete application (Backend + Frontend)
├── manifest.json         # PWA Web App Manifest (standalone app definition)
├── sw.js                 # PWA Service Worker (app shell & offline caching)
├── .htaccess             # Apache / cPanel MIME types & security headers
├── icon-192.png          # Standard 192x192 app icon
├── icon-512.png          # High-resolution 512x512 app icon
├── icon-maskable-512.png # Adaptive maskable icon for Android
├── apple-touch-icon.png  # Apple iOS Home Screen icon (180x180)
├── favicon.ico           # Browser shortcut favicon
├── README.md             # Documentation
└── storage/              # Storage directory (automatically created on first run)
    ├── .htaccess         # Security protection against direct chunk/auth access
    ├── .fm_auth.json     # Encrypted custom credentials (hidden from UI)
    ├── .fm_tmp/          # Chunk assembly temporary directory (auto-cleaned)
    └── ...               # Your uploaded files and folders
```

---

## 🛡️ Best Practices for cPanel & Shared Hosting

1. **Protect index.php**: Keep `index.php` file permissions set to `0644` and the parent folder to `0755`.
2. **Custom Storage Path**: If you wish to manage files in a different directory (such as your `public_html/uploads`), simply change `FM_BASE_DIR`:
   ```php
   define('FM_BASE_DIR', '/home/username/public_html/uploads');
   ```
3. **Change Default Password**: Always update the default password immediately after the first login.
4. **HTTPS / SSL**: Ensure your cPanel site has an active SSL certificate (Let's Encrypt / AutoSSL) so session cookies are transmitted securely (`cookie_secure`).

---

## 🤝 Contributing

Contributions, bug reports, and feature requests are welcome!
Feel free to open an issue or submit a Pull Request on GitHub.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📄 License

Distributed under the **MIT License**. See `LICENSE` for more information.

---

<p align="center">
  Crafted with care for developers, sysadmins, and webmasters.
</p>
