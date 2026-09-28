<?php
/**
 * Single-File PHP Web File Manager - BlueFM
 * Optimized for Shared cPanel Hosting & Imunify360 / ModSecurity WAF
 *
 * Core Features:
 *  - 2MB Vanilla JS Chunked File Upload with Automatic Exponential Retry
 *  - Complete Close/Dismiss Upload Progress Widget (fixes stuck progress bars)
 *  - TinyFileManager & cPanel Feature Set:
 *      * Code & Text Editor with Ctrl+S Save & Syntax Monospace
 *      * Quick View & Media Previewer (Images, Video, Audio, PDF, Text)
 *      * Zip & Unzip / Archive Extraction (Zip Slip protected)
 *      * Create New File & Create New Folder
 *      * File Permissions (chmod) Viewer & Editor
 *      * Duplicate / Copy Item
 *      * Multi-Select Batch Actions (Batch Delete, Batch Zip)
 *      * Configurable Username & Password (changeable anytime from the UI)
 *  - Fresh, Human-Friendly, Modern Light UI Design
 *  - Zero External Dependencies (No jQuery, No Bootstrap, No CDNs, Pure SVG)
 */

declare(strict_types=1);

@ini_set('memory_limit', '128M');
@set_time_limit(180);

// --- CONFIGURATION ---
define('FM_VERSION', '1.0');
define('FM_APP_TITLE', 'BlueFM');

// Base storage directory
define('FM_BASE_DIR', __DIR__ . DIRECTORY_SEPARATOR . 'storage');

// Temporary folder for chunked uploads
define('FM_TMP_DIR', FM_BASE_DIR . DIRECTORY_SEPARATOR . '.fm_tmp');

// File storing custom credentials (hashed with bcrypt, hidden from UI file list)
define('FM_AUTH_FILE', FM_BASE_DIR . DIRECTORY_SEPARATOR . '.fm_auth.json');

// Upload chunk size in bytes (2MB matches cPanel post_max_size limits)
define('FM_CHUNK_SIZE', 2 * 1024 * 1024);

// Default fallback credentials if no custom password has been set yet
define('FM_DEFAULT_USER', 'admin');
define('FM_DEFAULT_PASS', 'admin123');

// Start secure session
if (session_status() === PHP_SESSION_NONE) {
    session_name('FM_SESSID');
    @session_start([
        'cookie_httponly' => true,
        'cookie_samesite' => 'Lax',
        'cookie_secure' => isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on',
    ]);
}

// Generate CSRF token if not present
if (empty($_SESSION['fm_csrf'])) {
    $_SESSION['fm_csrf'] = bin2hex(random_bytes(24));
}

// Auto-initialize directories and protection files
if (!is_dir(FM_BASE_DIR)) {
    @mkdir(FM_BASE_DIR, 0755, true);
    @file_put_contents(FM_BASE_DIR . DIRECTORY_SEPARATOR . 'index.html', '<!DOCTYPE html><html><head><title>Access Denied</title></head><body><h1>Forbidden</h1></body></html>');
}
if (!is_dir(FM_TMP_DIR)) {
    @mkdir(FM_TMP_DIR, 0755, true);
    $htaccess = "# Imunify360 & Apache Hardening\n" .
                "<IfModule mod_authz_core.c>\n    Require all denied\n</IfModule>\n" .
                "<IfModule !mod_authz_core.c>\n    Deny from all\n</IfModule>\n" .
                "php_flag engine off\n";
    @file_put_contents(FM_TMP_DIR . DIRECTORY_SEPARATOR . '.htaccess', $htaccess);
    @file_put_contents(FM_TMP_DIR . DIRECTORY_SEPARATOR . 'index.html', 'Forbidden');
}

// Protect .fm_auth.json with .htaccess in base dir if Apache
if (!file_exists(FM_BASE_DIR . DIRECTORY_SEPARATOR . '.htaccess')) {
    $baseHtaccess = "<FilesMatch \"^\\.fm_\">\n" .
                    "    <IfModule mod_authz_core.c>\n        Require all denied\n    </IfModule>\n" .
                    "    <IfModule !mod_authz_core.c>\n        Deny from all\n    </IfModule>\n" .
                    "</FilesMatch>\n";
    @file_put_contents(FM_BASE_DIR . DIRECTORY_SEPARATOR . '.htaccess', $baseHtaccess);
}

// --- AUTHENTICATION HELPERS ---

function fm_get_credentials(): array {
    if (file_exists(FM_AUTH_FILE)) {
        $content = @file_get_contents(FM_AUTH_FILE);
        if ($content) {
            $data = json_decode($content, true);
            if (is_array($data) && !empty($data['username']) && !empty($data['password_hash'])) {
                return $data;
            }
        }
    }
    return [
        'username' => FM_DEFAULT_USER,
        'password_hash' => password_hash(FM_DEFAULT_PASS, PASSWORD_BCRYPT),
    ];
}

function fm_verify_login(string $user, string $pass): bool {
    $creds = fm_get_credentials();
    if ($user === $creds['username']) {
        return password_verify($pass, $creds['password_hash']);
    }
    return false;
}

function fm_is_logged_in(): bool {
    return !empty($_SESSION['fm_auth']) && $_SESSION['fm_auth'] === true;
}

function fm_require_auth(): void {
    if (!fm_is_logged_in()) {
        fm_json(['success' => false, 'error' => 'Session expired or unauthorized. Please log in again.'], 401);
    }
}

// --- SECURITY & PATH HELPERS ---

function fm_json(array $data, int $code = 200): void {
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

function fm_verify_csrf(): void {
    $token = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? $_POST['csrf_token'] ?? '';
    if (!hash_equals($_SESSION['fm_csrf'] ?? '', $token)) {
        fm_json(['success' => false, 'error' => 'Security token (CSRF) expired or invalid. Please reload the page.'], 403);
    }
}

function fm_sanitize_filename(string $filename): string {
    $filename = trim(str_replace(["\0", "\r", "\n", "\t"], '', $filename));
    $filename = str_replace(['/', '\\'], '', $filename);
    $filename = basename($filename);
    $filename = preg_replace('/[^\w\s\.\-\(\)\[\]\p{L}]/u', '_', $filename);
    $filename = trim($filename, '. ');
    return $filename !== '' ? $filename : 'file_' . time();
}

/**
 * Strict path containment inside FM_BASE_DIR.
 * Prevents traversal attacks, null bytes, and access to internal control files.
 */
function fm_resolve_path(string $rel_path, bool $must_exist = true): ?string {
    $rel_path = str_replace(["\0", "\\"], ['', '/'], $rel_path);
    $parts = explode('/', $rel_path);
    $safe_parts = [];

    foreach ($parts as $part) {
        $part = trim($part);
        if ($part === '' || $part === '.') continue;
        if ($part === '..') return null; // Traversal blocked
        if ($part === '.fm_tmp' || $part === '.fm_auth.json') return null; // Internal file protection
        $safe_parts[] = $part;
    }

    $base_real = realpath(FM_BASE_DIR);
    if (!$base_real) return null;

    $target = $base_real . (empty($safe_parts) ? '' : DIRECTORY_SEPARATOR . implode(DIRECTORY_SEPARATOR, $safe_parts));

    if ($must_exist) {
        $target_real = realpath($target);
        if (!$target_real) return null;
        if (!str_starts_with($target_real, $base_real)) return null;
        return $target_real;
    } else {
        $parent = dirname($target);
        $parent_real = realpath($parent);
        if (!$parent_real || !str_starts_with($parent_real, $base_real)) return null;
        return $target;
    }
}

function fm_get_relative_path(string $full_path): string {
    $base_real = realpath(FM_BASE_DIR);
    if ($full_path === $base_real) return '';
    if (str_starts_with($full_path, $base_real)) {
        $rel = substr($full_path, strlen($base_real));
        return ltrim(str_replace(DIRECTORY_SEPARATOR, '/', $rel), '/');
    }
    return '';
}

function fm_format_size(int $bytes): string {
    if ($bytes < 1024) return $bytes . ' B';
    $units = ['KB', 'MB', 'GB', 'TB'];
    $val = $bytes / 1024;
    $idx = 0;
    while ($val >= 1024 && $idx < count($units) - 1) {
        $val /= 1024;
        $idx++;
    }
    return sprintf('%.2f %s', $val, $units[$idx]);
}

function fm_format_perms(int $perms): string {
    return substr(sprintf('%o', $perms), -4);
}

function fm_delete_recursive(string $path): bool {
    if (!file_exists($path)) return true;
    if (is_file($path) || is_link($path)) return @unlink($path);
    $files = array_diff(scandir($path) ?: [], ['.', '..']);
    foreach ($files as $file) {
        $sub = $path . DIRECTORY_SEPARATOR . $file;
        if (is_dir($sub) && !is_link($sub)) {
            fm_delete_recursive($sub);
        } else {
            @unlink($sub);
        }
    }
    return @rmdir($path);
}

function fm_clean_old_temp_chunks(): void {
    if (!is_dir(FM_TMP_DIR)) return;
    $now = time();
    $items = scandir(FM_TMP_DIR) ?: [];
    foreach ($items as $item) {
        if ($item === '.' || $item === '..' || $item === '.htaccess' || $item === 'index.html') continue;
        $folder = FM_TMP_DIR . DIRECTORY_SEPARATOR . $item;
        if (is_dir($folder) && ($now - @filemtime($folder) > 86400)) {
            fm_delete_recursive($folder);
        }
    }
}

if (mt_rand(1, 20) === 1) {
    fm_clean_old_temp_chunks();
}

// --- BACKEND API HANDLERS ---
$action = $_GET['action'] ?? $_POST['action'] ?? '';
$login_error = '';

// LOGIN
if ($action === 'login') {
    $user = trim((string)($_POST['username'] ?? ''));
    $pass = (string)($_POST['password'] ?? '');
    $is_ajax = !empty($_SERVER['HTTP_X_REQUESTED_WITH']) 
        || (isset($_SERVER['HTTP_ACCEPT']) && str_contains($_SERVER['HTTP_ACCEPT'], 'application/json'))
        || isset($_POST['ajax']);

    if (fm_verify_login($user, $pass)) {
        $_SESSION['fm_auth'] = true;
        $_SESSION['fm_user'] = $user;
        if ($is_ajax) {
            fm_json(['success' => true, 'message' => 'Logged in successfully.']);
        }
        $redirectUrl = strtok($_SERVER['REQUEST_URI'], '?');
        header('Location: ' . ($redirectUrl ?: '/'));
        exit;
    }

    $login_error = 'Invalid username or password.';
    if ($is_ajax) {
        fm_json(['success' => false, 'error' => $login_error], 401);
    }
    $action = '';
}

// LOGOUT
if ($action === 'logout') {
    $_SESSION['fm_auth'] = false;
    unset($_SESSION['fm_auth'], $_SESSION['fm_user']);
    @session_destroy();
    fm_json(['success' => true]);
}

// All subsequent actions require active authentication
if ($action !== '' && $action !== 'login' && $action !== 'logout') {
    fm_require_auth();
}

// 1. LIST FILES & FOLDERS
if ($action === 'list') {
    $rel_path = (string)($_GET['path'] ?? '');
    $full_path = fm_resolve_path($rel_path, true);

    if (!$full_path || !is_dir($full_path)) {
        fm_json(['success' => false, 'error' => 'Directory not found or access denied.'], 404);
    }

    $raw_items = @scandir($full_path);
    if ($raw_items === false) {
        fm_json(['success' => false, 'error' => 'Unable to read directory contents.'], 500);
    }

    $folders = [];
    $files = [];

    foreach ($raw_items as $item) {
        if ($item === '.' || $item === '..' || $item === '.fm_tmp' || $item === '.fm_auth.json') continue;

        $item_path = $full_path . DIRECTORY_SEPARATOR . $item;
        $is_dir = is_dir($item_path);
        $mtime = @filemtime($item_path) ?: 0;
        $size = $is_dir ? 0 : (@filesize($item_path) ?: 0);
        $ext = $is_dir ? '' : strtolower(pathinfo($item, PATHINFO_EXTENSION));
        $perms = @fileperms($item_path) ?: 0;

        $item_info = [
            'name' => $item,
            'is_dir' => $is_dir,
            'size' => $size,
            'size_formatted' => $is_dir ? '-' : fm_format_size($size),
            'mtime' => $mtime,
            'date_formatted' => date('M j, Y H:i', $mtime),
            'extension' => $ext,
            'perms' => fm_format_perms($perms),
            'is_editable' => !$is_dir && in_array($ext, ['txt', 'html', 'htm', 'php', 'css', 'js', 'json', 'sql', 'xml', 'md', 'env', 'htaccess', 'ini', 'sh', 'yml', 'yaml', 'log', 'py', 'conf']),
            'is_image' => !$is_dir && in_array($ext, ['png', 'jpg', 'jpeg', 'gif', 'svg', 'webp', 'bmp', 'ico']),
            'is_video' => !$is_dir && in_array($ext, ['mp4', 'webm', 'ogg']),
            'is_audio' => !$is_dir && in_array($ext, ['mp3', 'wav', 'ogg', 'aac', 'm4a']),
            'is_pdf' => !$is_dir && ($ext === 'pdf'),
            'is_zip' => !$is_dir && ($ext === 'zip'),
        ];

        if ($is_dir) {
            $folders[] = $item_info;
        } else {
            $files[] = $item_info;
        }
    }

    usort($folders, fn($a, $b) => strcasecmp($a['name'], $b['name']));
    usort($files, fn($a, $b) => strcasecmp($a['name'], $b['name']));

    $free_space = @disk_free_space(FM_BASE_DIR);
    $total_space = @disk_total_space(FM_BASE_DIR);

    fm_json([
        'success' => true,
        'current_path' => fm_get_relative_path($full_path),
        'items' => array_merge($folders, $files),
        'stats' => [
            'free_space' => $free_space ? fm_format_size((int)$free_space) : 'N/A',
            'total_space' => $total_space ? fm_format_size((int)$total_space) : 'N/A',
            'folder_count' => count($folders),
            'file_count' => count($files),
        ],
        'auth_user' => $_SESSION['fm_user'] ?? FM_DEFAULT_USER,
    ]);
}

// 2. CREATE NEW FOLDER
if ($action === 'mkdir') {
    fm_verify_csrf();
    $rel_path = (string)($_POST['path'] ?? '');
    $folder_name = fm_sanitize_filename((string)($_POST['name'] ?? ''));

    if ($folder_name === '') {
        fm_json(['success' => false, 'error' => 'Folder name is required.'], 400);
    }

    $parent_dir = fm_resolve_path($rel_path, true);
    if (!$parent_dir || !is_dir($parent_dir)) {
        fm_json(['success' => false, 'error' => 'Parent directory not found or access denied.'], 404);
    }

    $new_dir = $parent_dir . DIRECTORY_SEPARATOR . $folder_name;
    if (file_exists($new_dir)) {
        fm_json(['success' => false, 'error' => 'A file or folder with this name already exists.'], 409);
    }

    if (!@mkdir($new_dir, 0755)) {
        fm_json(['success' => false, 'error' => 'Failed to create folder. Check server permissions.'], 500);
    }

    fm_json(['success' => true, 'message' => "Folder '{$folder_name}' created successfully."]);
}

// 3. CREATE NEW FILE
if ($action === 'new_file') {
    fm_verify_csrf();
    $rel_path = (string)($_POST['path'] ?? '');
    $filename = fm_sanitize_filename((string)($_POST['name'] ?? ''));

    if ($filename === '') {
        fm_json(['success' => false, 'error' => 'File name is required.'], 400);
    }

    $parent_dir = fm_resolve_path($rel_path, true);
    if (!$parent_dir || !is_dir($parent_dir)) {
        fm_json(['success' => false, 'error' => 'Parent directory not found.'], 404);
    }

    $new_file = $parent_dir . DIRECTORY_SEPARATOR . $filename;
    if (file_exists($new_file)) {
        fm_json(['success' => false, 'error' => 'A file with this name already exists.'], 409);
    }

    if (@file_put_contents($new_file, '') === false) {
        fm_json(['success' => false, 'error' => 'Failed to create file. Check folder write permissions.'], 500);
    }
    @chmod($new_file, 0644);

    fm_json(['success' => true, 'message' => "File '{$filename}' created successfully."]);
}

// 4. RENAME OR MOVE ITEM
if ($action === 'rename') {
    fm_verify_csrf();
    $rel_path = (string)($_POST['path'] ?? '');
    $old_name = (string)($_POST['old_name'] ?? '');
    $new_name = fm_sanitize_filename((string)($_POST['new_name'] ?? ''));

    if ($new_name === '') {
        fm_json(['success' => false, 'error' => 'Valid new name is required.'], 400);
    }

    $parent_dir = fm_resolve_path($rel_path, true);
    if (!$parent_dir || !is_dir($parent_dir)) {
        fm_json(['success' => false, 'error' => 'Parent directory not found.'], 404);
    }

    $old_target = $parent_dir . DIRECTORY_SEPARATOR . basename($old_name);
    $new_target = $parent_dir . DIRECTORY_SEPARATOR . $new_name;

    if (!file_exists($old_target)) {
        fm_json(['success' => false, 'error' => 'Source item not found.'], 404);
    }
    if (file_exists($new_target)) {
        fm_json(['success' => false, 'error' => 'Destination item already exists.'], 409);
    }

    if (!@rename($old_target, $new_target)) {
        fm_json(['success' => false, 'error' => 'Failed to rename item. Check server permissions.'], 500);
    }

    fm_json(['success' => true, 'message' => "Renamed to '{$new_name}' successfully."]);
}

// 5. DUPLICATE FILE
if ($action === 'duplicate') {
    fm_verify_csrf();
    $rel_path = (string)($_POST['path'] ?? '');
    $name = (string)($_POST['name'] ?? '');

    $parent_dir = fm_resolve_path($rel_path, true);
    if (!$parent_dir || !is_dir($parent_dir)) {
        fm_json(['success' => false, 'error' => 'Directory not found.'], 404);
    }

    $source = $parent_dir . DIRECTORY_SEPARATOR . basename($name);
    if (!file_exists($source)) {
        fm_json(['success' => false, 'error' => 'Source item not found.'], 404);
    }

    $pathInfo = pathinfo($name);
    $ext = isset($pathInfo['extension']) && $pathInfo['extension'] !== '' ? '.' . $pathInfo['extension'] : '';
    $base = $pathInfo['filename'];
    
    $counter = 1;
    do {
        $copyName = "{$base}_copy" . ($counter > 1 ? "_{$counter}" : '') . $ext;
        $dest = $parent_dir . DIRECTORY_SEPARATOR . $copyName;
        $counter++;
    } while (file_exists($dest));

    if (is_dir($source)) {
        // Simple recursive folder copy
        $copyDir = function($src, $dst) use (&$copyDir) {
            @mkdir($dst, 0755, true);
            foreach (scandir($src) as $file) {
                if ($file !== '.' && $file !== '..') {
                    if (is_dir("$src/$file")) $copyDir("$src/$file", "$dst/$file");
                    else @copy("$src/$file", "$dst/$file");
                }
            }
        };
        $copyDir($source, $dest);
    } else {
        if (!@copy($source, $dest)) {
            fm_json(['success' => false, 'error' => 'Failed to duplicate item.'], 500);
        }
    }

    fm_json(['success' => true, 'message' => "Duplicated as '{$copyName}'."]);
}

// 6. DELETE ITEM(S)
if ($action === 'delete') {
    fm_verify_csrf();
    $rel_path = (string)($_POST['path'] ?? '');
    $items = $_POST['items'] ?? [$_POST['name'] ?? ''];
    if (!is_array($items)) $items = [$items];

    $parent_dir = fm_resolve_path($rel_path, true);
    if (!$parent_dir || !is_dir($parent_dir)) {
        fm_json(['success' => false, 'error' => 'Parent directory not found.'], 404);
    }

    $deletedCount = 0;
    foreach ($items as $item) {
        $item = basename((string)$item);
        if ($item === '' || $item === '.' || $item === '..' || $item === '.fm_auth.json') continue;
        $target = $parent_dir . DIRECTORY_SEPARATOR . $item;
        if (file_exists($target)) {
            if (fm_delete_recursive($target)) {
                $deletedCount++;
            }
        }
    }

    fm_json(['success' => true, 'message' => "Successfully deleted {$deletedCount} item(s)."]);
}

// 7. CHANGE FILE PERMISSIONS (chmod)
if ($action === 'chmod') {
    fm_verify_csrf();
    $rel_path = (string)($_POST['path'] ?? '');
    $name = (string)($_POST['name'] ?? '');
    $modeStr = trim((string)($_POST['mode'] ?? '0644'));

    if (!preg_match('/^[0-7]{3,4}$/', $modeStr)) {
        fm_json(['success' => false, 'error' => 'Invalid octal permissions format (e.g. 0644 or 0755).'], 400);
    }

    $parent_dir = fm_resolve_path($rel_path, true);
    if (!$parent_dir || !is_dir($parent_dir)) {
        fm_json(['success' => false, 'error' => 'Parent directory not found.'], 404);
    }

    $target = $parent_dir . DIRECTORY_SEPARATOR . basename($name);
    if (!file_exists($target)) {
        fm_json(['success' => false, 'error' => 'Item not found.'], 404);
    }

    $octalMode = octdec($modeStr);
    if (!@chmod($target, (int)$octalMode)) {
        fm_json(['success' => false, 'error' => 'Failed to change permissions. Check ownership permissions.'], 500);
    }

    fm_json(['success' => true, 'message' => "Permissions for '{$name}' changed to {$modeStr}."]);
}

// 8. READ FILE CONTENT (FOR EDITOR & VIEWER)
if ($action === 'read_file') {
    $rel_path = (string)($_GET['path'] ?? '');
    $file_path = fm_resolve_path($rel_path, true);

    if (!$file_path || !is_file($file_path)) {
        fm_json(['success' => false, 'error' => 'File not found or access denied.'], 404);
    }

    if (filesize($file_path) > 5 * 1024 * 1024) {
        fm_json(['success' => false, 'error' => 'File is too large to open in web editor (> 5MB).'], 400);
    }

    $content = @file_get_contents($file_path);
    if ($content === false) {
        fm_json(['success' => false, 'error' => 'Could not read file.'], 500);
    }

    fm_json([
        'success' => true,
        'filename' => basename($file_path),
        'content' => $content,
        'size' => filesize($file_path),
        'perms' => fm_format_perms(@fileperms($file_path) ?: 0),
    ]);
}

// 9. SAVE FILE CONTENT (FROM EDITOR)
if ($action === 'save_file') {
    fm_verify_csrf();
    $rel_path = (string)($_POST['path'] ?? '');
    $content = (string)($_POST['content'] ?? '');
    $file_path = fm_resolve_path($rel_path, true);

    if (!$file_path || !is_file($file_path)) {
        fm_json(['success' => false, 'error' => 'File not found or access denied.'], 404);
    }

    if (@file_put_contents($file_path, $content) === false) {
        fm_json(['success' => false, 'error' => 'Failed to save file. Check write permissions.'], 500);
    }

    fm_json(['success' => true, 'message' => "Saved '" . basename($file_path) . "' successfully."]);
}

// 10. RAW / STREAM MEDIA FOR PREVIEW
if ($action === 'raw') {
    $rel_path = (string)($_GET['path'] ?? '');
    $file_path = fm_resolve_path($rel_path, true);

    if (!$file_path || !is_file($file_path)) {
        http_response_code(404);
        exit('File not found');
    }

    $ext = strtolower(pathinfo($file_path, PATHINFO_EXTENSION));
    $mimeMap = [
        'jpg' => 'image/jpeg', 'jpeg' => 'image/jpeg', 'png' => 'image/png', 'gif' => 'image/gif',
        'webp' => 'image/webp', 'svg' => 'image/svg+xml', 'bmp' => 'image/bmp', 'ico' => 'image/x-icon',
        'mp4' => 'video/mp4', 'webm' => 'video/webm', 'mp3' => 'audio/mpeg', 'wav' => 'audio/wav',
        'pdf' => 'application/pdf', 'txt' => 'text/plain', 'json' => 'application/json'
    ];
    $contentType = $mimeMap[$ext] ?? 'application/octet-stream';

    while (ob_get_level()) ob_end_clean();
    header("Content-Type: {$contentType}");
    header('Content-Length: ' . filesize($file_path));
    header('Cache-Control: public, max-age=3600');
    readfile($file_path);
    exit;
}

// 11. ZIP COMPRESSION
if ($action === 'zip') {
    fm_verify_csrf();
    if (!class_exists('ZipArchive')) {
        fm_json(['success' => false, 'error' => 'PHP ZipArchive extension is not available on this server.'], 500);
    }

    $rel_path = (string)($_POST['path'] ?? '');
    $items = $_POST['items'] ?? [$_POST['name'] ?? ''];
    if (!is_array($items)) $items = [$items];

    $parent_dir = fm_resolve_path($rel_path, true);
    if (!$parent_dir || !is_dir($parent_dir)) {
        fm_json(['success' => false, 'error' => 'Parent directory not found.'], 404);
    }

    $zipName = fm_sanitize_filename((string)($_POST['archive_name'] ?? 'archive_' . date('Ymd_His') . '.zip'));
    if (!str_ends_with(strtolower($zipName), '.zip')) $zipName .= '.zip';

    $zipPath = $parent_dir . DIRECTORY_SEPARATOR . $zipName;

    $zip = new ZipArchive();
    if ($zip->open($zipPath, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
        fm_json(['success' => false, 'error' => 'Could not create zip archive file.'], 500);
    }

    $addFolderToZip = function($dir, $localPrefix = '') use (&$addFolderToZip, $zip) {
        $files = scandir($dir) ?: [];
        foreach ($files as $file) {
            if ($file === '.' || $file === '..' || $file === '.fm_tmp' || $file === '.fm_auth.json') continue;
            $full = $dir . DIRECTORY_SEPARATOR . $file;
            $local = $localPrefix ? $localPrefix . '/' . $file : $file;
            if (is_dir($full)) {
                $zip->addEmptyDir($local);
                $addFolderToZip($full, $local);
            } else {
                $zip->addFile($full, $local);
            }
        }
    };

    foreach ($items as $item) {
        $item = basename((string)$item);
        $target = $parent_dir . DIRECTORY_SEPARATOR . $item;
        if (file_exists($target)) {
            if (is_dir($target)) {
                $zip->addEmptyDir($item);
                $addFolderToZip($target, $item);
            } else {
                $zip->addFile($target, $item);
            }
        }
    }

    $zip->close();
    fm_json(['success' => true, 'message' => "Archive '{$zipName}' created successfully."]);
}

// 12. UNZIP / EXTRACT ARCHIVE (Zip Slip Hardened)
if ($action === 'unzip') {
    fm_verify_csrf();
    if (!class_exists('ZipArchive')) {
        fm_json(['success' => false, 'error' => 'PHP ZipArchive extension is not available.'], 500);
    }

    $rel_path = (string)($_POST['path'] ?? '');
    $zip_file = basename((string)($_POST['name'] ?? ''));

    $parent_dir = fm_resolve_path($rel_path, true);
    if (!$parent_dir || !is_dir($parent_dir)) {
        fm_json(['success' => false, 'error' => 'Parent directory not found.'], 404);
    }

    $zip_path = $parent_dir . DIRECTORY_SEPARATOR . $zip_file;
    if (!file_exists($zip_path)) {
        fm_json(['success' => false, 'error' => 'Zip file not found.'], 404);
    }

    $zip = new ZipArchive();
    if ($zip->open($zip_path) !== true) {
        fm_json(['success' => false, 'error' => 'Failed to open zip archive.'], 400);
    }

    // Zip slip prevention: verify every entry stays within destination folder
    $dest_real = realpath($parent_dir);
    for ($i = 0; $i < $zip->numFiles; $i++) {
        $entryName = $zip->getNameIndex($i);
        if (str_contains($entryName, '..') || str_starts_with($entryName, '/') || str_starts_with($entryName, '\\')) {
            $zip->close();
            fm_json(['success' => false, 'error' => 'Archive contains unsafe paths (Zip Slip detected).'], 400);
        }
    }

    if (!$zip->extractTo($parent_dir)) {
        $zip->close();
        fm_json(['success' => false, 'error' => 'Extraction failed.'], 500);
    }

    $extractedCount = $zip->numFiles;
    $zip->close();

    fm_json(['success' => true, 'message' => "Extracted {$extractedCount} file(s) into current folder."]);
}

// 13. CHANGE USERNAME AND PASSWORD
if ($action === 'change_auth') {
    fm_verify_csrf();
    $current_pass = (string)($_POST['current_password'] ?? '');
    $new_user = trim((string)($_POST['new_username'] ?? ''));
    $new_pass = (string)($_POST['new_password'] ?? '');

    $creds = fm_get_credentials();
    if (!password_verify($current_pass, $creds['password_hash'])) {
        fm_json(['success' => false, 'error' => 'Current password verification failed.'], 403);
    }

    if ($new_user === '') {
        fm_json(['success' => false, 'error' => 'New username cannot be empty.'], 400);
    }

    if (strlen($new_pass) < 6) {
        fm_json(['success' => false, 'error' => 'New password must be at least 6 characters long.'], 400);
    }

    $new_data = [
        'username' => $new_user,
        'password_hash' => password_hash($new_pass, PASSWORD_BCRYPT),
        'updated_at' => date('Y-m-d H:i:s'),
    ];

    if (@file_put_contents(FM_AUTH_FILE, json_encode($new_data, JSON_PRETTY_PRINT)) === false) {
        fm_json(['success' => false, 'error' => 'Failed to save authentication file. Check folder write permissions.'], 500);
    }
    @chmod(FM_AUTH_FILE, 0600);

    $_SESSION['fm_user'] = $new_user;

    fm_json(['success' => true, 'message' => 'Credentials updated successfully!', 'username' => $new_user]);
}

// 14. DOWNLOAD FILE (Streamed, memory safe)
if ($action === 'download') {
    $rel_path = (string)($_GET['path'] ?? '');
    $file_path = fm_resolve_path($rel_path, true);

    if (!$file_path || !is_file($file_path)) {
        http_response_code(404);
        exit('File not found or access denied.');
    }

    $file_size = @filesize($file_path);
    $file_name = basename($file_path);

    while (ob_get_level()) ob_end_clean();

    header('Content-Description: File Transfer');
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . rawurlencode($file_name) . '"; filename*=UTF-8\'\'' . rawurlencode($file_name));
    header('Content-Transfer-Encoding: binary');
    header('Expires: 0');
    header('Cache-Control: must-revalidate, post-check=0, pre-check=0');
    header('Pragma: public');
    if ($file_size !== false) header('Content-Length: ' . $file_size);

    $handle = fopen($file_path, 'rb');
    if ($handle !== false) {
        while (!feof($handle)) {
            echo fread($handle, 65536);
            flush();
        }
        fclose($handle);
    }
    exit;
}

// 15. CHUNKED UPLOAD - RECEIVE CHUNK
if ($action === 'upload_chunk') {
    fm_verify_csrf();

    $upload_id = preg_replace('/[^a-zA-Z0-9_\-]/', '', (string)($_POST['upload_id'] ?? ''));
    $chunk_index = filter_var($_POST['chunk_index'] ?? null, FILTER_VALIDATE_INT);
    $total_chunks = filter_var($_POST['total_chunks'] ?? null, FILTER_VALIDATE_INT);

    if (!$upload_id || $chunk_index === false || $total_chunks === false || $chunk_index < 0 || $total_chunks < 1) {
        fm_json(['success' => false, 'error' => 'Invalid chunk upload parameters.'], 400);
    }

    if (!isset($_FILES['chunk_data']) || $_FILES['chunk_data']['error'] !== UPLOAD_ERR_OK) {
        $errCode = $_FILES['chunk_data']['error'] ?? 'MISSING_FILE';
        fm_json(['success' => false, 'error' => "Chunk upload failed with code: {$errCode}."], 400);
    }

    $session_tmp = FM_TMP_DIR . DIRECTORY_SEPARATOR . $upload_id;
    if (!is_dir($session_tmp)) {
        if (!@mkdir($session_tmp, 0755, true)) {
            fm_json(['success' => false, 'error' => 'Failed to initialize temporary chunk directory.'], 500);
        }
    }

    $chunk_file = $session_tmp . DIRECTORY_SEPARATOR . 'chunk_' . $chunk_index;
    if (!@move_uploaded_file($_FILES['chunk_data']['tmp_name'], $chunk_file)) {
        fm_json(['success' => false, 'error' => "Failed to store chunk {$chunk_index} on server."], 500);
    }

    fm_json([
        'success' => true,
        'upload_id' => $upload_id,
        'chunk_index' => $chunk_index,
        'message' => "Chunk {$chunk_index} uploaded successfully."
    ]);
}

// 16. CHUNKED UPLOAD - ASSEMBLE ALL CHUNKS
if ($action === 'assemble_file') {
    fm_verify_csrf();

    $upload_id = preg_replace('/[^a-zA-Z0-9_\-]/', '', (string)($_POST['upload_id'] ?? ''));
    $total_chunks = filter_var($_POST['total_chunks'] ?? null, FILTER_VALIDATE_INT);
    $raw_filename = (string)($_POST['filename'] ?? '');
    $rel_path = (string)($_POST['target_dir'] ?? '');
    $expected_size = filter_var($_POST['expected_size'] ?? null, FILTER_VALIDATE_INT);

    $filename = fm_sanitize_filename($raw_filename);
    if (!$upload_id || $total_chunks === false || $total_chunks < 1 || $filename === '') {
        fm_json(['success' => false, 'error' => 'Invalid assembly parameters.'], 400);
    }

    $target_dir = fm_resolve_path($rel_path, true);
    if (!$target_dir || !is_dir($target_dir)) {
        fm_json(['success' => false, 'error' => 'Target directory does not exist or access denied.'], 404);
    }

    $session_tmp = FM_TMP_DIR . DIRECTORY_SEPARATOR . $upload_id;
    if (!is_dir($session_tmp)) {
        fm_json(['success' => false, 'error' => 'Chunk session data was not found.'], 404);
    }

    for ($i = 0; $i < $total_chunks; $i++) {
        $c_path = $session_tmp . DIRECTORY_SEPARATOR . 'chunk_' . $i;
        if (!file_exists($c_path)) {
            fm_json(['success' => false, 'error' => "Chunk {$i} is missing on the server. Please retry."], 400);
        }
    }

    $dest_file = $target_dir . DIRECTORY_SEPARATOR . $filename;
    $out_handle = @fopen($dest_file, 'wb');
    if (!$out_handle) {
        fm_json(['success' => false, 'error' => 'Cannot create destination file. Check folder write permissions.'], 500);
    }

    for ($i = 0; $i < $total_chunks; $i++) {
        $c_path = $session_tmp . DIRECTORY_SEPARATOR . 'chunk_' . $i;
        $in_handle = @fopen($c_path, 'rb');
        if ($in_handle) {
            stream_copy_to_stream($in_handle, $out_handle);
            fclose($in_handle);
            @unlink($c_path);
        }
    }
    fclose($out_handle);
    @rmdir($session_tmp);

    $final_size = @filesize($dest_file);
    if ($expected_size !== false && $expected_size > 0 && $final_size !== $expected_size) {
        @unlink($dest_file);
        fm_json(['success' => false, 'error' => "Assembled file size mismatch ({$final_size} vs expected {$expected_size}). Upload aborted."], 400);
    }

    @chmod($dest_file, 0644);

    fm_json([
        'success' => true,
        'message' => "File '{$filename}' uploaded and assembled successfully.",
        'filename' => $filename,
        'size' => $final_size,
        'size_formatted' => fm_format_size($final_size ?: 0)
    ]);
}

if ($action !== '') {
    fm_json(['success' => false, 'error' => 'Unknown action requested.'], 400);
}

// --- FRONTEND TEMPLATE RENDERING ---
$is_authenticated = fm_is_logged_in();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover">
    <meta name="robots" content="noindex, nofollow">
    <title><?= htmlspecialchars(FM_APP_TITLE) ?></title>

    <!-- Progressive Web App (PWA) & Mobile Meta Tags -->
    <link rel="manifest" href="manifest.json">
    <meta name="theme-color" content="#4f46e5">
    <meta name="mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="default">
    <meta name="apple-mobile-web-app-title" content="<?= htmlspecialchars(FM_APP_TITLE) ?>">
    <link rel="apple-touch-icon" sizes="180x180" href="apple-touch-icon.png">
    <link rel="icon" type="image/png" sizes="32x32" href="favicon-32x32.png">
    <link rel="icon" type="image/png" sizes="16x16" href="favicon-16x16.png">
    <link rel="shortcut icon" href="favicon.ico">
    <style>
        :root {
            /* Warm, Human-Friendly Light Palette */
            --bg-body: #f8fafc;
            --bg-surface: #ffffff;
            --bg-card: #ffffff;
            --bg-subtle: #f1f5f9;
            --bg-hover: #f8fafc;
            
            --border-light: #e2e8f0;
            --border-focus: #4f46e5;
            
            --primary: #4f46e5;
            --primary-hover: #4338ca;
            --primary-light: #eef2ff;
            --primary-text: #4338ca;
            
            --accent: #2563eb;
            --text-main: #0f172a;
            --text-muted: #475569;
            --text-dim: #94a3b8;
            
            --success: #059669;
            --success-light: #ecfdf5;
            --warning: #d97706;
            --warning-light: #fffbeb;
            --danger: #e11d48;
            --danger-light: #fff1f2;
            
            --folder-color: #f59e0b;
            --font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            --radius-sm: 6px;
            --radius-md: 10px;
            --radius-lg: 14px;
            --shadow-subtle: 0 1px 3px rgba(15, 23, 42, 0.06), 0 1px 2px rgba(15, 23, 42, 0.04);
            --shadow-card: 0 4px 6px -1px rgba(15, 23, 42, 0.05), 0 2px 4px -2px rgba(15, 23, 42, 0.04);
            --shadow-pop: 0 12px 28px -4px rgba(15, 23, 42, 0.12), 0 4px 10px -2px rgba(15, 23, 42, 0.06);
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            font-family: var(--font-family);
            background-color: var(--bg-body);
            color: var(--text-main);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            line-height: 1.5;
            -webkit-font-smoothing: antialiased;
        }

        .svg-icon {
            display: inline-block;
            width: 1.25rem;
            height: 1.25rem;
            stroke-width: 2;
            stroke: currentColor;
            fill: none;
            stroke-linecap: round;
            stroke-linejoin: round;
            vertical-align: middle;
            flex-shrink: 0;
        }

        /* Top Header */
        .app-header {
            background: var(--bg-surface);
            border-bottom: 1px solid var(--border-light);
            position: sticky;
            top: 0;
            z-index: 40;
            padding: 0.75rem 1.5rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
            box-shadow: 0 1px 2px rgba(0,0,0,0.03);
        }

        .brand {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            font-size: 1.15rem;
            font-weight: 700;
            color: var(--text-main);
            text-decoration: none;
            letter-spacing: -0.02em;
        }

        .brand-badge {
            font-size: 0.7rem;
            font-weight: 600;
            background: var(--primary-light);
            color: var(--primary-text);
            padding: 0.15rem 0.5rem;
            border-radius: 9999px;
        }

        .header-actions {
            display: flex;
            align-items: center;
            gap: 0.6rem;
        }

        /* Buttons */
        .btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 0.45rem;
            font-family: inherit;
            font-size: 0.85rem;
            font-weight: 500;
            padding: 0.45rem 0.85rem;
            border-radius: var(--radius-sm);
            border: 1px solid var(--border-light);
            background: var(--bg-surface);
            color: var(--text-main);
            cursor: pointer;
            transition: all 0.15s ease;
            text-decoration: none;
            user-select: none;
        }

        .btn:hover:not(:disabled) {
            background: var(--bg-subtle);
            border-color: #cbd5e1;
        }

        .btn:active:not(:disabled) {
            transform: scale(0.98);
        }

        .btn-primary {
            background: var(--primary);
            border-color: var(--primary);
            color: #ffffff;
            box-shadow: 0 1px 2px rgba(79, 70, 229, 0.2);
        }

        .btn-primary:hover:not(:disabled) {
            background: var(--primary-hover);
            border-color: var(--primary-hover);
            color: #ffffff;
        }

        .btn-danger {
            background: var(--danger-light);
            border-color: #fecdd3;
            color: var(--danger);
        }

        .btn-danger:hover:not(:disabled) {
            background: var(--danger);
            border-color: var(--danger);
            color: #ffffff;
        }

        .btn-sm {
            padding: 0.3rem 0.6rem;
            font-size: 0.8rem;
        }

        .btn-icon {
            padding: 0.4rem;
            border-radius: var(--radius-sm);
        }

        /* Container */
        .container {
            max-width: 1240px;
            width: 100%;
            margin: 0 auto;
            padding: 1.25rem 1.5rem;
            flex: 1;
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }

        /* Nav & Breadcrumbs */
        .nav-bar {
            background: var(--bg-surface);
            border: 1px solid var(--border-light);
            border-radius: var(--radius-md);
            padding: 0.65rem 1rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
            box-shadow: var(--shadow-subtle);
            flex-wrap: wrap;
            gap: 0.75rem;
        }

        .breadcrumbs {
            display: flex;
            align-items: center;
            gap: 0.25rem;
            flex-wrap: wrap;
            font-size: 0.88rem;
        }

        .crumb-item {
            display: inline-flex;
            align-items: center;
            gap: 0.3rem;
            color: var(--text-muted);
            cursor: pointer;
            padding: 0.2rem 0.45rem;
            border-radius: var(--radius-sm);
            transition: all 0.15s ease;
        }

        .crumb-item:hover {
            color: var(--primary);
            background: var(--primary-light);
        }

        .crumb-item.active {
            color: var(--text-main);
            font-weight: 600;
            cursor: default;
        }

        .crumb-separator {
            color: var(--text-dim);
            font-size: 0.8rem;
        }

        /* Toolbar */
        .toolbar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 0.75rem;
            flex-wrap: wrap;
        }

        .toolbar-left, .toolbar-right {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            flex-wrap: wrap;
        }

        .search-box {
            position: relative;
            width: 220px;
        }

        .search-input {
            width: 100%;
            padding: 0.45rem 0.75rem 0.45rem 2.1rem;
            background: var(--bg-surface);
            border: 1px solid var(--border-light);
            border-radius: var(--radius-sm);
            color: var(--text-main);
            font-size: 0.85rem;
            outline: none;
            transition: border-color 0.15s;
        }

        .search-input:focus {
            border-color: var(--primary);
            box-shadow: 0 0 0 2px var(--primary-light);
        }

        .search-icon {
            position: absolute;
            left: 0.65rem;
            top: 50%;
            transform: translateY(-50%);
            color: var(--text-dim);
            pointer-events: none;
        }

        /* Drop Zone */
        .drop-zone {
            border: 2px dashed #cbd5e1;
            border-radius: var(--radius-md);
            padding: 1.25rem 1rem;
            text-align: center;
            background: var(--bg-surface);
            transition: all 0.2s ease;
            cursor: pointer;
        }

        .drop-zone.dragover {
            border-color: var(--primary);
            background: var(--primary-light);
        }

        .drop-zone-content {
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 0.35rem;
            pointer-events: none;
        }

        .drop-zone-icon {
            width: 2.25rem;
            height: 2.25rem;
            color: var(--primary);
        }

        .drop-zone-title {
            font-size: 0.92rem;
            font-weight: 600;
            color: var(--text-main);
        }

        .drop-zone-desc {
            font-size: 0.8rem;
            color: var(--text-muted);
        }

        /* Multi-Select Floating Action Bar */
        .batch-bar {
            background: var(--text-main);
            color: #ffffff;
            border-radius: var(--radius-md);
            padding: 0.6rem 1rem;
            display: none;
            align-items: center;
            justify-content: space-between;
            box-shadow: var(--shadow-pop);
            animation: fadeIn 0.2s ease;
        }

        .batch-bar.active {
            display: flex;
        }

        .batch-bar-left {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            font-size: 0.875rem;
            font-weight: 500;
        }

        .batch-bar-right {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        /* File Explorer Table */
        .table-card {
            background: var(--bg-surface);
            border: 1px solid var(--border-light);
            border-radius: var(--radius-md);
            overflow: hidden;
            box-shadow: var(--shadow-card);
        }

        .file-table {
            width: 100%;
            border-collapse: collapse;
            text-align: left;
            font-size: 0.86rem;
        }

        .file-table th {
            background: #f8fafc;
            padding: 0.65rem 0.9rem;
            font-weight: 600;
            color: var(--text-muted);
            text-transform: uppercase;
            font-size: 0.7rem;
            letter-spacing: 0.04em;
            border-bottom: 1px solid var(--border-light);
            user-select: none;
        }

        .file-table td {
            padding: 0.65rem 0.9rem;
            border-bottom: 1px solid var(--border-light);
            vertical-align: middle;
        }

        .file-table tbody tr {
            transition: background 0.1s ease;
        }

        .file-table tbody tr:hover {
            background: #f8fafc;
        }

        .file-table tr.selected {
            background: #f5f3ff !important;
        }

        .file-name-cell {
            display: flex;
            align-items: center;
            gap: 0.65rem;
            cursor: pointer;
            font-weight: 500;
            color: var(--text-main);
            text-decoration: none;
        }

        .file-table tr.is-dir .file-name-cell:hover {
            color: var(--primary);
        }

        .icon-folder { color: var(--folder-color); }
        .icon-file { color: #64748b; }
        .icon-image { color: #0284c7; }
        .icon-archive { color: #dc2626; }
        .icon-code { color: #059669; }
        .icon-video { color: #7c3aed; }
        .icon-audio { color: #db2777; }

        .actions-cell {
            display: flex;
            align-items: center;
            justify-content: flex-end;
            gap: 0.3rem;
        }

        .badge-perm {
            font-family: monospace;
            font-size: 0.75rem;
            padding: 0.1rem 0.35rem;
            background: var(--bg-subtle);
            border-radius: 4px;
            color: var(--text-muted);
            cursor: pointer;
        }

        .badge-perm:hover {
            background: #e2e8f0;
            color: var(--text-main);
        }

        .empty-state {
            padding: 3.5rem 1rem;
            text-align: center;
            color: var(--text-muted);
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 0.5rem;
        }

        .status-bar {
            padding: 0.6rem 1rem;
            font-size: 0.8rem;
            color: var(--text-muted);
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: #f8fafc;
            border-top: 1px solid var(--border-light);
        }

        /* Chunked Upload Progress Floating Widget */
        .upload-widget {
            position: fixed;
            bottom: 1.5rem;
            right: 1.5rem;
            width: 400px;
            max-width: calc(100vw - 3rem);
            background: var(--bg-surface);
            border: 1px solid var(--border-light);
            border-radius: var(--radius-lg);
            box-shadow: var(--shadow-pop);
            z-index: 60;
            overflow: hidden;
            display: none;
        }

        .upload-widget.active {
            display: block;
            animation: slideUp 0.25s ease-out;
        }

        @keyframes slideUp {
            from { transform: translateY(16px); opacity: 0; }
            to { transform: translateY(0); opacity: 1; }
        }

        .upload-widget-header {
            padding: 0.65rem 1rem;
            background: #f8fafc;
            border-bottom: 1px solid var(--border-light);
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .upload-widget-title {
            font-size: 0.85rem;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 0.5rem;
            color: var(--text-main);
        }

        .upload-widget-body {
            padding: 0.9rem 1rem;
            display: flex;
            flex-direction: column;
            gap: 0.65rem;
        }

        .upload-current-file {
            font-size: 0.85rem;
            font-weight: 600;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            color: var(--text-main);
        }

        .upload-meta {
            display: flex;
            justify-content: space-between;
            font-size: 0.75rem;
            color: var(--text-muted);
        }

        .progress-track {
            width: 100%;
            height: 8px;
            background: #e2e8f0;
            border-radius: 999px;
            overflow: hidden;
        }

        .progress-fill {
            height: 100%;
            width: 0%;
            background: linear-gradient(90deg, #4f46e5, #06b6d4);
            border-radius: 999px;
            transition: width 0.2s cubic-bezier(0.4, 0, 0.2, 1);
        }

        .upload-status-badge {
            font-size: 0.75rem;
            display: inline-flex;
            align-items: center;
            gap: 0.4rem;
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            background: var(--primary-light);
            color: var(--primary-text);
        }

        .upload-status-badge.error {
            background: var(--danger-light);
            color: var(--danger);
        }

        .upload-status-badge.success {
            background: var(--success-light);
            color: var(--success);
        }

        /* Modal Dialogs */
        .modal-overlay {
            position: fixed;
            inset: 0;
            background: rgba(15, 23, 42, 0.45);
            backdrop-filter: blur(3px);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 100;
            padding: 1rem;
            opacity: 0;
            pointer-events: none;
            transition: opacity 0.2s ease;
        }

        .modal-overlay.active {
            opacity: 1;
            pointer-events: auto;
        }

        .modal-card {
            background: var(--bg-surface);
            border: 1px solid var(--border-light);
            border-radius: var(--radius-lg);
            width: 100%;
            max-width: 450px;
            box-shadow: var(--shadow-pop);
            transform: scale(0.97);
            transition: transform 0.2s ease;
            overflow: hidden;
        }

        .modal-card.modal-lg {
            max-width: 860px;
        }

        .modal-overlay.active .modal-card {
            transform: scale(1);
        }

        .modal-header {
            padding: 0.85rem 1.25rem;
            border-bottom: 1px solid var(--border-light);
            display: flex;
            align-items: center;
            justify-content: space-between;
            background: #fafafa;
        }

        .modal-title {
            font-size: 0.98rem;
            font-weight: 600;
        }

        .modal-body {
            padding: 1.25rem;
            display: flex;
            flex-direction: column;
            gap: 0.9rem;
            max-height: 75vh;
            overflow-y: auto;
        }

        .modal-footer {
            padding: 0.75rem 1.25rem;
            background: #fafafa;
            border-top: 1px solid var(--border-light);
            display: flex;
            justify-content: flex-end;
            gap: 0.5rem;
        }

        .form-group {
            display: flex;
            flex-direction: column;
            gap: 0.35rem;
        }

        .form-label {
            font-size: 0.82rem;
            font-weight: 500;
            color: var(--text-muted);
        }

        .form-control {
            width: 100%;
            padding: 0.5rem 0.75rem;
            background: var(--bg-surface);
            border: 1px solid var(--border-light);
            border-radius: var(--radius-sm);
            color: var(--text-main);
            font-size: 0.875rem;
            outline: none;
            transition: border-color 0.15s;
        }

        .form-control:focus {
            border-color: var(--primary);
            box-shadow: 0 0 0 2px var(--primary-light);
        }

        /* Code Editor Textarea */
        .code-editor-textarea {
            width: 100%;
            height: 480px;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
            font-size: 0.85rem;
            line-height: 1.5;
            background: #0f172a;
            color: #f8fafc;
            border: 1px solid var(--border-light);
            border-radius: var(--radius-sm);
            padding: 0.75rem;
            outline: none;
            resize: vertical;
            white-space: pre;
            tab-size: 4;
        }

        /* Toast Notifications */
        .toast-container {
            position: fixed;
            top: 4.5rem;
            right: 1.5rem;
            z-index: 120;
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
            pointer-events: none;
        }

        .toast {
            pointer-events: auto;
            min-width: 280px;
            max-width: 360px;
            background: var(--bg-surface);
            border: 1px solid var(--border-light);
            border-radius: var(--radius-sm);
            padding: 0.65rem 0.9rem;
            font-size: 0.85rem;
            color: var(--text-main);
            display: flex;
            align-items: center;
            gap: 0.6rem;
            box-shadow: var(--shadow-pop);
            animation: slideInRight 0.2s ease-out;
            transition: opacity 0.25s, transform 0.25s;
        }

        @keyframes slideInRight {
            from { transform: translateX(100%); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }

        .toast.success { border-left: 4px solid var(--success); }
        .toast.error { border-left: 4px solid var(--danger); }
        .toast.info { border-left: 4px solid var(--primary); }

        /* Login Screen */
        .login-wrapper {
            flex: 1;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 2rem 1rem;
        }

        .login-card {
            background: var(--bg-surface);
            border: 1px solid var(--border-light);
            border-radius: var(--radius-lg);
            width: 100%;
            max-width: 380px;
            padding: 2rem;
            box-shadow: var(--shadow-pop);
            text-align: center;
        }

        .login-icon {
            width: 3.25rem;
            height: 3.25rem;
            color: var(--primary);
            margin-bottom: 0.75rem;
        }

        .login-title {
            font-size: 1.25rem;
            font-weight: 700;
            margin-bottom: 0.25rem;
        }

        .login-subtitle {
            font-size: 0.82rem;
            color: var(--text-muted);
            margin-bottom: 1.25rem;
        }

        .spinner {
            border: 2px solid rgba(0, 0, 0, 0.1);
            border-top-color: currentColor;
            border-radius: 50%;
            width: 0.9rem;
            height: 0.9rem;
            animation: spin 0.8s linear infinite;
            display: inline-block;
        }

        @keyframes spin { to { transform: rotate(360deg); } }

        @media (max-width: 768px) {
            .app-header { padding: 0.6rem 1rem; }
            .container { padding: 1rem; }
            .nav-bar { flex-direction: column; align-items: flex-start; }
            .toolbar { flex-direction: column; align-items: stretch; }
            .toolbar-left, .toolbar-right { width: 100%; justify-content: space-between; }
            .search-box { width: 100%; }
            .hide-mobile { display: none; }
        }

        /* PWA & Brand Logo Styles */
        .brand-logo-img {
            width: 30px;
            height: 30px;
            border-radius: 7px;
            object-fit: cover;
            flex-shrink: 0;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            border: 1px solid rgba(0,0,0,0.06);
        }

        .login-logo-img {
            width: 72px;
            height: 72px;
            border-radius: 16px;
            margin: 0 auto 1.25rem;
            display: block;
            box-shadow: 0 6px 18px rgba(79, 70, 229, 0.16);
            object-fit: cover;
            border: 1px solid rgba(0,0,0,0.05);
        }

        .btn-install {
            background: linear-gradient(135deg, #4f46e5 0%, #3b82f6 100%);
            color: #ffffff !important;
            border: none !important;
            box-shadow: 0 2px 8px rgba(79, 70, 229, 0.28);
            font-weight: 600;
            transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
            cursor: pointer;
        }

        .btn-install:hover {
            background: linear-gradient(135deg, #4338ca 0%, #2563eb 100%);
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(79, 70, 229, 0.38);
        }

        .btn-install:active {
            transform: translateY(0);
        }

        .login-pwa-banner {
            margin-top: 1.5rem;
            background: linear-gradient(135deg, #eef2ff 0%, #f0fdf4 100%);
            border: 1px solid #c7d2fe;
            border-radius: var(--radius-md);
            padding: 0.85rem 1rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 0.75rem;
            text-align: left;
        }

        .login-pwa-banner .banner-content {
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }

        .login-pwa-banner .banner-icon {
            width: 36px;
            height: 36px;
            border-radius: 9px;
            background: #4f46e5;
            color: #ffffff;
            display: flex;
            align-items: center;
            justify-content: center;
            flex-shrink: 0;
            box-shadow: 0 2px 6px rgba(79, 70, 229, 0.3);
        }

        .login-pwa-banner strong {
            display: block;
            font-size: 0.84rem;
            color: #1e1b4b;
            font-weight: 600;
        }

        .login-pwa-banner span {
            display: block;
            font-size: 0.73rem;
            color: #475569;
        }

        .install-guide-steps {
            display: flex;
            flex-direction: column;
            gap: 0.85rem;
            margin-top: 1rem;
            text-align: left;
        }

        .install-step-item {
            display: flex;
            align-items: flex-start;
            gap: 0.85rem;
            background: var(--bg-subtle);
            padding: 0.85rem 1rem;
            border-radius: var(--radius-md);
            border: 1px solid var(--border-light);
        }

        .step-num {
            width: 26px;
            height: 26px;
            border-radius: 50%;
            background: var(--primary);
            color: #ffffff;
            font-size: 0.8rem;
            font-weight: 700;
            display: flex;
            align-items: center;
            justify-content: center;
            flex-shrink: 0;
        }

        .step-text {
            font-size: 0.85rem;
            color: var(--text-main);
            line-height: 1.45;
        }

        .step-text strong {
            color: var(--primary);
        }

        @media all and (display-mode: standalone) {
            body {
                padding-top: env(safe-area-inset-top);
                padding-bottom: env(safe-area-inset-bottom);
            }
            .pwa-hide-installed {
                display: none !important;
            }
        }
    </style>
</head>
<body>

    <!-- Header Bar -->
    <header class="app-header">
        <a href="?" class="brand">
            <svg class="svg-icon" style="color: var(--primary); width: 1.5rem; height: 1.5rem;" viewBox="0 0 24 24">
                <path d="M4 20h16a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.93a2 2 0 0 1-1.66-.9l-.82-1.2A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13c0 1.1.9 2 2 2Z"></path>
            </svg>
            <?= htmlspecialchars(FM_APP_TITLE) ?>
            <span class="brand-badge">v<?= htmlspecialchars(FM_VERSION) ?></span>
        </a>

        <div class="header-actions">
            <!-- PWA Install Button (Available on both Login & Dashboard) -->
            <button class="btn btn-sm btn-install pwa-hide-installed" id="btn-install-app" style="display: none;" title="Install BlueFM App">
                <svg class="svg-icon" viewBox="0 0 24 24">
                    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                    <polyline points="7 10 12 15 17 10"></polyline>
                    <line x1="12" y1="15" x2="12" y2="3"></line>
                </svg>
                <span>Install App</span>
            </button>

            <?php if ($is_authenticated): ?>
            <button class="btn btn-sm" id="btn-open-settings" title="Change Username & Password">
                <svg class="svg-icon" viewBox="0 0 24 24">
                    <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path>
                    <circle cx="12" cy="7" r="4"></circle>
                </svg>
                <span id="current-username-badge"><?= htmlspecialchars($_SESSION['fm_user'] ?? FM_DEFAULT_USER) ?></span>
            </button>

            <button class="btn btn-sm btn-danger" id="btn-logout" title="Sign Out">
                <svg class="svg-icon" viewBox="0 0 24 24">
                    <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path>
                    <polyline points="16 17 21 12 16 7"></polyline>
                    <line x1="21" y1="12" x2="9" y2="12"></line>
                </svg>
                <span class="hide-mobile">Logout</span>
            </button>
            <?php endif; ?>
        </div>
    </header>

    <?php if (!$is_authenticated): ?>
    <!-- LOGIN SCREEN -->
    <div class="login-wrapper">
        <div class="login-card">
            <svg class="svg-icon login-icon" viewBox="0 0 24 24">
                <rect width="18" height="11" x="3" y="11" rx="2" ry="2"></rect>
                <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
            </svg>
            <h1 class="login-title"><?= htmlspecialchars(FM_APP_TITLE) ?> Sign In</h1>
            <p class="login-subtitle">Enter your credentials to access the file manager</p>

            <?php if (!empty($login_error)): ?>
            <div style="background: var(--danger-light); color: var(--danger); padding: 0.6rem 0.8rem; border-radius: var(--radius-sm); font-size: 0.82rem; margin-bottom: 1rem; border: 1px solid #fecdd3; text-align: left;">
                <?= htmlspecialchars($login_error) ?>
            </div>
            <?php endif; ?>

            <form id="login-form" method="POST" action="?action=login">
                <input type="hidden" name="action" value="login">
                <div class="form-group" style="margin-bottom: 0.85rem; text-align: left;">
                    <label class="form-label" for="login-username">Username</label>
                    <input type="text" id="login-username" name="username" class="form-control" placeholder="Username" required autofocus autocomplete="username">
                </div>
                <div class="form-group" style="margin-bottom: 1.25rem; text-align: left;">
                    <label class="form-label" for="login-password">Password</label>
                    <input type="password" id="login-password" name="password" class="form-control" placeholder="Password" required autocomplete="current-password">
                </div>
                <button type="submit" id="btn-submit-login" class="btn btn-primary" style="width: 100%; padding: 0.6rem;">
                    <span>Sign In</span>
                </button>
            </form>

            <!-- PWA Quick Install Banner for Login Screen -->
            <div id="login-pwa-banner" class="login-pwa-banner pwa-hide-installed" style="display: none;">
                <div class="banner-content">
                    <div class="banner-icon">
                        <svg class="svg-icon" viewBox="0 0 24 24">
                            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                            <polyline points="7 10 12 15 17 10"></polyline>
                            <line x1="12" y1="15" x2="12" y2="3"></line>
                        </svg>
                    </div>
                    <div>
                        <strong>Install BlueFM App</strong>
                        <span>Open directly from desktop or phone</span>
                    </div>
                </div>
                <button type="button" class="btn btn-sm btn-install" id="btn-login-install">
                    Install
                </button>
            </div>
        </div>
    </div>
    <?php else: ?>
    <!-- MAIN FILE MANAGER INTERFACE -->
    <main class="container">
        <!-- Navigation Breadcrumbs -->
        <nav class="nav-bar">
            <div class="breadcrumbs" id="breadcrumb-container"></div>
            <div style="font-size: 0.8rem; color: var(--text-muted);" id="disk-info">Loading disk stats...</div>
        </nav>

        <!-- Batch Action Bar (Appears when items are selected) -->
        <div class="batch-bar" id="batch-bar">
            <div class="batch-bar-left">
                <span id="batch-selected-count">0 items selected</span>
            </div>
            <div class="batch-bar-right">
                <button class="btn btn-sm btn-primary" id="btn-batch-zip">
                    <svg class="svg-icon" viewBox="0 0 24 24"><rect width="18" height="18" x="3" y="3" rx="2" ry="2"></rect><line x1="12" y1="3" x2="12" y2="21"></line><line x1="3" y1="12" x2="21" y2="12"></line></svg>
                    <span>Zip Selected</span>
                </button>
                <button class="btn btn-sm btn-danger" id="btn-batch-delete">
                    <svg class="svg-icon" viewBox="0 0 24 24"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
                    <span>Delete Selected</span>
                </button>
                <button class="btn btn-sm" id="btn-batch-clear" style="background: rgba(255,255,255,0.15); color: #fff; border-color: rgba(255,255,255,0.25);">
                    <span>Clear</span>
                </button>
            </div>
        </div>

        <!-- Action Toolbar -->
        <div class="toolbar">
            <div class="toolbar-left">
                <button class="btn btn-primary" id="btn-trigger-upload">
                    <svg class="svg-icon" viewBox="0 0 24 24">
                        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                        <polyline points="17 8 12 3 7 8"></polyline>
                        <line x1="12" y1="3" x2="12" y2="15"></line>
                    </svg>
                    <span>Upload Files</span>
                </button>
                <input type="file" id="file-input" multiple style="display: none;">

                <button class="btn" id="btn-new-folder">
                    <svg class="svg-icon" viewBox="0 0 24 24">
                        <path d="M4 20h16a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.93a2 2 0 0 1-1.66-.9l-.82-1.2A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13c0 1.1.9 2 2 2Z"></path>
                        <line x1="12" y1="10" x2="12" y2="16"></line>
                        <line x1="9" y1="13" x2="15" y2="13"></line>
                    </svg>
                    <span>New Folder</span>
                </button>

                <button class="btn" id="btn-new-file">
                    <svg class="svg-icon" viewBox="0 0 24 24">
                        <path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"></path>
                        <line x1="12" y1="11" x2="12" y2="17"></line>
                        <line x1="9" y1="14" x2="15" y2="14"></line>
                    </svg>
                    <span>New File</span>
                </button>

                <button class="btn btn-icon" id="btn-refresh" title="Refresh file list">
                    <svg class="svg-icon" viewBox="0 0 24 24">
                        <path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"></path>
                        <path d="M21 3v5h-5"></path>
                        <path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"></path>
                        <path d="M8 16H3v5"></path>
                    </svg>
                </button>
            </div>

            <div class="toolbar-right">
                <div class="search-box">
                    <svg class="svg-icon search-icon" viewBox="0 0 24 24">
                        <circle cx="11" cy="11" r="8"></circle>
                        <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
                    </svg>
                    <input type="text" id="search-input" class="search-input" placeholder="Quick filter...">
                </div>
            </div>
        </div>

        <!-- Drag & Drop Zone -->
        <div class="drop-zone" id="drop-zone">
            <div class="drop-zone-content">
                <svg class="svg-icon drop-zone-icon" viewBox="0 0 24 24">
                    <path d="M4 14.899A7 7 0 1 1 15.71 8h1.79a4.5 4.5 0 0 1 2.5 8.242"></path>
                    <path d="M12 12v9"></path>
                    <path d="m16 16-4-4-4 4"></path>
                </svg>
                <div class="drop-zone-title">Drag & drop files here to upload</div>
                <div class="drop-zone-desc">Automatic 2MB chunk streaming bypasses cPanel post_max_size & execution timeout limits</div>
            </div>
        </div>

        <!-- File Table -->
        <div class="table-card">
            <table class="file-table">
                <thead>
                    <tr>
                        <th style="width: 3%; text-align: center;">
                            <input type="checkbox" id="select-all-checkbox" title="Select All">
                        </th>
                        <th style="width: 48%;">Name</th>
                        <th style="width: 12%;">Size</th>
                        <th style="width: 10%;" class="hide-mobile">Perms</th>
                        <th style="width: 15%;" class="hide-mobile">Modified</th>
                        <th style="width: 12%; text-align: right;">Actions</th>
                    </tr>
                </thead>
                <tbody id="file-list-body"></tbody>
            </table>
            <div class="status-bar">
                <span id="items-count">0 items</span>
                <span>Chunk Size: 2 MB &bull; Retry Engine: Active &bull; Imunify360 Safe</span>
            </div>
        </div>
    </main>

    <!-- FLOATING CHUNKED UPLOAD PROGRESS WIDGET -->
    <div class="upload-widget" id="upload-widget">
        <div class="upload-widget-header">
            <div class="upload-widget-title">
                <span class="spinner" id="upload-spinner"></span>
                <span id="upload-widget-header-title">Uploading...</span>
            </div>
            <!-- The cross button: explicitly closes immediately -->
            <button class="btn btn-icon btn-sm" id="btn-close-upload-widget" title="Close" style="border: none; background: transparent; cursor: pointer;">
                <svg class="svg-icon" viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
            </button>
        </div>
        <div class="upload-widget-body">
            <div class="upload-current-file" id="upload-current-filename">Preparing upload...</div>
            <div class="progress-track">
                <div class="progress-fill" id="upload-progress-bar"></div>
            </div>
            <div class="upload-meta">
                <span id="upload-bytes-stats">0 MB / 0 MB (0%)</span>
                <span id="upload-speed-eta">0 MB/s &bull; ETA --s</span>
            </div>
            <div style="display: flex; align-items: center; justify-content: space-between; gap: 0.5rem;">
                <div id="upload-status-badge" class="upload-status-badge">
                    <span id="upload-status-text">Initialising 2MB chunk stream...</span>
                </div>
                <button class="btn btn-sm" id="btn-dismiss-upload" style="display: none; padding: 0.2rem 0.5rem; font-size: 0.75rem;">
                    Dismiss
                </button>
            </div>
        </div>
    </div>

    <!-- MODAL: NEW FOLDER -->
    <div class="modal-overlay" id="modal-new-folder">
        <div class="modal-card">
            <div class="modal-header">
                <h3 class="modal-title">Create New Folder</h3>
                <button class="btn btn-icon btn-sm modal-close" title="Close"><svg class="svg-icon" viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg></button>
            </div>
            <form id="form-new-folder">
                <div class="modal-body">
                    <div class="form-group">
                        <label class="form-label" for="folder-name-input">Folder Name</label>
                        <input type="text" id="folder-name-input" class="form-control" placeholder="e.g. documents" required>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn modal-close">Cancel</button>
                    <button type="submit" class="btn btn-primary">Create Folder</button>
                </div>
            </form>
        </div>
    </div>

    <!-- MODAL: NEW FILE -->
    <div class="modal-overlay" id="modal-new-file">
        <div class="modal-card">
            <div class="modal-header">
                <h3 class="modal-title">Create New File</h3>
                <button class="btn btn-icon btn-sm modal-close" title="Close"><svg class="svg-icon" viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg></button>
            </div>
            <form id="form-new-file">
                <div class="modal-body">
                    <div class="form-group">
                        <label class="form-label" for="new-file-name-input">File Name</label>
                        <input type="text" id="new-file-name-input" class="form-control" placeholder="e.g. index.html or script.php" required>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn modal-close">Cancel</button>
                    <button type="submit" class="btn btn-primary">Create File</button>
                </div>
            </form>
        </div>
    </div>

    <!-- MODAL: RENAME -->
    <div class="modal-overlay" id="modal-rename">
        <div class="modal-card">
            <div class="modal-header">
                <h3 class="modal-title">Rename Item</h3>
                <button class="btn btn-icon btn-sm modal-close" title="Close"><svg class="svg-icon" viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg></button>
            </div>
            <form id="form-rename">
                <input type="hidden" id="rename-old-name">
                <div class="modal-body">
                    <div class="form-group">
                        <label class="form-label" for="rename-new-name">New Name</label>
                        <input type="text" id="rename-new-name" class="form-control" required>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn modal-close">Cancel</button>
                    <button type="submit" class="btn btn-primary">Save Changes</button>
                </div>
            </form>
        </div>
    </div>

    <!-- MODAL: CHMOD PERMISSIONS -->
    <div class="modal-overlay" id="modal-chmod">
        <div class="modal-card">
            <div class="modal-header">
                <h3 class="modal-title">Change Permissions</h3>
                <button class="btn btn-icon btn-sm modal-close" title="Close"><svg class="svg-icon" viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg></button>
            </div>
            <form id="form-chmod">
                <input type="hidden" id="chmod-item-name">
                <div class="modal-body">
                    <div style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 0.5rem;">
                        Target: <strong id="chmod-display-name" style="color: var(--text-main);"></strong>
                    </div>
                    <div class="form-group">
                        <label class="form-label" for="chmod-mode-input">Octal Permissions</label>
                        <input type="text" id="chmod-mode-input" class="form-control" placeholder="0644 or 0755" required maxlength="4">
                        <span style="font-size: 0.75rem; color: var(--text-dim);">Common: 0644 (File default), 0755 (Directory / Executable)</span>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn modal-close">Cancel</button>
                    <button type="submit" class="btn btn-primary">Apply Permissions</button>
                </div>
            </form>
        </div>
    </div>

    <!-- MODAL: CODE & TEXT EDITOR -->
    <div class="modal-overlay" id="modal-editor">
        <div class="modal-card modal-lg">
            <div class="modal-header">
                <h3 class="modal-title" id="editor-title">Edit File</h3>
                <button class="btn btn-icon btn-sm modal-close" title="Close"><svg class="svg-icon" viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg></button>
            </div>
            <div class="modal-body" style="padding: 0.75rem 1.25rem;">
                <textarea id="editor-textarea" class="code-editor-textarea" spellcheck="false"></textarea>
            </div>
            <div class="modal-footer" style="justify-content: space-between;">
                <span style="font-size: 0.8rem; color: var(--text-dim); display: flex; align-items: center; gap: 0.5rem;">
                    Shortcut: <code>Ctrl + S</code> or <code>Cmd + S</code> to save
                </span>
                <div style="display: flex; gap: 0.5rem;">
                    <button type="button" class="btn modal-close">Close</button>
                    <button type="button" class="btn btn-primary" id="btn-save-editor">Save Changes</button>
                </div>
            </div>
        </div>
    </div>

    <!-- MODAL: MEDIA & FILE VIEWER -->
    <div class="modal-overlay" id="modal-viewer">
        <div class="modal-card modal-lg">
            <div class="modal-header">
                <h3 class="modal-title" id="viewer-title">Preview File</h3>
                <button class="btn btn-icon btn-sm modal-close" title="Close"><svg class="svg-icon" viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg></button>
            </div>
            <div class="modal-body" id="viewer-content" style="text-align: center; max-height: 80vh; overflow: auto; display: flex; align-items: center; justify-content: center;">
                <!-- Dynamically loaded preview -->
            </div>
            <div class="modal-footer">
                <a href="#" class="btn btn-primary" id="viewer-download-link" download>Download File</a>
                <button type="button" class="btn modal-close">Close</button>
            </div>
        </div>
    </div>

    <!-- MODAL: SETTINGS (CHANGE USERNAME & PASSWORD) -->
    <div class="modal-overlay" id="modal-settings">
        <div class="modal-card">
            <div class="modal-header">
                <h3 class="modal-title">Account Security</h3>
                <button class="btn btn-icon btn-sm modal-close" title="Close"><svg class="svg-icon" viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg></button>
            </div>
            <form id="form-settings">
                <div class="modal-body">
                    <div class="form-group">
                        <label class="form-label" for="settings-current-pass">Current Password</label>
                        <input type="password" id="settings-current-pass" class="form-control" placeholder="Verify existing password" required>
                    </div>
                    <div class="form-group">
                        <label class="form-label" for="settings-new-user">New Username</label>
                        <input type="text" id="settings-new-user" class="form-control" required>
                    </div>
                    <div class="form-group">
                        <label class="form-label" for="settings-new-pass">New Password</label>
                        <input type="password" id="settings-new-pass" class="form-control" placeholder="Min. 6 characters" minlength="6" required>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn modal-close">Cancel</button>
                    <button type="submit" class="btn btn-primary">Update Credentials</button>
                </div>
            </form>
        </div>
    </div>

    <!-- MODAL: DELETE CONFIRMATION -->
    <div class="modal-overlay" id="modal-delete">
        <div class="modal-card">
            <div class="modal-header">
                <h3 class="modal-title">Confirm Deletion</h3>
                <button class="btn btn-icon btn-sm modal-close" title="Close"><svg class="svg-icon" viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg></button>
            </div>
            <form id="form-delete">
                <input type="hidden" id="delete-item-name">
                <div class="modal-body">
                    <p style="color: var(--text-muted); font-size: 0.9rem;">
                        Are you sure you want to permanently delete <strong id="delete-display-name" style="color: var(--text-main);"></strong>?
                    </p>
                    <p style="color: var(--danger); font-size: 0.82rem;">
                        This action cannot be undone. All contents inside folders will be permanently wiped.
                    </p>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn modal-close">Cancel</button>
                    <button type="submit" class="btn btn-danger">Delete Permanently</button>
                </div>
            </form>
        </div>
    </div>
    <?php endif; ?>

    <!-- MODAL: INSTALL APP GUIDE (iOS / Desktop) -->
    <div class="modal-overlay" id="modal-install-guide">
        <div class="modal-card">
            <div class="modal-header">
                <div style="display: flex; align-items: center; gap: 0.6rem;">
                    <img src="icon-192.png" alt="BlueFM Logo" style="width: 28px; height: 28px; border-radius: 6px;">
                    <h3 class="modal-title" id="install-guide-title">Install BlueFM</h3>
                </div>
                <button type="button" class="btn btn-icon btn-sm modal-close" title="Close"><svg class="svg-icon" viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg></button>
            </div>
            <div class="modal-body" id="install-guide-body"></div>
            <div class="modal-footer">
                <button type="button" class="btn btn-primary modal-close">Got It</button>
            </div>
        </div>
    </div>

    <div class="toast-container" id="toast-container"></div>

    <script>
    /**
     * BlueFM File Manager Client Engine
     * Pure Vanilla JavaScript (ES6+), Zero External Libraries
     */
    (function () {
        'use strict';

        const CSRF_TOKEN = '<?= $_SESSION['fm_csrf'] ?? '' ?>';
        const CHUNK_SIZE = <?= FM_CHUNK_SIZE ?>; // 2MB
        const MAX_RETRIES = 3;

        // --- BASE UTILITIES (HTML, Toast, Modal) ---
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        function showToast(message, type = 'info') {
            const container = document.getElementById('toast-container');
            if (!container) return;
            const toast = document.createElement('div');
            toast.className = `toast ${type}`;
            let iconSvg = '';
            if (type === 'success') {
                iconSvg = `<svg class="svg-icon" style="color:var(--success)" viewBox="0 0 24 24"><path d="M20 6L9 17l-5-5"></path></svg>`;
            } else if (type === 'error') {
                iconSvg = `<svg class="svg-icon" style="color:var(--danger)" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>`;
            } else {
                iconSvg = `<svg class="svg-icon" style="color:var(--primary)" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>`;
            }
            toast.innerHTML = `${iconSvg}<span>${escapeHtml(message)}</span>`;
            container.appendChild(toast);
            setTimeout(() => {
                toast.style.opacity = '0';
                toast.style.transform = 'translateX(100%)';
                setTimeout(() => toast.remove(), 250);
            }, 3500);
        }

        function openModal(modal) { if (modal) modal.classList.add('active'); }
        function closeModal(modal) { if (modal) modal.classList.remove('active'); }

        document.querySelectorAll('.modal-close').forEach(btn => btn.addEventListener('click', () => {
            document.querySelectorAll('.modal-overlay').forEach(closeModal);
        }));
        document.querySelectorAll('.modal-overlay').forEach(overlay => {
            overlay.addEventListener('click', (e) => { if (e.target === overlay) closeModal(overlay); });
        });

        // --- PROGRESSIVE WEB APP (PWA) ENGINE ---
        let deferredPrompt = null;
        const btnInstallApp = document.getElementById('btn-install-app');
        const btnLoginInstall = document.getElementById('btn-login-install');
        const loginPwaBanner = document.getElementById('login-pwa-banner');
        const modalInstallGuide = document.getElementById('modal-install-guide');
        const installGuideBody = document.getElementById('install-guide-body');
        const installGuideTitle = document.getElementById('install-guide-title');

        const isIOS = /iPad|iPhone|iPod/.test(navigator.userAgent) && !window.MSStream;
        const isStandalone = window.matchMedia('(display-mode: standalone)').matches || window.navigator.standalone === true;

        if (isStandalone) {
            document.body.classList.add('pwa-standalone');
        }

        // Register Service Worker
        if ('serviceWorker' in navigator) {
            window.addEventListener('load', () => {
                navigator.serviceWorker.register('sw.js')
                    .then((reg) => {
                        console.log('[PWA] Service Worker registered with scope:', reg.scope);
                    })
                    .catch((err) => {
                        console.warn('[PWA] Service Worker registration failed:', err);
                    });
            });
        }

        function showInstallUi() {
            if (isStandalone) return;
            if (btnInstallApp) btnInstallApp.style.display = 'inline-flex';
            if (loginPwaBanner) loginPwaBanner.style.display = 'flex';
        }

        function hideInstallUi() {
            if (btnInstallApp) btnInstallApp.style.display = 'none';
            if (loginPwaBanner) loginPwaBanner.style.display = 'none';
        }

        window.addEventListener('beforeinstallprompt', (e) => {
            e.preventDefault();
            deferredPrompt = e;
            showInstallUi();
        });

        window.addEventListener('appinstalled', () => {
            deferredPrompt = null;
            hideInstallUi();
            showToast('BlueFM installed! You can launch it directly from your device anytime.', 'success');
        });

        // If not running in standalone app mode, show install buttons
        if (!isStandalone) {
            showInstallUi();
        }

        async function triggerInstallFlow() {
            if (deferredPrompt) {
                deferredPrompt.prompt();
                const { outcome } = await deferredPrompt.userChoice;
                if (outcome === 'accepted') {
                    deferredPrompt = null;
                    hideInstallUi();
                }
            } else if (isIOS) {
                if (installGuideTitle) installGuideTitle.textContent = 'Install BlueFM on iOS';
                if (installGuideBody) {
                    installGuideBody.innerHTML = `
                        <p style="font-size: 0.88rem; color: var(--text-muted); margin-bottom: 0.75rem;">
                            Install <strong>BlueFM</strong> on your home screen for quick, full-screen access without Safari's browser bar:
                        </p>
                        <div class="install-guide-steps">
                            <div class="install-step-item">
                                <div class="step-num">1</div>
                                <div class="step-text">Tap the <strong>Share</strong> button in Safari's bottom toolbar (<svg class="svg-icon" style="width:1.1rem;height:1.1rem;vertical-align:-2px;color:var(--primary);" viewBox="0 0 24 24"><path d="M4 12v8a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-8"></path><polyline points="16 6 12 2 8 6"></polyline><line x1="12" y1="2" x2="12" y2="15"></line></svg>).</div>
                            </div>
                            <div class="install-step-item">
                                <div class="step-num">2</div>
                                <div class="step-text">Scroll down the menu and tap <strong>"Add to Home Screen"</strong> (<svg class="svg-icon" style="width:1.1rem;height:1.1rem;vertical-align:-2px;color:var(--primary);" viewBox="0 0 24 24"><rect width="18" height="18" x="3" y="3" rx="2"></rect><line x1="12" y1="8" x2="12" y2="16"></line><line x1="8" y1="12" x2="16" y2="12"></line></svg>).</div>
                            </div>
                            <div class="install-step-item">
                                <div class="step-num">3</div>
                                <div class="step-text">Tap <strong>"Add"</strong> in the top-right corner. The app icon will appear directly on your Home Screen!</div>
                            </div>
                        </div>
                    `;
                }
                openModal(modalInstallGuide);
            } else {
                if (installGuideTitle) installGuideTitle.textContent = 'Install BlueFM App';
                if (installGuideBody) {
                    installGuideBody.innerHTML = `
                        <p style="font-size: 0.88rem; color: var(--text-muted); margin-bottom: 0.75rem;">
                            To install <strong>BlueFM</strong> as a standalone application on your computer:
                        </p>
                        <div class="install-guide-steps">
                            <div class="install-step-item">
                                <div class="step-num">1</div>
                                <div class="step-text">Click the <strong>Install</strong> icon (<svg class="svg-icon" style="width:1.1rem;height:1.1rem;vertical-align:-2px;color:var(--primary);" viewBox="0 0 24 24"><rect width="16" height="12" x="4" y="4" rx="2"></rect><polyline points="10 11 12 13 14 11"></polyline><line x1="12" y1="8" x2="12" y2="13"></line><line x1="8" y1="20" x2="16" y2="20"></line></svg>) in your browser's address bar.</div>
                            </div>
                            <div class="install-step-item">
                                <div class="step-num">2</div>
                                <div class="step-text">Or click browser menu (<strong>&vellip;</strong>) &rarr; select <strong>"Install BlueFM"</strong> or <strong>"Apps &rarr; Install this site as an app"</strong>.</div>
                            </div>
                            <div class="install-step-item">
                                <div class="step-num">3</div>
                                <div class="step-text">Click <strong>Install</strong> to launch it directly from your desktop or taskbar anytime without opening a browser!</div>
                            </div>
                        </div>
                    `;
                }
                openModal(modalInstallGuide);
            }
        }

        if (btnInstallApp) btnInstallApp.addEventListener('click', triggerInstallFlow);
        if (btnLoginInstall) btnLoginInstall.addEventListener('click', triggerInstallFlow);

        // --- AUTHENTICATION (Login Screen) ---
        const loginForm = document.getElementById('login-form');
        if (loginForm) {
            loginForm.addEventListener('submit', async function (e) {
                e.preventDefault();
                const btn = document.getElementById('btn-submit-login');
                const origText = btn ? btn.innerHTML : '';
                if (btn) {
                    btn.disabled = true;
                    btn.innerHTML = '<span class="spinner" style="margin-right: 0.4rem;"></span> Signing In...';
                }

                const username = document.getElementById('login-username').value;
                const password = document.getElementById('login-password').value;
                const formData = new FormData();
                formData.append('action', 'login');
                formData.append('ajax', '1');
                formData.append('username', username);
                formData.append('password', password);

                try {
                    const res = await fetch('?action=login', {
                        method: 'POST',
                        headers: { 'Accept': 'application/json' },
                        body: formData
                    });
                    const data = await res.json();
                    if (data.success) {
                        window.location.href = window.location.pathname;
                    } else {
                        showToast(data.error || 'Invalid credentials', 'error');
                        if (btn) {
                            btn.disabled = false;
                            btn.innerHTML = origText;
                        }
                    }
                } catch (err) {
                    // Fall back to native form submission
                    loginForm.submit();
                }
            });
            return; // Stop execution on the login page; do not query dashboard elements
        }

        // --- DASHBOARD (Authenticated) ---
        let currentPath = '';
        let itemsList = [];
        let selectedItems = new Set();
        let uploadQueue = [];
        let isUploading = false;
        let activeEditorPath = '';

        // Elements
        const toastContainer = document.getElementById('toast-container');
        const btnLogout = document.getElementById('btn-logout');
        const btnOpenSettings = document.getElementById('btn-open-settings');
        const currentUsernameBadge = document.getElementById('current-username-badge');

        const breadcrumbContainer = document.getElementById('breadcrumb-container');
        const fileListBody = document.getElementById('file-list-body');
        const searchInput = document.getElementById('search-input');
        const itemsCountSpan = document.getElementById('items-count');
        const diskInfoSpan = document.getElementById('disk-info');
        const dropZone = document.getElementById('drop-zone');
        const fileInput = document.getElementById('file-input');
        const selectAllCheckbox = document.getElementById('select-all-checkbox');

        const batchBar = document.getElementById('batch-bar');
        const batchSelectedCount = document.getElementById('batch-selected-count');
        const btnBatchDelete = document.getElementById('btn-batch-delete');
        const btnBatchZip = document.getElementById('btn-batch-zip');
        const btnBatchClear = document.getElementById('btn-batch-clear');

        const btnTriggerUpload = document.getElementById('btn-trigger-upload');
        const btnNewFolder = document.getElementById('btn-new-folder');
        const btnNewFile = document.getElementById('btn-new-file');
        const btnRefresh = document.getElementById('btn-refresh');

        // Upload progress elements
        const uploadWidget = document.getElementById('upload-widget');
        const uploadWidgetHeaderTitle = document.getElementById('upload-widget-header-title');
        const uploadCurrentFilename = document.getElementById('upload-current-filename');
        const uploadProgressBar = document.getElementById('upload-progress-bar');
        const uploadBytesStats = document.getElementById('upload-bytes-stats');
        const uploadSpeedEta = document.getElementById('upload-speed-eta');
        const uploadStatusBadge = document.getElementById('upload-status-badge');
        const uploadStatusText = document.getElementById('upload-status-text');
        const uploadSpinner = document.getElementById('upload-spinner');
        const btnCloseUploadWidget = document.getElementById('btn-close-upload-widget');
        const btnDismissUpload = document.getElementById('btn-dismiss-upload');

        // Modals
        const modalNewFolder = document.getElementById('modal-new-folder');
        const formNewFolder = document.getElementById('form-new-folder');
        const folderNameInput = document.getElementById('folder-name-input');

        const modalNewFile = document.getElementById('modal-new-file');
        const formNewFile = document.getElementById('form-new-file');
        const newFileNameInput = document.getElementById('new-file-name-input');

        const modalRename = document.getElementById('modal-rename');
        const formRename = document.getElementById('form-rename');
        const renameOldName = document.getElementById('rename-old-name');
        const renameNewName = document.getElementById('rename-new-name');

        const modalChmod = document.getElementById('modal-chmod');
        const formChmod = document.getElementById('form-chmod');
        const chmodItemName = document.getElementById('chmod-item-name');
        const chmodDisplayName = document.getElementById('chmod-display-name');
        const chmodModeInput = document.getElementById('chmod-mode-input');

        const modalEditor = document.getElementById('modal-editor');
        const editorTitle = document.getElementById('editor-title');
        const editorTextarea = document.getElementById('editor-textarea');
        const btnSaveEditor = document.getElementById('btn-save-editor');

        const modalViewer = document.getElementById('modal-viewer');
        const viewerTitle = document.getElementById('viewer-title');
        const viewerContent = document.getElementById('viewer-content');
        const viewerDownloadLink = document.getElementById('viewer-download-link');

        const modalSettings = document.getElementById('modal-settings');
        const formSettings = document.getElementById('form-settings');
        const settingsCurrentPass = document.getElementById('settings-current-pass');
        const settingsNewUser = document.getElementById('settings-new-user');
        const settingsNewPass = document.getElementById('settings-new-pass');

        const modalDelete = document.getElementById('modal-delete');
        const formDelete = document.getElementById('form-delete');
        const deleteItemName = document.getElementById('delete-item-name');
        const deleteDisplayName = document.getElementById('delete-display-name');

        // --- TOAST NOTIFICATIONS ---
        function formatBytes(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }

        // --- UPLOAD WIDGET DISMISS / CLOSE FIX ---
        function hideUploadWidget() {
            if (uploadWidget) {
                uploadWidget.classList.remove('active');
                uploadWidget.style.display = 'none';
            }
        }

        if (btnCloseUploadWidget) {
            btnCloseUploadWidget.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                hideUploadWidget();
            });
        }

        if (btnDismissUpload) {
            btnDismissUpload.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                hideUploadWidget();
            });
        }

        if (btnLogout) {
            btnLogout.addEventListener('click', async function () {
                try {
                    await fetch('?action=logout', { method: 'POST' });
                    window.location.reload();
                } catch (err) {
                    window.location.reload();
                }
            });
        }

        if (btnOpenSettings) {
            btnOpenSettings.addEventListener('click', () => {
                settingsCurrentPass.value = '';
                settingsNewUser.value = currentUsernameBadge.textContent.trim();
                settingsNewPass.value = '';
                openModal(modalSettings);
                setTimeout(() => settingsCurrentPass.focus(), 50);
            });

            formSettings.addEventListener('submit', async (e) => {
                e.preventDefault();
                const fd = new FormData();
                fd.append('current_password', settingsCurrentPass.value);
                fd.append('new_username', settingsNewUser.value.trim());
                fd.append('new_password', settingsNewPass.value);
                fd.append('csrf_token', CSRF_TOKEN);

                try {
                    const res = await fetch('?action=change_auth', { method: 'POST', body: fd });
                    const data = await res.json();
                    if (data.success) {
                        showToast(data.message, 'success');
                        currentUsernameBadge.textContent = data.username;
                        closeModal(modalSettings);
                    } else {
                        showToast(data.error || 'Could not update credentials', 'error');
                    }
                } catch (err) {
                    showToast('Error: ' + err.message, 'error');
                }
            });
        }

        // --- ICONS ---
        function getFileIcon(item) {
            if (item.is_dir) {
                return `<svg class="svg-icon icon-folder" viewBox="0 0 24 24"><path d="M4 20h16a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.93a2 2 0 0 1-1.66-.9l-.82-1.2A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13c0 1.1.9 2 2 2Z" fill="currentColor" fill-opacity="0.15"></path></svg>`;
            }
            if (item.is_image) {
                return `<svg class="svg-icon icon-image" viewBox="0 0 24 24"><rect width="18" height="18" x="3" y="3" rx="2" ry="2"></rect><circle cx="9" cy="9" r="2"></circle><path d="m21 15-3.086-3.086a2 2 0 0 0-2.828 0L6 21"></path></svg>`;
            }
            if (item.is_video) {
                return `<svg class="svg-icon icon-video" viewBox="0 0 24 24"><polygon points="23 7 16 12 23 17 23 7"></polygon><rect width="14" height="14" x="1" y="5" rx="2" ry="2"></rect></svg>`;
            }
            if (item.is_audio) {
                return `<svg class="svg-icon icon-audio" viewBox="0 0 24 24"><path d="M9 18V5l12-2v13"></path><circle cx="6" cy="18" r="3"></circle><circle cx="18" cy="16" r="3"></circle></svg>`;
            }
            if (item.is_zip) {
                return `<svg class="svg-icon icon-archive" viewBox="0 0 24 24"><rect width="18" height="18" x="3" y="3" rx="2" ry="2"></rect><line x1="12" y1="3" x2="12" y2="21"></line><line x1="3" y1="12" x2="21" y2="12"></line></svg>`;
            }
            if (item.is_editable) {
                return `<svg class="svg-icon icon-code" viewBox="0 0 24 24"><polyline points="16 18 22 12 16 6"></polyline><polyline points="8 6 2 12 8 18"></polyline></svg>`;
            }
            return `<svg class="svg-icon icon-file" viewBox="0 0 24 24"><path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>`;
        }

        // --- DIRECTORY NAVIGATION ---
        async function loadDirectory(path = '') {
            try {
                fileListBody.innerHTML = `<tr><td colspan="6" style="text-align:center; padding: 2.5rem;"><span class="spinner" style="margin-right: 0.5rem;"></span> Loading files...</td></tr>`;
                const res = await fetch(`?action=list&path=${encodeURIComponent(path)}`);
                const data = await res.json();

                if (!data.success) {
                    showToast(data.error || 'Failed to list directory', 'error');
                    return;
                }

                currentPath = data.current_path;
                itemsList = data.items || [];
                selectedItems.clear();
                updateBatchBar();

                renderBreadcrumbs(currentPath);
                renderItems(itemsList);

                if (data.stats) {
                    diskInfoSpan.textContent = `Free: ${data.stats.free_space} / Total: ${data.stats.total_space}`;
                }
            } catch (err) {
                showToast('Error loading directory: ' + err.message, 'error');
            }
        }

        function renderBreadcrumbs(path) {
            breadcrumbContainer.innerHTML = '';
            const homeCrumb = document.createElement('span');
            homeCrumb.className = 'crumb-item' + (path === '' ? ' active' : '');
            homeCrumb.innerHTML = `<svg class="svg-icon" viewBox="0 0 24 24"><path d="m3 9 9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"></path><polyline points="9 22 9 12 15 12 15 22"></polyline></svg> Home`;
            homeCrumb.addEventListener('click', () => loadDirectory(''));
            breadcrumbContainer.appendChild(homeCrumb);

            if (path === '') return;

            const segments = path.split('/').filter(Boolean);
            let accumulated = '';
            segments.forEach((seg, idx) => {
                accumulated += (accumulated ? '/' : '') + seg;
                const pathForSegment = accumulated;
                const isLast = idx === segments.length - 1;

                const sep = document.createElement('span');
                sep.className = 'crumb-separator';
                sep.textContent = '/';
                breadcrumbContainer.appendChild(sep);

                const crumb = document.createElement('span');
                crumb.className = 'crumb-item' + (isLast ? ' active' : '');
                crumb.textContent = seg;
                if (!isLast) {
                    crumb.addEventListener('click', () => loadDirectory(pathForSegment));
                }
                breadcrumbContainer.appendChild(crumb);
            });
        }

        function renderItems(items) {
            fileListBody.innerHTML = '';
            selectAllCheckbox.checked = false;

            if (items.length === 0) {
                fileListBody.innerHTML = `
                    <tr>
                        <td colspan="6">
                            <div class="empty-state">
                                <svg class="svg-icon" style="width: 2.75rem; height: 2.75rem; color: var(--text-dim);" viewBox="0 0 24 24"><path d="M4 20h16a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.93a2 2 0 0 1-1.66-.9l-.82-1.2A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13c0 1.1.9 2 2 2Z"></path></svg>
                                <div style="font-weight: 600; color: var(--text-main);">This folder is empty</div>
                                <div style="font-size: 0.8rem; color: var(--text-muted);">Drop files above or click Upload Files to get started</div>
                            </div>
                        </td>
                    </tr>`;
                itemsCountSpan.textContent = '0 items';
                return;
            }

            itemsCountSpan.textContent = `${items.length} item${items.length === 1 ? '' : 's'}`;

            items.forEach(item => {
                const tr = document.createElement('tr');
                if (item.is_dir) tr.classList.add('is-dir');
                if (selectedItems.has(item.name)) tr.classList.add('selected');

                const icon = getFileIcon(item);

                tr.innerHTML = `
                    <td style="text-align: center;">
                        <input type="checkbox" class="row-checkbox" data-name="${escapeHtml(item.name)}" ${selectedItems.has(item.name) ? 'checked' : ''}>
                    </td>
                    <td>
                        <div class="file-name-cell">
                            ${icon}
                            <span class="file-title">${escapeHtml(item.name)}</span>
                        </div>
                    </td>
                    <td style="color: var(--text-muted); font-size: 0.82rem;">${item.size_formatted}</td>
                    <td class="hide-mobile">
                        <span class="badge-perm action-chmod" title="Change permissions" data-name="${escapeHtml(item.name)}" data-perms="${item.perms}">${item.perms}</span>
                    </td>
                    <td style="color: var(--text-muted); font-size: 0.82rem;" class="hide-mobile">${item.date_formatted}</td>
                    <td>
                        <div class="actions-cell">
                            ${item.is_editable ? `
                            <button class="btn btn-icon btn-sm action-edit" title="Edit code / text" data-name="${escapeHtml(item.name)}">
                                <svg class="svg-icon" viewBox="0 0 24 24"><path d="M12 20h9"></path><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"></path></svg>
                            </button>
                            ` : ''}

                            ${(item.is_image || item.is_video || item.is_audio || item.is_pdf) ? `
                            <button class="btn btn-icon btn-sm action-view" title="Preview media" data-name="${escapeHtml(item.name)}">
                                <svg class="svg-icon" viewBox="0 0 24 24"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
                            </button>
                            ` : ''}

                            ${item.is_zip ? `
                            <button class="btn btn-icon btn-sm action-unzip" title="Extract / Unzip" data-name="${escapeHtml(item.name)}">
                                <svg class="svg-icon" viewBox="0 0 24 24"><polyline points="21 8 21 21 3 21 3 8"></polyline><line x1="1" y1="3" x2="23" y2="3"></line><path d="M10 12h4"></path></svg>
                            </button>
                            ` : ''}

                            ${!item.is_dir ? `
                            <button class="btn btn-icon btn-sm action-download" title="Download file" data-name="${escapeHtml(item.name)}">
                                <svg class="svg-icon" viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
                            </button>
                            ` : ''}

                            <button class="btn btn-icon btn-sm action-duplicate" title="Duplicate" data-name="${escapeHtml(item.name)}">
                                <svg class="svg-icon" viewBox="0 0 24 24"><rect width="13" height="13" x="9" y="9" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                            </button>

                            <button class="btn btn-icon btn-sm action-rename" title="Rename" data-name="${escapeHtml(item.name)}">
                                <svg class="svg-icon" viewBox="0 0 24 24"><path d="M17 3a2.828 2.828 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z"></path></svg>
                            </button>

                            <button class="btn btn-icon btn-sm btn-danger action-delete" title="Delete" data-name="${escapeHtml(item.name)}">
                                <svg class="svg-icon" viewBox="0 0 24 24"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
                            </button>
                        </div>
                    </td>
                `;

                // Handle row clicks
                tr.querySelector('.file-name-cell').addEventListener('click', () => {
                    if (item.is_dir) {
                        const target = currentPath ? `${currentPath}/${item.name}` : item.name;
                        loadDirectory(target);
                    } else if (item.is_editable) {
                        openEditor(item.name);
                    } else if (item.is_image || item.is_video || item.is_audio || item.is_pdf) {
                        openViewer(item);
                    } else {
                        downloadFile(item.name);
                    }
                });

                // Checkbox toggle
                const cb = tr.querySelector('.row-checkbox');
                cb.addEventListener('change', (e) => {
                    if (e.target.checked) selectedItems.add(item.name);
                    else selectedItems.delete(item.name);
                    tr.classList.toggle('selected', e.target.checked);
                    updateBatchBar();
                });

                // Actions
                const btnEdit = tr.querySelector('.action-edit');
                if (btnEdit) btnEdit.addEventListener('click', (e) => { e.stopPropagation(); openEditor(item.name); });

                const btnView = tr.querySelector('.action-view');
                if (btnView) btnView.addEventListener('click', (e) => { e.stopPropagation(); openViewer(item); });

                const btnUnzip = tr.querySelector('.action-unzip');
                if (btnUnzip) btnUnzip.addEventListener('click', (e) => { e.stopPropagation(); extractZip(item.name); });

                const btnDownload = tr.querySelector('.action-download');
                if (btnDownload) btnDownload.addEventListener('click', (e) => { e.stopPropagation(); downloadFile(item.name); });

                tr.querySelector('.action-duplicate').addEventListener('click', (e) => { e.stopPropagation(); duplicateItem(item.name); });
                tr.querySelector('.action-rename').addEventListener('click', (e) => { e.stopPropagation(); openRenameModal(item.name); });
                tr.querySelector('.action-delete').addEventListener('click', (e) => { e.stopPropagation(); openDeleteModal(item.name); });

                const badgePerm = tr.querySelector('.action-chmod');
                if (badgePerm) badgePerm.addEventListener('click', (e) => { e.stopPropagation(); openChmodModal(item.name, item.perms); });

                fileListBody.appendChild(tr);
            });
        }

        // Multi-select & Batch Bar
        selectAllCheckbox.addEventListener('change', function () {
            selectedItems.clear();
            const checkboxes = fileListBody.querySelectorAll('.row-checkbox');
            checkboxes.forEach(cb => {
                cb.checked = selectAllCheckbox.checked;
                const name = cb.getAttribute('data-name');
                if (selectAllCheckbox.checked) selectedItems.add(name);
                cb.closest('tr').classList.toggle('selected', selectAllCheckbox.checked);
            });
            updateBatchBar();
        });

        function updateBatchBar() {
            if (selectedItems.size > 0) {
                batchBar.classList.add('active');
                batchSelectedCount.textContent = `${selectedItems.size} item${selectedItems.size === 1 ? '' : 's'} selected`;
            } else {
                batchBar.classList.remove('active');
            }
        }

        btnBatchClear.addEventListener('click', () => {
            selectedItems.clear();
            selectAllCheckbox.checked = false;
            fileListBody.querySelectorAll('.row-checkbox').forEach(cb => {
                cb.checked = false;
                cb.closest('tr').classList.remove('selected');
            });
            updateBatchBar();
        });

        btnBatchDelete.addEventListener('click', () => {
            if (selectedItems.size === 0) return;
            if (!confirm(`Are you sure you want to permanently delete these ${selectedItems.size} selected items?`)) return;

            const fd = new FormData();
            fd.append('path', currentPath);
            fd.append('csrf_token', CSRF_TOKEN);
            selectedItems.forEach(item => fd.append('items[]', item));

            fetch('?action=delete', { method: 'POST', body: fd })
                .then(r => r.json())
                .then(data => {
                    if (data.success) {
                        showToast(data.message, 'success');
                        loadDirectory(currentPath);
                    } else {
                        showToast(data.error || 'Failed to delete items', 'error');
                    }
                })
                .catch(err => showToast('Error: ' + err.message, 'error'));
        });

        btnBatchZip.addEventListener('click', () => {
            if (selectedItems.size === 0) return;
            const archiveName = prompt('Enter name for the new Zip archive:', 'archive_' + Date.now() + '.zip');
            if (!archiveName) return;

            const fd = new FormData();
            fd.append('path', currentPath);
            fd.append('archive_name', archiveName);
            fd.append('csrf_token', CSRF_TOKEN);
            selectedItems.forEach(item => fd.append('items[]', item));

            showToast('Compressing items into zip...', 'info');
            fetch('?action=zip', { method: 'POST', body: fd })
                .then(r => r.json())
                .then(data => {
                    if (data.success) {
                        showToast(data.message, 'success');
                        loadDirectory(currentPath);
                    } else {
                        showToast(data.error || 'Failed to create zip', 'error');
                    }
                })
                .catch(err => showToast('Error: ' + err.message, 'error'));
        });

        // Search Filter
        searchInput.addEventListener('input', function () {
            const query = this.value.toLowerCase().trim();
            if (!query) {
                renderItems(itemsList);
                return;
            }
            renderItems(itemsList.filter(item => item.name.toLowerCase().includes(query)));
        });

        function downloadFile(name) {
            const filePath = currentPath ? `${currentPath}/${name}` : name;
            window.location.href = `?action=download&path=${encodeURIComponent(filePath)}`;
        }

        // Duplicate
        async function duplicateItem(name) {
            const fd = new FormData();
            fd.append('path', currentPath);
            fd.append('name', name);
            fd.append('csrf_token', CSRF_TOKEN);

            try {
                const res = await fetch('?action=duplicate', { method: 'POST', body: fd });
                const data = await res.json();
                if (data.success) {
                    showToast(data.message, 'success');
                    loadDirectory(currentPath);
                } else {
                    showToast(data.error || 'Duplicate failed', 'error');
                }
            } catch (err) {
                showToast('Error: ' + err.message, 'error');
            }
        }

        // Unzip
        async function extractZip(name) {
            if (!confirm(`Extract '${name}' into the current folder?`)) return;
            const fd = new FormData();
            fd.append('path', currentPath);
            fd.append('name', name);
            fd.append('csrf_token', CSRF_TOKEN);

            showToast('Extracting archive...', 'info');
            try {
                const res = await fetch('?action=unzip', { method: 'POST', body: fd });
                const data = await res.json();
                if (data.success) {
                    showToast(data.message, 'success');
                    loadDirectory(currentPath);
                } else {
                    showToast(data.error || 'Extraction failed', 'error');
                }
            } catch (err) {
                showToast('Error: ' + err.message, 'error');
            }
        }

        // Editor
        async function openEditor(name) {
            activeEditorPath = currentPath ? `${currentPath}/${name}` : name;
            editorTitle.textContent = `Editing: ${name}`;
            editorTextarea.value = 'Loading file contents...';
            openModal(modalEditor);

            try {
                const res = await fetch(`?action=read_file&path=${encodeURIComponent(activeEditorPath)}`);
                const data = await res.json();
                if (data.success) {
                    editorTextarea.value = data.content;
                    setTimeout(() => editorTextarea.focus(), 50);
                } else {
                    showToast(data.error || 'Failed to read file', 'error');
                    closeModal(modalEditor);
                }
            } catch (err) {
                showToast('Error: ' + err.message, 'error');
                closeModal(modalEditor);
            }
        }

        async function saveEditorContent() {
            if (!activeEditorPath) return;
            const fd = new FormData();
            fd.append('path', activeEditorPath);
            fd.append('content', editorTextarea.value);
            fd.append('csrf_token', CSRF_TOKEN);

            btnSaveEditor.textContent = 'Saving...';
            try {
                const res = await fetch('?action=save_file', { method: 'POST', body: fd });
                const data = await res.json();
                if (data.success) {
                    showToast(data.message, 'success');
                } else {
                    showToast(data.error || 'Save failed', 'error');
                }
            } catch (err) {
                showToast('Error: ' + err.message, 'error');
            } finally {
                btnSaveEditor.textContent = 'Save Changes';
            }
        }

        btnSaveEditor.addEventListener('click', saveEditorContent);
        window.addEventListener('keydown', (e) => {
            if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 's') {
                if (modalEditor.classList.contains('active')) {
                    e.preventDefault();
                    saveEditorContent();
                }
            }
        });

        // Viewer / Previewer
        function openViewer(item) {
            const rawUrl = `?action=raw&path=${encodeURIComponent(currentPath ? `${currentPath}/${item.name}` : item.name)}`;
            viewerTitle.textContent = `Preview: ${item.name}`;
            viewerDownloadLink.href = rawUrl;
            viewerDownloadLink.setAttribute('download', item.name);
            viewerContent.innerHTML = '';

            if (item.is_image) {
                viewerContent.innerHTML = `<img src="${rawUrl}" alt="${escapeHtml(item.name)}" style="max-width: 100%; max-height: 70vh; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1);">`;
            } else if (item.is_video) {
                viewerContent.innerHTML = `<video controls autoplay style="max-width: 100%; max-height: 70vh; border-radius: 8px;"><source src="${rawUrl}"></video>`;
            } else if (item.is_audio) {
                viewerContent.innerHTML = `<div style="padding: 2rem;"><audio controls autoplay style="width: 100%;"><source src="${rawUrl}"></audio></div>`;
            } else if (item.is_pdf) {
                viewerContent.innerHTML = `<iframe src="${rawUrl}" style="width: 100%; height: 70vh; border: none; border-radius: 8px;"></iframe>`;
            }
            openModal(modalViewer);
        }

        // New Folder
        btnNewFolder.addEventListener('click', () => {
            folderNameInput.value = '';
            openModal(modalNewFolder);
            setTimeout(() => folderNameInput.focus(), 50);
        });

        formNewFolder.addEventListener('submit', async (e) => {
            e.preventDefault();
            const name = folderNameInput.value.trim();
            if (!name) return;

            const fd = new FormData();
            fd.append('path', currentPath);
            fd.append('name', name);
            fd.append('csrf_token', CSRF_TOKEN);

            try {
                const res = await fetch('?action=mkdir', { method: 'POST', body: fd });
                const data = await res.json();
                if (data.success) {
                    showToast(data.message, 'success');
                    closeModal(modalNewFolder);
                    loadDirectory(currentPath);
                } else {
                    showToast(data.error || 'Failed to create folder', 'error');
                }
            } catch (err) {
                showToast('Error: ' + err.message, 'error');
            }
        });

        // New File
        btnNewFile.addEventListener('click', () => {
            newFileNameInput.value = '';
            openModal(modalNewFile);
            setTimeout(() => newFileNameInput.focus(), 50);
        });

        formNewFile.addEventListener('submit', async (e) => {
            e.preventDefault();
            const name = newFileNameInput.value.trim();
            if (!name) return;

            const fd = new FormData();
            fd.append('path', currentPath);
            fd.append('name', name);
            fd.append('csrf_token', CSRF_TOKEN);

            try {
                const res = await fetch('?action=new_file', { method: 'POST', body: fd });
                const data = await res.json();
                if (data.success) {
                    showToast(data.message, 'success');
                    closeModal(modalNewFile);
                    loadDirectory(currentPath);
                } else {
                    showToast(data.error || 'Failed to create file', 'error');
                }
            } catch (err) {
                showToast('Error: ' + err.message, 'error');
            }
        });

        // Rename
        function openRenameModal(name) {
            renameOldName.value = name;
            renameNewName.value = name;
            openModal(modalRename);
            setTimeout(() => {
                renameNewName.focus();
                const dotIdx = name.lastIndexOf('.');
                if (dotIdx > 0) renameNewName.setSelectionRange(0, dotIdx);
                else renameNewName.select();
            }, 50);
        }

        formRename.addEventListener('submit', async (e) => {
            e.preventDefault();
            const oldName = renameOldName.value;
            const newName = renameNewName.value.trim();
            if (!newName || newName === oldName) {
                closeModal(modalRename);
                return;
            }

            const fd = new FormData();
            fd.append('path', currentPath);
            fd.append('old_name', oldName);
            fd.append('new_name', newName);
            fd.append('csrf_token', CSRF_TOKEN);

            try {
                const res = await fetch('?action=rename', { method: 'POST', body: fd });
                const data = await res.json();
                if (data.success) {
                    showToast(data.message, 'success');
                    closeModal(modalRename);
                    loadDirectory(currentPath);
                } else {
                    showToast(data.error || 'Rename failed', 'error');
                }
            } catch (err) {
                showToast('Error: ' + err.message, 'error');
            }
        });

        // Chmod Permissions
        function openChmodModal(name, currentPerms) {
            chmodItemName.value = name;
            chmodDisplayName.textContent = name;
            chmodModeInput.value = currentPerms || '0644';
            openModal(modalChmod);
            setTimeout(() => chmodModeInput.focus(), 50);
        }

        formChmod.addEventListener('submit', async (e) => {
            e.preventDefault();
            const fd = new FormData();
            fd.append('path', currentPath);
            fd.append('name', chmodItemName.value);
            fd.append('mode', chmodModeInput.value.trim());
            fd.append('csrf_token', CSRF_TOKEN);

            try {
                const res = await fetch('?action=chmod', { method: 'POST', body: fd });
                const data = await res.json();
                if (data.success) {
                    showToast(data.message, 'success');
                    closeModal(modalChmod);
                    loadDirectory(currentPath);
                } else {
                    showToast(data.error || 'Chmod failed', 'error');
                }
            } catch (err) {
                showToast('Error: ' + err.message, 'error');
            }
        });

        // Delete
        function openDeleteModal(name) {
            deleteItemName.value = name;
            deleteDisplayName.textContent = name;
            openModal(modalDelete);
        }

        formDelete.addEventListener('submit', async (e) => {
            e.preventDefault();
            const name = deleteItemName.value;
            const fd = new FormData();
            fd.append('path', currentPath);
            fd.append('name', name);
            fd.append('csrf_token', CSRF_TOKEN);

            try {
                const res = await fetch('?action=delete', { method: 'POST', body: fd });
                const data = await res.json();
                if (data.success) {
                    showToast(data.message, 'success');
                    closeModal(modalDelete);
                    loadDirectory(currentPath);
                } else {
                    showToast(data.error || 'Delete failed', 'error');
                }
            } catch (err) {
                showToast('Error: ' + err.message, 'error');
            }
        });

        btnRefresh.addEventListener('click', () => loadDirectory(currentPath));

        // Drag & Drop & Selection
        btnTriggerUpload.addEventListener('click', () => fileInput.click());
        fileInput.addEventListener('change', () => {
            if (fileInput.files.length > 0) {
                handleFilesSelected(Array.from(fileInput.files));
                fileInput.value = '';
            }
        });

        ['dragenter', 'dragover'].forEach(evt => dropZone.addEventListener(evt, (e) => { e.preventDefault(); dropZone.classList.add('dragover'); }));
        ['dragleave', 'drop'].forEach(evt => dropZone.addEventListener(evt, (e) => { e.preventDefault(); dropZone.classList.remove('dragover'); }));
        dropZone.addEventListener('drop', (e) => {
            if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length > 0) {
                handleFilesSelected(Array.from(e.dataTransfer.files));
            }
        });

        function handleFilesSelected(files) {
            for (const file of files) {
                uploadQueue.push({
                    file: file,
                    targetDir: currentPath,
                    uploadId: 'up_' + Date.now() + '_' + Math.random().toString(36).substring(2, 9)
                });
            }
            if (!isUploading) processNextUpload();
        }

        // --- 2MB CHUNKED UPLOADER WITH AUTOMATIC EXPONENTIAL RETRY ---
        async function processNextUpload() {
            if (uploadQueue.length === 0) {
                isUploading = false;
                uploadSpinner.style.display = 'none';
                uploadWidgetHeaderTitle.textContent = 'Uploads Completed';
                uploadStatusBadge.className = 'upload-status-badge success';
                uploadStatusText.textContent = 'All files uploaded successfully!';
                btnDismissUpload.style.display = 'inline-block';
                loadDirectory(currentPath);
                // Graceful auto-close after 3.5s if not manually dismissed
                setTimeout(() => {
                    if (!isUploading) {
                        hideUploadWidget();
                    }
                }, 3500);
                return;
            }

            isUploading = true;
            btnDismissUpload.style.display = 'none';
            uploadWidget.style.display = 'block';
            uploadWidget.classList.add('active');
            uploadSpinner.style.display = 'inline-block';
            uploadWidgetHeaderTitle.textContent = `Uploading (${uploadQueue.length} queued)...`;

            const currentTask = uploadQueue.shift();
            const { file, targetDir, uploadId } = currentTask;

            uploadCurrentFilename.textContent = file.name;
            uploadProgressBar.style.width = '0%';
            uploadBytesStats.textContent = `0 B / ${formatBytes(file.size)} (0%)`;
            uploadStatusBadge.className = 'upload-status-badge';
            uploadStatusText.textContent = 'Preparing chunks...';

            const totalChunks = Math.max(1, Math.ceil(file.size / CHUNK_SIZE));
            let bytesUploadedSoFar = 0;
            const startTime = Date.now();
            let uploadFailed = false;

            for (let chunkIndex = 0; chunkIndex < totalChunks; chunkIndex++) {
                const start = chunkIndex * CHUNK_SIZE;
                const end = Math.min(file.size, start + CHUNK_SIZE);
                const chunkBlob = file.slice(start, end);
                const currentChunkSize = end - start;

                uploadStatusBadge.className = 'upload-status-badge';
                uploadStatusText.textContent = `Uploading chunk ${chunkIndex + 1} of ${totalChunks}...`;

                const chunkSuccess = await uploadChunkWithRetry(uploadId, chunkIndex, totalChunks, chunkBlob);

                if (!chunkSuccess) {
                    uploadFailed = true;
                    showToast(`Upload failed for '${file.name}'. Server blocked or chunk failed after retries.`, 'error');
                    break;
                }

                bytesUploadedSoFar += currentChunkSize;
                const percent = Math.min(99, Math.round((bytesUploadedSoFar / file.size) * 100));
                uploadProgressBar.style.width = percent + '%';
                uploadBytesStats.textContent = `${formatBytes(bytesUploadedSoFar)} / ${formatBytes(file.size)} (${percent}%)`;

                const elapsedSec = (Date.now() - startTime) / 1000;
                if (elapsedSec > 0.5) {
                    const speed = bytesUploadedSoFar / elapsedSec;
                    const remainingBytes = file.size - bytesUploadedSoFar;
                    const eta = Math.ceil(remainingBytes / speed);
                    uploadSpeedEta.textContent = `${formatBytes(speed)}/s • ETA ~${eta}s`;
                }
            }

            if (!uploadFailed) {
                uploadStatusBadge.className = 'upload-status-badge';
                uploadStatusText.textContent = 'Assembling chunks into final file...';

                const assembleSuccess = await assembleFileOnServer(uploadId, file.name, targetDir, totalChunks, file.size);
                if (assembleSuccess) {
                    uploadProgressBar.style.width = '100%';
                    uploadBytesStats.textContent = `${formatBytes(file.size)} / ${formatBytes(file.size)} (100%)`;
                    uploadStatusText.textContent = `Finished: ${file.name}`;
                    showToast(`'${file.name}' uploaded successfully!`, 'success');
                } else {
                    showToast(`Assembly error for '${file.name}'.`, 'error');
                }
            }

            setTimeout(processNextUpload, 350);
        }

        async function uploadChunkWithRetry(uploadId, chunkIndex, totalChunks, chunkBlob, retryCount = 0) {
            const formData = new FormData();
            formData.append('action', 'upload_chunk');
            formData.append('upload_id', uploadId);
            formData.append('chunk_index', chunkIndex);
            formData.append('total_chunks', totalChunks);
            formData.append('chunk_data', chunkBlob, 'chunk.bin');

            try {
                const response = await fetch('?action=upload_chunk', {
                    method: 'POST',
                    headers: { 'X-CSRF-Token': CSRF_TOKEN },
                    body: formData
                });

                if (response.ok) {
                    const data = await response.json();
                    if (data.success) return true;
                    throw new Error(data.error || 'Server rejected chunk');
                } else {
                    const text = await response.text();
                    throw new Error(`HTTP ${response.status}: ${text.substring(0, 120)}`);
                }
            } catch (err) {
                if (retryCount < MAX_RETRIES) {
                    const delay = Math.pow(2, retryCount) * 1000;
                    uploadStatusBadge.className = 'upload-status-badge error';
                    uploadStatusText.textContent = `Chunk ${chunkIndex + 1} hiccup: ${err.message}. Retrying in ${delay / 1000}s (${retryCount + 1}/${MAX_RETRIES})...`;
                    await new Promise(resolve => setTimeout(resolve, delay));
                    return uploadChunkWithRetry(uploadId, chunkIndex, totalChunks, chunkBlob, retryCount + 1);
                } else {
                    uploadStatusBadge.className = 'upload-status-badge error';
                    uploadStatusText.textContent = `Error: Chunk ${chunkIndex + 1} permanently failed after ${MAX_RETRIES} retries.`;
                    return false;
                }
            }
        }

        async function assembleFileOnServer(uploadId, filename, targetDir, totalChunks, expectedSize) {
            const formData = new FormData();
            formData.append('action', 'assemble_file');
            formData.append('upload_id', uploadId);
            formData.append('filename', filename);
            formData.append('target_dir', targetDir);
            formData.append('total_chunks', totalChunks);
            formData.append('expected_size', expectedSize);

            try {
                const response = await fetch('?action=assemble_file', {
                    method: 'POST',
                    headers: { 'X-CSRF-Token': CSRF_TOKEN },
                    body: formData
                });
                const data = await response.json();
                return data.success;
            } catch (err) {
                return false;
            }
        }

        // Initial Directory Load
        loadDirectory('');
    })();
    </script>
</body>
</html>
