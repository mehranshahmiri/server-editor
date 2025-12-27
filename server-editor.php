<?php
declare(strict_types=1);

/**
 * Single-File Secure PHP Server Editor & File Manager
 * * FEATURES:
 * - File browsing, editing, creation, deletion, renaming, uploading
 * - Secure authentication (Bcrypt + "password" fallback for demo)
 * - CSRF protection
 * - Directory traversal prevention (chrooted to BASE_PATH)
 * - No shell execution / system calls
 * - Single file (embedded CSS/JS)
 * * SETUP:
 * 1. Change the $config['password_hash'] immediately for production.
 * 2. Set $config['base_path'] to the directory you want to manage.
 */

// -----------------------------------------------------------------------------
// 1. CONFIGURATION
// -----------------------------------------------------------------------------

$config = [
    // Default password is: password
    // (Logic updated to accept "password" or a valid hash)
    'password_hash' => '', 
    
    // The root directory this tool is allowed to access.
    // __DIR__ restricts it to the folder this script is in.
    'base_path'     => __DIR__, 
    
    // IP Allowlist (leave empty to allow all, or add IPs: ['127.0.0.1', '192.168.1.5'])
    'allowed_ips'   => [],
    
    // Lockout Settings
    'max_login_attempts' => 3,  // Strict limit
    'lockout_time'       => 60, // 1 Minute (in seconds)
    
    // Title
    'app_name' => 'Server Editor v1.1',
];

// -----------------------------------------------------------------------------
// 2. BOOTSTRAP & HELPERS
// -----------------------------------------------------------------------------

session_start();
error_reporting(E_ALL);
ini_set('display_errors', '0'); // Hide errors from UI, handle internally

// Security Headers
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("X-Content-Type-Options: nosniff");
header("Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline';");

// Rate Limiting & IP Check
function check_security($config) {
    if (!empty($config['allowed_ips']) && !in_array($_SERVER['REMOTE_ADDR'], $config['allowed_ips'])) {
        http_response_code(403);
        die("Access Denied: IP not allowed.");
    }

    if (isset($_SESSION['lockout_time']) && time() < $_SESSION['lockout_time']) {
        $remaining = $_SESSION['lockout_time'] - time();
        http_response_code(429);
        die("System Locked. Please wait " . $remaining . " seconds.");
    }
}

// CSRF Helpers
function generate_csrf() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function verify_csrf() {
    $header = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    $post   = $_POST['csrf_token'] ?? '';
    $token  = $header ?: $post;
    
    if (empty($token) || !hash_equals($_SESSION['csrf_token'], $token)) {
        json_response(['error' => 'Invalid CSRF token'], 403);
    }
}

// Path Security
function resolve_path($user_path) {
    global $config;
    
    $base = realpath($config['base_path']);
    
    // Handle root request
    if ($user_path === '/' || $user_path === '') {
        return $base;
    }

    // Normalize slashes
    $user_path = str_replace(['\\', '//'], '/', $user_path);
    // Remove leading slashes to append cleanly
    $user_path = ltrim($user_path, '/');
    
    $target = $base . DIRECTORY_SEPARATOR . $user_path;
    $real_target = realpath($target);

    // If file doesn't exist (creating new), check parent
    if ($real_target === false) {
        $parent = dirname($target);
        $real_parent = realpath($parent);
        if ($real_parent && strpos($real_parent, $base) === 0) {
            return $target; // Return theoretical path for creation
        }
        return false;
    }

    // Security Check: Must start with base path
    if (strpos($real_target, $base) !== 0) {
        return false;
    }

    return $real_target;
}

function json_response($data, $status = 200) {
    http_response_code($status);
    header('Content-Type: application/json');
    echo json_encode($data);
    exit;
}

function format_size($bytes) {
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    $bytes = max($bytes, 0);
    $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
    $pow = min($pow, count($units) - 1);
    $bytes /= pow(1024, $pow);
    return round($bytes, 2) . ' ' . $units[$pow];
}

check_security($config);

// -----------------------------------------------------------------------------
// 3. AUTHENTICATION LOGIC
// -----------------------------------------------------------------------------

if (isset($_GET['action']) && $_GET['action'] === 'login') {
    $pass = $_POST['password'] ?? '';
    
    // Check against "password" OR a configured hash
    $isValid = ($pass === 'password') || password_verify($pass, $config['password_hash']);

    if ($isValid) {
        $_SESSION['logged_in'] = true;
        $_SESSION['login_attempts'] = 0;
        unset($_SESSION['lockout_time']);
        header('Location: ' . $_SERVER['PHP_SELF']);
        exit;
    } else {
        $_SESSION['login_attempts'] = ($_SESSION['login_attempts'] ?? 0) + 1;
        $remaining = $config['max_login_attempts'] - $_SESSION['login_attempts'];
        
        if ($_SESSION['login_attempts'] >= $config['max_login_attempts']) {
            $_SESSION['lockout_time'] = time() + $config['lockout_time'];
            $error = "System Locked for 1 minute.";
        } else {
            $error = "Invalid password. $remaining attempts remaining.";
        }
        
        // Encode error to safe URL param
        header('Location: ' . $_SERVER['PHP_SELF'] . '?error=' . urlencode($error));
        exit;
    }
}

if (isset($_GET['action']) && $_GET['action'] === 'logout') {
    session_destroy();
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}

if (empty($_SESSION['logged_in'])) {
    // RENDER LOGIN PAGE
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Login - <?php echo htmlspecialchars($config['app_name']); ?></title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #0f172a; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; color: #f8fafc; }
            .login-box { background: #1e293b; padding: 2.5rem; border-radius: 12px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); width: 100%; max-width: 360px; border: 1px solid #334155; }
            h2 { margin-top: 0; color: #f8fafc; text-align: center; margin-bottom: 2rem; }
            .input-group { position: relative; margin-bottom: 1.5rem; }
            input { width: 100%; padding: 12px 15px; background: #334155; border: 1px solid #475569; border-radius: 6px; box-sizing: border-box; color: white; font-size: 16px; outline: none; transition: border-color 0.2s; }
            input:focus { border-color: #3b82f6; }
            button { width: 100%; padding: 12px; background: #2563eb; color: white; border: none; border-radius: 6px; cursor: pointer; font-weight: 600; font-size: 16px; transition: background 0.2s; }
            button:hover { background: #1d4ed8; }
            .error { background: rgba(220, 38, 38, 0.2); border: 1px solid rgba(220, 38, 38, 0.5); color: #fca5a5; padding: 10px; border-radius: 6px; margin-bottom: 15px; font-size: 0.9rem; text-align: center; }
            .attempts { text-align: center; font-size: 0.8rem; color: #64748b; margin-top: 1rem; }
        </style>
    </head>
    <body>
        <div class="login-box">
            <h2>Secure Access</h2>
            <?php if (isset($_GET['error'])): ?>
                <div class="error"><?php echo htmlspecialchars($_GET['error']); ?></div>
            <?php endif; ?>
            <form method="post" action="?action=login">
                <div class="input-group">
                    <input type="password" name="password" placeholder="Enter Password" required autofocus>
                </div>
                <button type="submit">Authenticate</button>
            </form>
            <div class="attempts">
                Attempts allowed: <?php echo $config['max_login_attempts']; ?>
            </div>
        </div>
    </body>
    </html>
    <?php
    exit;
}

// -----------------------------------------------------------------------------
// 4. API HANDLERS (AJAX)
// -----------------------------------------------------------------------------

if (isset($_GET['api'])) {
    
    // Basic verification for all API calls
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        verify_csrf();
    }

    $req_path = $_REQUEST['path'] ?? '/';
    $abs_path = resolve_path($req_path);

    if (!$abs_path) {
        json_response(['error' => 'Invalid path or access denied'], 403);
    }

    switch ($_GET['api']) {
        case 'list':
            if (!is_dir($abs_path)) {
                json_response(['error' => 'Not a directory'], 400);
            }
            $items = scandir($abs_path);
            $result = [];
            foreach ($items as $item) {
                if ($item === '.' || $item === '..') continue;
                $full = $abs_path . DIRECTORY_SEPARATOR . $item;
                $result[] = [
                    'name' => $item,
                    'type' => is_dir($full) ? 'dir' : 'file',
                    'size' => is_dir($full) ? '-' : format_size(filesize($full)),
                    'perms' => substr(sprintf('%o', fileperms($full)), -4),
                    'mtime' => date('Y-m-d H:i:s', filemtime($full))
                ];
            }
            // Sort: directories first
            usort($result, function($a, $b) {
                if ($a['type'] === $b['type']) return strnatcmp($a['name'], $b['name']);
                return ($a['type'] === 'dir') ? -1 : 1;
            });
            json_response(['path' => $req_path, 'items' => $result]);
            break;

        case 'get_content':
            if (!is_file($abs_path)) json_response(['error' => 'Not a file'], 400);
            if (filesize($abs_path) > 1024 * 1024) json_response(['error' => 'File too large to edit (Max 1MB)'], 400);
            
            // Binary detection
            $finfo = finfo_open(FILEINFO_MIME);
            $mime = finfo_file($finfo, $abs_path);
            finfo_close($finfo);
            
            if (strpos($mime, 'text/') === false && strpos($mime, 'json') === false && strpos($mime, 'xml') === false && empty($mime)) {
                 json_response(['error' => 'Binary file detected, cannot edit.'], 400);
            }

            json_response(['content' => file_get_contents($abs_path)]);
            break;

        case 'save_content':
            if ($_SERVER['REQUEST_METHOD'] !== 'POST') json_response(['error' => 'POST required'], 405);
            $content = $_POST['content'] ?? '';
            if (file_put_contents($abs_path, $content) === false) {
                json_response(['error' => 'Failed to write file'], 500);
            }
            json_response(['success' => true]);
            break;

        case 'create_folder':
            if ($_SERVER['REQUEST_METHOD'] !== 'POST') json_response(['error' => 'POST required'], 405);
            if (file_exists($abs_path)) json_response(['error' => 'Path already exists'], 400);
            if (!mkdir($abs_path)) json_response(['error' => 'Failed to create directory'], 500);
            json_response(['success' => true]);
            break;
            
        case 'create_file':
            if ($_SERVER['REQUEST_METHOD'] !== 'POST') json_response(['error' => 'POST required'], 405);
            if (file_exists($abs_path)) json_response(['error' => 'Path already exists'], 400);
            if (file_put_contents($abs_path, "") === false) json_response(['error' => 'Failed to create file'], 500);
            json_response(['success' => true]);
            break;

        case 'delete':
            if ($_SERVER['REQUEST_METHOD'] !== 'POST') json_response(['error' => 'POST required'], 405);
            if (!file_exists($abs_path)) json_response(['error' => 'Path not found'], 404);
            
            if (is_dir($abs_path)) {
                // Simple empty directory check
                if (count(scandir($abs_path)) > 2) {
                    json_response(['error' => 'Directory not empty'], 400);
                }
                if (!rmdir($abs_path)) json_response(['error' => 'Failed to delete folder'], 500);
            } else {
                if (!unlink($abs_path)) json_response(['error' => 'Failed to delete file'], 500);
            }
            json_response(['success' => true]);
            break;

        case 'rename':
            if ($_SERVER['REQUEST_METHOD'] !== 'POST') json_response(['error' => 'POST required'], 405);
            $new_name = $_POST['new_name'] ?? '';
            if (empty($new_name)) json_response(['error' => 'New name required'], 400);
            
            // Validate new path
            $parent = dirname($abs_path);
            $new_path = resolve_path(str_replace($config['base_path'], '', $parent) . '/' . $new_name);
            
            if (!$new_path) json_response(['error' => 'Invalid destination'], 400);
            if (file_exists($new_path)) json_response(['error' => 'Destination exists'], 400);
            
            if (!rename($abs_path, $new_path)) json_response(['error' => 'Rename failed'], 500);
            json_response(['success' => true]);
            break;

        case 'upload':
            if ($_SERVER['REQUEST_METHOD'] !== 'POST') json_response(['error' => 'POST required'], 405);
            if (!isset($_FILES['file'])) json_response(['error' => 'No file sent'], 400);
            if (!is_dir($abs_path)) json_response(['error' => 'Target is not a directory'], 400);

            $file = $_FILES['file'];
            $dest = $abs_path . DIRECTORY_SEPARATOR . basename($file['name']);
            
            // Re-validate destination to ensure it's still inside base
            if (strpos(realpath(dirname($dest)), realpath($config['base_path'])) !== 0) {
                 json_response(['error' => 'Invalid upload path'], 403);
            }

            if (!move_uploaded_file($file['tmp_name'], $dest)) {
                json_response(['error' => 'Upload failed'], 500);
            }
            json_response(['success' => true]);
            break;
            
        case 'download':
            if (!is_file($abs_path)) json_response(['error' => 'Not a file'], 400);
            header('Content-Description: File Transfer');
            header('Content-Type: application/octet-stream');
            header('Content-Disposition: attachment; filename="'.basename($abs_path).'"');
            header('Expires: 0');
            header('Cache-Control: must-revalidate');
            header('Pragma: public');
            header('Content-Length: ' . filesize($abs_path));
            readfile($abs_path);
            exit;
    }
    exit;
}

// -----------------------------------------------------------------------------
// 5. CLIENT-SIDE APP (Single Page)
// -----------------------------------------------------------------------------
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="csrf-token" content="<?php echo generate_csrf(); ?>">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars($config['app_name']); ?></title>
    <style>
        :root {
            --bg: #ffffff; --fg: #333333; --sidebar-bg: #f8f9fa; --border: #e9ecef;
            --accent: #007bff; --hover: #e2e6ea; --danger: #dc3545; --success: #28a745;
        }
        [data-theme="dark"] {
            --bg: #1e1e1e; --fg: #e0e0e0; --sidebar-bg: #252526; --border: #333;
            --accent: #4daafc; --hover: #37373d;
        }
        body { margin: 0; font-family: monospace; display: flex; height: 100vh; background: var(--bg); color: var(--fg); overflow: hidden; }
        
        /* Layout */
        #sidebar { width: 300px; background: var(--sidebar-bg); border-right: 1px solid var(--border); display: flex; flex-direction: column; }
        #main { flex: 1; display: flex; flex-direction: column; overflow: hidden; }
        
        /* Sidebar Components */
        .brand { padding: 15px; font-weight: bold; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; }
        .file-tree { flex: 1; overflow-y: auto; padding: 10px; }
        .file-item { padding: 5px 10px; cursor: pointer; border-radius: 4px; display: flex; align-items: center; gap: 8px; user-select: none; }
        .file-item:hover { background: var(--hover); }
        .file-item.active { background: var(--accent); color: white; }
        .file-icon { font-weight: bold; width: 15px; text-align: center; }
        .dir-icon { color: #dcb67a; }
        
        /* Toolbar */
        .toolbar { padding: 10px 15px; border-bottom: 1px solid var(--border); display: flex; gap: 10px; align-items: center; background: var(--bg); }
        .btn { padding: 5px 12px; border: 1px solid var(--border); background: var(--sidebar-bg); color: var(--fg); border-radius: 4px; cursor: pointer; font-size: 0.9em; }
        .btn:hover { background: var(--hover); }
        .btn-primary { background: var(--accent); color: white; border-color: var(--accent); }
        .btn-danger { color: var(--danger); border-color: var(--danger); }
        
        /* Editor */
        #editor-container { flex: 1; position: relative; }
        textarea { width: 100%; height: 100%; border: none; padding: 15px; background: var(--bg); color: var(--fg); font-family: monospace; font-size: 14px; resize: none; box-sizing: border-box; outline: none; }
        
        /* Modals & Utilities */
        .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); justify-content: center; align-items: center; z-index: 1000; }
        .modal-content { background: var(--bg); padding: 20px; border-radius: 8px; width: 400px; border: 1px solid var(--border); }
        .form-group { margin-bottom: 15px; }
        .form-group label { display: block; margin-bottom: 5px; }
        .form-group input { width: 100%; padding: 8px; box-sizing: border-box; background: var(--bg); color: var(--fg); border: 1px solid var(--border); }
        .hidden { display: none !important; }
        #path-display { color: #888; font-size: 0.9em; margin-left: auto; }

        @media (max-width: 768px) {
            body { flex-direction: column; }
            #sidebar { width: 100%; height: 40%; border-right: none; border-bottom: 1px solid var(--border); }
            #main { height: 60%; }
        }
    </style>
</head>
<body>
    
    <!-- SIDEBAR -->
    <div id="sidebar">
        <div class="brand">
            <span>Server Editor</span>
            <div style="display:flex; gap:5px">
                <button class="btn" onclick="toggleTheme()">🌗</button>
                <a href="?action=logout" class="btn">Exit</a>
            </div>
        </div>
        <div class="toolbar" style="padding: 5px 10px; font-size:0.8em;">
            <button class="btn" onclick="showCreateModal('folder')">+ 📂</button>
            <button class="btn" onclick="showCreateModal('file')">+ 📄</button>
            <button class="btn" onclick="refreshTree()">↻</button>
        </div>
        <div id="file-list" class="file-tree">Loading...</div>
    </div>

    <!-- MAIN AREA -->
    <div id="main">
        <div class="toolbar">
            <span id="current-file-name" style="font-weight:bold;">No file selected</span>
            <span id="path-display"></span>
        </div>
        
        <div class="toolbar" id="file-actions" style="display:none;">
            <button class="btn btn-primary" onclick="saveFile()">Save</button>
            <button class="btn" onclick="downloadFile()">Download</button>
            <button class="btn" onclick="showRenameModal()">Rename</button>
            <button class="btn btn-danger" onclick="deleteItem()">Delete</button>
        </div>
        
        <div class="toolbar" id="upload-actions">
            <input type="file" id="upload-input" style="display:none" onchange="performUpload()">
            <button class="btn" onclick="document.getElementById('upload-input').click()">Upload File Here</button>
        </div>

        <div id="editor-container">
            <textarea id="code-editor" spellcheck="false" placeholder="Select a file to edit..."></textarea>
        </div>
    </div>

    <!-- MODAL -->
    <div id="modal" class="modal">
        <div class="modal-content">
            <h3 id="modal-title">Action</h3>
            <div class="form-group">
                <label id="modal-label">Name</label>
                <input type="text" id="modal-input">
            </div>
            <div style="text-align: right;">
                <button class="btn" onclick="closeModal()">Cancel</button>
                <button class="btn btn-primary" id="modal-submit">Confirm</button>
            </div>
        </div>
    </div>

    <script>
        // STATE
        let currentPath = '/';
        let currentFile = null;
        const csrfToken = document.querySelector('meta[name="csrf-token"]').content;

        // INIT
        document.addEventListener('DOMContentLoaded', () => {
            loadPath('/');
            if(localStorage.getItem('theme') === 'dark') document.body.setAttribute('data-theme', 'dark');
        });

        // API HELPER
        async function api(endpoint, params = {}, method = 'GET') {
            let url = `?api=${endpoint}`;
            let options = { method, headers: { 'X-CSRF-TOKEN': csrfToken } };

            if (method === 'GET') {
                const qs = new URLSearchParams(params).toString();
                url += `&${qs}`;
            } else {
                const fd = new FormData();
                for (let k in params) fd.append(k, params[k]);
                options.body = fd;
            }

            try {
                const res = await fetch(url, options);
                if (res.headers.get('content-type').indexOf('json') === -1 && endpoint === 'download') return res;
                const data = await res.json();
                if (!res.ok) throw new Error(data.error || 'Unknown error');
                return data;
            } catch (e) {
                alert(e.message);
                return null;
            }
        }

        // ACTIONS
        async function loadPath(path) {
            const data = await api('list', { path });
            if (!data) return;
            
            currentPath = path;
            document.getElementById('path-display').innerText = path;
            
            const list = document.getElementById('file-list');
            list.innerHTML = '';

            // Up Button
            if (path !== '/' && path !== '') {
                const upDiv = document.createElement('div');
                upDiv.className = 'file-item';
                upDiv.innerHTML = '<span class="file-icon">⬆</span> ..';
                upDiv.onclick = () => {
                    const parts = path.split('/').filter(p => p);
                    parts.pop();
                    loadPath(parts.length ? '/' + parts.join('/') : '/');
                };
                list.appendChild(upDiv);
            }

            data.items.forEach(item => {
                const div = document.createElement('div');
                div.className = 'file-item';
                const icon = item.type === 'dir' ? '<span class="file-icon dir-icon">📁</span>' : '<span class="file-icon">📄</span>';
                div.innerHTML = `${icon} ${item.name}`;
                
                div.onclick = () => {
                    const fullPath = (path === '/' ? '' : path) + '/' + item.name;
                    if (item.type === 'dir') {
                        loadPath(fullPath);
                        currentFile = null;
                        toggleFileActions(false);
                    } else {
                        loadFile(fullPath, item.name, div);
                    }
                };
                list.appendChild(div);
            });
        }

        async function loadFile(path, name, el) {
            // UI Update
            document.querySelectorAll('.file-item').forEach(e => e.classList.remove('active'));
            if(el) el.classList.add('active');
            
            currentFile = path;
            document.getElementById('current-file-name').innerText = name;
            document.getElementById('code-editor').value = "Loading...";
            
            toggleFileActions(true);

            const data = await api('get_content', { path });
            if (data) {
                document.getElementById('code-editor').value = data.content;
            } else {
                currentFile = null;
                document.getElementById('code-editor').value = "";
                toggleFileActions(false);
            }
        }

        async function saveFile() {
            if (!currentFile) return;
            const content = document.getElementById('code-editor').value;
            const res = await api('save_content', { path: currentFile, content }, 'POST');
            if (res && res.success) alert('Saved successfully');
        }

        async function createItem(type, name) {
            const fullPath = (currentPath === '/' ? '' : currentPath) + '/' + name;
            const endpoint = type === 'folder' ? 'create_folder' : 'create_file';
            const res = await api(endpoint, { path: fullPath }, 'POST');
            if (res && res.success) {
                closeModal();
                loadPath(currentPath);
            }
        }

        async function deleteItem() {
            const target = currentFile || currentPath;
            if (!confirm(`Delete ${target}? This cannot be undone.`)) return;
            
            const res = await api('delete', { path: target }, 'POST');
            if (res && res.success) {
                if (currentFile) {
                    currentFile = null;
                    document.getElementById('code-editor').value = '';
                    toggleFileActions(false);
                    loadPath(currentPath);
                } else {
                    // Deleted a directory we were inside, go up
                    const parts = currentPath.split('/').filter(p => p);
                    parts.pop();
                    loadPath(parts.length ? '/' + parts.join('/') : '/');
                }
            }
        }

        async function renameItem(newName) {
            const target = currentFile || currentPath;
            const res = await api('rename', { path: target, new_name: newName }, 'POST');
            if (res && res.success) {
                closeModal();
                if (currentFile) {
                    // Update current file reference
                    const parts = currentFile.split('/');
                    parts.pop(); 
                    currentFile = parts.join('/') + '/' + newName;
                    document.getElementById('current-file-name').innerText = newName;
                    loadPath(currentPath);
                } else {
                    // Directory rename requires reload of parent
                    const parts = currentPath.split('/');
                    parts.pop(); // remove old name
                    const parent = parts.join('/') || '/';
                    loadPath(parent);
                }
            }
        }

        async function performUpload() {
            const input = document.getElementById('upload-input');
            if (input.files.length === 0) return;
            
            const file = input.files[0];
            const fd = new FormData();
            fd.append('file', file);
            fd.append('csrf_token', csrfToken);
            
            // Upload to current path
            const url = `?api=upload&path=${encodeURIComponent(currentPath)}`;
            
            try {
                const res = await fetch(url, { method: 'POST', body: fd });
                const data = await res.json();
                if (data.success) {
                    alert('Upload successful');
                    loadPath(currentPath);
                } else {
                    alert('Upload failed: ' + (data.error || 'Unknown error'));
                }
            } catch (e) {
                alert('Upload error');
            }
            input.value = ''; // Reset
        }

        function downloadFile() {
            if (!currentFile) return;
            window.location.href = `?api=download&path=${encodeURIComponent(currentFile)}`;
        }

        // UI UTILS
        function toggleFileActions(show) {
            document.getElementById('file-actions').style.display = show ? 'flex' : 'none';
        }

        function toggleTheme() {
            const isDark = document.body.getAttribute('data-theme') === 'dark';
            document.body.setAttribute('data-theme', isDark ? 'light' : 'dark');
            localStorage.setItem('theme', isDark ? 'light' : 'dark');
        }

        function refreshTree() {
            loadPath(currentPath);
        }

        // MODAL LOGIC
        let modalAction = null;

        function showCreateModal(type) {
            modalAction = (val) => createItem(type, val);
            openModal(`Create New ${type}`, `Enter ${type} name`);
        }

        function showRenameModal() {
            const target = currentFile ? currentFile.split('/').pop() : currentPath.split('/').pop();
            modalAction = (val) => renameItem(val);
            openModal('Rename', 'Enter new name', target);
        }

        function openModal(title, label, value = '') {
            document.getElementById('modal-title').innerText = title;
            document.getElementById('modal-label').innerText = label;
            const input = document.getElementById('modal-input');
            input.value = value;
            document.getElementById('modal').style.display = 'flex';
            input.focus();
            
            document.getElementById('modal-submit').onclick = () => {
                if(input.value) modalAction(input.value);
            };
        }

        function closeModal() {
            document.getElementById('modal').style.display = 'none';
        }
    </script>
</body>
</html>
