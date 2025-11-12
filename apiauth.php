<?php
require_once 'config.php';
session_start();

// === AUTHENTICATION ===
if (!isset($_SESSION['user_id'])) {
    $_SESSION['user_id'] = 1;
    $_SESSION['username'] = 'admin';
}

// === APPLICATION MANAGER ===
class ApplicationManager {
    public static function getApps($ownerId = 1) {
        try {
            $pdo = Config::getDB();
            $stmt = $pdo->prepare("SELECT * FROM applications WHERE owner_id = ? ORDER BY created_at DESC");
            $stmt->execute([$ownerId]);
            return $stmt->fetchAll();
        } catch (Exception $e) {
            return [];
        }
    }

    public static function getApp($appId, $ownerId = 1) {
        try {
            $pdo = Config::getDB();
            $stmt = $pdo->prepare("SELECT * FROM applications WHERE id = ? AND owner_id = ?");
            $stmt->execute([$appId, $ownerId]);
            return $stmt->fetch();
        } catch (Exception $e) {
            return null;
        }
    }

    public static function regenerateSecret($appId, $ownerId = 1) {
        try {
            $pdo = Config::getDB();
            $secret = bin2hex(random_bytes(32));
            $stmt = $pdo->prepare("UPDATE applications SET secret_key = ? WHERE id = ? AND owner_id = ?");
            if ($stmt->execute([$secret, $appId, $ownerId])) {
                return ['success' => true, 'secret_key' => $secret, 'message' => 'Secret regenerated'];
            }
            return ['success' => false, 'message' => 'Failed to regenerate'];
        } catch (Exception $e) {
            return ['success' => false, 'message' => 'Error: ' . $e->getMessage()];
        }
    }
}

// === GET CURRENT STATE ===
$currentAppId = $_GET['app'] ?? null;
$apps = ApplicationManager::getApps($_SESSION['user_id']);
$currentApp = $currentAppId ? ApplicationManager::getApp($currentAppId, $_SESSION['user_id']) : null;

// === HANDLE POST ACTIONS ===
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $input = json_decode(file_get_contents('php://input'), true);
    if ($input && isset($input['app_id'])) {
        $result = ApplicationManager::regenerateSecret($input['app_id'], $_SESSION['user_id']);
        header('Content-Type: application/json');
        echo json_encode($result);
        exit;
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API Settings - KeyAuth</title>
    <link rel="stylesheet" href="style.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@400;500;600;700&family=Roboto:wght@300;400;500&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-primary: #0a0a0a;
            --bg-secondary: #1a1a1a;
            --bg-card: #2a2a2a;
            --text-primary: #ffffff;
            --text-secondary: #b0b0b0;
            --accent-red: #ff3333;
            --success-green: #00cc66;
            --border-color: #333333;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            font-family: 'Montserrat', sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            overflow-x: hidden;
        }

        /* Mobile Menu Toggle */
        #menu-toggle {
            display: none;
            position: fixed;
            top: 20px;
            left: 20px;
            z-index: 1002;
            background: var(--accent-red);
            color: white;
            border: none;
            width: 30px;
            height: 30px;
            border-radius: 0 5px 0 5px;
            font-size: 1.3rem;
            cursor: pointer;
            transition: all 0.3s ease;
        }

        #menu-toggle:hover { transform: scale(1.05); }

        /* Sidebar */
        .apps-sidebar {
            position: fixed;
            left: 0; top: 0;
            width: 300px;
            height: 100vh;
            background: var(--bg-secondary);
            border-right: 1px solid var(--border-color);
            padding: 20px;
            overflow-y: auto;
            z-index: 1001;
            transition: transform 0.3s ease;
        }

        @media (max-width: 992px) {
            .apps-sidebar { transform: translateX(-100%); }
            .apps-sidebar.active { transform: translateX(0); }
            #menu-toggle { display: flex !important; align-items: center; justify-content: center; }
            .main-content-with-sidebar { margin-left: 0 !important; padding-top: 80px; }
        }

        @media (min-width: 993px) {
            .main-content-with-sidebar { margin-left: 300px; }
        }

        .logo { display: flex; align-items: center; gap: 12px; margin-bottom: 30px; padding-bottom: 20px; border-bottom: 1px solid var(--border-color); }
        .logo-icon { width: 40px; height: 40px; background: var(--accent-red); border-radius: 10px; display: flex; align-items: center; justify-content: center; color: white; font-size: 1.3rem; }
        .logo h1 { font-size: 1.5rem; margin: 0; }
        .tagline { font-size: 0.8rem; color: var(--text-secondary); font-family: 'Roboto', sans-serif; }

        .btn-full { width: 100%; margin-bottom: 12px; padding: 12px; text-align: center; font-weight: 500; }
        .app-item { display: flex; align-items: center; padding: 14px; margin-bottom: 8px; background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 10px; text-decoration: none; color: var(--text-primary); transition: all 0.3s ease; }
        .app-item:hover, .app-item.active { background: var(--accent-red); color: white; border-color: var(--accent-red); }
        .app-icon { width: 40px; height: 40px; background: rgba(255,255,255,0.1); border-radius: 8px; display: flex; align-items: center; justify-content: center; margin-right: 12px; font-size: 1.1rem; }
        .app-info strong { display: block; font-weight: 600; }
        .app-info span { font-size: 0.8rem; opacity: 0.8; }

        .main-content-with-sidebar { padding: 30px; min-height: 100vh; }

        /* API Settings Specific */
        .page-header { margin-bottom: 30px; padding-bottom: 20px; border-bottom: 1px solid var(--border-color); }
        .page-header h2 { display: flex; align-items: center; gap: 10px; font-size: 1.8rem; }
        .page-header p { color: var(--text-secondary); margin-top: 8px; }

        .empty-state, .error-state { text-align: center; padding: 60px 20px; color: var(--text-secondary); }
        .empty-state i, .error-state i { font-size: 3.5rem; margin-bottom: 20px; opacity: 0.7; }

        .api-settings-grid { display: grid; gap: 25px; }

        .settings-card {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            overflow: hidden;
        }

        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 20px;
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--border-color);
        }

        .card-header h3 { display: flex; align-items: center; gap: 10px; font-size: 1.3rem; }

        .action-buttons { display: flex; gap: 10px; }

        .card-body { padding: 25px; }

        .form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }

        .form-group { margin-bottom: 20px; }
        .form-group label { display: flex; align-items: center; gap: 8px; font-size: 0.9rem; margin-bottom: 8px; color: var(--text-secondary); }
        .form-input { background: var(--bg-secondary); padding: 12px; border-radius: 8px; border: 1px solid var(--border-color); color: var(--text-primary); }

        .secret-display-large {
            display: flex;
            align-items: center;
            gap: 10px;
            background: var(--bg-primary);
            padding: 15px;
            border-radius: 8px;
            border: 1px dashed var(--border-color);
            font-family: monospace;
            font-size: 0.95rem;
            word-break: break-all;
        }

        .secret-display-large code { flex: 1; color: var(--accent-red); }

        .form-hint {
            font-size: 0.8rem;
            color: var(--text-secondary);
            margin-top: 8px;
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .endpoint-display {
            display: flex;
            align-items: center;
            gap: 10px;
            background: var(--bg-secondary);
            padding: 15px;
            border-radius: 8px;
            font-family: monospace;
        }

        .endpoint-display code { flex: 1; color: #00cc66; }

        .code-examples { margin-top: 30px; }
        .code-examples h3 { display: flex; align-items: center; gap: 10px; margin-bottom: 15px; font-size: 1.2rem; }

        .code-tabs { border: 1px solid var(--border-color); border-radius: 10px; overflow: hidden; }

        .tab-buttons {
            display: flex;
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--border-color);
        }

        .tab-btn {
            flex: 1;
            padding: 12px;
            background: transparent;
            border: none;
            color: var(--text-secondary);
            font-size: 0.9rem;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            transition: all 0.3s ease;
        }

        .tab-btn.active, .tab-btn:hover {
            background: var(--accent-red);
            color: white;
        }

        .tab-content {
            display: none;
            background: #111;
            padding: 20px;
            max-height: 400px;
            overflow-y: auto;
        }

        .tab-content.active { display: block; }

        .tab-content pre {
            margin: 0;
            white-space: pre-wrap;
            word-wrap: break-word;
            font-size: 0.85rem;
        }

        .tab-content code { color: #00cc66; }

        .notification {
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 15px 20px;
            background: var(--bg-card);
            border-left: 4px solid;
            border-radius: 8px;
            color: white;
            z-index: 1003;
            display: flex;
            align-items: center;
            gap: 10px;
            animation: slideIn 0.3s ease;
            max-width: 350px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
        }

        .notification.success { border-color: var(--success-green); }
        .notification.error { border-color: #ff4444; }

        @keyframes slideIn {
            from { transform: translateX(100%); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }

        @media (max-width: 768px) {
            .form-row { grid-template-columns: 1fr; }
            .card-header { flex-direction: column; align-items: flex-start; gap: 15px; }
            .action-buttons { width: 100%; justify-content: flex-end; }
        }
    </style>
</head>
<body>

    <!-- Mobile Menu Toggle -->
    <button id="menu-toggle" onclick="document.querySelector('.apps-sidebar').classList.toggle('active')">
        <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16m-7 6h7"></path>
        </svg>
    </button>

    <!-- Sidebar -->
    <div class="apps-sidebar">
        <div class="logo">
            <div class="logo-icon">
                <i class="fas fa-key"></i>
            </div>
            <div>
                <h1>AuthGen</h1>
                <div class="tagline">Applications</div>
            </div>
        </div>

        <div class="apps-list">
            <?php if (empty($apps)): ?>
                <div style="text-align: center; padding: 40px 20px; color: var(--text-secondary);">
                    <i class="fas fa-folder-plus" style="font-size: 3rem; margin-bottom: 15px;"></i>
                    <p>No applications yet</p>
                </div>
            <?php else: ?>
                <?php foreach ($apps as $app): ?>
                    <a href="?app=<?= $app['id'] ?>" 
                       class="app-item <?= $currentAppId == $app['id'] ? 'active' : '' ?>"
                       onclick="closeMobileMenu()">
                        <div class="app-icon">
                            <i class="fas fa-cube"></i>
                        </div>
                        <div class="app-info">
                            <strong><?= htmlspecialchars($app['name']) ?></strong>
                            <span>Created <?= date('M j, Y', strtotime($app['created_at'])) ?></span>
                        </div>
                    </a>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>

        <?php if ($currentApp): ?>
            <div style="margin-top: 20px; padding-top: 20px; border-top: 1px solid var(--border-color);">
                <a href="index.php?app=<?= $currentAppId ?>&page=dashboard" class="btn btn-primary btn-full" onclick="closeMobileMenu()">
                    <i class="fas fa-plus-circle"></i> Add Key
                </a>
                <a href="header.php?app=<?= $currentAppId ?>&page=generate" class="btn btn-primary btn-full" onclick="closeMobileMenu()">
                    <i class="fas fa-plus-circle"></i> Add Key
                </a>
                <a href="header.php?app=<?= $currentAppId ?>&page=keys" class="btn btn-primary btn-full" onclick="closeMobileMenu()">
                    <i class="fas fa-key"></i> All Keys
                </a>
                <a href="header.php?app=<?= $currentAppId ?>&page=users" class="btn btn-primary btn-full" onclick="closeMobileMenu()">
                    <i class="fas fa-users"></i> All Users
                </a>
                <a href="webhooks.php?app=<?= $currentAppId ?>" class="btn btn-primary btn-full" onclick="closeMobileMenu()">
                    <i class="fas fa-globe"></i> Webhooks
                </a>
            </div>
        <?php endif; ?>

        <div style="margin-top: auto; padding-top: 20px; border-top: 1px solid var(--border-color);">
            <div style="display: flex; align-items: center; gap: 8px; font-size: 0.9rem;">
                <div style="width: 10px; height: 10px; background: var(--success-green); border-radius: 50%;"></div>
                <span>System Online</span>
            </div>
            <div style="font-size: 0.8rem; color: var(--text-secondary);">v3.0.0</div>
        </div>
    </div>

    <!-- Main Content -->
    <div class="main-content-with-sidebar">
        <?php if (!$currentApp): ?>
            <div style="text-align: center; padding: 80px 20px; max-width: 700px; margin: 0 auto; color: var(--text-secondary);">
                <i class="fas fa-code-branch" style="font-size: 4.5rem; margin-bottom: 20px; opacity: 0.7;"></i>
                <h2>Select an Application</h2>
                <p>Choose an application from the sidebar to manage its API settings.</p>
            </div>
        <?php else: ?>
            <div class="page-header">
                <h2><i class="fas fa-code"></i> API Settings</h2>
                <p>Manage API keys, endpoints, and integration code for <strong><?= htmlspecialchars($currentApp['name']) ?></strong></p>
            </div>

            <div class="api-settings-grid">
                <div class="settings-card">
                    <div class="card-header">
                        <h3><i class="fas fa-cube"></i> <?= htmlspecialchars($currentApp['name']) ?></h3>
                        <div class="action-buttons">
                            <button onclick="regenerateSecret(<?= $currentApp['id'] ?>)" class="btn btn-danger">
                                <i class="fas fa-sync-alt"></i> Regenerate Secret
                            </button>
                            <button onclick="testEndpoint(<?= $currentApp['id'] ?>)" class="btn btn-primary">
                                <i class="fas fa-vial"></i> Test API
                            </button>
                        </div>
                    </div>

                    <div class="card-body">
                        <div class="form-row">
                            <div class="form-group">
                                <label><i class="fas fa-id-card"></i> Application ID</label>
                                <div class="form-input"><?= $currentApp['id'] ?></div>
                            </div>
                            <div class="form-group">
                                <label><i class="fas fa-calendar"></i> Created</label>
                                <div class="form-input"><?= date('M j, Y g:i A', strtotime($currentApp['created_at'])) ?></div>
                            </div>
                        </div>

                        <div class="form-group">
                            <label><i class="fas fa-key"></i> Secret Key</label>
                            <div class="secret-display-large">
                                <code><?= htmlspecialchars($currentApp['secret_key']) ?></code>
                                <button class="btn btn-secondary" onclick="copyToClipboard('<?= $currentApp['secret_key'] ?>')">
                                    <i class="fas fa-copy"></i> Copy
                                </button>
                            </div>
                            <div class="form-hint">
                                <i class="fas fa-exclamation-triangle"></i> Keep this secret! Do not share publicly.
                            </div>
                        </div>

                        <div class="form-group">
                            <label><i class="fas fa-link"></i> API Endpoint</label>
                            <div class="endpoint-display">
                                <code>POST https://<?= $_SERVER['HTTP_HOST'] ?>/verify.php</code>
                                <button class="btn btn-secondary" onclick="copyToClipboard('https://<?= $_SERVER['HTTP_HOST'] ?>/verify.php')">
                                    <i class="fas fa-copy"></i> Copy
                                </button>
                            </div>
                            <div class="form-hint">
                                <i class="fas fa-info-circle"></i> Use this to validate license keys
                            </div>
                        </div>

                        <div class="code-examples">
                            <h3><i class="fas fa-code"></i> Integration Examples</h3>
                            <div class="code-tabs">
                                <div class="tab-buttons">
                                    <button class="tab-btn active" onclick="switchTab('php-<?= $currentApp['id'] ?>', this)"><i class="fab fa-php"></i> PHP</button>
                                    <button class="tab-btn" onclick="switchTab('python-<?= $currentApp['id'] ?>', this)"><i class="fab fa-python"></i> Python</button>
                                    <button class="tab-btn" onclick="switchTab('js-<?= $currentApp['id'] ?>', this)"><i class="fab fa-js"></i> JS</button>
                                    <button class="tab-btn" onclick="switchTab('curl-<?= $currentApp['id'] ?>', this)"><i class="fas fa-terminal"></i> cURL</button>
                                </div>

                                <div id="php-<?= $currentApp['id'] ?>" class="tab-content active">
                                    <pre><code>&lt;?php
$data = [
    'key' => 'USER_LICENSE_KEY',
    'secret' => '<?= $currentApp['secret_key'] ?>'
];

$ch = curl_init('https://<?= $_SERVER['HTTP_HOST'] ?>/verify.php');
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
$response = curl_exec($ch);
curl_close($ch);

print_r(json_decode($response, true));
?&gt;</code></pre>
                                    <div style="padding: 15px; border-top: 1px solid var(--border-color);">
                                        <button class="btn btn-primary" onclick="copyCode('php-<?= $currentApp['id'] ?>')">
                                            <i class="fas fa-copy"></i> Copy PHP Code
                                        </button>
                                    </div>
                                </div>

                                <div id="python-<?= $currentApp['id'] ?>" class="tab-content">
                                    <pre><code>import requests

data = {
    'key': 'USER_LICENSE_KEY',
    'secret': '<?= $currentApp['secret_key'] ?>'
}

response = requests.post('https://<?= $_SERVER['HTTP_HOST'] ?>/verify.php', data=data)
print(response.json())</code></pre>
                                    <div style="padding: 15px; border-top: 1px solid var(--border-color);">
                                        <button class="btn btn-primary" onclick="copyCode('python-<?= $currentApp['id'] ?>')">
                                            <i class="fas fa-copy"></i> Copy Python Code
                                        </button>
                                    </div>
                                </div>

                                <div id="js-<?= $currentApp['id'] ?>" class="tab-content">
                                    <pre><code>fetch('https://<?= $_SERVER['HTTP_HOST'] ?>/verify.php', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
        'key': 'USER_LICENSE_KEY',
        'secret': '<?= $currentApp['secret_key'] ?>'
    })
})
.then(r => r.json())
.then(console.log);</code></pre>
                                    <div style="padding: 15px; border-top: 1px solid var(--border-color);">
                                        <button class="btn btn-primary" onclick="copyCode('js-<?= $currentApp['id'] ?>')">
                                            <i class="fas fa-copy"></i> Copy JS Code
                                        </button>
                                    </div>
                                </div>

                                <div id="curl-<?= $currentApp['id'] ?>" class="tab-content">
                                    <pre><code>curl -X POST "https://<?= $_SERVER['HTTP_HOST'] ?>/verify.php" \
  -d "key=USER_LICENSE_KEY" \
  -d "secret=<?= $currentApp['secret_key'] ?>"</code></pre>
                                    <div style="padding: 15px; border-top: 1px solid var(--border-color);">
                                        <button class="btn btn-primary" onclick="copyCode('curl-<?= $currentApp['id'] ?>')">
                                            <i class="fas fa-copy"></i> Copy cURL
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        <?php endif; ?>
    </div>

    <script>
        function closeMobileMenu() {
            if (window.innerWidth <= 992) {
                document.querySelector('.apps-sidebar').classList.remove('active');
            }
        }

        function switchTab(tabId, btn) {
            document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.getElementById(tabId).classList.add('active');
            btn.classList.add('active');
        }

        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(() => {
                showNotification('Copied!', 'success');
            }).catch(() => {
                showNotification('Copy failed', 'error');
            });
        }

        function copyCode(id) {
            const code = document.querySelector(`#${id} code`).textContent;
            copyToClipboard(code);
        }

        async function regenerateSecret(appId) {
            if (!confirm('Regenerate secret key? This will break all current integrations.')) return;

            try {
                const res = await fetch('apiauth.php', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ app_id: appId })
                });
                const data = await res.json();
                if (data.success) {
                    showNotification('Secret regenerated!', 'success');
                    setTimeout(() => location.reload(), 1500);
                } else {
                    showNotification(data.message, 'error');
                }
            } catch (e) {
                showNotification('Error: ' + e.message, 'error');
            }
        }

        async function testEndpoint(appId) {
            const key = prompt('Enter a license key to test:');
            if (!key) return;

            try {
                const res = await fetch('verify.php', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: new URLSearchParams({
                        key: key,
                        secret: '<?= $currentApp['secret_key'] ?>'
                    })
                });
                const data = await res.json();
                showNotification(data.valid ? 'Valid Key!' : 'Invalid: ' + data.message, data.valid ? 'success' : 'error');
            } catch (e) {
                showNotification('Test failed', 'error');
            }
        }

        function showNotification(msg, type) {
            const n = Object.assign(document.createElement('div'), {
                className: `notification ${type}`,
                innerHTML: `<i class="fas fa-${type === 'success' ? 'check' : 'exclamation'}"></i> ${msg}`
            });
            document.body.appendChild(n);
            setTimeout(() => n.remove(), 4000);
        }
    </script>
</body>
</html>