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
    public static function createApp($name, $ownerId = 1) {
        try {
            $pdo = Config::getDB();
            $secret = bin2hex(random_bytes(32));
           
            $stmt = $pdo->prepare("INSERT INTO applications (name, owner_id, secret_key) VALUES (?, ?, ?)");
            if ($stmt->execute([$name, $ownerId, $secret])) {
                return [
                    'success' => true,
                    'app_id' => $pdo->lastInsertId(),
                    'secret_key' => $secret,
                    'message' => 'Application created successfully'
                ];
            }
            return ['success' => false, 'message' => 'Failed to create application'];
        } catch (Exception $e) {
            return ['success' => false, 'message' => 'Application name already exists'];
        }
    }
   
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
   
    public static function deleteApp($appId, $ownerId = 1) {
        try {
            $pdo = Config::getDB();
            $stmt = $pdo->prepare("DELETE FROM applications WHERE id = ? AND owner_id = ?");
            return $stmt->execute([$appId, $ownerId]);
        } catch (Exception $e) {
            return false;
        }
    }
}

// === GET CURRENT STATE ===
$currentPage = $_GET['page'] ?? 'dashboard';
$currentAppId = $_GET['app'] ?? null;

// === FETCH DATA ===
$apps = ApplicationManager::getApps($_SESSION['user_id']);
$currentApp = null;
$keyStats = $userStats = [];

if ($currentAppId) {
    $currentApp = ApplicationManager::getApp($currentAppId, $_SESSION['user_id']);
    if ($currentApp) {
        $keyStats = class_exists('LicenseManager') ? LicenseManager::getKeyStats($currentAppId) : [];
        $userStats = class_exists('UserManager') ? UserManager::getUserStats($currentAppId) : [];
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>KeyAuth - Professional Authentication System</title>
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

        /* Mobile Menu Toggle Button */
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

        #menu-toggle:hover {
            transform: scale(1.05);
            box-shadow: 0 6px 20px rgba(255, 51, 51, 0.4);
        }

        /* Sidebar */
        .apps-sidebar {
            position: fixed;
            left: 0;
            top: 0;
            width: 300px;
            height: 100vh;
            background: var(--bg-secondary);
            border-right: 1px solid var(--border-color);
            padding: 20px;
            overflow-y: auto;
            z-index: 1001;
            transition: transform 0.3s ease;
        }

        /* Mobile: Hide sidebar by default */
        @media (max-width: 992px) {
            .apps-sidebar {
                transform: translateX(-100%);
            }
            .apps-sidebar.active {
                transform: translateX(0);
            }
            #menu-toggle {
                display: flex !important;
                align-items: center;
                justify-content: center;
            }
            .main-content-with-sidebar {
                margin-left: 0 !important;
                padding-top: 80px;
            }
        }

        /* Desktop: Always visible */
        @media (min-width: 993px) {
            .apps-sidebar {
                transform: translateX(0) !important;
            }
            .main-content-with-sidebar {
                margin-left: 300px;
            }
        }

        /* Rest of your styles (unchanged) */
        .logo {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 1px solid var(--border-color);
        }
        .logo-icon {
            width: 40px;
            height: 40px;
            background: var(--accent-red);
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 1.3rem;
        }
        .logo h1 { font-size: 1.5rem; margin: 0; }
        .tagline { font-size: 0.8rem; color: var(--text-secondary); font-family: 'Roboto', sans-serif; }

        .btn-full { width: 100%; margin-bottom: 12px; padding: 12px; text-align: center; font-weight: 500; }
        .app-item { display: flex; align-items: center; padding: 14px; margin-bottom: 8px; background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 10px; text-decoration: none; color: var(--text-primary); transition: all 0.3s ease; }
        .app-item:hover, .app-item.active { background: var(--accent-red); color: white; border-color: var(--accent-red); }
        .app-icon { width: 40px; height: 40px; background: rgba(255,255,255,0.1); border-radius: 8px; display: flex; align-items: center; justify-content: center; margin-right: 12px; font-size: 1.1rem; }
        .app-info strong { display: block; font-weight: 600; }
        .app-info span { font-size: 0.8rem; opacity: 0.8; }
        .no-apps { text-align: center; padding: 40px 20px; color: var(--text-secondary); }
        .no-apps i { font-size: 3rem; margin-bottom: 15px; opacity: 0.5; }

        .main-content-with-sidebar {
            padding: 30px;
            min-height: 100vh;
            transition: margin-left 0.3s ease;
        }

        .welcome-screen {
            text-align: center;
            padding: 80px 20px;
            max-width: 700px;
            margin: 0 auto;
        }
        .welcome-screen i { font-size: 4.5rem; color: var(--accent-red); margin-bottom: 20px; }
        .welcome-screen h2 { font-size: 2.2rem; margin-bottom: 15px; }
        .welcome-screen p { color: var(--text-secondary); margin-bottom: 30px; font-size: 1.1rem; }
        .btn-large { padding: 16px 32px; font-size: 1.1rem; }

        .app-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 1px solid var(--border-color);
        }
        .app-title h2 { display: flex; align-items: center; gap: 10px; font-size: 1.8rem; }
        .secret-key-display {
            background: var(--bg-primary);
            padding: 12px 16px;
            border-radius: 8px;
            border: 1px dashed var(--border-color);
            font-family: monospace;
            font-size: 0.9rem;
            color: var(--accent-red);
            word-break: break-all;
        }

        .nav-tabs {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-bottom: 30px;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 10px;
        }
        .tab-btn {
            padding: 10px 16px;
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            color: var(--text-secondary);
            text-decoration: none;
            font-size: 0.9rem;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .tab-btn:hover, .tab-btn.active { background: var(--accent-red); color: white; border-color: var(--accent-red); }

        .modal {
            display: none;
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background: rgba(0,0,0,0.8);
            z-index: 1000;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .modal-content {
            background: var(--bg-card);
            border-radius: 12px;
            width: 100%;
            max-width: 500px;
            border: 1px solid var(--border-color);
        }
        .modal-header {
            padding: 20px;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .modal-header h3 { display: flex; align-items: center; gap: 10px; font-size: 1.3rem; }
        .btn-close { background: none; border: none; font-size: 1.5rem; color: var(--text-secondary); cursor: pointer; }
        .modal-body { padding: 20px; }
        .form-hint { font-size: 0.8rem; color: var(--text-secondary); margin-top: 5px; }
        .modal-footer { padding: 20px; border-top: 1px solid var(--border-color); display: flex; justify-content: flex-end; gap: 10px; }

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
    </style>
</head>
<body>

    <!-- Mobile Menu Toggle Button -->
    <button id="menu-toggle" onclick="document.querySelector('.apps-sidebar').classList.toggle('active')">
        <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16m-7 6h7"></path>
        </svg>
    </button>

    <!-- Applications Sidebar -->
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

        <button class="btn btn-primary btn-full" onclick="showAppModal()">
            <i class="fas fa-plus"></i> New Application
        </button>

        <div class="apps-list">
            <?php if (empty($apps)): ?>
                <div class="no-apps">
                    <i class="fas fa-folder-plus"></i>
                    <p>No applications yet</p>
                </div>
            <?php else: ?>
                <?php foreach ($apps as $app): ?>
                    <a href="?app=<?= $app['id'] ?>&page=dashboard"
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

        <!-- App-Specific Actions -->
        <?php if ($currentApp): ?>
            <div style="margin-top: 20px; padding-top: 20px; border-top: 1px solid var(--border-color);">
                <a href="?app=<?= $currentAppId ?>&page=generate" class="btn btn-primary btn-full" onclick="closeMobileMenu()">
                    <i class="fas fa-plus-circle"></i> Add Key
                </a>
                <a href="?app=<?= $currentAppId ?>&page=adduser" class="btn btn-primary btn-full" onclick="closeMobileMenu()">
                    <i class="fas fa-user-plus"></i> Add User
                </a>
                <a href="?app=<?= $currentAppId ?>&page=keys" class="btn btn-primary btn-full" onclick="closeMobileMenu()">
                    <i class="fas fa-key"></i> All Keys
                </a>
                <a href="?app=<?= $currentAppId ?>&page=users" class="btn btn-primary btn-full" onclick="closeMobileMenu()">
                    <i class="fas fa-users"></i> All Users
                </a>
                <a href="apiauth.php?app=<?= $currentAppId ?>" class="btn btn-primary btn-full" style="background: var(--accent-red); border-color: var(--accent-red);" onclick="closeMobileMenu()">
                    <i class="fas fa-code"></i> API Settings
                </a>
                <a href="webhooks.php?app=<?= $currentAppId ?>" class="btn btn-primary btn-full" onclick="closeMobileMenu()">
                    <i class="fas fa-globe"></i> Webhooks
                </a>
            </div>
        <?php endif; ?>

        <div class="sidebar-footer" style="margin-top: auto; padding-top: 20px; border-top: 1px solid var(--border-color);">
            <div class="system-status" style="display: flex; align-items: center; gap: 8px; font-size: 0.9rem;">
                <div class="status-indicator online" style="width: 10px; height: 10px; background: var(--success-green); border-radius: 50%;"></div>
                <span>System Online</span>
            </div>
            <div class="version-info" style="font-size: 0.8rem; color: var(--text-secondary);">v3.0.0</div>
        </div>
    </div>

    <!-- Main Content -->
    <div class="main-content-with-sidebar">
        <?php if (!$currentApp): ?>
            <div class="welcome-screen">
                <i class="fas fa-key"></i>
                <h2>Welcome to KeyAuth</h2>
                <p>Create your first application to get started with professional license key management, user authentication, and advanced analytics.</p>
                <button class="btn btn-primary btn-large" onclick="showAppModal()">
                    <i class="fas fa-plus"></i> Create Your First Application
                </button>
            </div>
        <?php else: ?>
            
        <?php endif; ?>
    </div>

    <!-- Create App Modal -->
    <div id="appModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3><i class="fas fa-plus"></i> Create New Application</h3>
                <button class="btn-close" onclick="closeAppModal()">×</button>
            </div>
            <div class="modal-body">
                <form id="appForm">
                    <div class="form-group">
                        <label>Application Name</label>
                        <input type="text" name="app_name" class="form-input" required
                               placeholder="e.g., LIAMH4X Premium" maxlength="50">
                        <div class="form-hint">Unique name for your application</div>
                    </div>
                </form>
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" onclick="closeAppModal()">Cancel</button>
                <button class="btn btn-primary" onclick="createApp()">
                    <i class="fas fa-plus"></i> Create
                </button>
            </div>
        </div>
    </div>

    <script>
        // Close mobile menu on link click
        function closeMobileMenu() {
            if (window.innerWidth <= 992) {
                document.querySelector('.apps-sidebar').classList.remove('active');
            }
        }

        // Modal Controls
        function showAppModal() {
            document.getElementById('appModal').style.display = 'flex';
            setTimeout(() => document.querySelector('#appForm input').focus(), 100);
        }

        function closeAppModal() {
            document.getElementById('appModal').style.display = 'none';
            document.getElementById('appForm').reset();
        }

        // Create App
        function createApp() {
            const form = document.getElementById('appForm');
            const name = form.app_name.value.trim();
            if (!name) return showNotification('Please enter an application name', 'error');

            const btn = event.target;
            btn.disabled = true;
            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Creating...';

            fetch('', {
                method: 'POST',
                body: new URLSearchParams({
                    action: 'create_app',
                    app_name: name
                })
            })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    showNotification('Application created!', 'success');
                    setTimeout(() => location.href = `?app=${data.app_id}&page=dashboard`, 800);
                } else {
                    showNotification(data.message || 'Failed to create app', 'error');
                }
            })
            .catch(() => showNotification('Network error', 'error'))
            .finally(() => {
                btn.disabled = false;
                btn.innerHTML = '<i class="fas fa-plus"></i> Create';
            });
        }

        // Notification
        function showNotification(message, type = 'info') {
            const n = document.createElement('div');
            n.className = `notification ${type}`;
            n.innerHTML = `<i class="fas fa-${type === 'success' ? 'check' : 'exclamation'}"></i> ${message}`;
            document.body.appendChild(n);
            setTimeout(() => n.remove(), 4000);
        }

        // Handle POST response
        document.addEventListener('DOMContentLoaded', () => {
            <?php if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'create_app'): ?>
                <?php
                $result = ApplicationManager::createApp($_POST['app_name']);
                echo "showNotification(" . json_encode($result['message']) . ", " . json_encode($result['success'] ? 'success' : 'error') . ");";
                if ($result['success']) {
                    echo "setTimeout(() => location.href = '?app={$result['app_id']}&page=dashboard', 1500);";
                }
                ?>
            <?php endif; ?>
        });
    </script>
</body>
</html>