<?php
require_once 'config.php';
session_start();

// Initialize session
if (!isset($_SESSION['user_id'])) {
    $_SESSION['user_id'] = 1;
    $_SESSION['username'] = 'admin';
}

class ApplicationManager {
    
    // Create new application
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
    
    // Get all applications
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
    
    // Get specific application
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
    
    // Delete application
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

class LicenseManager {
    
    // Generate license key
    public static function generateKey($appId, $expiryDate, $keyType = 'standard') {
        try {
            $pdo = Config::getDB();
            
            // Validate expiry date
            $expiryTimestamp = DateTime::createFromFormat('Y-m-d', $expiryDate);
            if (!$expiryTimestamp) {
                throw new Exception('Invalid expiry date format. Use YYYY-MM-DD');
            }
            
            $today = new DateTime();
            $today->setTime(0, 0, 0);
            $expiryTimestamp->setTime(0, 0, 0);
            
            if ($expiryTimestamp <= $today) {
                throw new Exception('Expiry date must be in the future');
            }
            
            // Determine key length based on type
            $keyLengths = ['standard' => 16, 'premium' => 24, 'enterprise' => 32];
            $length = $keyLengths[$keyType] ?? 16;
            
            // Generate unique key
            $key = '';
            $attempts = 0;
            $maxAttempts = 10;
            
            do {
                $key = self::generateRandomKey($length);
                
                // Check if key already exists in your 'keys' table
                $stmt = $pdo->prepare("SELECT id FROM `keys` WHERE key_string = ?");
                $stmt->execute([$key]);
                $exists = $stmt->fetch();
                
                $attempts++;
                if ($attempts > $maxAttempts) {
                    throw new Exception('Failed to generate unique key after multiple attempts');
                }
            } while ($exists);
            
            $expiryTimestamp->setTime(23, 59, 59);
            
            // Insert into your existing 'keys' table
            $stmt = $pdo->prepare("INSERT INTO `keys` (key_string, expiry_timestamp, key_type) VALUES (?, ?, ?)");
            $success = $stmt->execute([$key, $expiryTimestamp->format('Y-m-d H:i:s'), $keyType]);
            
            if ($success) {
                return [
                    'success' => true,
                    'key' => $key,
                    'expiry' => $expiryTimestamp->format('M j, Y'),
                    'key_type' => $keyType,
                    'message' => 'License key generated successfully'
                ];
            }
            
            throw new Exception('Failed to save key to database');
            
        } catch (Exception $e) {
            return ['success' => false, 'message' => $e->getMessage()];
        }
    }
    
    // Get all keys for app (updated for your 'keys' table)
    public static function getKeys($appId, $page = 1, $perPage = 50, $search = '', $statusFilter = '') {
        try {
            $pdo = Config::getDB();
            $offset = ($page - 1) * $perPage;
            
            // Updated query for your 'keys' table structure
            $query = "
                SELECT k.*, 
                       DATEDIFF(k.expiry_timestamp, NOW()) as days_remaining,
                       CASE 
                         WHEN k.expiry_timestamp < NOW() THEN 'expired'
                         WHEN k.last_used IS NULL THEN 'unused' 
                         ELSE 'active'
                       END as status
                FROM `keys` k 
                WHERE 1=1
            ";
            
            $params = [];
            
            // Add search filter
            if (!empty($search)) {
                $query .= " AND (k.key_string LIKE ? OR k.last_used_ip LIKE ?)";
                $searchTerm = "%$search%";
                $params[] = $searchTerm;
                $params[] = $searchTerm;
            }
            
            // Add status filter
            if (!empty($statusFilter)) {
                switch ($statusFilter) {
                    case 'active':
                        $query .= " AND k.expiry_timestamp > NOW() AND k.last_used IS NOT NULL";
                        break;
                    case 'expired':
                        $query .= " AND k.expiry_timestamp <= NOW()";
                        break;
                    case 'unused':
                        $query .= " AND k.expiry_timestamp > NOW() AND k.last_used IS NULL";
                        break;
                }
            }
            
            $query .= " ORDER BY k.created_at DESC LIMIT ? OFFSET ?";
            $params[] = $perPage;
            $params[] = $offset;
            
            $stmt = $pdo->prepare($query);
            $stmt->execute($params);
            return $stmt->fetchAll();
        } catch (Exception $e) {
            error_log("Error getting keys: " . $e->getMessage());
            return [];
        }
    }
    
    // Get key statistics (updated for your 'keys' table)
    public static function getKeyStats($appId) {
        try {
            $pdo = Config::getDB();
            
            $stats = [
                'total_keys' => 0,
                'active_keys' => 0,
                'expired_keys' => 0,
                'today_usage' => 0
            ];
            
            // Total keys
            $stmt = $pdo->query("SELECT COUNT(*) as count FROM `keys`");
            $stats['total_keys'] = $stmt->fetch()['count'];
            
            // Active keys (not expired and used at least once)
            $stmt = $pdo->query("SELECT COUNT(*) as count FROM `keys` WHERE expiry_timestamp > NOW() AND last_used IS NOT NULL");
            $stats['active_keys'] = $stmt->fetch()['count'];
            
            // Expired keys
            $stmt = $pdo->query("SELECT COUNT(*) as count FROM `keys` WHERE expiry_timestamp <= NOW()");
            $stats['expired_keys'] = $stmt->fetch()['count'];
            
            // Today's usage count
            $stmt = $pdo->query("SELECT COUNT(*) as count FROM `keys` WHERE DATE(last_used) = CURDATE()");
            $stats['today_usage'] = $stmt->fetch()['count'];
            
            return $stats;
        } catch (Exception $e) {
            error_log("Error getting key stats: " . $e->getMessage());
            return [];
        }
    }
    
    private static function generateRandomKey($length) {
        $characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        $key = '';
        
        for ($i = 0; $i < $length; $i++) {
            $key .= $characters[random_int(0, strlen($characters) - 1)];
            if (($i + 1) % 4 === 0 && $i < $length - 1) {
                $key .= '-';
            }
        }
        
        return $key;
    }
}

class UserManager {
    
    // Create new user - matches your actual table structure
    public static function createUser($appId, $username, $password, $email, $expiryDate, $hwid = null) {
        try {
            $pdo = Config::getDB();
            
            // Validate expiry date (you don't have expiry_date column, so we'll store in permissions or skip)
            $expiry = DateTime::createFromFormat('Y-m-d', $expiryDate);
            if (!$expiry || $expiry <= new DateTime()) {
                throw new Exception('Invalid or past expiry date');
            }
            
            // Check if username/email already exists
            $stmt = $pdo->prepare("SELECT id FROM users WHERE username = ? OR email = ?");
            $stmt->execute([$username, $email]);
            if ($stmt->fetch()) {
                throw new Exception('Username or email already exists');
            }
            
            $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
            
            // Build permissions data to store expiry date
            $permissionsData = [
                'expiry_date' => $expiryDate,
                'hwid' => $hwid,
                'license_type' => 'standard'
            ];
            
            // Insert into users table with your actual column names
            $stmt = $pdo->prepare("
                INSERT INTO users (
                    app_id, username, email, password_hash, 
                    first_name, last_name, role, is_active,
                    permissions
                ) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ");
            
            $success = $stmt->execute([
                $appId,
                $username,
                $email,
                $hashedPassword,
                '', // first_name (empty for now)
                '', // last_name (empty for now)
                'user', // role
                1, // is_active
                json_encode($permissionsData) // store expiry and hwid in permissions
            ]);
            
            if ($success) {
                return [
                    'success' => true,
                    'user_id' => $pdo->lastInsertId(),
                    'message' => 'User created successfully',
                    'username' => $username,
                    'email' => $email,
                    'expiry_date' => $expiryDate
                ];
            }
            
            throw new Exception('Failed to create user');
            
        } catch (Exception $e) {
            error_log("User creation error: " . $e->getMessage());
            return ['success' => false, 'message' => $e->getMessage()];
        }
    }
    
    // Get all users - matches your table structure
    public static function getUsers($appId, $page = 1, $perPage = 50, $search = '') {
        try {
            $pdo = Config::getDB();
            $offset = ($page - 1) * $perPage;
            
            $query = "SELECT * FROM users WHERE app_id = ?";
            $params = [$appId];
            
            if (!empty($search)) {
                $query .= " AND (username LIKE ? OR email LIKE ? OR first_name LIKE ? OR last_name LIKE ?)";
                $searchTerm = "%$search%";
                $params[] = $searchTerm;
                $params[] = $searchTerm;
                $params[] = $searchTerm;
                $params[] = $searchTerm;
            }
            
            $query .= " ORDER BY created_at DESC LIMIT ? OFFSET ?";
            $params[] = $perPage;
            $params[] = $offset;
            
            $stmt = $pdo->prepare($query);
            $stmt->execute($params);
            
            $users = $stmt->fetchAll();
            
            // Parse permissions JSON for each user
            foreach ($users as &$user) {
                if (!empty($user['permissions'])) {
                    $user['permissions_data'] = json_decode($user['permissions'], true);
                } else {
                    $user['permissions_data'] = [];
                }
            }
            
            return $users;
        } catch (Exception $e) {
            error_log("Error getting users: " . $e->getMessage());
            return [];
        }
    }
    
    // Get user statistics - matches your table structure
    public static function getUserStats($appId) {
        try {
            $pdo = Config::getDB();
            
            $stats = [
                'total_users' => 0,
                'active_users' => 0,
                'expired_users' => 0,
                'banned_users' => 0
            ];
            
            // Total users for this app
            $stmt = $pdo->prepare("SELECT COUNT(*) as count FROM users WHERE app_id = ?");
            $stmt->execute([$appId]);
            $stats['total_users'] = $stmt->fetch()['count'];
            
            // Active users (is_active = 1 and not expired)
            $stmt = $pdo->prepare("SELECT COUNT(*) as count FROM users WHERE app_id = ? AND is_active = 1");
            $stmt->execute([$appId]);
            $stats['active_users'] = $stmt->fetch()['count'];
            
            // Expired users - we'll check permissions field for expiry date
            // This is a simplified approach - you might want to improve this
            $stmt = $pdo->prepare("SELECT COUNT(*) as count FROM users WHERE app_id = ? AND is_active = 0");
            $stmt->execute([$appId]);
            $stats['expired_users'] = $stmt->fetch()['count'];
            
            // Banned users (you don't have a banned status, so using is_active = 0)
            $stmt = $pdo->prepare("SELECT COUNT(*) as count FROM users WHERE app_id = ? AND is_active = 0");
            $stmt->execute([$appId]);
            $stats['banned_users'] = $stmt->fetch()['count'];
            
            return $stats;
        } catch (Exception $e) {
            error_log("Error getting user stats: " . $e->getMessage());
            return [];
        }
    }
    
    // Update user expiry date
    public static function updateUserExpiry($userId, $expiryDate) {
        try {
            $pdo = Config::getDB();
            
            // Get current permissions
            $stmt = $pdo->prepare("SELECT permissions FROM users WHERE id = ?");
            $stmt->execute([$userId]);
            $user = $stmt->fetch();
            
            if (!$user) {
                throw new Exception('User not found');
            }
            
            $permissions = [];
            if (!empty($user['permissions'])) {
                $permissions = json_decode($user['permissions'], true);
            }
            
            // Update expiry date in permissions
            $permissions['expiry_date'] = $expiryDate;
            
            $stmt = $pdo->prepare("UPDATE users SET permissions = ? WHERE id = ?");
            $success = $stmt->execute([json_encode($permissions), $userId]);
            
            return $success;
            
        } catch (Exception $e) {
            error_log("Error updating user expiry: " . $e->getMessage());
            return false;
        }
    }
    
    // Check if user is expired
    public static function isUserExpired($userId) {
        try {
            $pdo = Config::getDB();
            
            $stmt = $pdo->prepare("SELECT permissions FROM users WHERE id = ?");
            $stmt->execute([$userId]);
            $user = $stmt->fetch();
            
            if (!$user || empty($user['permissions'])) {
                return false;
            }
            
            $permissions = json_decode($user['permissions'], true);
            
            if (isset($permissions['expiry_date'])) {
                $expiry = DateTime::createFromFormat('Y-m-d', $permissions['expiry_date']);
                $today = new DateTime();
                
                return $expiry <= $today;
            }
            
            return false;
            
        } catch (Exception $e) {
            error_log("Error checking user expiry: " . $e->getMessage());
            return false;
        }
    }
}
// Handle POST requests
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json');
    
    if (isset($_POST['action'])) {
        switch ($_POST['action']) {
            case 'create_app':
                $response = ApplicationManager::createApp($_POST['app_name'], $_SESSION['user_id']);
                echo json_encode($response);
                exit;
                
            case 'generate_key':
                $response = LicenseManager::generateKey($_POST['app_id'], $_POST['expiry_date'], $_POST['key_type'] ?? 'standard');
                echo json_encode($response);
                exit;
                
            case 'create_user':
                $response = UserManager::createUser(
                    $_POST['app_id'],
                    $_POST['username'],
                    $_POST['password'],
                    $_POST['email'],
                    $_POST['expiry_date'],
                    $_POST['hwid'] ?? null
                );
                echo json_encode($response);
                exit;
        }
    }
}

// Get current state
$currentPage = $_GET['page'] ?? 'dashboard';
$currentApp = $_GET['app'] ?? null;

// Get applications
$apps = ApplicationManager::getApps($_SESSION['user_id']);
$currentAppData = $currentApp ? ApplicationManager::getApp($currentApp, $_SESSION['user_id']) : null;

// Get statistics
$keyStats = $currentAppData ? LicenseManager::getKeyStats($currentApp) : [];
$userStats = $currentAppData ? UserManager::getUserStats($currentApp) : [];
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
    
    .app-item {
        display: flex;
        align-items: center;
        padding: 15px;
        margin-bottom: 10px;
        background: var(--bg-card);
        border: 1px solid var(--border-color);
        border-radius: 10px;
        text-decoration: none;
        color: var(--text-primary);
        transition: all 0.3s ease;
    }
    
    .app-item:hover, .app-item.active {
        background: var(--accent-red);
        color: white;
        border-color: var(--accent-red);
    }
    
    .app-icon {
        width: 40px;
        height: 40px;
        background: rgba(255,255,255,0.1);
        border-radius: 8px;
        display: flex;
        align-items: center;
        justify-content: center;
        margin-right: 15px;
    }
    
    .app-info strong {
        display: block;
        font-weight: 600;
    }
    
    .app-info span {
        font-size: 0.8rem;
        opacity: 0.8;
    }
    
    .welcome-screen {
        text-align: center;
        padding: 60px 20px;
    }
    
    .welcome-screen i {
        font-size: 4rem;
        color: var(--accent-red);
        margin-bottom: 20px;
    }
    
    .feature-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
        gap: 20px;
        margin-top: 40px;
    }
    
    .feature-card {
        background: var(--bg-card);
        padding: 30px;
        border-radius: 10px;
        border: 1px solid var(--border-color);
        text-align: center;
    }
    
    .feature-card i {
        font-size: 2.5rem;
        color: var(--accent-red);
        margin-bottom: 15px;
    }
    
    .app-header {
        display: flex;
        justify-content: between;
        align-items: center;
        margin-bottom: 30px;
        padding-bottom: 20px;
        border-bottom: 1px solid var(--border-color);
    }
    
    .app-title h2 {
        display: flex;
        align-items: center;
        gap: 10px;
        margin-bottom: 5px;
    }
    
    .secret-key-display {
        background: var(--bg-primary);
        padding: 15px;
        border-radius: 8px;
        border: 1px solid var(--border-color);
        margin-top: 10px;
    }
    
    .secret-key-display code {
        color: var(--accent-red);
        font-weight: 600;
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

    <!-- Applications Sidebar -->
    <div class="apps-sidebar">
        <div class="logo" style="margin-bottom: 30px;">
            <div class="logo-icon" style="width: 40px; height: 40px;">
                <i class="fas fa-key"></i>
            </div>
            <div class="logo-text">
                <h1 style="font-size: 1.5rem;">AuthGen</h1>
                <span class="tagline">Applications</span>
            </div>
        </div>
        
        <button class="btn btn-primary btn-full" onclick="showAppModal()" style="margin-bottom: 20px;">
            <i class="fas fa-plus"></i> New Application
        </button>
       
        
        <div class="apps-list">
            <?php if (empty($apps)): ?>
                <div class="no-apps" style="text-align: center; padding: 40px 20px; color: var(--text-secondary);">
                    <i class="fas fa-folder-plus" style="font-size: 3rem; margin-bottom: 15px;"></i>
                    <p>No applications yet</p>
                </div>
            <?php else: ?>
                <?php foreach ($apps as $app): ?>
                    <a href="?app=<?= $app['id'] ?>&page=dashboard" 
                       class="app-item <?= $currentApp == $app['id'] ? 'active' : '' ?>">
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
            <!-- In the apps-sidebar section -->
<a href="?app=<?= $currentApp ?>&page=generate" class="btn btn-primary btn-full" style="margin-bottom: 15px;">
    <i class="fas fa-plus-circle"></i> Add Key
</a>
<a href="?app=<?= $currentApp ?>&page=adduser" class="btn btn-primary btn-full" style="margin-bottom: 15px;">
    <i class="fas fa-user-plus"></i> Add User
</a>
<a href="?app=<?= $currentApp ?>&page=keys" class="btn btn-primary btn-full" style="margin-bottom: 15px;">
    <i class="fas fa-key"></i> All Keys
</a>
<a href="?app=<?= $currentApp ?>&page=users" class="btn btn-primary btn-full" style="margin-bottom: 15px;">
    <i class="fas fa-users"></i> All Users
</a>
<a href="apiauth.php?app=<?= $currentApp ?>" class="btn btn-primary btn-full" style="margin-bottom: 15px; background: var(--accent-red); border-color: var(--accent-red);">
    <i class="fas fa-code"></i> API Settings
</a>
<a href="webhooks.php?app=<?= $currentApp ?>" class="btn btn-primary btn-full" style="margin-bottom: 15px;">
    <i class="fas fa-globe"></i> Webhooks
</a>
        </div>
        
        <div class="sidebar-footer" style="margin-top: 30px; padding-top: 20px; border-top: 1px solid var(--border-color);">
            <div class="system-status">
                <div class="status-indicator online"></div>
                <span>System Online</span>
            </div>
            <div class="version-info">v3.0.0</div>
        </div>
    </div>

    <!-- Main Content -->
    <div class="main-content-with-sidebar">
        <?php if (!$currentAppData): ?>
            <!-- Welcome Screen -->
            <div class="welcome-screen">
                <i class="fas fa-key"></i>
                <h2>Welcome to KeyAuth</h2>
                <p style="max-width: 600px; margin: 0 auto 30px; color: var(--text-secondary);">
                    Create your first application to get started with professional license key management, 
                    user authentication, and advanced analytics.
                </p>
                <button class="btn btn-primary btn-large" onclick="showAppModal()">
                    <i class="fas fa-plus"></i> Create Your First Application
                </button>
                
                <div class="feature-grid">
                    <div class="feature-card">
                        <i class="fas fa-key"></i>
                        <h4>License Management</h4>
                        <p>Generate and manage license keys with expiry dates and usage limits</p>
                    </div>
                    <div class="feature-card">
                        <i class="fas fa-users"></i>
                        <h4>User Management</h4>
                        <p>Create users with usernames, passwords, and hardware ID locking</p>
                    </div>
                    <div class="feature-card">
                        <i class="fas fa-shield-alt"></i>
                        <h4>Secure Authentication</h4>
                        <p>Enterprise-grade security with API keys and encryption</p>
                    </div>
                    <div class="feature-card">
                        <i class="fas fa-chart-bar"></i>
                        <h4>Advanced Analytics</h4>
                        <p>Track usage, monitor performance, and generate reports</p>
                    </div>
                </div>
            </div>

        <?php else: ?>
            <!-- Application Header -->
            <div class="app-header">
                <div class="app-title">
                    <h2><i class="fas fa-cube"></i> <?= htmlspecialchars($currentAppData['name']) ?></h2>
                    <p>Application Dashboard & Management</p>
                    
                    <!-- Secret Key Display -->
                    <div class="secret-key-display">
                        <strong>Secret Key:</strong>
                        <code><?= htmlspecialchars($currentAppData['secret_key']) ?></code>
                        <button class="btn-copy-sm" onclick="copyText('<?= $currentAppData['secret_key'] ?>')">
                            <i class="fas fa-copy"></i>
                        </button>
                        <div style="font-size: 0.8rem; color: var(--text-secondary); margin-top: 5px;">
                            Use this key for API authentication
                        </div>
                    </div>
                </div>
                
                <div class="header-actions">
                    <button class="btn btn-outline" onclick="testVerification()">
                        <i class="fas fa-bolt"></i> Test Auth
                    </button>
                    <a href="api.php?app=<?= $currentApp ?>" class="btn btn-primary">
                        <i class="fas fa-code"></i> API Docs
                    </a>
                </div>
            </div>

            <!-- Navigation Tabs -->
            <div class="nav-tabs" style="margin-bottom: 30px;">
                <a href="?app=<?= $currentApp ?>&page=dashboard" 
                   class="tab-btn <?= $currentPage === 'dashboard' ? 'active' : '' ?>">
                    <i class="fas fa-tachometer-alt"></i> Dashboard
                </a>
                <a href="?app=<?= $currentApp ?>&page=keys" 
                   class="tab-btn <?= $currentPage === 'keys' ? 'active' : '' ?>">
                    <i class="fas fa-key"></i> License Keys
                </a>
                <a href="?app=<?= $currentApp ?>&page=generate" 
                   class="tab-btn <?= $currentPage === 'generate' ? 'active' : '' ?>">
                    <i class="fas fa-plus-circle"></i> Generate Key
                </a>
                <a href="?app=<?= $currentApp ?>&page=users" 
                   class="tab-btn <?= $currentPage === 'users' ? 'active' : '' ?>">
                    <i class="fas fa-users"></i> Users
                </a>
                <a href="?app=<?= $currentApp ?>&page=adduser" 
                   class="tab-btn <?= $currentPage === 'adduser' ? 'active' : '' ?>">
                    <i class="fas fa-user-plus"></i> Add User
                </a>
                <a href="?app=<?= $currentApp ?>&page=settings" 
                   class="tab-btn <?= $currentPage === 'settings' ? 'active' : '' ?>">
                    <i class="fas fa-cog"></i> Settings
                </a>
            </div>

            <!-- Page Content -->
            <?php if ($currentPage === 'dashboard'): ?>
                <!-- Dashboard Content -->
                <div class="stats-grid">
                    <!-- Key Statistics -->
                    <div class="stat-card">
                        <div class="stat-icon">
                            <i class="fas fa-key"></i>
                        </div>
                        <div class="stat-info">
                            <h3><?= $keyStats['total_keys'] ?? 0 ?></h3>
                            <span>Total Keys</span>
                        </div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-icon active">
                            <i class="fas fa-check-circle"></i>
                        </div>
                        <div class="stat-info">
                            <h3><?= $keyStats['active_keys'] ?? 0 ?></h3>
                            <span>Active Keys</span>
                        </div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-icon expired">
                            <i class="fas fa-clock"></i>
                        </div>
                        <div class="stat-info">
                            <h3><?= $keyStats['expired_keys'] ?? 0 ?></h3>
                            <span>Expired Keys</span>
                        </div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-icon usage">
                            <i class="fas fa-chart-line"></i>
                        </div>
                        <div class="stat-info">
                            <h3><?= $keyStats['today_usage'] ?? 0 ?></h3>
                            <span>Today's Usage</span>
                        </div>
                    </div>
                    
                    <!-- User Statistics -->
                    <div class="stat-card">
                        <div class="stat-icon">
                            <i class="fas fa-users"></i>
                        </div>
                        <div class="stat-info">
                            <h3><?= $userStats['total_users'] ?? 0 ?></h3>
                            <span>Total Users</span>
                        </div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-icon active">
                            <i class="fas fa-user-check"></i>
                        </div>
                        <div class="stat-info">
                            <h3><?= $userStats['active_users'] ?? 0 ?></h3>
                            <span>Active Users</span>
                        </div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-icon expired">
                            <i class="fas fa-user-clock"></i>
                        </div>
                        <div class="stat-info">
                            <h3><?= $userStats['expired_users'] ?? 0 ?></h3>
                            <span>Expired Users</span>
                        </div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-icon banned">
                            <i class="fas fa-user-slash"></i>
                        </div>
                        <div class="stat-info">
                            <h3><?= $userStats['banned_users'] ?? 0 ?></h3>
                            <span>Banned Users</span>
                        </div>
                    </div>
                </div>

                <!-- Quick Actions -->
                <div class="dashboard-grid" style="margin-top: 30px;">
                    <div class="dashboard-card">
                        <div class="card-header">
                            <h3>Quick Actions</h3>
                        </div>
                        <div class="card-body">
                            <div class="actions-grid">
                                <a href="?app=<?= $currentApp ?>&page=generate" class="action-btn">
                                    <i class="fas fa-key"></i>
                                    <span>Generate License Key</span>
                                </a>
                                <a href="?app=<?= $currentApp ?>&page=adduser" class="action-btn">
                                    <i class="fas fa-user-plus"></i>
                                    <span>Add New User</span>
                                </a>
                                <button class="action-btn" onclick="testVerification()">
                                    <i class="fas fa-bolt"></i>
                                    <span>Test Authentication</span>
                                </button>
                                <a href="api.php?app=<?= $currentApp ?>" class="action-btn">
                                    <i class="fas fa-code"></i>
                                    <span>API Documentation</span>
                                </a>
                            </div>
                        </div>
                    </div>

                    <!-- Recent Activity -->
                    <div class="dashboard-card">
                        <div class="card-header">
                            <h3>Recent Activity</h3>
                            <div>
                                <a href="?app=<?= $currentApp ?>&page=keys" class="view-all">Keys</a>
                                <a href="?app=<?= $currentApp ?>&page=users" class="view-all">Users</a>
                            </div>
                        </div>
                        <div class="card-body">
                            <?php
                            $recentKeys = LicenseManager::getKeys($currentApp, 1, 5);
                            $recentUsers = UserManager::getUsers($currentApp, 1, 5);
                            ?>
                            
                            <?php if (!empty($recentKeys) || !empty($recentUsers)): ?>
                                <div class="activity-list">
                                    <?php foreach (array_slice($recentKeys, 0, 3) as $key): ?>
                                        <div class="activity-item">
                                            <div class="activity-icon" style="background: var(--accent-red);">
                                                <i class="fas fa-key"></i>
                                            </div>
                                            <div class="activity-details">
                                                <div class="activity-title">License Key Generated</div>
                                                <div class="activity-meta">
                                                    <?= substr($key['key_string'], 0, 8) ?>... • 
                                                    <?= $key['key_type'] ?> • 
                                                    Expires: <?= date('M j, Y', strtotime($key['expiry_timestamp'])) ?>
                                                </div>
                                            </div>
                                            <div class="activity-badge status-<?= $key['status'] ?>">
                                                <?= ucfirst($key['status']) ?>
                                            </div>
                                        </div>
                                    <?php endforeach; ?>
                                    
                                    <?php foreach (array_slice($recentUsers, 0, 2) as $user): ?>
                                        <div class="activity-item">
                                            <div class="activity-icon" style="background: #10b981;">
                                                <i class="fas fa-user"></i>
                                            </div>
                                            <div class="activity-details">
                                                <div class="activity-title">User Created</div>
                                                <div class="activity-meta">
                                                    <?= htmlspecialchars($user['username']) ?> • 
                                                    <?= htmlspecialchars($user['email']) ?>
                                                </div>
                                            </div>
                                            <div class="activity-badge status-<?= $user['status'] ?>">
                                                <?= ucfirst($user['status']) ?>
                                            </div>
                                        </div>
                                    <?php endforeach; ?>
                                </div>
                            <?php else: ?>
                                <div class="empty-state-small">
                                    <i class="fas fa-history"></i>
                                    <p>No recent activity</p>
                                    <p style="font-size: 0.8rem; margin-top: 5px;">Generate keys or add users to see activity</p>
                                </div>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>

            <?php elseif ($currentPage === 'keys'): ?>
                <!-- Keys Management Page -->
                <div class="page-header">
                    <h2><i class="fas fa-key"></i> License Keys</h2>
                    <p>Manage all license keys for <?= htmlspecialchars($currentAppData['name']) ?></p>
                </div>

                <?php
                $search = $_GET['search'] ?? '';
                $statusFilter = $_GET['status'] ?? '';
                $page = $_GET['page_num'] ?? 1;
                $keys = LicenseManager::getKeys($currentApp, $page, 20, $search, $statusFilter);
                ?>

                <div class="table-container">
                    <div class="table-actions">
                        <div class="search-box">
                            <input type="text" id="searchKeys" placeholder="Search keys..." class="form-input" 
                                   value="<?= htmlspecialchars($search) ?>">
                            <i class="fas fa-search"></i>
                        </div>
                        <div class="table-filters">
                            <select id="statusFilter" class="form-input-sm">
                                <option value="">All Status</option>
                                <option value="active" <?= $statusFilter === 'active' ? 'selected' : '' ?>>Active</option>
                                <option value="expired" <?= $statusFilter === 'expired' ? 'selected' : '' ?>>Expired</option>
                                <option value="unused" <?= $statusFilter === 'unused' ? 'selected' : '' ?>>Unused</option>
                            </select>
                            <button class="btn btn-outline" onclick="applyFilters()">Apply</button>
                        </div>
                        <div class="table-actions-right">
                            <a href="?app=<?= $currentApp ?>&page=generate" class="btn btn-primary">
                                <i class="fas fa-plus"></i> Generate Key
                            </a>
                            <button class="btn btn-outline" onclick="exportKeys()">
                                <i class="fas fa-download"></i> Export
                            </button>
                        </div>
                    </div>

                    <div class="table-responsive">
                        <table class="data-table">
                            <thead>
                                <tr>
                                    <th>License Key</th>
                                    <th>Type</th>
                                    <th>Status</th>
                                    <th>Expiry Date</th>
                                    <th>Usage</th>
                                    <th>Last Used</th>
                                    <th>Created</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php if (!empty($keys)): ?>
                                    <?php foreach ($keys as $key): ?>
                                        <tr>
                                            <td>
                                                <div class="key-display">
                                                    <code><?= 
                                                        substr($key['key_string'], 0, 4) . '-' . 
                                                        substr($key['key_string'], 4, 4) . '-' . 
                                                        substr($key['key_string'], 8, 4) . '-' . 
                                                        substr($key['key_string'], 12, 4) 
                                                    ?></code>
                                                    <button class="btn-copy-sm" onclick="copyText('<?= $key['key_string'] ?>')">
                                                        <i class="fas fa-copy"></i>
                                                    </button>
                                                </div>
                                            </td>
                                            <td>
                                                <span class="key-type-badge type-<?= $key['key_type'] ?>">
                                                    <?= ucfirst($key['key_type']) ?>
                                                </span>
                                            </td>
                                            <td>
                                                <span class="status-badge status-<?= $key['status'] ?>">
                                                    <i class="fas fa-circle"></i>
                                                    <?= ucfirst($key['status']) ?>
                                                </span>
                                            </td>
                                            <td>
                                                <?= date('M j, Y', strtotime($key['expiry_timestamp'])) ?>
                                                <?php if ($key['days_remaining'] > 0 && $key['days_remaining'] <= 7): ?>
                                                    <div class="expiry-warning">Expires in <?= $key['days_remaining'] ?> days</div>
                                                <?php endif; ?>
                                            </td>
                                            <td>
                                                <span class="usage-count"><?= $key['usage_count'] ?> uses</span>
                                                <?php if ($key['last_used_ip']): ?>
                                                    <div class="ip-address"><?= $key['last_used_ip'] ?></div>
                                                <?php endif; ?>
                                            </td>
                                            <td>
                                                <?= $key['last_used'] ? date('M j, g:i A', strtotime($key['last_used'])) : 'Never' ?>
                                            </td>
                                            <td>
                                                <?= date('M j, Y', strtotime($key['created_at'])) ?>
                                            </td>
                                            <td>
                                                <div class="action-buttons">
                                                    <button class="btn-action" title="Test Key" onclick="testKey('<?= $key['key_string'] ?>')">
                                                        <i class="fas fa-bolt"></i>
                                                    </button>
                                                    <button class="btn-action" title="View Logs" onclick="viewKeyLogs(<?= $key['id'] ?>)">
                                                        <i class="fas fa-history"></i>
                                                    </button>
                                                    <button class="btn-action btn-danger" title="Delete Key" onclick="deleteKey(<?= $key['id'] ?>)">
                                                        <i class="fas fa-trash"></i>
                                                    </button>
                                                </div>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                <?php else: ?>
                                    <tr>
                                        <td colspan="8" class="text-center">
                                            <div class="empty-state">
                                                <i class="fas fa-key"></i>
                                                <h4>No License Keys</h4>
                                                <p><?= $search || $statusFilter ? 'Try adjusting your search or filters' : 'Generate your first license key to get started' ?></p>
                                                <a href="?app=<?= $currentApp ?>&page=generate" class="btn btn-primary">
                                                    Generate Key
                                                </a>
                                            </div>
                                        </td>
                                    </tr>
                                <?php endif; ?>
                            </tbody>
                        </table>
                    </div>
                </div>

            <?php elseif ($currentPage === 'generate'): ?>
                <!-- Generate Key Page -->
                <div class="page-header">
                    <h2><i class="fas fa-plus-circle"></i> Generate License Key</h2>
                    <p>Create new license keys for <?= htmlspecialchars($currentAppData['name']) ?></p>
                </div>

                <div class="form-card">
                    <form id="generateKeyForm">
                        <input type="hidden" name="app_id" value="<?= $currentApp ?>">
                        <input type="hidden" name="action" value="generate_key">
                        
                        <div class="form-row">
                            <div class="form-group">
                                <label for="keyType">
                                    <i class="fas fa-tag"></i> Key Type
                                </label>
                                <select id="keyType" name="key_type" class="form-input" onchange="updateKeyType()">
                                    <option value="standard">Standard (16 characters)</option>
                                    <option value="premium">Premium (24 characters)</option>
                                    <option value="enterprise">Enterprise (32 characters)</option>
                                </select>
                                <div class="form-hint" id="keyTypeHint">
                                    16-character alphanumeric key with basic features
                                </div>
                            </div>

                            <div class="form-group">
                                <label for="expiryDate">
                                    <i class="fas fa-calendar-alt"></i> Expiration Date
                                </label>
                                <input type="date" id="expiryDate" name="expiry_date" required class="form-input">
                                <div class="form-hint">Select a future date for key expiration</div>
                            </div>
                        </div>

                        <div class="form-actions">
                            <a href="?app=<?= $currentApp ?>&page=keys" class="btn btn-secondary">
                                <i class="fas fa-arrow-left"></i> Back to Keys
                            </a>
                            <button type="submit" class="btn btn-primary">
                                <i class="fas fa-key"></i> Generate License Key
                            </button>
                        </div>
                    </form>

                    <div id="keyResult" class="result-container" style="display: none; margin-top: 30px;">
                        <!-- Result will be shown here -->
                    </div>
                </div>

            <?php elseif ($currentPage === 'users'): ?>
                <!-- Users Management Page -->
                <div class="page-header">
                    <h2><i class="fas fa-users"></i> User Management</h2>
                    <p>Manage all users for <?= htmlspecialchars($currentAppData['name']) ?></p>
                </div>

                <?php
                $search = $_GET['search'] ?? '';
                $page = $_GET['page_num'] ?? 1;
                $users = UserManager::getUsers($currentApp, $page, 20, $search);
                ?>

                <div class="table-container">
                    <div class="table-actions">
                        <div class="search-box">
                            <input type="text" id="searchUsers" placeholder="Search users..." class="form-input" 
                                   value="<?= htmlspecialchars($search) ?>" onkeyup="filterUsers()">
                            <i class="fas fa-search"></i>
                        </div>
                        <div class="table-actions-right">
                            <a href="?app=<?= $currentApp ?>&page=adduser" class="btn btn-primary">
                                <i class="fas fa-user-plus"></i> Add User
                            </a>
                            <button class="btn btn-outline" onclick="exportUsers()">
                                <i class="fas fa-download"></i> Export
                            </button>
                        </div>
                    </div>

                    <div class="table-responsive">
                        <table class="data-table" id="usersTable">
                            <thead>
                                <tr>
                                    <th>Username</th>
                                    <th>Email</th>
                                    <th>License Key</th>
                                    <th>Status</th>
                                    <th>Expiry Date</th>
                                    <th>Last Login</th>
                                    <th>Created</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php if (!empty($users)): ?>
                                    <?php foreach ($users as $user): ?>
                                        <tr>
                                            <td>
                                                <div class="user-info">
                                                    <div class="user-avatar">
                                                        <i class="fas fa-user"></i>
                                                    </div>
                                                    <div class="user-details">
                                                        <strong><?= htmlspecialchars($user['username']) ?></strong>
                                                    </div>
                                                </div>
                                            </td>
                                            <td><?= htmlspecialchars($user['email']) ?></td>
                                            <td>
                                                <div class="license-display">
                                                    <code><?= $user['license_key'] ?></code>
                                                    <button class="btn-copy-sm" onclick="copyText('<?= $user['license_key'] ?>')">
                                                        <i class="fas fa-copy"></i>
                                                    </button>
                                                </div>
                                            </td>
                                            <td>
                                                <span class="status-badge status-<?= $user['status'] ?>">
                                                    <i class="fas fa-circle"></i>
                                                    <?= ucfirst($user['status']) ?>
                                                </span>
                                            </td>
                                            <td>
                                                <?= date('M j, Y', strtotime($user['expiry_date'])) ?>
                                                <?php if (strtotime($user['expiry_date']) < time()): ?>
                                                    <div class="expiry-warning">Expired</div>
                                                <?php endif; ?>
                                            </td>
                                            <td>
                                                <?= $user['last_login'] ? date('M j, g:i A', strtotime($user['last_login'])) : 'Never' ?>
                                            </td>
                                            <td>
                                                <?= date('M j, Y', strtotime($user['created_at'])) ?>
                                            </td>
                                            <td>
                                                <div class="action-buttons">
                                                    <button class="btn-action" title="Edit User" onclick="editUser(<?= $user['id'] ?>)">
                                                        <i class="fas fa-edit"></i>
                                                    </button>
                                                    <button class="btn-action" title="View Logs" onclick="viewUserLogs(<?= $user['id'] ?>)">
                                                        <i class="fas fa-history"></i>
                                                    </button>
                                                    <button class="btn-action btn-danger" title="Delete User" onclick="deleteUser(<?= $user['id'] ?>)">
                                                        <i class="fas fa-trash"></i>
                                                    </button>
                                                </div>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                <?php else: ?>
                                    <tr>
                                        <td colspan="8" class="text-center">
                                            <div class="empty-state">
                                                <i class="fas fa-users"></i>
                                                <h4>No Users Found</h4>
                                                <p><?= $search ? 'Try adjusting your search' : 'Get started by adding your first user' ?></p>
                                                <a href="?app=<?= $currentApp ?>&page=adduser" class="btn btn-primary">
                                                    Add User
                                                </a>
                                            </div>
                                        </td>
                                    </tr>
                                <?php endif; ?>
                            </tbody>
                        </table>
                    </div>
                </div>

            <?php elseif ($currentPage === 'adduser'): ?>
                <!-- Add User Page -->
                <div class="page-header">
                    <h2><i class="fas fa-user-plus"></i> Add New User</h2>
                    <p>Create a new user account for <?= htmlspecialchars($currentAppData['name']) ?></p>
                </div>

                <div class="form-card">
                    <form id="addUserForm">
                        <input type="hidden" name="app_id" value="<?= $currentApp ?>">
                        <input type="hidden" name="action" value="create_user">
                        
                        <div class="form-row">
                            <div class="form-group">
                                <label for="username">
                                    <i class="fas fa-user"></i> Username
                                </label>
                                <input type="text" id="username" name="username" class="form-input" required 
                                       placeholder="Enter username">
                                <div class="form-hint">Unique username for authentication</div>
                            </div>

                            <div class="form-group">
                                <label for="email">
                                    <i class="fas fa-envelope"></i> Email Address
                                </label>
                                <input type="email" id="email" name="email" class="form-input" required 
                                       placeholder="Enter email address">
                                <div class="form-hint">User's email address</div>
                            </div>
                        </div>

                        <div class="form-row">
                            <div class="form-group">
                                <label for="password">
                                    <i class="fas fa-lock"></i> Password
                                </label>
                                <input type="password" id="password" name="password" class="form-input" required 
                                       placeholder="Enter password">
                                <div class="form-hint">User's login password</div>
                            </div>

                            <div class="form-group">
                                <label for="expiry_date">
                                    <i class="fas fa-calendar-alt"></i> Expiry Date
                                </label>
                                <input type="date" id="expiry_date" name="expiry_date" required 
                                       class="form-input" min="<?= date('Y-m-d', strtotime('+1 day')) ?>">
                                <div class="form-hint">When the user's license expires</div>
                            </div>
                        </div>

                        <div class="form-group">
                            <label for="hwid">
                                <i class="fas fa-desktop"></i> HWID Lock (Optional)
                            </label>
                            <input type="text" id="hwid" name="hwid" class="form-input" 
                                   placeholder="Enter hardware ID">
                            <div class="form-hint">Lock user to specific hardware</div>
                        </div>

                        <div class="form-actions">
                            <a href="?app=<?= $currentApp ?>&page=users" class="btn btn-secondary">
                                <i class="fas fa-arrow-left"></i> Back to Users
                            </a>
                            <button type="submit" class="btn btn-primary">
                                <i class="fas fa-save"></i> Create User
                            </button>
                        </div>
                    </form>

                    <div id="userResult" class="result-container" style="display: none; margin-top: 30px;">
                        <!-- Result will be shown here -->
                    </div>
                </div>

            <?php else: ?>
                <!-- Other Pages -->
                <div class="page-header">
                    <h2><?= ucfirst($currentPage) ?></h2>
                    <p>This page is under development</p>
                </div>
                <div class="coming-soon">
                    <i class="fas fa-tools"></i>
                    <h3>Coming Soon</h3>
                    <p>This feature is currently being developed and will be available in the next update.</p>
                    <a href="?app=<?= $currentApp ?>&page=dashboard" class="btn btn-primary">
                        Return to Dashboard
                    </a>
                </div>
            <?php endif; ?>
        <?php endif; ?>
    </div>

    <!-- Modals -->
    <div id="appModal" class="modal" style="display: none;">
        <div class="modal-content">
            <div class="modal-header">
                <h3><i class="fas fa-plus"></i> Create New Application</h3>
                <button class="btn-close" onclick="closeAppModal()">&times;</button>
            </div>
            <div class="modal-body">
                <form id="appForm">
                    <div class="form-group">
                        <label>Application Name</label>
                        <input type="text" name="app_name" class="form-input" required 
                               placeholder="Enter application name (e.g., LIAMH4X)">
                        <div class="form-hint">This will be your application's unique identifier</div>
                    </div>
                </form>
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" onclick="closeAppModal()">Cancel</button>
                <button class="btn btn-primary" onclick="createApp()">
                    <i class="fas fa-plus"></i> Create Application
                </button>
            </div>
        </div>
    </div>

    <div id="testModal" class="modal" style="display: none;">
        <div class="modal-content">
            <div class="modal-header">
                <h3><i class="fas fa-bolt"></i> Test Authentication</h3>
                <button class="btn-close" onclick="closeTestModal()">&times;</button>
            </div>
            <div class="modal-body">
                <div class="form-group">
                    <label>Username:</label>
                    <input type="text" id="testUsername" placeholder="Enter username" class="form-input">
                </div>
                <div class="form-group">
                    <label>Password:</label>
                    <input type="password" id="testPassword" placeholder="Enter password" class="form-input">
                </div>
                <div class="form-group">
                    <label>HWID (Optional):</label>
                    <input type="text" id="testHwid" placeholder="Enter hardware ID" class="form-input">
                </div>
                <div id="testResult" class="test-result"></div>
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" onclick="closeTestModal()">Cancel</button>
                <button class="btn btn-primary" onclick="testAuthentication()">
                    <i class="fas fa-check"></i> Test Auth
                </button>
            </div>
        </div>
    </div>

    <script>
    // Application Management
    function showAppModal() {
        document.getElementById('appModal').style.display = 'flex';
    }

    function closeAppModal() {
        document.getElementById('appModal').style.display = 'none';
    }

    function createApp() {
        const form = document.getElementById('appForm');
        const formData = new FormData(form);
        formData.append('action', 'create_app');
        
        fetch('', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                showNotification('Application created successfully!', 'success');
                closeAppModal();
                setTimeout(() => {
                    window.location.href = `?app=${data.app_id}&page=dashboard`;
                }, 1000);
            } else {
                showNotification(data.message || 'Failed to create application', 'error');
            }
        })
        .catch(error => {
            showNotification('Network error: ' + error.message, 'error');
        });
    }

    // Key Management
    document.getElementById('generateKeyForm')?.addEventListener('submit', function(e) {
        e.preventDefault();
        generateKey();
    });

    function generateKey() {
        const form = document.getElementById('generateKeyForm');
        const formData = new FormData(form);
        
        fetch('', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            const resultDiv = document.getElementById('keyResult');
            if (data.success) {
                resultDiv.innerHTML = `
                    <div class="success-alert">
                        <i class="fas fa-check-circle"></i>
                        <div class="alert-content">
                            <h3>Key Generated Successfully!</h3>
                            <div class="key-display">
                                <code>${data.key}</code>
                                <button class="btn-copy" onclick="copyText('${data.key}')">
                                    <i class="fas fa-copy"></i>
                                </button>
                            </div>
                            <div class="key-details">
                                <div class="detail-item">
                                    <i class="fas fa-clock"></i>
                                    <span>Expires: <strong>${data.expiry}</strong></span>
                                </div>
                                <div class="detail-item">
                                    <i class="fas fa-tag"></i>
                                    <span>Type: <strong>${data.key_type}</strong></span>
                                </div>
                            </div>
                        </div>
                    </div>
                `;
                resultDiv.style.display = 'block';
                form.reset();
                setDefaultExpiryDate();
            } else {
                resultDiv.innerHTML = `
                    <div class="error-alert">
                        <i class="fas fa-exclamation-triangle"></i>
                        <div class="alert-content">
                            <h3>Key Generation Failed</h3>
                            <p>${data.message}</p>
                        </div>
                    </div>
                `;
                resultDiv.style.display = 'block';
            }
        })
        .catch(error => {
            showNotification('Network error: ' + error.message, 'error');
        });
    }

    // User Management
    document.getElementById('addUserForm')?.addEventListener('submit', function(e) {
        e.preventDefault();
        createUser();
    });

    function createUser() {
        const form = document.getElementById('addUserForm');
        const formData = new FormData(form);
        
        fetch('', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            const resultDiv = document.getElementById('userResult');
            if (data.success) {
                resultDiv.innerHTML = `
                    <div class="success-alert">
                        <i class="fas fa-check-circle"></i>
                        <div class="alert-content">
                            <h3>User Created Successfully!</h3>
                            <div class="key-display">
                                <code>${data.license_key}</code>
                                <button class="btn-copy" onclick="copyText('${data.license_key}')">
                                    <i class="fas fa-copy"></i>
                                </button>
                            </div>
                            <div class="key-details">
                                <div class="detail-item">
                                    <i class="fas fa-user"></i>
                                    <span>Username: <strong>${form.username.value}</strong></span>
                                </div>
                                <div class="detail-item">
                                    <i class="fas fa-envelope"></i>
                                    <span>Email: <strong>${form.email.value}</strong></span>
                                </div>
                                <div class="detail-item">
                                    <i class="fas fa-clock"></i>
                                    <span>Expires: <strong>${form.expiry_date.value}</strong></span>
                                </div>
                            </div>
                        </div>
                    </div>
                `;
                resultDiv.style.display = 'block';
                form.reset();
                setDefaultExpiryDate();
            } else {
                resultDiv.innerHTML = `
                    <div class="error-alert">
                        <i class="fas fa-exclamation-triangle"></i>
                        <div class="alert-content">
                            <h3>User Creation Failed</h3>
                            <p>${data.message}</p>
                        </div>
                    </div>
                `;
                resultDiv.style.display = 'block';
            }
        })
        .catch(error => {
            showNotification('Network error: ' + error.message, 'error');
        });
    }

    // Test Authentication
    function testVerification() {
        document.getElementById('testModal').style.display = 'flex';
        document.getElementById('testUsername').focus();
        document.getElementById('testResult').style.display = 'none';
    }

    function closeTestModal() {
        document.getElementById('testModal').style.display = 'none';
        document.getElementById('testUsername').value = '';
        document.getElementById('testPassword').value = '';
        document.getElementById('testHwid').value = '';
        document.getElementById('testResult').style.display = 'none';
    }

    function testAuthentication() {
        const username = document.getElementById('testUsername').value.trim();
        const password = document.getElementById('testPassword').value.trim();
        const hwid = document.getElementById('testHwid').value.trim();
        const testResult = document.getElementById('testResult');
        
        if (!username || !password) {
            testResult.innerHTML = '<i class="fas fa-exclamation-triangle"></i> Please enter username and password';
            testResult.className = 'test-result error';
            testResult.style.display = 'block';
            return;
        }

        // This would call your verify.php endpoint
        // For now, we'll simulate a response
        setTimeout(() => {
            testResult.innerHTML = `
                <i class="fas fa-check-circle"></i> 
                <strong>Authentication Successful!</strong><br>
                This is a simulation. In production, this would verify against your API.
            `;
            testResult.className = 'test-result success';
            testResult.style.display = 'block';
        }, 1000);
    }
 function closeMobileMenu() {
            if (window.innerWidth <= 992) {
                document.querySelector('.apps-sidebar').classList.remove('active');
            }
        }
    // Utility Functions
    function copyText(text) {
        navigator.clipboard.writeText(text).then(() => {
            showNotification('Copied to clipboard!', 'success');
        });
    }

    function showNotification(message, type = 'info') {
        // Create notification element
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.innerHTML = `
            <i class="fas fa-${type === 'error' ? 'exclamation-triangle' : 'check-circle'}"></i>
            <span>${message}</span>
            <button class="notification-close" onclick="this.parentElement.remove()">&times;</button>
        `;
        
        // Add styles and append to body
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 15px 20px;
            background: ${type === 'error' ? '#ff4444' : '#00cc66'};
            color: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.5);
            z-index: 1001;
            display: flex;
            align-items: center;
            gap: 10px;
            max-width: 400px;
            animation: slideInRight 0.3s ease;
        `;
        
        document.body.appendChild(notification);
        
        // Auto remove after 5 seconds
        setTimeout(() => {
            if (notification.parentElement) {
                notification.remove();
            }
        }, 5000);
    }

    function updateKeyType() {
        const keyType = document.getElementById('keyType').value;
        const hint = document.getElementById('keyTypeHint');
        
        const descriptions = {
            'standard': '16-character alphanumeric key with basic features',
            'premium': '24-character key with enhanced security and priority support',
            'enterprise': '32-character key with advanced features and SLA guarantee'
        };
        
        hint.textContent = descriptions[keyType] || descriptions.standard;
    }

    function setDefaultExpiryDate() {
        const expiryInput = document.getElementById('expiry_date');
        if (expiryInput) {
            const defaultDate = new Date();
            defaultDate.setDate(defaultDate.getDate() + 30);
            expiryInput.value = defaultDate.toISOString().split('T')[0];
        }
    }

    // Initialize
    document.addEventListener('DOMContentLoaded', function() {
        updateKeyType();
        setDefaultExpiryDate();
        
        // Set default expiry for key generation
        const keyExpiryInput = document.getElementById('expiryDate');
        if (keyExpiryInput) {
            const defaultDate = new Date();
            defaultDate.setDate(defaultDate.getDate() + 30);
            keyExpiryInput.value = defaultDate.toISOString().split('T')[0];
            keyExpiryInput.min = new Date().toISOString().split('T')[0];
        }
    });
    </script>
</body>
</html>