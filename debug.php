<?php
class ProtectedDebugApp {
    private $apiUrl;
    private $secretKey;
    private $appName;
    
    public function __construct($secretKey, $appName = "Protected Debug Application") {
        $this->secretKey = $secretKey;
        $this->appName = $appName;
        $this->apiUrl = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http") . "://$_SERVER[HTTP_HOST]" . dirname($_SERVER['SCRIPT_NAME']) . '/verify.php';
        
        // Start session for authentication state
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
    }
    
    public function validateAndLogin($licenseKey, $hwid = null) {
        try {
            $payload = [
                'key' => $licenseKey,
                'secret' => $this->secretKey
            ];
            
            if ($hwid) {
                $payload['hwid'] = $hwid;
            }
            
            $ch = curl_init();
            curl_setopt_array($ch, [
                CURLOPT_URL => $this->apiUrl,
                CURLOPT_POST => true,
                CURLOPT_POSTFIELDS => http_build_query($payload),
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT => 30,
                CURLOPT_SSL_VERIFYPEER => false,
                CURLOPT_HTTPHEADER => [
                    'Content-Type: application/x-www-form-urlencoded',
                    'User-Agent: ProtectedDebugApp/1.0'
                ]
            ]);
            
            $response = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $error = curl_error($ch);
            curl_close($ch);
            
            if ($error) {
                return [
                    'success' => false,
                    'authenticated' => false,
                    'message' => 'Network error: ' . $error
                ];
            }
            
            $data = json_decode($response, true);
            
            if (json_last_error() !== JSON_ERROR_NONE) {
                return [
                    'success' => false,
                    'authenticated' => false,
                    'message' => 'Invalid API response'
                ];
            }
            
            if (isset($data['valid']) && $data['valid'] === true) {
                // Successful authentication - store session
                $_SESSION['debug_app_authenticated'] = true;
                $_SESSION['debug_app_license_key'] = $licenseKey;
                $_SESSION['debug_app_license_data'] = $data;
                $_SESSION['debug_app_login_time'] = time();
                
                return [
                    'success' => true,
                    'authenticated' => true,
                    'message' => 'Authentication successful!',
                    'license_data' => $data
                ];
            } else {
                return [
                    'success' => false,
                    'authenticated' => false,
                    'message' => $data['message'] ?? 'Invalid license key',
                    'api_response' => $data
                ];
            }
            
        } catch (Exception $e) {
            return [
                'success' => false,
                'authenticated' => false,
                'message' => 'System error: ' . $e->getMessage()
            ];
        }
    }
    
    public function isAuthenticated() {
        return isset($_SESSION['debug_app_authenticated']) && $_SESSION['debug_app_authenticated'] === true;
    }
    
    public function getLicenseData() {
        return $_SESSION['debug_app_license_data'] ?? null;
    }
    
    public function logout() {
        session_destroy();
        header('Location: ' . $_SERVER['PHP_SELF']);
        exit;
    }
    
    public function generateHWID() {
        $hwidData = [
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown',
            'remote_addr' => $_SERVER['REMOTE_ADDR'] ?? 'Unknown',
            'server_name' => $_SERVER['SERVER_NAME'] ?? 'Unknown'
        ];
        
        return hash('sha256', json_encode($hwidData));
    }
}

// Initialize the protected application
$debugApp = new ProtectedDebugApp('896f643bd84fe37dbcfef641948259c520062df5ecd695574d856bc4efd115d8', 'LIAMH4X');

// Handle logout
if (isset($_GET['logout'])) {
    $debugApp->logout();
}

// Handle login form submission
$loginResult = null;
$licenseKey = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['license_key'])) {
    $licenseKey = trim($_POST['license_key']);
    $useHWID = isset($_POST['use_hwid']);
    $customHWID = trim($_POST['custom_hwid'] ?? '');
    
    if (!empty($licenseKey)) {
        $hwid = $useHWID ? ($customHWID ?: $debugApp->generateHWID()) : null;
        $loginResult = $debugApp->validateAndLogin($licenseKey, $hwid);
    }
}

// Check if user is already authenticated
$isAuthenticated = $debugApp->isAuthenticated();
$licenseData = $debugApp->getLicenseData();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Protected Debug Application - Key Required</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        :root {
            --bg-primary: #0a0a0a;
            --bg-secondary: #1a1a1a;
            --bg-card: #2a2a2a;
            --text-primary: #ffffff;
            --text-secondary: #b0b0b0;
            --accent-red: #ff3333;
            --success-green: #00cc66;
            --error-red: #ff4444;
            --border-color: #333333;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
        }

        .container {
            max-width: 1000px;
            margin: 0 auto;
            padding: 20px;
        }

        .header {
            text-align: center;
            margin-bottom: 30px;
            padding: 30px;
            background: var(--bg-card);
            border-radius: 15px;
            border: 1px solid var(--border-color);
        }

        .header h1 {
            color: var(--accent-red);
            margin-bottom: 10px;
            font-size: 2.5rem;
        }

        .header p {
            color: var(--text-secondary);
            font-size: 1.1rem;
        }

        .auth-container {
            background: var(--bg-card);
            padding: 30px;
            border-radius: 15px;
            border: 1px solid var(--border-color);
            margin-bottom: 20px;
        }

        .form-group {
            margin-bottom: 20px;
        }

        label {
            display: block;
            margin-bottom: 8px;
            color: var(--text-primary);
            font-weight: 500;
            font-size: 1.1rem;
        }

        .form-input {
            width: 100%;
            padding: 15px;
            background: var(--bg-secondary);
            border: 2px solid var(--border-color);
            border-radius: 8px;
            color: var(--text-primary);
            font-size: 16px;
            transition: border-color 0.3s ease;
        }

        .form-input:focus {
            outline: none;
            border-color: var(--accent-red);
        }

        .checkbox-group {
            display: flex;
            align-items: center;
            gap: 10px;
            margin: 15px 0;
        }

        .checkbox-group input[type="checkbox"] {
            width: 20px;
            height: 20px;
        }

        .btn {
            background: var(--accent-red);
            color: white;
            border: none;
            padding: 15px 30px;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.3s ease;
            width: 100%;
            margin-top: 10px;
        }

        .btn:hover {
            background: #ff5555;
        }

        .btn-logout {
            background: var(--error-red);
            width: auto;
            padding: 10px 20px;
        }

        .result-container {
            margin-top: 25px;
        }

        .success-box {
            background: rgba(0, 204, 102, 0.1);
            border: 1px solid var(--success-green);
            color: var(--success-green);
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 15px;
        }

        .error-box {
            background: rgba(255, 68, 68, 0.1);
            border: 1px solid var(--error-red);
            color: var(--error-red);
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 15px;
        }

        .debug-content {
            background: var(--bg-card);
            padding: 30px;
            border-radius: 15px;
            border: 1px solid var(--accent-red);
            margin-top: 30px;
        }

        .license-info {
            background: var(--bg-secondary);
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 25px;
            border-left: 4px solid var(--success-green);
        }

        .feature-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 25px 0;
        }

        .feature-card {
            background: var(--bg-secondary);
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            border: 1px solid var(--border-color);
            transition: transform 0.3s ease;
        }

        .feature-card:hover {
            transform: translateY(-5px);
            border-color: var(--accent-red);
        }

        .feature-card i {
            font-size: 2.5rem;
            color: var(--accent-red);
            margin-bottom: 15px;
        }

        .status-badge {
            display: inline-block;
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 14px;
            font-weight: 600;
            margin-left: 10px;
        }

        .status-active { background: var(--success-green); color: white; }
        .status-expired { background: var(--error-red); color: white; }

        .sample-keys {
            background: var(--bg-secondary);
            padding: 20px;
            border-radius: 10px;
            margin-top: 20px;
        }

        .sample-key {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 12px;
            margin: 8px 0;
            background: var(--bg-primary);
            border-radius: 6px;
            cursor: pointer;
            transition: background 0.3s ease;
        }

        .sample-key:hover {
            background: var(--bg-card);
        }

        .copy-btn {
            background: var(--accent-red);
            color: white;
            border: none;
            padding: 6px 12px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
        }

        .login-form {
            max-width: 500px;
            margin: 0 auto;
        }

        .welcome-message {
            text-align: center;
            margin-bottom: 30px;
        }

        .welcome-message h2 {
            color: var(--success-green);
            margin-bottom: 10px;
        }
    </style>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Protected Debug Application</h1>
            <p>Valid license key required to access debug tools and features</p>
        </div>

        <?php if (!$isAuthenticated): ?>
            <!-- LOGIN FORM -->
            <div class="auth-container">
                <div class="login-form">
                    <h2 style="text-align: center; margin-bottom: 25px; color: var(--accent-red);">
                        <i class="fas fa-lock"></i> Authentication Required
                    </h2>
                    
                    <?php if ($loginResult && !$loginResult['authenticated']): ?>
                        <div class="error-box">
                            <h3><i class="fas fa-exclamation-triangle"></i> Access Denied</h3>
                            <p><?php echo htmlspecialchars($loginResult['message']); ?></p>
                        </div>
                    <?php endif; ?>

                    <form method="POST">
                        <div class="form-group">
                            <label for="license_key"><i class="fas fa-key"></i> Enter License Key:</label>
                            <input type="text" id="license_key" name="license_key" class="form-input" 
                                   placeholder="XXXX-XXXX-XXXX-XXXX" 
                                   value="<?php echo htmlspecialchars($licenseKey); ?>" required
                                   style="font-size: 18px; text-align: center; letter-spacing: 2px;">
                        </div>

                        <div class="checkbox-group">
                            <input type="checkbox" id="use_hwid" name="use_hwid">
                            <label for="use_hwid">Enable Hardware Locking</label>
                        </div>

                        <button type="submit" class="btn">
                            <i class="fas fa-sign-in-alt"></i> Authenticate & Access Debug Tools
                        </button>
                    </form>
                </div>

                <div class="sample-keys">
                    <h3 style="margin-bottom: 15px;"><i class="fas fa-vial"></i> Test Keys:</h3>
                    <div class="sample-key" onclick="setKey('A1B2-C3D4-E5F6-G7H8')">
                        <span><i class="fas fa-key"></i> A1B2-C3D4-E5F6-G7H8</span>
                        <button class="copy-btn" onclick="event.stopPropagation(); copyText('A1B2-C3D4-E5F6-G7H8')">
                            <i class="fas fa-copy"></i>
                        </button>
                    </div>
                    
                    <div class="sample-key" onclick="setKey('X9Y8-Z7W6-V5U4-T3S2')">
                        <span><i class="fas fa-key"></i> X9Y8-Z7W6-V5U4-T3S2</span>
                        <button class="copy-btn" onclick="event.stopPropagation(); copyText('X9Y8-Z7W6-V5U4-T3S2')">
                            <i class="fas fa-copy"></i>
                        </button>
                    </div>
                </div>
            </div>

        <?php else: ?>
            <!-- PROTECTED DEBUG CONTENT -->
            <div class="welcome-message">
                <h2><i class="fas fa-unlock"></i> Access Granted!</h2>
                <p>Welcome to the Protected Debug Application</p>
            </div>

            <div class="license-info">
                <h3><i class="fas fa-id-card"></i> License Information</h3>
                <div style="margin-top: 15px;">
                    <strong>Key:</strong> <?php echo htmlspecialchars($licenseData['key'] ?? 'Unknown'); ?><br>
                    <strong>Status:</strong> 
                    <span class="status-badge status-<?php echo strtolower($licenseData['status'] ?? 'active'); ?>">
                        <?php echo ucfirst($licenseData['status'] ?? 'Active'); ?>
                    </span><br>
                    <strong>Expires:</strong> <?php echo htmlspecialchars($licenseData['expires'] ?? 'Never'); ?><br>
                    <strong>Days Remaining:</strong> <?php echo $licenseData['days_remaining'] ?? 'Unlimited'; ?><br>
                    <strong>Usage Count:</strong> <?php echo $licenseData['usage_count'] ?? '1'; ?>
                </div>
                <a href="?logout=true" class="btn btn-logout" style="margin-top: 15px;">
                    <i class="fas fa-sign-out-alt"></i> Logout
                </a>
            </div>

            <div class="debug-content">
                <h2 style="color: var(--accent-red); margin-bottom: 25px;">
                    <i class="fas fa-tools"></i> Debug Tools & Features
                </h2>

                <div class="feature-grid">
                    <div class="feature-card">
                        <i class="fas fa-bug"></i>
                        <h3>Error Debugger</h3>
                        <p>Real-time error tracking and analysis</p>
                    </div>
                    
                    <div class="feature-card">
                        <i class="fas fa-database"></i>
                        <h3>Database Inspector</h3>
                        <p>Query and analyze database operations</p>
                    </div>
                    
                    <div class="feature-card">
                        <i class="fas fa-chart-bar"></i>
                        <h3>Performance Metrics</h3>
                        <p>Monitor application performance</p>
                    </div>
                    
                    <div class="feature-card">
                        <i class="fas fa-shield-alt"></i>
                        <h3>Security Scanner</h3>
                        <p>Security vulnerability detection</p>
                    </div>
                </div>

                <div style="background: var(--bg-secondary); padding: 20px; border-radius: 10px; margin-top: 25px;">
                    <h3><i class="fas fa-terminal"></i> System Information</h3>
                    <pre style="color: var(--text-secondary); margin-top: 15px; font-family: 'Courier New', monospace;">
PHP Version: <?php echo phpversion(); ?>
Server: <?php echo $_SERVER['SERVER_SOFTWARE'] ?? 'Unknown'; ?>
Authenticated: <?php echo $isAuthenticated ? 'Yes' : 'No'; ?>
License Key: <?php echo htmlspecialchars($_SESSION['debug_app_license_key'] ?? 'None'); ?>
Login Time: <?php echo date('Y-m-d H:i:s', $_SESSION['debug_app_login_time'] ?? time()); ?>
                    </pre>
                </div>

                <div style="text-align: center; margin-top: 30px;">
                    <button class="btn" onclick="alert('Debug feature activated!')">
                        <i class="fas fa-rocket"></i> Execute Debug Routine
                    </button>
                </div>
            </div>
        <?php endif; ?>
    </div>

    <script>
        // Set key from sample
        function setKey(key) {
            document.getElementById('license_key').value = key;
            document.getElementById('license_key').focus();
        }

        // Copy text to clipboard
        function copyText(text) {
            navigator.clipboard.writeText(text).then(() => {
                alert('Copied to clipboard: ' + text);
            });
        }

        // Auto-focus license key field
        <?php if (!$isAuthenticated): ?>
            document.getElementById('license_key').focus();
        <?php endif; ?>
    </script>
</body>
</html>