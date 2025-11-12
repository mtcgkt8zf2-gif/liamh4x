<?php
require_once 'config.php';

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

// Handle preflight OPTIONS request
if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
    http_response_code(200);
    exit();
}

try {
    // Get database connection FIRST
    $pdo = Config::getDB();
    
    // SIMPLE PARAMETER HANDLING - TRY MULTIPLE METHODS
    $key = '';
    $secret = '';

    // Method 1: Direct POST (should work for iOS)
    if (isset($_POST['key']) && isset($_POST['secret'])) {
        $key = $_POST['key'];
        $secret = $_POST['secret'];
        error_log("Method 1: Using direct POST parameters");
    } 
    // Method 2: Form data parsing (fallback)
    else {
        $input = file_get_contents('php://input');
        error_log("Method 2: Raw input: " . $input);
        
        if (!empty($input)) {
            parse_str($input, $data);
            $key = $data['key'] ?? '';
            $secret = $data['secret'] ?? '';
            error_log("Method 2: Parsed - Key: '$key', Secret: " . (!empty($secret) ? 'YES' : 'NO'));
        }
    }

    // DEBUG OUTPUT TO SEE WHAT'S RECEIVED
    error_log("=== VERIFY.PH DEBUG ===");
    error_log("Request Method: " . $_SERVER['REQUEST_METHOD']);
    error_log("Content Type: " . ($_SERVER['CONTENT_TYPE'] ?? 'NOT SET'));
    error_log("POST Data: " . print_r($_POST, true));
    error_log("Final - Key: '$key', Secret: " . (!empty($secret) ? 'YES' : 'NO'));
    error_log("=======================");

    // Validate required parameters
    if (empty($key) || empty($secret)) {
        http_response_code(400);
        echo json_encode([
            'valid' => false,
            'message' => 'Missing required parameters: key and secret',
            'debug' => [
                'received_key' => $key,
                'received_secret' => !empty($secret),
                'method' => $_SERVER['REQUEST_METHOD'],
                'content_type' => $_SERVER['CONTENT_TYPE'] ?? 'none',
                'post_data' => $_POST
            ]
        ]);
        exit;
    }

    // Verify application secret FROM APPLICATIONS TABLE
    $stmt = $pdo->prepare("SELECT id, name, secret_key FROM applications WHERE secret_key = ?");
    $stmt->execute([$secret]);
    $app = $stmt->fetch();

    if (!$app) {
        http_response_code(401);
        echo json_encode([
            'valid' => false,
            'message' => 'Invalid application secret key'
        ]);
        exit;
    }

    // Clean the key (remove dashes and spaces)
    $cleanKey = str_replace(['-', ' ', '_'], '', trim($key));
    
    // Validate key format
    if (strlen($cleanKey) != 16 || !ctype_alnum($cleanKey)) {
        echo json_encode([
            'valid' => false,
            'message' => 'Invalid key format. Must be 16 alphanumeric characters',
            'debug' => ['cleaned_key' => $cleanKey, 'key_length' => strlen($cleanKey)]
        ]);
        exit;
    }

    // Find the key in database
    $stmt = $pdo->prepare("
        SELECT *, 
               DATEDIFF(expiry_timestamp, NOW()) as days_remaining,
               CASE 
                 WHEN expiry_timestamp < NOW() THEN 'expired'
                 WHEN last_used IS NULL THEN 'unused' 
                 ELSE 'active'
               END as status
        FROM `keys` 
        WHERE key_string = ?
    ");
    
    $stmt->execute([$cleanKey]);
    $keyData = $stmt->fetch();

    if (!$keyData) {
        echo json_encode([
            'valid' => false,
            'message' => 'License key not found in system',
            'debug' => ['searched_key' => $cleanKey]
        ]);
        exit;
    }
    
    // Check if key is active
    if (isset($keyData['is_active']) && !$keyData['is_active']) {
        echo json_encode([
            'valid' => false,
            'message' => 'License key has been deactivated',
            'expires' => $keyData['expiry_timestamp']
        ]);
        exit;
    }

    $now = new DateTime();
    $expiry = new DateTime($keyData['expiry_timestamp']);
    
    // Check if key has expired
    if ($now > $expiry) {
        echo json_encode([
            'valid' => false,
            'expires' => $expiry->format('Y-m-d'),
            'message' => 'License key has expired',
            'days_remaining' => 0
        ]);
        exit;
    }
    
    $clientIP = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
    
    // Check if this is first use
    $isFirstUse = empty($keyData['last_used']);
    
    // Update usage statistics
    $updateStmt = $pdo->prepare("
        UPDATE `keys` 
        SET last_used_ip = ?, 
            last_used = NOW(), 
            usage_count = usage_count + 1 
        WHERE id = ?
    ");
    $updateStmt->execute([$clientIP, $keyData['id']]);
    
    // Log the verification
    try {
        $logStmt = $pdo->prepare("
            INSERT INTO key_usage_logs (key_id, ip_address, user_agent, verification_result, verification_message, application_id) 
            VALUES (?, ?, ?, 'success', 'Key verification successful', ?)
        ");
        $logStmt->execute([$keyData['id'], $clientIP, $userAgent, $app['id']]);
    } catch (Exception $e) {
        error_log("Failed to log usage: " . $e->getMessage());
        // Continue even if logging fails
    }
    
    // Calculate days remaining
    $daysRemaining = $keyData['days_remaining'] ?? 
        (int)$expiry->diff($now)->format('%a');
    
    // Format the key for display
    $formattedKey = substr($cleanKey, 0, 4) . '-' . 
                   substr($cleanKey, 4, 4) . '-' . 
                   substr($cleanKey, 8, 4) . '-' . 
                   substr($cleanKey, 12, 4);
    
    // Successful verification
    echo json_encode([
        'valid' => true,
        'key' => $formattedKey,
        'expires' => $expiry->format('Y-m-d H:i:s'),
        'days_remaining' => max(0, $daysRemaining),
        'first_use' => $isFirstUse,
        'usage_count' => ($keyData['usage_count'] ?? 0) + 1,
        'message' => $isFirstUse ? 
            'License activated successfully! Welcome!' : 
            'License verification successful!',
        'status' => $keyData['status'] ?? 'active',
        'application' => $app['name']
    ]);

} catch (Exception $e) {
    error_log("Key verification error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode([
        'valid' => false,
        'message' => 'Server error during verification',
        'error' => $e->getMessage()
    ]);
}
?>