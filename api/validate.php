<?php
require_once '../config.php';

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['success' => false, 'message' => 'POST method required']);
    exit;
}

$input = file_get_contents('php://input');
$data = json_decode($input, true);

if (json_last_error() !== JSON_ERROR_NONE) {
    echo json_encode(['success' => false, 'message' => 'Invalid JSON']);
    exit;
}

$appId = $data['app_id'] ?? null;
$secretKey = $data['secret_key'] ?? null;
$userKey = $data['user_key'] ?? null;

if (!$appId || !$secretKey || !$userKey) {
    echo json_encode(['success' => false, 'message' => 'Missing required fields']);
    exit;
}

try {
    $pdo = Config::getDB();
    
    // Verify app and secret key
    $stmt = $pdo->prepare("SELECT id FROM applications WHERE id = ? AND secret_key = ?");
    $stmt->execute([$appId, $secretKey]);
    $app = $stmt->fetch();
    
    if (!$app) {
        echo json_encode(['success' => false, 'message' => 'Invalid application or secret key']);
        exit;
    }
    
    // Validate the user key
    $stmt = $pdo->prepare("
        SELECT *, 
               DATEDIFF(expiry_timestamp, NOW()) as days_remaining,
               CASE 
                 WHEN expiry_timestamp < NOW() THEN 'expired'
                 WHEN last_used IS NULL THEN 'unused' 
                 ELSE 'active'
               END as status
        FROM `keys` 
        WHERE key_string = ? AND app_id = ?
    ");
    $stmt->execute([$userKey, $appId]);
    $key = $stmt->fetch();
    
    if (!$key) {
        echo json_encode(['success' => false, 'message' => 'Invalid key']);
        exit;
    }
    
    // Update key usage
    $stmt = $pdo->prepare("
        UPDATE `keys` 
        SET last_used = NOW(), 
            usage_count = usage_count + 1,
            last_used_ip = ?
        WHERE id = ?
    ");
    $stmt->execute([$_SERVER['REMOTE_ADDR'] ?? 'unknown', $key['id']]);
    
    echo json_encode([
        'success' => true,
        'message' => 'Key validated successfully',
        'key_data' => [
            'status' => $key['status'],
            'days_remaining' => $key['days_remaining'],
            'total_uses' => $key['usage_count'] + 1,
            'created_at' => $key['created_at'],
            'expires_at' => $key['expiry_timestamp']
        ]
    ]);
    
} catch (Exception $e) {
    echo json_encode(['success' => false, 'message' => 'Database error: ' . $e->getMessage()]);
}
?>