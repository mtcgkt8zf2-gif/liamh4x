<?php
require_once 'config.php';

header('Content-Type: application/json');

// Simple authentication for key generation
$adminSecret = 'ADMIN123'; // Change this in production

if ($_POST['admin_secret'] !== $adminSecret) {
    echo json_encode(['error' => 'Unauthorized']);
    exit;
}

try {
    $pdo = Config::getDB();
    
    // Generate random 16-character key
    $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    $key = '';
    for ($i = 0; $i < 16; $i++) {
        $key .= $chars[rand(0, strlen($chars) - 1)];
    }
    
    // Set expiry (30 days from now)
    $expiry = date('Y-m-d H:i:s', strtotime('+30 days'));
    
    // Insert into database
    $stmt = $pdo->prepare("
        INSERT INTO `keys` (key_string, expiry_timestamp, created_at) 
        VALUES (?, ?, NOW())
    ");
    
    $stmt->execute([$key, $expiry]);
    
    // Format for display
    $formattedKey = substr($key, 0, 4) . '-' . 
                   substr($key, 4, 4) . '-' . 
                   substr($key, 8, 4) . '-' . 
                   substr($key, 12, 4);
    
    echo json_encode([
        'success' => true,
        'key' => $formattedKey,
        'raw_key' => $key,
        'expires' => $expiry,
        'message' => 'Key generated successfully'
    ]);
    
} catch (Exception $e) {
    echo json_encode(['error' => $e->getMessage()]);
}
?>