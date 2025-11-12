<?php
require_once 'config.php';

echo "<pre>";
echo "=== Verifying Key in Database ===\n\n";

try {
    $pdo = Config::getDB();
    
    // Check all keys in database
    $stmt = $pdo->query("SELECT key_string, expiry_timestamp, created_at FROM `keys` ORDER BY created_at DESC");
    $keys = $stmt->fetchAll();
    
    echo "Total keys in database: " . count($keys) . "\n\n";
    
    if (count($keys) > 0) {
        echo "Recent keys:\n";
        foreach ($keys as $key) {
            $formattedKey = substr($key['key_string'], 0, 4) . '-' . 
                           substr($key['key_string'], 4, 4) . '-' . 
                           substr($key['key_string'], 8, 4) . '-' . 
                           substr($key['key_string'], 12, 4);
            echo "🔑 $formattedKey | Expires: " . $key['expiry_timestamp'] . " | Created: " . $key['created_at'] . "\n";
        }
    } else {
        echo "No keys found in database.\n";
    }
    
} catch (Exception $e) {
    echo "Error: " . $e->getMessage() . "\n";
}

echo "</pre>";
?>