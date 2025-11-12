<?php
class Config {
    private static $pdo = null;
    
    public static function getDB() {
        if (self::$pdo === null) {
            // Use your EXACT database name with capital letters
            $dbname = 'if0_36991956_Key_auth';
            $host = 'sql210.infinityfree.com';
            $user = 'if0_36991956';
            $pass = 'gby69mqc';
            
            try {
                self::$pdo = new PDO("mysql:host=$host;dbname=$dbname;charset=utf8mb4", $user, $pass, [
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                    PDO::ATTR_EMULATE_PREPARES => false
                ]);
                
                error_log("✅ Successfully connected to database: $dbname");
                
            } catch(PDOException $e) {
                $error = "Database connection failed.\n";
                $error .= "Database: $dbname\n";
                $error .= "Error: " . $e->getMessage() . "\n";
                throw new Exception($error);
            }
        }
        return self::$pdo;
    }
    
    public static function getAppSecret() {
        return 'LIAMH4XID2025FFPANELKEY';
    }
    
    
    // Get all users
    public static function getAllUsers() {
        try {
            $pdo = self::getDB();
            $stmt = $pdo->query("SELECT * FROM users ORDER BY created_at DESC");
            return $stmt->fetchAll();
        } catch (Exception $e) {
            error_log("Error getting users: " . $e->getMessage());
            return [];
        }
    }
    
    // Get all keys with pagination, search and filters
    public static function getAllKeys($page = 1, $perPage = 50, $search = '', $statusFilter = '') {
        try {
            $pdo = self::getDB();
            $offset = ($page - 1) * $perPage;
            
            // Build base query
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
                $query .= " AND (k.key_string LIKE :search OR k.last_used_ip LIKE :search)";
                $params[':search'] = "%$search%";
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
                    case 'inactive':
                        $query .= " AND k.expiry_timestamp > NOW() AND k.last_used IS NOT NULL";
                        break;
                }
            }
            
            $query .= " ORDER BY k.created_at DESC LIMIT :limit OFFSET :offset";
            
            $stmt = $pdo->prepare($query);
            
            // Bind search parameter if exists
            if (!empty($search)) {
                $stmt->bindValue(':search', "%$search%", PDO::PARAM_STR);
            }
            
            // Bind pagination parameters
            $stmt->bindValue(':limit', (int)$perPage, PDO::PARAM_INT);
            $stmt->bindValue(':offset', (int)$offset, PDO::PARAM_INT);
            
            $stmt->execute();
            
            return $stmt->fetchAll();
        } catch (Exception $e) {
            error_log("Error getting keys: " . $e->getMessage());
            return [];
        }
    }
    
    // Get total key count with search and filters
    public static function getTotalKeys($search = '', $statusFilter = '') {
        try {
            $pdo = self::getDB();
            
            $query = "SELECT COUNT(*) as total FROM `keys` k WHERE 1=1";
            $params = [];
            
            // Add search filter
            if (!empty($search)) {
                $query .= " AND (k.key_string LIKE :search OR k.last_used_ip LIKE :search)";
                $params[':search'] = "%$search%";
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
                    case 'inactive':
                        $query .= " AND k.expiry_timestamp > NOW() AND k.last_used IS NOT NULL";
                        break;
                }
            }
            
            $stmt = $pdo->prepare($query);
            
            // Bind search parameter if exists
            if (!empty($search)) {
                $stmt->bindValue(':search', "%$search%", PDO::PARAM_STR);
            }
            
            $stmt->execute();
            return $stmt->fetch()['total'];
        } catch (Exception $e) {
            return 0;
        }
    }
    
    // Get key statistics (updated with today's usage)
    public static function getKeyStats() {
        try {
            $pdo = self::getDB();
            
            $stats = [
                'total' => 0,
                'active' => 0,
                'expired' => 0,
                'unused' => 0,
                'inactive' => 0,
                'today_usage' => 0
            ];
            
            // Total keys
            $stmt = $pdo->query("SELECT COUNT(*) as count FROM `keys`");
            $stats['total'] = $stmt->fetch()['count'];
            
            // Active keys (not expired and used at least once)
            $stmt = $pdo->query("SELECT COUNT(*) as count FROM `keys` WHERE expiry_timestamp > NOW() AND last_used IS NOT NULL");
            $stats['active'] = $stmt->fetch()['count'];
            
            // Expired keys
            $stmt = $pdo->query("SELECT COUNT(*) as count FROM `keys` WHERE expiry_timestamp <= NOW()");
            $stats['expired'] = $stmt->fetch()['count'];
            
            // Unused keys (not expired but never used)
            $stmt = $pdo->query("SELECT COUNT(*) as count FROM `keys` WHERE expiry_timestamp > NOW() AND last_used IS NULL");
            $stats['unused'] = $stmt->fetch()['count'];
            
            // Inactive keys (not expired but not active - same as active for now)
            $stmt = $pdo->query("SELECT COUNT(*) as count FROM `keys` WHERE expiry_timestamp > NOW() AND last_used IS NOT NULL");
            $stats['inactive'] = $stmt->fetch()['count'];
            
            // Today's usage count
            $stmt = $pdo->query("SELECT COUNT(*) as count FROM `keys` WHERE DATE(last_used) = CURDATE()");
            $stats['today_usage'] = $stmt->fetch()['count'];
            
            return $stats;
        } catch (Exception $e) {
            return [];
        }
    }
    
    // Delete a key
    public static function deleteKey($keyId) {
        try {
            $pdo = self::getDB();
            $stmt = $pdo->prepare("DELETE FROM `keys` WHERE id = ?");
            return $stmt->execute([$keyId]);
        } catch (Exception $e) {
            error_log("Error deleting key: " . $e->getMessage());
            return false;
        }
    }
    
    // Toggle key status (active/inactive)
    public static function toggleKeyStatus($keyId, $newStatus) {
        try {
            $pdo = self::getDB();
            
            // For now, we'll implement a simple active/inactive toggle
            // You might want to modify your database structure to have an explicit 'active' field
            // For this implementation, we'll assume we're just updating a status field
            $stmt = $pdo->prepare("UPDATE `keys` SET is_active = ? WHERE id = ?");
            return $stmt->execute([$newStatus, $keyId]);
            
        } catch (Exception $e) {
            error_log("Error toggling key status: " . $e->getMessage());
            return false;
        }
    }
    
    // Get key by ID
    public static function getKeyById($keyId) {
        try {
            $pdo = self::getDB();
            $stmt = $pdo->prepare("
                SELECT k.*, 
                       DATEDIFF(k.expiry_timestamp, NOW()) as days_remaining,
                       CASE 
                         WHEN k.expiry_timestamp < NOW() THEN 'expired'
                         WHEN k.last_used IS NULL THEN 'unused' 
                         ELSE 'active'
                       END as status
                FROM `keys` k 
                WHERE k.id = ?
            ");
            $stmt->execute([$keyId]);
            return $stmt->fetch();
        } catch (Exception $e) {
            error_log("Error getting key by ID: " . $e->getMessage());
            return null;
        }
    }
    
    // Get key usage logs
    public static function getKeyUsageLogs($keyId) {
        try {
            $pdo = self::getDB();
            
            // If you have a separate usage_logs table, query it here
            // For now, return basic usage info from the keys table
            $stmt = $pdo->prepare("
                SELECT 
                    key_string,
                    last_used,
                    last_used_ip,
                    usage_count,
                    created_at
                FROM `keys` 
                WHERE id = ?
            ");
            $stmt->execute([$keyId]);
            
            return $stmt->fetch();
        } catch (Exception $e) {
            error_log("Error getting key usage logs: " . $e->getMessage());
            return [];
        }
    }
}
?>