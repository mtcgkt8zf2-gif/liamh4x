<?php
require_once 'config.php';

header('Content-Type: text/html');
$keyId = $_GET['key_id'] ?? 0;

if (!$keyId) {
    echo '<div class="error-state">Invalid key ID</div>';
    exit;
}

try {
    $logs = Config::getKeyUsageLogs($keyId, 100);
    $key = Config::getKeyById($keyId); // You'll need to add this method to Config
    
    if (empty($logs)) {
        echo '<div class="empty-state-small">';
        echo '<i class="fas fa-history"></i>';
        echo '<h4>No Usage Logs</h4>';
        echo '<p>This key has not been used yet.</p>';
        echo '</div>';
        exit;
    }
    ?>
    
    <div class="logs-header">
        <h4>Usage History for Key: <?= substr($key['key_string'], 0, 4) . '-' . substr($key['key_string'], 4, 4) . '...' ?></h4>
        <div class="logs-stats">
            Total Uses: <?= count($logs) ?> | Last Used: <?= $key['last_used'] ? date('M j, Y g:i A', strtotime($key['last_used'])) : 'Never' ?>
        </div>
    </div>
    
    <div class="logs-table">
        <table>
            <thead>
                <tr>
                    <th>Date & Time</th>
                    <th>IP Address</th>
                    <th>Result</th>
                    <th>Message</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($logs as $log): ?>
                <tr>
                    <td><?= date('M j, Y g:i A', strtotime($log['created_at'])) ?></td>
                    <td><?= htmlspecialchars($log['ip_address']) ?></td>
                    <td>
                        <span class="status-badge status-<?= $log['verification_result'] === 'success' ? 'success' : 'error' ?>">
                            <?= ucfirst($log['verification_result']) ?>
                        </span>
                    </td>
                    <td><?= htmlspecialchars($log['verification_message'] ?? 'N/A') ?></td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    
    <?php
} catch (Exception $e) {
    echo '<div class="error-state">Error loading logs: ' . htmlspecialchars($e->getMessage()) . '</div>';
}
?>