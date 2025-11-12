class KeyAuthDashboard {
    constructor() {
        this.init();
    }

    init() {
        this.setMinDate();
        this.attachEventListeners();
        this.showWelcomeNotification();
    }

    setMinDate() {
        const tomorrow = new Date();
        tomorrow.setDate(tomorrow.getDate() + 1);
        const expiryInput = document.getElementById('expiryDate');
        expiryInput.min = tomorrow.toISOString().split('T')[0];
        
        // Set default date to 30 days from now
        const defaultDate = new Date();
        defaultDate.setDate(defaultDate.getDate() + 30);
        expiryInput.value = defaultDate.toISOString().split('T')[0];
    }

    attachEventListeners() {
        const form = document.getElementById('keyForm');
        form.addEventListener('submit', (e) => this.handleFormSubmit(e));
        
        // Add input formatting for better UX
        const expiryInput = document.getElementById('expiryDate');
        expiryInput.addEventListener('change', (e) => this.validateExpiryDate(e.target));
    }

    validateExpiryDate(input) {
        const selectedDate = new Date(input.value);
        const tomorrow = new Date();
        tomorrow.setDate(tomorrow.getDate() + 1);
        tomorrow.setHours(0, 0, 0, 0);

        if (selectedDate < tomorrow) {
            this.showError('Please select a future date');
            input.value = tomorrow.toISOString().split('T')[0];
        }
    }

    async handleFormSubmit(e) {
        e.preventDefault();
        
        const formData = new FormData(e.target);
        const submitButton = e.target.querySelector('button[type="submit"]');
        const originalText = submitButton.innerHTML;
        
        // Show loading state
        submitButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Generating Key...';
        submitButton.disabled = true;

        try {
            console.log('Submitting form...');
            
            const response = await fetch('', {
                method: 'POST',
                body: formData,
                headers: {
                    'Accept': 'application/json',
                }
            });

            console.log('Response status:', response.status);
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const result = await response.json();
            console.log('Response result:', result);

            if (result.success) {
                this.showSuccessResult(result);
                this.logKeyGeneration(result.key);
            } else {
                this.showError(result.message || 'Unknown error occurred');
            }
        } catch (error) {
            console.error('Generation error details:', error);
            this.showError(`Network error: ${error.message}. Please check your connection and server configuration.`);
        } finally {
            // Restore button
            submitButton.innerHTML = '<i class="fas fa-key"></i> Generate License Key';
            submitButton.disabled = false;
        }
    }

    showSuccessResult(result) {
        const resultDiv = document.getElementById('result');
        const keyElement = document.getElementById('generatedKey');
        const expiryElement = document.getElementById('expiryDisplay');

        keyElement.textContent = result.key;
        expiryElement.textContent = result.expiry;

        resultDiv.style.display = 'block';
        resultDiv.scrollIntoView({ behavior: 'smooth', block: 'center' });
        
        // Celebrate!
        this.celebrateSuccess();
    }

    showError(message) {
        this.showNotification(message, 'error');
    }

    showSuccess(message) {
        this.showNotification(message, 'success');
    }

    showNotification(message, type = 'info') {
        // Create notification element
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.innerHTML = `
            <i class="fas fa-${type === 'error' ? 'exclamation-triangle' : type === 'success' ? 'check-circle' : 'info-circle'}"></i>
            <span>${message}</span>
            <button class="notification-close" onclick="this.parentElement.remove()">&times;</button>
        `;
        
        // Add styles
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 15px 20px;
            background: ${type === 'error' ? 'var(--error-red)' : type === 'success' ? 'var(--success-green)' : 'var(--bg-card)'};
            color: white;
            border-radius: 10px;
            box-shadow: var(--shadow-lg);
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

    showWelcomeNotification() {
        setTimeout(() => {
            this.showSuccess('Welcome to KeyAuth! Ready to generate secure license keys.');
        }, 1000);
    }

    celebrateSuccess() {
        // Add subtle celebration effect
        const resultDiv = document.getElementById('result');
        resultDiv.style.animation = 'pulse 0.5s ease';
        setTimeout(() => {
            resultDiv.style.animation = '';
        }, 500);
    }

    logKeyGeneration(key) {
        console.log(`Key generated: ${key} at ${new Date().toISOString()}`);
    }
}

// Global functions for modal and clipboard
function copyToClipboard() {
    const keyElement = document.getElementById('generatedKey');
    const key = keyElement.textContent;

    if (!key) {
        alert('No key to copy!');
        return;
    }

    navigator.clipboard.writeText(key).then(() => {
        const copyBtn = document.querySelector('.btn-copy');
        const originalHtml = copyBtn.innerHTML;
        
        copyBtn.innerHTML = '<i class="fas fa-check"></i> Copied!';
        copyBtn.style.background = 'var(--success-green)';
        copyBtn.style.borderColor = 'var(--success-green)';
        copyBtn.style.color = 'white';
        
        setTimeout(() => {
            copyBtn.innerHTML = originalHtml;
            copyBtn.style.background = '';
            copyBtn.style.borderColor = '';
            copyBtn.style.color = '';
        }, 2000);
    }).catch(err => {
        console.error('Failed to copy: ', err);
        // Fallback for older browsers
        const textArea = document.createElement('textarea');
        textArea.value = key;
        document.body.appendChild(textArea);
        textArea.select();
        document.execCommand('copy');
        document.body.removeChild(textArea);
        
        const copyBtn = document.querySelector('.btn-copy');
        copyBtn.innerHTML = '<i class="fas fa-check"></i> Copied!';
        setTimeout(() => {
            copyBtn.innerHTML = '<i class="fas fa-copy"></i>';
        }, 2000);
    });
}

function testVerification() {
    document.getElementById('testModal').style.display = 'flex';
    document.getElementById('testKey').focus();
    document.getElementById('testResult').style.display = 'none';
}

function closeModal() {
    document.getElementById('testModal').style.display = 'none';
    document.getElementById('testKey').value = '';
    document.getElementById('testResult').style.display = 'none';
}

function showSecretInfo() {
    document.getElementById('secretModal').style.display = 'flex';
}

function closeSecretModal() {
    document.getElementById('secretModal').style.display = 'none';
}

async function verifyTestKey() {
    const testKey = document.getElementById('testKey').value.trim();
    const testResult = document.getElementById('testResult');
    
    if (!testKey) {
        testResult.textContent = 'Please enter a key to test';
        testResult.className = 'test-result error';
        testResult.style.display = 'block';
        return;
    }

    // Validate key format
    const cleanKey = testKey.replace(/-/g, '');
    if (cleanKey.length !== 16 || !/^[A-Z0-9]{16}$/.test(cleanKey)) {
        testResult.textContent = 'Invalid key format. Key should be 16 alphanumeric characters.';
        testResult.className = 'test-result error';
        testResult.style.display = 'block';
        return;
    }

    const verifyBtn = document.querySelector('#testModal .btn-primary');
    const originalText = verifyBtn.innerHTML;
    
    verifyBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Verifying...';
    verifyBtn.disabled = true;

    try {
        const deviceHash = await generateDeviceHash();
        
        const response = await fetch('verify.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: new URLSearchParams({
                key: testKey,
                secret: 'K7$gH2!pQ9@zR5*mX8#vB3&nC6^jM1_lF4',
                device_hash: deviceHash
            })
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const result = await response.json();

        if (result.valid) {
            testResult.innerHTML = `
                <i class="fas fa-check-circle"></i> 
                <strong>Valid Key!</strong><br>
                ${result.message}<br>
                Expires: ${result.expires}<br>
                ${result.first_use ? '<em>First time usage</em>' : '<em>Previously used</em>'}
            `;
            testResult.className = 'test-result success';
        } else {
            testResult.innerHTML = `
                <i class="fas fa-exclamation-triangle"></i> 
                <strong>Invalid Key</strong><br>
                ${result.message}
            `;
            testResult.className = 'test-result error';
        }
        testResult.style.display = 'block';

    } catch (error) {
        testResult.innerHTML = `
            <i class="fas fa-exclamation-triangle"></i> 
            <strong>Verification Failed</strong><br>
            ${error.message}
        `;
        testResult.className = 'test-result error';
        testResult.style.display = 'block';
    } finally {
        verifyBtn.innerHTML = originalText;
        verifyBtn.disabled = false;
    }
}

async function generateDeviceHash() {
    try {
        const fingerprint = (await getClientIP()) + navigator.userAgent + navigator.language + screen.width + screen.height;
        const encoder = new TextEncoder();
        const data = encoder.encode(fingerprint);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    } catch (error) {
        console.error('Device hash generation failed:', error);
        return 'fallback_device_hash_' + Math.random().toString(36).substr(2, 9);
    }
}

async function getClientIP() {
    try {
        const response = await fetch('https://api.ipify.org?format=json', { 
            method: 'GET',
            headers: { 'Content-Type': 'application/json' }
        });
        const data = await response.json();
        return data.ip;
    } catch {
        return '127.0.0.1';
    }
}

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new KeyAuthDashboard();
});

// Close modal when clicking outside
document.addEventListener('click', (e) => {
    const testModal = document.getElementById('testModal');
    const secretModal = document.getElementById('secretModal');
    
    if (e.target === testModal) {
        closeModal();
    }
    if (e.target === secretModal) {
        closeSecretModal();
    }
});

// Add CSS for notifications
const notificationStyles = `
@keyframes slideInRight {
    from { transform: translateX(100%); opacity: 0; }
    to { transform: translateX(0); opacity: 1; }
}

@keyframes pulse {
    0% { transform: scale(1); }
    50% { transform: scale(1.02); }
    100% { transform: scale(1); }
}

.notification-close {
    background: none;
    border: none;
    color: inherit;
    font-size: 1.2rem;
    cursor: pointer;
    padding: 0;
    width: 20px;
    height: 20px;
    display: flex;
    align-items: center;
    justify-content: center;
}
`;

// Inject styles
const styleSheet = document.createElement('style');
styleSheet.textContent = notificationStyles;
document.head.appendChild(styleSheet);

// API Settings Functions
function copySecretKey() {
    const secretKey = document.getElementById('secretKey').textContent;
    copyToClipboardText(secretKey, 'Secret key copied to clipboard!');
}

function copyApiEndpoint() {
    const endpoint = document.getElementById('apiEndpoint').textContent;
    copyToClipboardText(endpoint, 'API endpoint copied to clipboard!');
}

function copyKey(keyString) {
    const formattedKey = 
        keyString.substring(0, 4) + '-' +
        keyString.substring(4, 8) + '-' +
        keyString.substring(8, 12) + '-' +
        keyString.substring(12, 16);
    copyToClipboardText(formattedKey, 'License key copied to clipboard!');
}

function copyToClipboardText(text, message) {
    navigator.clipboard.writeText(text).then(() => {
        showNotification(message, 'success');
    }).catch(err => {
        console.error('Failed to copy: ', err);
        showNotification('Failed to copy to clipboard', 'error');
    });
}

// User Management Functions
function showAddUserModal() {
    showNotification('Add user functionality coming soon!', 'info');
}

function editUser(userId) {
    showNotification(`Edit user ${userId} - coming soon!`, 'info');
}

function viewUserActivity(userId) {
    showNotification(`View activity for user ${userId} - coming soon!`, 'info');
}

function deleteUser(userId) {
    if (confirm('Are you sure you want to delete this user? This action cannot be undone.')) {
        showNotification(`Delete user ${userId} - coming soon!`, 'warning');
    }
}

// Keys Management Functions
function filterKeys() {
    showNotification('Filter functionality coming soon!', 'info');
}

function testKey(keyString) {
    const formattedKey = 
        keyString.substring(0, 4) + '-' +
        keyString.substring(4, 8) + '-' +
        keyString.substring(8, 12) + '-' +
        keyString.substring(12, 16);
    
    document.getElementById('testKey').value = formattedKey;
    closeModal();
    testVerification();
}

function viewKeyDetails(keyId) {
    showNotification(`View details for key ${keyId} - coming soon!`, 'info');
}

function renewKey(keyId) {
    showNotification(`Renew key ${keyId} - coming soon!`, 'info');
}

function revokeKey(keyId) {
    if (confirm('Are you sure you want to revoke this key? It will become invalid immediately.')) {
        showNotification(`Revoke key ${keyId} - coming soon!`, 'warning');
    }
}

function exportKeys() {
    showNotification('Export functionality coming soon!', 'info');
}

// Notification function
function showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.innerHTML = `
        <i class="fas fa-${type === 'error' ? 'exclamation-triangle' : type === 'success' ? 'check-circle' : type === 'warning' ? 'exclamation-circle' : 'info-circle'}"></i>
        <span>${message}</span>
        <button class="notification-close" onclick="this.parentElement.remove()">&times;</button>
    `;
    
    // Add styles
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 15px 20px;
        background: ${type === 'error' ? 'var(--error-red)' : type === 'success' ? 'var(--success-green)' : type === 'warning' ? 'var(--warning-orange)' : 'var(--bg-card)'};
        color: white;
        border-radius: 10px;
        box-shadow: var(--shadow-lg);
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