<?php
require_once 'config.php';

$baseUrl = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http") . "://$_SERVER[HTTP_HOST]";
$scriptPath = dirname($_SERVER['SCRIPT_NAME']);
$apiUrl = rtrim($baseUrl . $scriptPath, '/') . '/verify.php';
$appSecret = Config::getAppSecret();

// Generate sample keys for demonstration
$sampleKeys = [
    'standard' => 'A1B2-C3D4-E5F6-G7H8',
    'premium' => 'P1R2-E3M4-I5U6-M7K8-Y9Z0-A1B2',
    'enterprise' => 'E1N2-T3E4-R5P6-R7I8-S9E0-K1E2-Y3Z4-A5B6'
];
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API Documentation - KeyAuth | Professional License Key Management</title>
    <meta name="description" content="Complete API documentation for KeyAuth license key verification system. Integration guides for all programming languages.">
    <link rel="stylesheet" href="style.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@400;500;600;700&family=Roboto:wght@300;400;500&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.8.0/styles/atom-one-dark.min.css">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.8.0/highlight.min.js"></script>
</head>
<body>
    <!-- Mobile Menu Toggle -->
    <div class="mobile-menu-toggle" onclick="toggleMobileMenu()">
        <i class="fas fa-bars"></i>
    </div>

    <div class="container">
        <header class="dashboard-header">
            <div class="logo">
                <div class="logo-icon">
                    <i class="fas fa-key"></i>
                </div>
                <div class="logo-text">
                    <h1>KeyAuth</h1>
                    <span class="tagline">API Documentation</span>
                </div>
            </div>
            <div class="header-actions">
                <a href="index.php" class="btn btn-secondary">
                    <i class="fas fa-arrow-left"></i> Dashboard
                </a>
                <button class="btn btn-primary" onclick="testVerification()">
                    <i class="fas fa-bolt"></i> Test API
                </button>
            </div>
        </header>

        <!-- API Navigation Sidebar -->
        <div class="api-layout">
            <nav class="api-sidebar">
                <div class="sidebar-section">
                    <h4>Getting Started</h4>
                    <ul>
                        <li><a href="#quick-start" class="nav-link active">Quick Start</a></li>
                        <li><a href="#authentication" class="nav-link">Authentication</a></li>
                        <li><a href="#endpoints" class="nav-link">API Endpoints</a></li>
                    </ul>
                </div>
                
                <div class="sidebar-section">
                    <h4>Integration</h4>
                    <ul>
                        <li><a href="#web-integration" class="nav-link">Web Applications</a></li>
                        <li><a href="#desktop-integration" class="nav-link">Desktop Apps</a></li>
                        <li><a href="#mobile-integration" class="nav-link">Mobile Apps</a></li>
                        <li><a href="#game-integration" class="nav-link">Game Development</a></li>
                    </ul>
                </div>
                
                <div class="sidebar-section">
                    <h4>Code Examples</h4>
                    <ul>
                        <li><a href="#python" class="nav-link">Python</a></li>
                        <li><a href="#javascript" class="nav-link">JavaScript/Node.js</a></li>
                        <li><a href="#php" class="nav-link">PHP</a></li>
                        <li><a href="#csharp" class="nav-link">C#/.NET</a></li>
                        <li><a href="#java" class="nav-link">Java</a></li>
                        <li><a href="#objective-c" class="nav-link">Objective-C</a></li>
                        <li><a href="#cpp" class="nav-link">C++</a></li>
                        <li><a href="#golang" class="nav-link">Go</a></li>
                        <li><a href="#rust" class="nav-link">Rust</a></li>
                    </ul>
                </div>
                
                <div class="sidebar-section">
                    <h4>Advanced</h4>
                    <ul>
                        <li><a href="#error-handling" class="nav-link">Error Handling</a></li>
                        <li><a href="#security" class="nav-link">Security</a></li>
                        <li><a href="#best-practices" class="nav-link">Best Practices</a></li>
                        <li><a href="#webhooks" class="nav-link">Webhooks</a></li>
                    </ul>
                </div>
            </nav>

            <main class="api-main-content">
                <!-- Quick Start -->
                <section id="quick-start" class="api-section">
                    <div class="section-header">
                        <h2><i class="fas fa-rocket"></i> Quick Start</h2>
                        <p>Get your application integrated with KeyAuth in under 5 minutes</p>
                    </div>
                    
                    <div class="quick-steps">
                        <div class="step">
                            <div class="step-number">1</div>
                            <div class="step-content">
                                <h4>Get Your Credentials</h4>
                                <p>Copy your API endpoint and secret key:</p>
                                <div class="credentials-grid">
                                    <div class="credential-item">
                                        <label>API Endpoint</label>
                                        <div class="credential-value">
                                            <code><?= htmlspecialchars($apiUrl) ?></code>
                                            <button class="btn-copy" onclick="copyText('<?= htmlspecialchars($apiUrl) ?>')">
                                                <i class="fas fa-copy"></i>
                                            </button>
                                        </div>
                                    </div>
                                    <div class="credential-item">
                                        <label>Secret Key</label>
                                        <div class="credential-value">
                                            <code><?= htmlspecialchars($appSecret) ?></code>
                                            <button class="btn-copy" onclick="copyText('<?= htmlspecialchars($appSecret) ?>')">
                                                <i class="fas fa-copy"></i>
                                            </button>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="step">
                            <div class="step-number">2</div>
                            <div class="step-content">
                                <h4>Choose Your Integration</h4>
                                <p>Select the appropriate code example for your programming language:</p>
                                <div class="integration-badges">
                                    <span class="integration-badge" onclick="scrollToSection('python')">Python</span>
                                    <span class="integration-badge" onclick="scrollToSection('javascript')">JavaScript</span>
                                    <span class="integration-badge" onclick="scrollToSection('csharp')">C#</span>
                                    <span class="integration-badge" onclick="scrollToSection('objective-c')">Objective-C</span>
                                    <span class="integration-badge" onclick="scrollToSection('java')">Java</span>
                                </div>
                            </div>
                        </div>
                        
                        <div class="step">
                            <div class="step-number">3</div>
                            <div class="step-content">
                                <h4>Test Your Integration</h4>
                                <p>Use our test keys to verify your implementation:</p>
                                <div class="test-keys">
                                    <?php foreach ($sampleKeys as $type => $key): ?>
                                        <div class="test-key-item">
                                            <span class="key-type"><?= ucfirst($type) ?></span>
                                            <code><?= $key ?></code>
                                            <button class="btn-copy-sm" onclick="copyText('<?= $key ?>')">
                                                <i class="fas fa-copy"></i>
                                            </button>
                                        </div>
                                    <?php endforeach; ?>
                                </div>
                            </div>
                        </div>
                    </div>
                </section>

                <!-- Authentication -->
                <section id="authentication" class="api-section">
                    <div class="section-header">
                        <h2><i class="fas fa-shield-alt"></i> Authentication</h2>
                        <p>Secure your API requests with proper authentication</p>
                    </div>
                    
                    <div class="auth-info">
                        <div class="info-card">
                            <i class="fas fa-key"></i>
                            <h4>Secret Key Authentication</h4>
                            <p>All API requests must include your secret key in the request body for authentication.</p>
                        </div>
                        
                        <div class="info-card">
                            <i class="fas fa-lock"></i>
                            <h4>HTTPS Required</h4>
                            <p>All API calls must be made over HTTPS to ensure data security and integrity.</p>
                        </div>
                    </div>
                    
                    <div class="code-block">
                        <div class="code-header">
                            <span>Authentication Parameters</span>
                        </div>
                        <pre><code class="language-json">{
  "key": "string (required)",
  "secret": "string (required)",
  "hwid": "string (optional)",
  "session_id": "string (optional)"
}</code></pre>
                    </div>
                </section>

                <!-- API Endpoints -->
                <section id="endpoints" class="api-section">
                    <div class="section-header">
                        <h2><i class="fas fa-plug"></i> API Endpoints</h2>
                        <p>Complete list of available API endpoints</p>
                    </div>
                    
                    <div class="endpoints-grid">
                        <div class="endpoint-card">
                            <div class="endpoint-method post">POST</div>
                            <div class="endpoint-info">
                                <h4>Verify License Key</h4>
                                <code><?= htmlspecialchars($apiUrl) ?></code>
                                <p>Validate a license key and check its status</p>
                            </div>
                        </div>
                        
                        <div class="endpoint-card">
                            <div class="endpoint-method get">GET</div>
                            <div class="endpoint-info">
                                <h4>Check Key Status</h4>
                                <code><?= htmlspecialchars($apiUrl) ?>?key=LICENSE_KEY</code>
                                <p>Quick status check without full validation</p>
                            </div>
                        </div>
                    </div>
                </section>

                <!-- Web Integration -->
                <section id="web-integration" class="api-section">
                    <div class="section-header">
                        <h2><i class="fas fa-globe"></i> Web Applications</h2>
                        <p>Integrate KeyAuth into your web applications</p>
                    </div>
                    
                    <div class="integration-tabs">
                        <div class="tab-buttons">
                            <button class="tab-btn active" onclick="openIntegrationTab(event, 'frontend-tab')">Frontend</button>
                            <button class="tab-btn" onclick="openIntegrationTab(event, 'backend-tab')">Backend</button>
                        </div>
                        
                        <div id="frontend-tab" class="tab-content active">
                            <h4>Client-Side Implementation</h4>
                            <p>For single-page applications and client-side validation:</p>
                            <div class="code-block">
                                <div class="code-header">
                                    <span>JavaScript Frontend Example</span>
                                    <button class="btn-copy" onclick="copyCode('frontendJs')">
                                        <i class="fas fa-copy"></i>
                                    </button>
                                </div>
                                <pre id="frontendJs"><code class="language-javascript">class KeyAuthClient {
    constructor(apiUrl, secret) {
        this.apiUrl = apiUrl;
        this.secret = secret;
    }

    async validateLicense(key, hwid = null) {
        try {
            const payload = {
                key: key,
                secret: this.secret,
                hwid: hwid || this.generateHWID()
            };

            const response = await fetch(this.apiUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(payload)
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const data = await response.json();
            
            if (data.valid) {
                // Store session data
                localStorage.setItem('keyauth_session', JSON.stringify({
                    key: key,
                    expires: data.expires,
                    session_id: data.session_id
                }));
                return true;
            } else {
                throw new Error(data.message || 'Invalid license key');
            }
        } catch (error) {
            console.error('License validation failed:', error);
            return false;
        }
    }

    generateHWID() {
        // Generate a simple hardware ID
        return btoa(navigator.userAgent + screen.width + screen.height);
    }

    async checkSession() {
        const session = localStorage.getItem('keyauth_session');
        if (!session) return false;

        const sessionData = JSON.parse(session);
        return await this.validateLicense(sessionData.key);
    }
}

// Usage
const auth = new KeyAuthClient('<?= htmlspecialchars($apiUrl) ?>', '<?= htmlspecialchars($appSecret) ?>');</code></pre>
                            </div>
                        </div>
                        
                        <div id="backend-tab" class="tab-content">
                            <h4>Server-Side Implementation</h4>
                            <p>For secure server-side validation:</p>
                            <div class="code-block">
                                <div class="code-header">
                                    <span>Node.js Backend Example</span>
                                    <button class="btn-copy" onclick="copyCode('backendNode')">
                                        <i class="fas fa-copy"></i>
                                    </button>
                                </div>
                                <pre id="backendNode"><code class="language-javascript">const express = require('express');
const axios = require('axios');

class KeyAuthMiddleware {
    constructor(apiUrl, secret) {
        this.apiUrl = apiUrl;
        this.secret = secret;
    }

    async validateKey(req, res, next) {
        const { license_key, hwid } = req.body;
        
        if (!license_key) {
            return res.status(400).json({ error: 'License key is required' });
        }

        try {
            const response = await axios.post(this.apiUrl, {
                key: license_key,
                secret: this.secret,
                hwid: hwid
            });

            if (response.data.valid) {
                req.licenseData = response.data;
                next();
            } else {
                res.status(403).json({ error: response.data.message });
            }
        } catch (error) {
            console.error('Key validation error:', error);
            res.status(500).json({ error: 'License server unavailable' });
        }
    }
}

// Express middleware usage
const authMiddleware = new KeyAuthMiddleware('<?= htmlspecialchars($apiUrl) ?>', '<?= htmlspecialchars($appSecret) ?>');
app.post('/api/feature', authMiddleware.validateKey, (req, res) => {
    res.json({ success: true, data: 'Premium feature accessed' });
});</code></pre>
                            </div>
                        </div>
                    </div>
                </section>

                <!-- Desktop Integration -->
                <section id="desktop-integration" class="api-section">
                    <div class="section-header">
                        <h2><i class="fas fa-desktop"></i> Desktop Applications</h2>
                        <p>Integrate KeyAuth into desktop applications</p>
                    </div>
                    
                    <div class="integration-tabs">
                        <div class="tab-buttons">
                            <button class="tab-btn active" onclick="openIntegrationTab(event, 'csharp-desktop')">C#/.NET</button>
                            <button class="tab-btn" onclick="openIntegrationTab(event, 'python-desktop')">Python</button>
                            <button class="tab-btn" onclick="openIntegrationTab(event, 'cpp-desktop')">C++</button>
                        </div>
                        
                        <div id="csharp-desktop" class="tab-content active">
                            <div class="code-block">
                                <div class="code-header">
                                    <span>C# WPF/Windows Forms</span>
                                    <button class="btn-copy" onclick="copyCode('csharpDesktop')">
                                        <i class="fas fa-copy"></i>
                                    </button>
                                </div>
                                <pre id="csharpDesktop"><code class="language-csharp">using System;
using System.Net.Http;
using System.Windows.Forms;
using System.Security.Cryptography;
using System.Text;

public class KeyAuthDesktop
{
    private readonly string _apiUrl = "<?= htmlspecialchars($apiUrl) ?>";
    private readonly string _secret = "<?= htmlspecialchars($appSecret) ?>";
    private readonly HttpClient _httpClient;

    public KeyAuthDesktop()
    {
        _httpClient = new HttpClient();
        _httpClient.Timeout = TimeSpan.FromSeconds(30);
    }

    public async Task&lt;bool&gt; ValidateLicense(string licenseKey)
    {
        try
        {
            var hwid = GenerateHWID();
            var values = new Dictionary&lt;string, string&gt;
            {
                { "key", licenseKey },
                { "secret", _secret },
                { "hwid", hwid }
            };

            var content = new FormUrlEncodedContent(values);
            var response = await _httpClient.PostAsync(_apiUrl, content);
            var responseContent = await response.Content.ReadAsStringAsync();

            if (response.IsSuccessStatusCode)
            {
                var result = Newtonsoft.Json.JsonConvert.DeserializeObject&lt;dynamic&gt;(responseContent);
                return result.valid == true;
            }
            
            return false;
        }
        catch (Exception ex)
        {
            MessageBox.Show($"License validation failed: {ex.Message}", "Error", 
                MessageBoxButtons.OK, MessageBoxIcon.Error);
            return false;
        }
    }

    private string GenerateHWID()
    {
        using (var sha256 = SHA256.Create())
        {
            var hwid = $"{Environment.MachineName}{Environment.UserName}{Environment.OSVersion}";
            var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(hwid));
            return Convert.ToBase64String(hash);
        }
    }
}

// Usage in Form
private async void btnValidate_Click(object sender, EventArgs e)
{
    var auth = new KeyAuthDesktop();
    bool isValid = await auth.ValidateLicense(txtLicenseKey.Text);
    
    if (isValid)
    {
        // Grant access to application
        this.Hide();
        new MainForm().Show();
    }
    else
    {
        MessageBox.Show("Invalid license key", "Validation Failed", 
            MessageBoxButtons.OK, MessageBoxIcon.Warning);
    }
}</code></pre>
                            </div>
                        </div>
                        
                        <div id="python-desktop" class="tab-content">
                            <div class="code-block">
                                <div class="code-header">
                                    <span>Python Tkinter/PyQt</span>
                                    <button class="btn-copy" onclick="copyCode('pythonDesktop')">
                                        <i class="fas fa-copy"></i>
                                    </button>
                                </div>
                                <pre id="pythonDesktop"><code class="language-python">import tkinter as tk
from tkinter import messagebox
import requests
import hashlib
import uuid

class KeyAuthDesktop:
    def __init__(self):
        self.api_url = "<?= htmlspecialchars($apiUrl) ?>"
        self.secret = "<?= htmlspecialchars($appSecret) ?>"
    
    def validate_license(self, license_key):
        try:
            hwid = self.generate_hwid()
            data = {
                'key': license_key,
                'secret': self.secret,
                'hwid': hwid
            }
            
            response = requests.post(self.api_url, data=data, timeout=30)
            result = response.json()
            
            return result.get('valid', False)
            
        except Exception as e:
            messagebox.showerror("Error", f"License validation failed: {str(e)}")
            return False
    
    def generate_hwid(self):
        # Generate unique hardware ID
        system_info = f"{uuid.getnode()}"
        return hashlib.sha256(system_info.encode()).hexdigest()

class LicenseWindow(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("License Validation")
        self.geometry("400x200")
        self.auth = KeyAuthDesktop()
        self.create_widgets()
    
    def create_widgets(self):
        tk.Label(self, text="Enter License Key:").pack(pady=10)
        
        self.license_entry = tk.Entry(self, width=40, font=("Arial", 12))
        self.license_entry.pack(pady=5)
        
        tk.Button(self, text="Validate", command=self.validate_license, 
                 bg="green", fg="white", font=("Arial", 12)).pack(pady=20)
    
    def validate_license(self):
        license_key = self.license_entry.get().strip()
        if not license_key:
            messagebox.showwarning("Warning", "Please enter a license key")
            return
        
        if self.auth.validate_license(license_key):
            messagebox.showinfo("Success", "License validated successfully!")
            # Proceed to main application
            self.destroy()
            MainApplication()
        else:
            messagebox.showerror("Error", "Invalid license key")

if __name__ == "__main__":
    app = LicenseWindow()
    app.mainloop()</code></pre>
                            </div>
                        </div>
                    </div>
                </section>

                <!-- Mobile Integration -->
                <section id="mobile-integration" class="api-section">
                    <div class="section-header">
                        <h2><i class="fas fa-mobile-alt"></i> Mobile Applications</h2>
                        <p>Integrate KeyAuth into iOS and Android applications</p>
                    </div>
                    
                    <div class="integration-tabs">
                        <div class="tab-buttons">
                            <button class="tab-btn active" onclick="openIntegrationTab(event, 'swift-tab')">Swift</button>
                            <button class="tab-btn" onclick="openIntegrationTab(event, 'kotlin-tab')">Kotlin</button>
                            <button class="tab-btn" onclick="openIntegrationTab(event, 'react-native-tab')">React Native</button>
                        </div>
                        
                        <div id="swift-tab" class="tab-content active">
                            <div class="code-block">
                                <div class="code-header">
                                    <span>Swift for iOS</span>
                                    <button class="btn-copy" onclick="copyCode('swiftCode')">
                                        <i class="fas fa-copy"></i>
                                    </button>
                                </div>
                                <pre id="swiftCode"><code class="language-swift">import UIKit
import Foundation

class KeyAuthService {
    private let apiUrl = "<?= htmlspecialchars($apiUrl) ?>"
    private let secret = "<?= htmlspecialchars($appSecret) ?>"
    
    func validateLicense(key: String, completion: @escaping (Bool, String?) -> Void) {
        guard let url = URL(string: apiUrl) else {
            completion(false, "Invalid API URL")
            return
        }
        
        let hwid = generateHWID()
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        
        let body = "key=\(key)&secret=\(secret)&hwid=\(hwid)"
        request.httpBody = body.data(using: .utf8)
        
        let task = URLSession.shared.dataTask(with: request) { data, response, error in
            if let error = error {
                DispatchQueue.main.async {
                    completion(false, "Network error: \(error.localizedDescription)")
                }
                return
            }
            
            guard let data = data else {
                DispatchQueue.main.async {
                    completion(false, "No data received")
                }
                return
            }
            
            do {
                if let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] {
                    let isValid = json["valid"] as? Bool ?? false
                    let message = json["message"] as? String
                    
                    DispatchQueue.main.async {
                        if isValid {
                            // Store license info in Keychain
                            self.saveLicenseInfo(key: key)
                        }
                        completion(isValid, message)
                    }
                }
            } catch {
                DispatchQueue.main.async {
                    completion(false, "JSON parsing error")
                }
            }
        }
        
        task.resume()
    }
    
    private func generateHWID() -> String {
        let device = UIDevice.current
        let hwid = "\(device.name)-\(device.systemName)-\(device.systemVersion)"
        return hwid.data(using: .utf8)?.base64EncodedString() ?? "default-hwid"
    }
    
    private func saveLicenseInfo(key: String) {
        // Save to Keychain for secure storage
        KeychainHelper.save(key: "license_key", data: key)
    }
}

// Usage in ViewController
class LicenseViewController: UIViewController {
    @IBOutlet weak var licenseTextField: UITextField!
    @IBOutlet weak var validateButton: UIButton!
    
    let authService = KeyAuthService()
    
    @IBAction func validateButtonTapped(_ sender: UIButton) {
        guard let licenseKey = licenseTextField.text, !licenseKey.isEmpty else {
            showAlert(title: "Error", message: "Please enter a license key")
            return
        }
        
        validateButton.isEnabled = false
        validateButton.setTitle("Validating...", for: .normal)
        
        authService.validateLicense(key: licenseKey) { [weak self] isValid, message in
            DispatchQueue.main.async {
                self?.validateButton.isEnabled = true
                self?.validateButton.setTitle("Validate", for: .normal)
                
                if isValid {
                    self?.showAlert(title: "Success", message: "License validated successfully!") {
                        self?.proceedToMainApp()
                    }
                } else {
                    self?.showAlert(title: "Validation Failed", message: message ?? "Invalid license key")
                }
            }
        }
    }
    
    private func proceedToMainApp() {
        // Navigate to main application
        let mainStoryboard = UIStoryboard(name: "Main", bundle: nil)
        if let mainVC = mainStoryboard.instantiateInitialViewController() {
            UIApplication.shared.windows.first?.rootViewController = mainVC
        }
    }
    
    private func showAlert(title: String, message: String, completion: (() -> Void)? = nil) {
        let alert = UIAlertController(title: title, message: message, preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "OK", style: .default) { _ in
            completion?()
        })
        present(alert, animated: true)
    }
}</code></pre>
                            </div>
                        </div>
                        
                        <div id="kotlin-tab" class="tab-content">
                            <div class="code-block">
                                <div class="code-header">
                                    <span>Kotlin for Android</span>
                                    <button class="btn-copy" onclick="copyCode('kotlinCode')">
                                        <i class="fas fa-copy"></i>
                                    </button>
                                </div>
                                <pre id="kotlinCode"><code class="language-kotlin">import android.content.Context
import android.os.AsyncTask
import android.widget.Toast
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.io.IOException
import java.util.*

class KeyAuthManager(private val context: Context) {
    private val apiUrl = "<?= htmlspecialchars($apiUrl) ?>"
    private val secret = "<?= htmlspecialchars($appSecret) ?>"
    private val client = OkHttpClient()
    
    interface ValidationCallback {
        fun onSuccess(valid: Boolean, message: String?)
        fun onError(error: String)
    }
    
    fun validateLicense(licenseKey: String, callback: ValidationCallback) {
        ValidationTask(callback).execute(licenseKey)
    }
    
    private inner class ValidationTask(private val callback: ValidationCallback) : 
        AsyncTask<String, Void, Pair<Boolean, String?>>() {
        
        override fun doInBackground(vararg params: String): Pair<Boolean, String?> {
            val licenseKey = params[0]
            val hwid = generateHWID()
            
            val formBody = FormBody.Builder()
                .add("key", licenseKey)
                .add("secret", secret)
                .add("hwid", hwid)
                .build()
            
            val request = Request.Builder()
                .url(apiUrl)
                .post(formBody)
                .build()
            
            return try {
                client.newCall(request).execute().use { response ->
                    if (!response.isSuccessful) {
                        return Pair(false, "HTTP error: ${response.code}")
                    }
                    
                    val responseBody = response.body?.string()
                    val json = JSONObject(responseBody)
                    val isValid = json.optBoolean("valid", false)
                    val message = json.optString("message", null)
                    
                    if (isValid) {
                        saveLicenseInfo(licenseKey)
                    }
                    
                    Pair(isValid, message)
                }
            } catch (e: IOException) {
                Pair(false, "Network error: ${e.message}")
            } catch (e: Exception) {
                Pair(false, "Validation error: ${e.message}")
            }
        }
        
        override fun onPostExecute(result: Pair<Boolean, String?>) {
            if (result.first) {
                callback.onSuccess(true, result.second)
            } else {
                callback.onError(result.second ?: "Unknown error")
            }
        }
    }
    
    private fun generateHWID(): String {
        val deviceId = android.provider.Settings.Secure.getString(
            context.contentResolver,
            android.provider.Settings.Secure.ANDROID_ID
        )
        return Base64.getEncoder().encodeToString(deviceId.toByteArray())
    }
    
    private fun saveLicenseInfo(licenseKey: String) {
        val prefs = context.getSharedPreferences("keyauth", Context.MODE_PRIVATE)
        prefs.edit().putString("license_key", licenseKey).apply()
    }
}

// Usage in Activity
class LicenseActivity : AppCompatActivity() {
    private lateinit var authManager: KeyAuthManager
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_license)
        
        authManager = KeyAuthManager(this)
        
        validateButton.setOnClickListener {
            val licenseKey = licenseEditText.text.toString().trim()
            if (licenseKey.isEmpty()) {
                Toast.makeText(this, "Please enter a license key", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            
            validateButton.isEnabled = false
            validateButton.text = "Validating..."
            
            authManager.validateLicense(licenseKey, object : KeyAuthManager.ValidationCallback {
                override fun onSuccess(valid: Boolean, message: String?) {
                    runOnUiThread {
                        validateButton.isEnabled = true
                        validateButton.text = "Validate"
                        
                        if (valid) {
                            Toast.makeText(this@LicenseActivity, 
                                "License validated successfully!", Toast.LENGTH_LONG).show()
                            proceedToMainApp()
                        } else {
                            Toast.makeText(this@LicenseActivity, 
                                message ?: "Invalid license key", Toast.LENGTH_LONG).show()
                        }
                    }
                }
                
                override fun onError(error: String) {
                    runOnUiThread {
                        validateButton.isEnabled = true
                        validateButton.text = "Validate"
                        Toast.makeText(this@LicenseActivity, error, Toast.LENGTH_LONG).show()
                    }
                }
            })
        }
    }
    
    private fun proceedToMainApp() {
        val intent = Intent(this, MainActivity::class.java)
        startActivity(intent)
        finish()
    }
}</code></pre>
                            </div>
                        </div>
                    </div>
                </section>

                <!-- Objective-C Integration -->
                <section id="objective-c" class="api-section">
                    <div class="section-header">
                        <h2><i class="fab fa-apple"></i> Objective-C Integration</h2>
                        <p>Complete Objective-C implementation for macOS and iOS applications</p>
                    </div>
                    
                    <div class="code-block">
                        <div class="code-header">
                            <span>KeyAuthManager.h</span>
                            <button class="btn-copy" onclick="copyCode('objcHeader')">
                                <i class="fas fa-copy"></i>
                            </button>
                        </div>
                        <pre id="objcHeader"><code class="language-objectivec">#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef void (^KeyAuthValidationCompletion)(BOOL isValid, NSString * _Nullable message, NSError * _Nullable error);

@interface KeyAuthManager : NSObject

@property (nonatomic, strong, readonly) NSString *apiUrl;
@property (nonatomic, strong, readonly) NSString *secret;

- (instancetype)initWithSecret:(NSString *)secret;
- (void)validateLicense:(NSString *)licenseKey 
             completion:(KeyAuthValidationCompletion)completion;
- (void)validateLicense:(NSString *)licenseKey 
                   hwid:(NSString * _Nullable)hwid
             completion:(KeyAuthValidationCompletion)completion;

// Utility methods
- (NSString *)generateHWID;
- (void)saveLicenseInfo:(NSString *)licenseKey;
- (BOOL)hasValidLicense;
- (NSString * _Nullable)getStoredLicenseKey;

@end

NS_ASSUME_NONNULL_END</code></pre>
                    </div>
                    
                    <div class="code-block">
                        <div class="code-header">
                            <span>KeyAuthManager.m</span>
                            <button class="btn-copy" onclick="copyCode('objcImplementation')">
                                <i class="fas fa-copy"></i>
                            </button>
                        </div>
                        <pre id="objcImplementation"><code class="language-objectivec">#import "KeyAuthManager.h"
#import <CommonCrypto/CommonCrypto.h>
#import <Security/Security.h>

@implementation KeyAuthManager

- (instancetype)initWithSecret:(NSString *)secret {
    self = [super init];
    if (self) {
        _apiUrl = @"<?= htmlspecialchars($apiUrl) ?>";
        _secret = [secret copy];
    }
    return self;
}

- (instancetype)init {
    return [self initWithSecret:@"<?= htmlspecialchars($appSecret) ?>"];
}

- (void)validateLicense:(NSString *)licenseKey completion:(KeyAuthValidationCompletion)completion {
    NSString *hwid = [self generateHWID];
    [self validateLicense:licenseKey hwid:hwid completion:completion];
}

- (void)validateLicense:(NSString *)licenseKey 
                   hwid:(NSString *)hwid
             completion:(KeyAuthValidationCompletion)completion {
    
    if (!licenseKey || licenseKey.length == 0) {
        if (completion) {
            completion(NO, @"License key is required", nil);
        }
        return;
    }
    
    NSURL *url = [NSURL URLWithString:self.apiUrl];
    if (!url) {
        if (completion) {
            NSError *error = [NSError errorWithDomain:@"KeyAuthError" 
                                                 code:1001 
                                             userInfo:@{NSLocalizedDescriptionKey: @"Invalid API URL"}];
            completion(NO, nil, error);
        }
        return;
    }
    
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    request.HTTPMethod = @"POST";
    [request setValue:@"application/x-www-form-urlencoded" forHTTPHeaderField:@"Content-Type"];
    
    NSString *bodyString = [NSString stringWithFormat:@"key=%@&secret=%@&hwid=%@",
                           [self urlEncode:licenseKey],
                           [self urlEncode:self.secret],
                           [self urlEncode:hwid]];
    
    request.HTTPBody = [bodyString dataUsingEncoding:NSUTF8StringEncoding];
    
    NSURLSessionConfiguration *config = [NSURLSessionConfiguration defaultSessionConfiguration];
    config.timeoutIntervalForRequest = 30.0;
    NSURLSession *session = [NSURLSession sessionWithConfiguration:config];
    
    NSURLSessionDataTask *task = [session dataTaskWithRequest:request 
                                            completionHandler:^(NSData * _Nullable data, 
                                                                NSURLResponse * _Nullable response, 
                                                                NSError * _Nullable error) {
        
        if (error) {
            dispatch_async(dispatch_get_main_queue(), ^{
                if (completion) {
                    completion(NO, nil, error);
                }
            });
            return;
        }
        
        NSHTTPURLResponse *httpResponse = (NSHTTPURLResponse *)response;
        if (httpResponse.statusCode != 200) {
            dispatch_async(dispatch_get_main_queue(), ^{
                NSString *errorMsg = [NSString stringWithFormat:@"HTTP error: %ld", (long)httpResponse.statusCode];
                NSError *httpError = [NSError errorWithDomain:@"KeyAuthError" 
                                                         code:httpResponse.statusCode 
                                                     userInfo:@{NSLocalizedDescriptionKey: errorMsg}];
                if (completion) {
                    completion(NO, nil, httpError);
                }
            });
            return;
        }
        
        NSError *jsonError = nil;
        NSDictionary *jsonResponse = [NSJSONSerialization JSONObjectWithData:data options:0 error:&jsonError];
        
        if (jsonError) {
            dispatch_async(dispatch_get_main_queue(), ^{
                if (completion) {
                    completion(NO, nil, jsonError);
                }
            });
            return;
        }
        
        BOOL isValid = [jsonResponse[@"valid"] boolValue];
        NSString *message = jsonResponse[@"message"];
        
        if (isValid) {
            [self saveLicenseInfo:licenseKey];
        }
        
        dispatch_async(dispatch_get_main_queue(), ^{
            if (completion) {
                completion(isValid, message, nil);
            }
        });
    }];
    
    [task resume];
}

#pragma mark - Utility Methods

- (NSString *)generateHWID {
    NSString *model = [[UIDevice currentDevice] model];
    NSString *systemVersion = [[UIDevice currentDevice] systemVersion];
    NSString *bundleIdentifier = [[NSBundle mainBundle] bundleIdentifier];
    
    NSString *hwidString = [NSString stringWithFormat:@"%@%@%@", model, systemVersion, bundleIdentifier];
    NSData *hwidData = [hwidString dataUsingEncoding:NSUTF8StringEncoding];
    
    unsigned char hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(hwidData.bytes, (CC_LONG)hwidData.length, hash);
    
    NSMutableString *hashedString = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [hashedString appendFormat:@"%02x", hash[i]];
    }
    
    return [hashedString copy];
}

- (NSString *)urlEncode:(NSString *)string {
    NSCharacterSet *allowedCharacters = [NSCharacterSet URLQueryAllowedCharacterSet];
    return [string stringByAddingPercentEncodingWithAllowedCharacters:allowedCharacters];
}

- (void)saveLicenseInfo:(NSString *)licenseKey {
    [[NSUserDefaults standardUserDefaults] setObject:licenseKey forKey:@"keyauth_license_key"];
    [[NSUserDefaults standardUserDefaults] synchronize];
}

- (BOOL)hasValidLicense {
    return [self getStoredLicenseKey] != nil;
}

- (NSString *)getStoredLicenseKey {
    return [[NSUserDefaults standardUserDefaults] stringForKey:@"keyauth_license_key"];
}

@end</code></pre>
                    </div>
                    
                    <div class="code-block">
                        <div class="code-header">
                            <span>Usage in ViewController</span>
                            <button class="btn-copy" onclick="copyCode('objcUsage')">
                                <i class="fas fa-copy"></i>
                            </button>
                        </div>
                        <pre id="objcUsage"><code class="language-objectivec">#import "ViewController.h"
#import "KeyAuthManager.h"

@interface ViewController ()

@property (weak, nonatomic) IBOutlet UITextField *licenseTextField;
@property (weak, nonatomic) IBOutlet UIButton *validateButton;
@property (strong, nonatomic) KeyAuthManager *authManager;

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.authManager = [[KeyAuthManager alloc] init];
    
    // Check for existing license
    if ([self.authManager hasValidLicense]) {
        [self proceedToMainApp];
    }
}

- (IBAction)validateButtonTapped:(id)sender {
    NSString *licenseKey = [self.licenseTextField.text stringByTrimmingCharactersInSet:
                           [NSCharacterSet whitespaceAndNewlineCharacterSet]];
    
    if (licenseKey.length == 0) {
        [self showAlertWithTitle:@"Error" message:@"Please enter a license key"];
        return;
    }
    
    [self.validateButton setEnabled:NO];
    [self.validateButton setTitle:@"Validating..." forState:UIControlStateNormal];
    
    __weak typeof(self) weakSelf = self;
    [self.authManager validateLicense:licenseKey completion:^(BOOL isValid, NSString *message, NSError *error) {
        dispatch_async(dispatch_get_main_queue(), ^{
            [weakSelf.validateButton setEnabled:YES];
            [weakSelf.validateButton setTitle:@"Validate" forState:UIControlStateNormal];
            
            if (error) {
                [weakSelf showAlertWithTitle:@"Error" 
                                    message:[NSString stringWithFormat:@"Validation failed: %@", error.localizedDescription]];
            } else if (isValid) {
                [weakSelf showAlertWithTitle:@"Success" message:@"License validated successfully!" completion:^{
                    [weakSelf proceedToMainApp];
                }];
            } else {
                [weakSelf showAlertWithTitle:@"Validation Failed" 
                                    message:message ?: @"Invalid license key"];
            }
        });
    }];
}

- (void)proceedToMainApp {
    UIStoryboard *mainStoryboard = [UIStoryboard storyboardWithName:@"Main" bundle:nil];
    UIViewController *mainVC = [mainStoryboard instantiateInitialViewController];
    
    if (mainVC) {
        [UIApplication sharedApplication].windows.firstObject.rootViewController = mainVC;
    }
}

- (void)showAlertWithTitle:(NSString *)title message:(NSString *)message {
    [self showAlertWithTitle:title message:message completion:nil];
}

- (void)showAlertWithTitle:(NSString *)title message:(NSString *)message completion:(void (^)(void))completion {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:title
                                                                   message:message
                                                            preferredStyle:UIAlertControllerStyleAlert];
    
    UIAlertAction *okAction = [UIAlertAction actionWithTitle:@"OK"
                                                       style:UIAlertActionStyleDefault
                                                     handler:^(UIAlertAction * _Nonnull action) {
        if (completion) {
            completion();
        }
    }];
    
    [alert addAction:okAction];
    [self presentViewController:alert animated:YES completion:nil];
}

@end</code></pre>
                    </div>
                </section>

                <!-- More sections for other languages would follow the same pattern -->

                <!-- Error Handling -->
                <section id="error-handling" class="api-section">
                    <div class="section-header">
                        <h2><i class="fas fa-exclamation-triangle"></i> Error Handling</h2>
                        <p>Comprehensive guide for handling API errors</p>
                    </div>
                    
                    <div class="error-codes-grid">
                        <div class="error-card">
                            <div class="error-code">400</div>
                            <div class="error-info">
                                <h4>Bad Request</h4>
                                <p>Missing required parameters or invalid request format</p>
                                <code class="error-solution">Check request parameters and format</code>
                            </div>
                        </div>
                        
                        <div class="error-card">
                            <div class="error-code">401</div>
                            <div class="error-info">
                                <h4>Unauthorized</h4>
                                <p>Invalid application secret key</p>
                                <code class="error-solution">Verify your secret key configuration</code>
                            </div>
                        </div>
                        
                        <div class="error-card">
                            <div class="error-code">404</div>
                            <div class="error-info">
                                <h4>Key Not Found</h4>
                                <p>The provided license key does not exist</p>
                                <code class="error-solution">Check key spelling and existence</code>
                            </div>
                        </div>
                        
                        <div class="error-card">
                            <div class="error-code">410</div>
                            <div class="error-info">
                                <h4>Key Expired</h4>
                                <p>The license key has expired</p>
                                <code class="error-solution">Renew the license key</code>
                            </div>
                        </div>
                        
                        <div class="error-card">
                            <div class="error-code">423</div>
                            <div class="error-info">
                                <h4>Key Banned</h4>
                                <p>The license key has been banned</p>
                                <code class="error-solution">Contact support for assistance</code>
                            </div>
                        </div>
                        
                        <div class="error-card">
                            <div class="error-code">429</div>
                            <div class="error-info">
                                <h4>Rate Limit Exceeded</h4>
                                <p>Too many requests from your IP address</p>
                                <code class="error-solution">Wait before making more requests</code>
                            </div>
                        </div>
                    </div>
                </section>

                <!-- Security Best Practices -->
                <section id="security" class="api-section">
                    <div class="section-header">
                        <h2><i class="fas fa-user-shield"></i> Security Best Practices</h2>
                        <p>Ensure your implementation is secure and robust</p>
                    </div>
                    
                    <div class="security-grid">
                        <div class="security-card">
                            <i class="fas fa-lock"></i>
                            <h4>Secure Storage</h4>
                            <p>Store secret keys in environment variables or secure keychains, never in source code.</p>
                        </div>
                        
                        <div class="security-card">
                            <i class="fas fa-shield-alt"></i>
                            <h4>Input Validation</h4>
                            <p>Always validate license keys on the server-side to prevent client-side manipulation.</p>
                        </div>
                        
                        <div class="security-card">
                            <i class="fas fa-sync-alt"></i>
                            <h4>Regular Validation</h4>
                            <p>Implement periodic license checks to detect revoked or expired keys.</p>
                        </div>
                        
                        <div class="security-card">
                            <i class="fas fa-bug"></i>
                            <h4>Error Handling</h4>
                            <p>Implement proper error handling for network failures and API errors.</p>
                        </div>
                    </div>
                </section>
            </main>
        </div>
    </div>

    <!-- Test Modal -->
    <div id="testModal" class="modal" style="display: none;">
        <div class="modal-content">
            <div class="modal-header">
                <h3><i class="fas fa-bolt"></i> Test API Integration</h3>
                <button class="btn-close" onclick="closeModal()">&times;</button>
            </div>
            <div class="modal-body">
                <div class="form-group">
                    <label>License Key:</label>
                    <input type="text" id="testKey" placeholder="XXXX-XXXX-XXXX-XXXX" class="form-input">
                    <div class="form-hint">Use one of the sample keys or your own</div>
                </div>
                <div class="form-group">
                    <label>HWID (Optional):</label>
                    <input type="text" id="testHwid" placeholder="Hardware ID" class="form-input">
                    <div class="form-hint">Leave empty for auto-generation</div>
                </div>
                <div id="testResult" class="test-result"></div>
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" onclick="closeModal()">Cancel</button>
                <button class="btn btn-primary" onclick="verifyTestKey()">
                    <i class="fas fa-check"></i> Test Verification
                </button>
            </div>
        </div>
    </div>

    <script src="script.js"></script>
    <script>
    // Initialize syntax highlighting
    hljs.highlightAll();
    
    // API Page Specific Functions
    function copyText(text) {
        navigator.clipboard.writeText(text).then(() => {
            showNotification('Copied to clipboard!', 'success');
        }).catch(err => {
            console.error('Failed to copy: ', err);
            showNotification('Failed to copy to clipboard', 'error');
        });
    }

    function copyCode(elementId) {
        const element = document.getElementById(elementId);
        const text = element.textContent || element.innerText;
        copyText(text);
    }

    function openIntegrationTab(evt, tabName) {
        const tabcontent = document.querySelectorAll('.integration-tabs .tab-content');
        tabcontent.forEach(tab => tab.classList.remove('active'));

        const tablinks = document.querySelectorAll('.integration-tabs .tab-btn');
        tablinks.forEach(link => link.classList.remove('active'));

        document.getElementById(tabName).classList.add('active');
        evt.currentTarget.classList.add('active');
    }

    function scrollToSection(sectionId) {
        document.getElementById(sectionId).scrollIntoView({ 
            behavior: 'smooth' 
        });
    }

    // Smooth scrolling for navigation
    document.querySelectorAll('.nav-link').forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            const targetId = this.getAttribute('href').substring(1);
            document.getElementById(targetId).scrollIntoView({ 
                behavior: 'smooth' 
            });
            
            // Update active nav link
            document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
            this.classList.add('active');
        });
    });

    // Test verification functions
    function testVerification() {
        document.getElementById('testModal').style.display = 'flex';
        document.getElementById('testKey').focus();
        document.getElementById('testResult').style.display = 'none';
    }

    function closeModal() {
        document.getElementById('testModal').style.display = 'none';
        document.getElementById('testKey').value = '';
        document.getElementById('testHwid').value = '';
        document.getElementById('testResult').style.display = 'none';
    }

    async function verifyTestKey() {
        const testKey = document.getElementById('testKey').value.trim();
        const testHwid = document.getElementById('testHwid').value.trim();
        const testResult = document.getElementById('testResult');
        
        if (!testKey) {
            testResult.innerHTML = '<i class="fas fa-exclamation-triangle"></i> Please enter a license key';
            testResult.className = 'test-result error';
            testResult.style.display = 'block';
            return;
        }

        const verifyBtn = document.querySelector('#testModal .btn-primary');
        const originalText = verifyBtn.innerHTML;
        
        verifyBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Testing...';
        verifyBtn.disabled = true;

        try {
            const payload = {
                key: testKey,
                secret: '<?= htmlspecialchars($appSecret) ?>'
            };

            if (testHwid) {
                payload.hwid = testHwid;
            }

            const response = await fetch('<?= htmlspecialchars($apiUrl) ?>', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: new URLSearchParams(payload)
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

    // Mobile menu functionality
    function toggleMobileMenu() {
        document.querySelector('.api-sidebar').classList.toggle('active');
    }

    // Close mobile menu when clicking outside
    document.addEventListener('click', function(event) {
        const sidebar = document.querySelector('.api-sidebar');
        const toggle = document.querySelector('.mobile-menu-toggle');
        if (!sidebar.contains(event.target) && !toggle.contains(event.target)) {
            sidebar.classList.remove('active');
        }
    });

    // Initialize
    document.addEventListener('DOMContentLoaded', function() {
        // Set up intersection observer for active nav links
        const sections = document.querySelectorAll('.api-section');
        const navLinks = document.querySelectorAll('.nav-link');
        
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    navLinks.forEach(link => link.classList.remove('active'));
                    const activeLink = document.querySelector(`.nav-link[href="#${entry.target.id}"]`);
                    if (activeLink) {
                        activeLink.classList.add('active');
                    }
                }
            });
        }, { threshold: 0.5 });

        sections.forEach(section => observer.observe(section));
    });
    </script>

    <style>
    /* Additional styles for API documentation */
    .api-layout {
        display: grid;
        grid-template-columns: 280px 1fr;
        gap: 30px;
        margin-top: 30px;
    }

    .api-sidebar {
        position: sticky;
        top: 20px;
        height: calc(100vh - 100px);
        overflow-y: auto;
        background: var(--bg-card);
        border: 1px solid var(--border-color);
        border-radius: 12px;
        padding: 20px;
    }

    .sidebar-section {
        margin-bottom: 25px;
    }

    .sidebar-section h4 {
        color: var(--text-primary);
        margin-bottom: 12px;
        font-size: 0.9rem;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }

    .sidebar-section ul {
        list-style: none;
        padding: 0;
        margin: 0;
    }

    .sidebar-section li {
        margin-bottom: 8px;
    }

    .nav-link {
        display: block;
        padding: 8px 12px;
        color: var(--text-secondary);
        text-decoration: none;
        border-radius: 6px;
        transition: all 0.3s ease;
        font-size: 0.9rem;
    }

    .nav-link:hover,
    .nav-link.active {
        background: var(--accent-red);
        color: white;
    }

    .api-main-content {
        min-height: 100vh;
    }

    .api-section {
        margin-bottom: 50px;
        padding: 30px;
        background: var(--bg-card);
        border: 1px solid var(--border-color);
        border-radius: 12px;
    }

    .quick-steps {
        display: flex;
        flex-direction: column;
        gap: 30px;
    }

    .step {
        display: flex;
        gap: 20px;
        align-items: flex-start;
    }

    .step-number {
        width: 40px;
        height: 40px;
        background: var(--accent-red);
        color: white;
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        font-weight: bold;
        flex-shrink: 0;
    }

    .step-content {
        flex: 1;
    }

    .credentials-grid {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 15px;
        margin-top: 15px;
    }

    .credential-item label {
        display: block;
        margin-bottom: 5px;
        color: var(--text-secondary);
        font-size: 0.9rem;
    }

    .credential-value {
        display: flex;
        align-items: center;
        gap: 10px;
        background: var(--bg-primary);
        padding: 10px 15px;
        border-radius: 8px;
        border: 1px solid var(--border-color);
    }

    .credential-value code {
        flex: 1;
        font-size: 0.85rem;
    }

    .integration-badges {
        display: flex;
        flex-wrap: wrap;
        gap: 10px;
        margin-top: 15px;
    }

    .integration-badge {
        background: var(--bg-secondary);
        padding: 8px 16px;
        border-radius: 20px;
        font-size: 0.85rem;
        cursor: pointer;
        transition: all 0.3s ease;
        border: 1px solid var(--border-color);
    }

    .integration-badge:hover {
        background: var(--accent-red);
        color: white;
        border-color: var(--accent-red);
    }

    .test-keys {
        display: flex;
        flex-direction: column;
        gap: 10px;
        margin-top: 15px;
    }

    .test-key-item {
        display: flex;
        align-items: center;
        gap: 10px;
        background: var(--bg-primary);
        padding: 10px 15px;
        border-radius: 8px;
        border: 1px solid var(--border-color);
    }

    .key-type {
        background: var(--accent-red);
        color: white;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 0.8rem;
        font-weight: 500;
    }

    .test-key-item code {
        flex: 1;
        font-size: 0.85rem;
    }

    .auth-info {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 20px;
        margin-bottom: 25px;
    }

    .info-card {
        text-align: center;
        padding: 25px;
        background: var(--bg-primary);
        border: 1px solid var(--border-color);
        border-radius: 10px;
    }

    .info-card i {
        font-size: 2.5rem;
        color: var(--accent-red);
        margin-bottom: 15px;
    }

    .info-card h4 {
        margin-bottom: 10px;
        color: var(--text-primary);
    }

    .info-card p {
        color: var(--text-secondary);
        font-size: 0.9rem;
        line-height: 1.5;
    }

    .endpoints-grid {
        display: grid;
        grid-template-columns: 1fr;
        gap: 15px;
    }

    .endpoint-card {
        display: flex;
        align-items: center;
        gap: 15px;
        padding: 20px;
        background: var(--bg-primary);
        border: 1px solid var(--border-color);
        border-radius: 10px;
    }

    .endpoint-method {
        padding: 8px 16px;
        border-radius: 6px;
        font-weight: bold;
        font-size: 0.85rem;
        text-transform: uppercase;
    }

    .endpoint-method.post {
        background: #10b981;
        color: white;
    }

    .endpoint-method.get {
        background: #3b82f6;
        color: white;
    }

    .endpoint-info {
        flex: 1;
    }

    .endpoint-info h4 {
        margin-bottom: 5px;
        color: var(--text-primary);
    }

    .endpoint-info code {
        color: var(--accent-red);
        font-size: 0.9rem;
    }

    .endpoint-info p {
        margin-top: 5px;
        color: var(--text-secondary);
        font-size: 0.9rem;
    }

    .integration-tabs {
        margin-top: 20px;
    }

    .integration-tabs .tab-buttons {
        display: flex;
        gap: 5px;
        margin-bottom: 20px;
        flex-wrap: wrap;
    }

    .integration-tabs .tab-btn {
        background: var(--bg-secondary);
        border: 1px solid var(--border-color);
        padding: 10px 20px;
        border-radius: 6px;
        color: var(--text-secondary);
        cursor: pointer;
        transition: all 0.3s ease;
    }

    .integration-tabs .tab-btn.active {
        background: var(--accent-red);
        color: white;
        border-color: var(--accent-red);
    }

    .integration-tabs .tab-content {
        display: none;
    }

    .integration-tabs .tab-content.active {
        display: block;
    }

    .error-codes-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
        gap: 20px;
    }

    .error-card {
        display: flex;
        gap: 15px;
        padding: 20px;
        background: var(--bg-primary);
        border: 1px solid var(--border-color);
        border-radius: 10px;
    }

    .error-code {
        width: 60px;
        height: 60px;
        background: var(--error-red);
        color: white;
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        font-weight: bold;
        font-size: 1.2rem;
        flex-shrink: 0;
    }

    .error-info {
        flex: 1;
    }

    .error-info h4 {
        margin-bottom: 5px;
        color: var(--text-primary);
    }

    .error-info p {
        color: var(--text-secondary);
        font-size: 0.9rem;
        margin-bottom: 10px;
    }

    .error-solution {
        background: var(--bg-secondary);
        padding: 8px 12px;
        border-radius: 6px;
        font-size: 0.85rem;
        color: var(--text-primary);
    }

    .security-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
        gap: 20px;
    }

    .security-card {
        text-align: center;
        padding: 25px;
        background: var(--bg-primary);
        border: 1px solid var(--border-color);
        border-radius: 10px;
    }

    .security-card i {
        font-size: 2rem;
        color: var(--accent-red);
        margin-bottom: 15px;
    }

    .security-card h4 {
        margin-bottom: 10px;
        color: var(--text-primary);
    }

    .security-card p {
        color: var(--text-secondary);
        font-size: 0.9rem;
        line-height: 1.5;
    }

    /* Mobile responsiveness */
    @media (max-width: 1024px) {
        .api-layout {
            grid-template-columns: 1fr;
        }

        .api-sidebar {
            position: static;
            height: auto;
            display: none;
        }

        .api-sidebar.active {
            display: block;
        }

        .credentials-grid {
            grid-template-columns: 1fr;
        }

        .auth-info {
            grid-template-columns: 1fr;
        }
    }

    @media (max-width: 768px) {
        .api-section {
            padding: 20px;
        }

        .step {
            flex-direction: column;
            text-align: center;
        }

        .step-number {
            align-self: center;
        }

        .integration-tabs .tab-buttons {
            flex-direction: column;
        }

        .error-codes-grid {
            grid-template-columns: 1fr;
        }

        .security-grid {
            grid-template-columns: 1fr;
        }
    }

    /* Syntax highlighting overrides */
    .hljs {
        background: var(--bg-primary) !important;
        border-radius: 0 0 8px 8px;
    }

    .code-block pre {
        margin: 0;
        border-radius: 0 0 8px 8px;
    }

    .code-block .code-header {
        background: var(--bg-secondary);
        padding: 12px 20px;
        border-bottom: 1px solid var(--border-color);
        border-radius: 8px 8px 0 0;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }

    .code-block .code-header span {
        color: var(--text-primary);
        font-weight: 500;
    }
    </style>
</body>
</html>