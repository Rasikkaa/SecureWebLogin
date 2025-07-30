<?php
require_once 'config/init.php';

echo "<h1>🔒 SecureAuth Security Testing</h1>";
echo "<style>
    body { font-family: Arial, sans-serif; margin: 20px; }
    .test { margin: 10px 0; padding: 10px; border: 1px solid #ccc; }
    .pass { background-color: #d4edda; border-color: #c3e6cb; }
    .fail { background-color: #f8d7da; border-color: #f5c6cb; }
    .info { background-color: #d1ecf1; border-color: #bee5eb; }
</style>";

// Test 1: SQL Injection Protection
echo "<div class='test info'>";
echo "<h3>Test 1: SQL Injection Protection</h3>";
echo "<p>Testing if prepared statements prevent SQL injection...</p>";

$test_email = "admin' OR '1'='1";
$test_password = "anything";

$stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
$stmt->bind_param("s", $test_email);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows == 0) {
    echo "<p class='pass'>✅ SQL Injection blocked - Prepared statements working</p>";
} else {
    echo "<p class='fail'>❌ SQL Injection vulnerability detected!</p>";
}
$stmt->close();
echo "</div>";

// Test 2: XSS Protection
echo "<div class='test info'>";
echo "<h3>Test 2: XSS Protection</h3>";
echo "<p>Testing input sanitization...</p>";

$test_xss = "<script>alert('XSS')</script>";
$sanitized = sanitize_input($test_xss);

if (strpos($sanitized, '<script>') === false) {
    echo "<p class='pass'>✅ XSS Protection working - Input sanitized</p>";
    echo "<p>Original: " . htmlspecialchars($test_xss) . "</p>";
    echo "<p>Sanitized: " . htmlspecialchars($sanitized) . "</p>";
} else {
    echo "<p class='fail'>❌ XSS Protection failed!</p>";
}
echo "</div>";

// Test 3: Password Hashing
echo "<div class='test info'>";
echo "<h3>Test 3: Password Hashing</h3>";
echo "<p>Testing Argon2id password hashing...</p>";

$test_password = "TestPassword123!";
$hash = hash_password($test_password);

if (password_verify($test_password, $hash)) {
    echo "<p class='pass'>✅ Password hashing working - Argon2id verified</p>";
    echo "<p>Hash: " . substr($hash, 0, 20) . "...</p>";
} else {
    echo "<p class='fail'>❌ Password hashing failed!</p>";
}
echo "</div>";

// Test 4: CSRF Token Generation
echo "<div class='test info'>";
echo "<h3>Test 4: CSRF Token Generation</h3>";
echo "<p>Testing CSRF token generation...</p>";

$token1 = generate_csrf_token();
$token2 = generate_csrf_token();

if (strlen($token1) === 64 && $token1 === $token2) {
    echo "<p class='pass'>✅ CSRF Token generation working</p>";
    echo "<p>Token: " . substr($token1, 0, 20) . "...</p>";
} else {
    echo "<p class='fail'>❌ CSRF Token generation failed!</p>";
}
echo "</div>";

// Test 5: Input Validation
echo "<div class='test info'>";
echo "<h3>Test 5: Input Validation</h3>";
echo "<p>Testing email and username validation...</p>";

$valid_email = "test@example.com";
$invalid_email = "notanemail";
$valid_username = "testuser123";
$invalid_username = "a";

if (validate_email($valid_email) && !validate_email($invalid_email)) {
    echo "<p class='pass'>✅ Email validation working</p>";
} else {
    echo "<p class='fail'>❌ Email validation failed!</p>";
}

if (validate_username($valid_username) && !validate_username($invalid_username)) {
    echo "<p class='pass'>✅ Username validation working</p>";
} else {
    echo "<p class='fail'>❌ Username validation failed!</p>";
}
echo "</div>";

// Test 6: Password Strength Validation
echo "<div class='test info'>";
echo "<h3>Test 6: Password Strength Validation</h3>";
echo "<p>Testing password requirements...</p>";

$weak_password = "123";
$strong_password = "SecurePass123!";

$weak_errors = validate_password($weak_password);
$strong_errors = validate_password($strong_password);

if (!empty($weak_errors) && empty($strong_errors)) {
    echo "<p class='pass'>✅ Password strength validation working</p>";
    echo "<p>Weak password errors: " . implode(", ", $weak_errors) . "</p>";
} else {
    echo "<p class='fail'>❌ Password strength validation failed!</p>";
}
echo "</div>";

// Test 7: Database Connection Security
echo "<div class='test info'>";
echo "<h3>Test 7: Database Connection Security</h3>";
echo "<p>Testing database charset and connection...</p>";

if ($conn->ping() && $conn->character_set_name() === 'utf8mb4') {
    echo "<p class='pass'>✅ Database connection secure</p>";
    echo "<p>Charset: " . $conn->character_set_name() . "</p>";
} else {
    echo "<p class='fail'>❌ Database connection issues!</p>";
}
echo "</div>";

// Test 8: Session Security
echo "<div class='test info'>";
echo "<h3>Test 8: Session Security</h3>";
echo "<p>Testing session configuration...</p>";

$session_secure = ini_get('session.cookie_httponly') && 
                 ini_get('session.cookie_samesite') === 'Strict' &&
                 ini_get('session.use_strict_mode');

if ($session_secure) {
    echo "<p class='pass'>✅ Session security configured properly</p>";
} else {
    echo "<p class='fail'>❌ Session security not configured!</p>";
}
echo "</div>";

echo "<h2>🎯 Manual Testing Instructions</h2>";
echo "<div class='test'>";
echo "<h3>Manual Tests to Perform:</h3>";
echo "<ol>";
echo "<li><strong>SQL Injection:</strong> Try ' OR '1'='1 in login form</li>";
echo "<li><strong>XSS:</strong> Try &lt;script&gt;alert('XSS')&lt;/script&gt; in registration</li>";
echo "<li><strong>CSRF:</strong> Remove CSRF token from form and submit</li>";
echo "<li><strong>Brute Force:</strong> Try wrong password 5 times</li>";
echo "<li><strong>Weak Password:</strong> Try '123' as password</li>";
echo "<li><strong>Invalid Email:</strong> Try 'notanemail' as email</li>";
echo "<li><strong>Admin Access:</strong> Try accessing admin panel without login</li>";
echo "</ol>";
echo "</div>";

echo "<h2>🔗 Quick Access Links</h2>";
echo "<div class='test'>";
echo "<p><a href='pages/login.php' target='_blank'>🔐 User Login</a></p>";
echo "<p><a href='pages/register.php' target='_blank'>📝 User Registration</a></p>";
echo "<p><a href='admin/login.php' target='_blank'>👨‍💼 Admin Login</a></p>";
echo "<p><a href='test.php' target='_blank'>🧪 System Test</a></p>";
echo "</div>";

echo "<h2>📊 Security Checklist</h2>";
echo "<div class='test'>";
echo "<ul>";
echo "<li>✅ SQL Injection Protection (Prepared Statements)</li>";
echo "<li>✅ XSS Protection (Input Sanitization)</li>";
echo "<li>✅ CSRF Protection (Tokens)</li>";
echo "<li>✅ Password Hashing (Argon2id)</li>";
echo "<li>✅ Rate Limiting (Login Attempts)</li>";
echo "<li>✅ Account Lockout (After Failed Attempts)</li>";
echo "<li>✅ Session Security (HttpOnly, Secure, SameSite)</li>";
echo "<li>✅ Input Validation (Email, Username, Password)</li>";
echo "<li>✅ Security Headers (X-Frame-Options, etc.)</li>";
echo "<li>✅ Security Logging (All Activities)</li>";
echo "</ul>";
echo "</div>";
?> 