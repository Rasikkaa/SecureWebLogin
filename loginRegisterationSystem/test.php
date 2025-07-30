<?php
require_once 'config/init.php';

echo "<h1>SecureAuth System Test</h1>";

// Test database connection
echo "<h2>Database Connection Test</h2>";
if ($conn->ping()) {
    echo "<p style='color: green;'>✅ Database connection successful</p>";
} else {
    echo "<p style='color: red;'>❌ Database connection failed</p>";
}

// Test security functions
echo "<h2>Security Functions Test</h2>";

// Test password validation
$test_password = "TestPassword123!";
$errors = validate_password($test_password);
if (empty($errors)) {
    echo "<p style='color: green;'>✅ Password validation working</p>";
} else {
    echo "<p style='color: red;'>❌ Password validation failed: " . implode(", ", $errors) . "</p>";
}

// Test email validation
$test_email = "test@example.com";
if (validate_email($test_email)) {
    echo "<p style='color: green;'>✅ Email validation working</p>";
} else {
    echo "<p style='color: red;'>❌ Email validation failed</p>";
}

// Test username validation
$test_username = "testuser123";
if (validate_username($test_username)) {
    echo "<p style='color: green;'>✅ Username validation working</p>";
} else {
    echo "<p style='color: red;'>❌ Username validation failed</p>";
}

// Test password hashing
$test_hash = hash_password($test_password);
if (verify_password($test_password, $test_hash)) {
    echo "<p style='color: green;'>✅ Password hashing and verification working</p>";
} else {
    echo "<p style='color: red;'>❌ Password hashing failed</p>";
}

// Test CSRF token generation
$csrf_token = generate_csrf_token();
if (strlen($csrf_token) === 64) {
    echo "<p style='color: green;'>✅ CSRF token generation working</p>";
} else {
    echo "<p style='color: red;'>❌ CSRF token generation failed</p>";
}

// Test session
echo "<h2>Session Test</h2>";
if (session_status() === PHP_SESSION_ACTIVE) {
    echo "<p style='color: green;'>✅ Session is active</p>";
} else {
    echo "<p style='color: red;'>❌ Session is not active</p>";
}

// Test database tables
echo "<h2>Database Tables Test</h2>";
$tables = ['users', 'user_sessions', 'login_logs', 'admin_users'];
foreach ($tables as $table) {
    $result = $conn->query("SHOW TABLES LIKE '$table'");
    if ($result->num_rows > 0) {
        echo "<p style='color: green;'>✅ Table '$table' exists</p>";
    } else {
        echo "<p style='color: red;'>❌ Table '$table' does not exist</p>";
    }
}

echo "<h2>System Status</h2>";
echo "<p><strong>PHP Version:</strong> " . phpversion() . "</p>";
echo "<p><strong>Session Status:</strong> " . session_status() . "</p>";
echo "<p><strong>Database:</strong> " . $conn->server_info . "</p>";

echo "<h2>Next Steps</h2>";
echo "<p>1. <a href='pages/login.php'>Go to User Login</a></p>";
echo "<p>2. <a href='admin/login.php'>Go to Admin Login</a></p>";
echo "<p>3. <a href='pages/register.php'>Go to Registration</a></p>";

echo "<h2>Default Admin Credentials</h2>";
echo "<p><strong>Username:</strong> admin</p>";
echo "<p><strong>Password:</strong> admin123</p>";
echo "<p><em>Remember to change the default password after first login!</em></p>";
?> 