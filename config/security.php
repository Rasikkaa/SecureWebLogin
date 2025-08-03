<?php
// Security Configuration for SecureAuth
// This file contains security functions only
// Session settings are handled in init.php

// Security functions
function validate_password($password) {
    $errors = [];
    
    if (strlen($password) < PASSWORD_MIN_LENGTH) {
        $errors[] = "Password must be at least " . PASSWORD_MIN_LENGTH . " characters long";
    }
    
    if (!preg_match('/[A-Z]/', $password)) {
        $errors[] = "Password must contain at least one uppercase letter";
    }
    
    if (!preg_match('/[a-z]/', $password)) {
        $errors[] = "Password must contain at least one lowercase letter";
    }
    
    if (!preg_match('/[0-9]/', $password)) {
        $errors[] = "Password must contain at least one number";
    }
    
    if (!preg_match('/[^A-Za-z0-9]/', $password)) {
        $errors[] = "Password must contain at least one special character";
    }
    
    return $errors;
}

function validate_email($email) {
    return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
}

function validate_username($username) {
    // Username should be 3-20 characters, alphanumeric and underscore only
    return preg_match('/^[a-zA-Z0-9_]{3,20}$/', $username);
}

function generate_secure_token($length = 32) {
    return bin2hex(random_bytes($length));
}

function hash_password($password) {
    return password_hash($password, PASSWORD_ARGON2ID, [
        'memory_cost' => 65536,
        'time_cost' => 4,
        'threads' => 3
    ]);
}

function verify_password($password, $hash) {
    return password_verify($password, $hash);
}

function is_account_locked($user_id) {
    global $conn;
    $stmt = $conn->prepare("SELECT account_locked, account_locked_until FROM users WHERE id = ?");
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $result = $stmt->get_result();
    $user = $result->fetch_assoc();
    $stmt->close();
    
    if ($user['account_locked'] && $user['account_locked_until'] > date('Y-m-d H:i:s')) {
        return true;
    }
    
    return false;
}

function increment_login_attempts($email) {
    global $conn;
    $stmt = $conn->prepare("UPDATE users SET login_attempts = login_attempts + 1, last_login_attempt = NOW() WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $stmt->close();
}

function reset_login_attempts($email) {
    global $conn;
    $stmt = $conn->prepare("UPDATE users SET login_attempts = 0, account_locked = FALSE, account_locked_until = NULL WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $stmt->close();
}

function lock_account($email) {
    global $conn;
    $lock_until = date('Y-m-d H:i:s', time() + LOCKOUT_DURATION);
    $stmt = $conn->prepare("UPDATE users SET account_locked = TRUE, account_locked_until = ? WHERE email = ?");
    $stmt->bind_param("ss", $lock_until, $email);
    $stmt->execute();
    $stmt->close();
}

function create_secure_session($user_id, $username) {
    // Generate new session ID to prevent session fixation
    session_regenerate_id(true);
    
    $_SESSION['user_id'] = $user_id;
    $_SESSION['username'] = $username;
    $_SESSION['login_time'] = time();
    $_SESSION['ip_address'] = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
    
    // Store session in database
    global $conn;
    $session_id = session_id();
    $expires = date('Y-m-d H:i:s', time() + SESSION_TIMEOUT);
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
    
    $stmt = $conn->prepare("INSERT INTO user_sessions (user_id, session_id, ip_address, user_agent, expires_at) VALUES (?, ?, ?, ?, ?)");
    $stmt->bind_param("issss", $user_id, $session_id, $ip, $user_agent, $expires);
    $stmt->execute();
    $stmt->close();
}

function validate_session() {
    if (!isset($_SESSION['user_id']) || !isset($_SESSION['login_time'])) {
        return false;
    }
    
    // Check session timeout
    if (time() - $_SESSION['login_time'] > SESSION_TIMEOUT) {
        session_destroy();
        return false;
    }
    
    // Check IP address (optional security measure)
    if (isset($_SESSION['ip_address']) && $_SESSION['ip_address'] !== ($_SERVER['REMOTE_ADDR'] ?? 'unknown')) {
        session_destroy();
        return false;
    }
    
    // Update session time
    $_SESSION['login_time'] = time();
    
    return true;
}

function logout_user() {
    global $conn;
    
    // Remove session from database
    if (isset($_SESSION['user_id'])) {
        $session_id = session_id();
        $stmt = $conn->prepare("UPDATE user_sessions SET is_active = FALSE WHERE session_id = ?");
        $stmt->bind_param("s", $session_id);
        $stmt->execute();
        $stmt->close();
    }
    
    // Destroy session
    session_destroy();
}

// Rate limiting function
function check_rate_limit($ip_address, $action = 'login', $max_attempts = 5, $time_window = 300) {
    global $conn;
    
    $stmt = $conn->prepare("SELECT COUNT(*) as attempts FROM login_logs WHERE ip_address = ? AND attempt_time > DATE_SUB(NOW(), INTERVAL ? SECOND)");
    $stmt->bind_param("si", $ip_address, $time_window);
    $stmt->execute();
    $result = $stmt->get_result();
    $row = $result->fetch_assoc();
    $stmt->close();
    
    return $row['attempts'] < $max_attempts;
}

function create_secure_admin_session($admin_id, $username) {
    session_regenerate_id(true);
    $_SESSION['admin_id'] = $admin_id;
    $_SESSION['admin_username'] = $username;
    $_SESSION['login_time'] = time();
    $_SESSION['user_type'] = 'admin';
    // Optionally, update last login time if you want:
    global $conn;
    if ($conn) {
        $stmt = $conn->prepare("UPDATE admin_users SET last_login = NOW() WHERE id = ?");
        $stmt->bind_param("i", $admin_id);
        $stmt->execute();
        $stmt->close();
    }
}
?> 