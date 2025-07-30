<?php
require_once '../config/init.php';

// Log the logout event
if (isset($_SESSION['user_id'])) {
    $user_id = $_SESSION['user_id'];
    $username = $_SESSION['username'] ?? 'unknown';
    log_security_event("LOGOUT", "User: $username, ID: $user_id");
}

// Perform secure logout
logout_user();

// Clear all session data
session_unset();
session_destroy();

// Clear session cookie
if (isset($_COOKIE[session_name()])) {
    setcookie(session_name(), '', time() - 3600, '/');
}

// Redirect to login page with success message
header('Location: login.php?message=logged_out');
exit();
?> 