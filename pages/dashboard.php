<?php
require_once '../config/init.php';

// Check if user is logged in
if (!validate_session()) {
    header('Location: login.php');
    exit();
}

// Get user information
$user_id = $_SESSION['user_id'];
$username = $_SESSION['username'];

// Get user details from database
$stmt = $conn->prepare("SELECT id, username, email, email_verified, created_at, last_login_attempt FROM users WHERE id = ?");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$result = $stmt->get_result();
$user = $result->fetch_assoc();
$stmt->close();

// Get recent login attempts
$stmt = $conn->prepare("SELECT attempt_time, success, ip_address FROM login_logs WHERE email = ? ORDER BY attempt_time DESC LIMIT 5");
$stmt->bind_param("s", $user['email']);
$stmt->execute();
$login_logs = $stmt->get_result();
$stmt->close();

// Get active sessions
$stmt = $conn->prepare("SELECT created_at, ip_address, user_agent FROM user_sessions WHERE user_id = ? AND is_active = TRUE ORDER BY created_at DESC");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$active_sessions = $stmt->get_result();
$stmt->close();

// Handle logout
if (isset($_POST['logout']) && verify_csrf_token($_POST['csrf_token'])) {
    logout_user();
    header('Location: login.php');
    exit();
}

$csrf_token = generate_csrf_token();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="SecureAuth - User Dashboard">
    <meta name="robots" content="noindex, nofollow">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.css">
    <link rel="shortcut icon" href="https://cdn-icons-png.flaticon.com/512/295/295128.png">
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/js/bootstrap.bundle.min.js"></script>
    <title>SecureAuth - Dashboard</title>
    <style>
        body {
            background: linear-gradient(135deg, #009688 0%, #00796B 100%);
            min-height: 100vh;
        }
        .navbar {
            background: rgba(255, 255, 255, 0.1) !important;
            backdrop-filter: blur(10px);
            border-bottom: 1px solid rgba(255, 255, 255, 0.2);
        }
        .card {
            border: none;
            border-radius: 15px;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.1);
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
        }
        .card-header {
            background: linear-gradient(135deg, #009688 0%, #00796B 100%);
            color: white;
            border-radius: 15px 15px 0 0 !important;
        }
        .btn-primary {
            background: linear-gradient(135deg, #009688 0%, #00796B 100%);
            border: none;
            border-radius: 25px;
            padding: 8px 20px;
            font-weight: 600;
        }
        .btn-danger {
            background: linear-gradient(135deg, #dc3545 0%, #c82333 100%);
            border: none;
            border-radius: 25px;
            padding: 8px 20px;
            font-weight: 600;
        }
        .security-badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: 600;
        }
        .badge-success { background-color: #28a745; color: white; }
        .badge-warning { background-color: #ffc107; color: #212529; }
        .badge-danger { background-color: #dc3545; color: white; }
        .activity-item {
            padding: 10px;
            border-left: 3px solid #009688;
            margin-bottom: 10px;
            background: rgba(0, 150, 136, 0.1);
            border-radius: 5px;
        }
        .session-item {
            background: rgba(255, 255, 255, 0.8);
            border-radius: 10px;
            padding: 15px;
            margin-bottom: 10px;
            border-left: 4px solid #28a745;
        }
    </style>
</head>

<body>
    <!-- Navigation -->
    <nav class="navbar navbar-expand-lg navbar-dark">
        <div class="container">
            <a class="navbar-brand" href="#">
                <i class="fa fa-shield"></i> SecureAuth
            </a>
            <div class="navbar-nav ms-auto">
                <span class="navbar-text me-3">
                    Welcome, <strong><?php echo htmlspecialchars($username); ?></strong>
                </span>
                <form method="POST" class="d-inline">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                    <button type="submit" name="logout" class="btn btn-outline-light btn-sm">
                        <i class="fa fa-sign-out"></i> Logout
                    </button>
                </form>
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        <div class="row">
            <!-- User Profile Card -->
            <div class="col-md-4 mb-4">
                <div class="card">
                    <div class="card-header text-center">
                        <h5><i class="fa fa-user"></i> User Profile</h5>
                    </div>
                    <div class="card-body">
                        <div class="text-center mb-3">
                            <i class="fa fa-user-circle" style="font-size: 4rem; color: #667eea;"></i>
                        </div>
                        <div class="mb-3">
                            <strong>Username:</strong> <?php echo htmlspecialchars($user['username']); ?>
                        </div>
                        <div class="mb-3">
                            <strong>Email:</strong> <?php echo htmlspecialchars($user['email']); ?>
                        </div>
                        <div class="mb-3">
                            <strong>Email Status:</strong> 
                            <?php if ($user['email_verified']): ?>
                                <span class="security-badge badge-success">
                                    <i class="fa fa-check"></i> Verified
                                </span>
                            <?php else: ?>
                                <span class="security-badge badge-warning">
                                    <i class="fa fa-exclamation-triangle"></i> Unverified
                                </span>
                            <?php endif; ?>
                        </div>
                        <div class="mb-3">
                            <strong>Member Since:</strong><br>
                            <?php echo date('F j, Y', strtotime($user['created_at'])); ?>
                        </div>
                        <div class="mb-3">
                            <strong>Last Login:</strong><br>
                            <?php echo $user['last_login_attempt'] ? date('F j, Y g:i A', strtotime($user['last_login_attempt'])) : 'Never'; ?>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Security Status -->
            <div class="col-md-8 mb-4">
                <div class="card">
                    <div class="card-header">
                        <h5><i class="fa fa-shield"></i> Security Status</h5>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-6 mb-3">
                                <div class="d-flex align-items-center">
                                    <i class="fa fa-lock text-success me-2"></i>
                                    <div>
                                        <strong>Account Security</strong><br>
                                        <small class="text-muted">Your account is protected</small>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-6 mb-3">
                                <div class="d-flex align-items-center">
                                    <i class="fa fa-clock text-info me-2"></i>
                                    <div>
                                        <strong>Session Timeout</strong><br>
                                        <small class="text-muted">Auto-logout in 1 hour</small>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-6 mb-3">
                                <div class="d-flex align-items-center">
                                    <i class="fa fa-eye text-warning me-2"></i>
                                    <div>
                                        <strong>Login Attempts</strong><br>
                                        <small class="text-muted">Account lockout protection</small>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-6 mb-3">
                                <div class="d-flex align-items-center">
                                    <i class="fa fa-history text-primary me-2"></i>
                                    <div>
                                        <strong>Activity Logging</strong><br>
                                        <small class="text-muted">All activities are logged</small>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="row">
            <!-- Recent Login Activity -->
            <div class="col-md-6 mb-4">
                <div class="card">
                    <div class="card-header">
                        <h5><i class="fa fa-history"></i> Recent Login Activity</h5>
                    </div>
                    <div class="card-body">
                        <?php if ($login_logs->num_rows > 0): ?>
                            <?php while ($log = $login_logs->fetch_assoc()): ?>
                                <div class="activity-item">
                                    <div class="d-flex justify-content-between align-items-center">
                                        <div>
                                            <strong><?php echo $log['success'] ? 'Successful' : 'Failed'; ?> Login</strong><br>
                                            <small class="text-muted">
                                                <?php echo date('M j, Y g:i A', strtotime($log['attempt_time'])); ?>
                                            </small>
                                        </div>
                                        <span class="security-badge <?php echo $log['success'] ? 'badge-success' : 'badge-danger'; ?>">
                                            <?php echo $log['success'] ? 'SUCCESS' : 'FAILED'; ?>
                                        </span>
                                    </div>
                                    <small class="text-muted">IP: <?php echo htmlspecialchars($log['ip_address']); ?></small>
                                </div>
                            <?php endwhile; ?>
                        <?php else: ?>
                            <p class="text-muted">No recent login activity</p>
                        <?php endif; ?>
                    </div>
                </div>
            </div>

            <!-- Active Sessions -->
            <div class="col-md-6 mb-4">
                <div class="card">
                    <div class="card-header">
                        <h5><i class="fa fa-desktop"></i> Active Sessions</h5>
                    </div>
                    <div class="card-body">
                        <?php if ($active_sessions->num_rows > 0): ?>
                            <?php while ($session = $active_sessions->fetch_assoc()): ?>
                                <div class="session-item">
                                    <div class="d-flex justify-content-between align-items-center">
                                        <div>
                                            <strong>Current Session</strong><br>
                                            <small class="text-muted">
                                                Started: <?php echo date('M j, Y g:i A', strtotime($session['created_at'])); ?>
                                            </small>
                                        </div>
                                        <span class="security-badge badge-success">ACTIVE</span>
                                    </div>
                                    <small class="text-muted">IP: <?php echo htmlspecialchars($session['ip_address']); ?></small>
                                </div>
                            <?php endwhile; ?>
                        <?php else: ?>
                            <p class="text-muted">No active sessions</p>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>

        <!-- Security Tips -->
        <div class="row">
            <div class="col-12">
                <div class="card">
                    <div class="card-header">
                        <h5><i class="fa fa-lightbulb-o"></i> Security Tips</h5>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-6">
                                <ul class="list-unstyled">
                                    <li><i class="fa fa-check text-success me-2"></i> Use a strong, unique password</li>
                                    <li><i class="fa fa-check text-success me-2"></i> Enable two-factor authentication if available</li>
                                    <li><i class="fa fa-check text-success me-2"></i> Keep your email address updated</li>
                                </ul>
                            </div>
                            <div class="col-md-6">
                                <ul class="list-unstyled">
                                    <li><i class="fa fa-check text-success me-2"></i> Logout from shared computers</li>
                                    <li><i class="fa fa-check text-success me-2"></i> Monitor your login activity regularly</li>
                                    <li><i class="fa fa-check text-success me-2"></i> Report suspicious activity immediately</li>
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Auto-refresh session status every 30 seconds
        setInterval(function() {
            // You could add AJAX call here to check session status
            console.log('Session status check...');
        }, 30000);

        // Warn user before session expires
        setTimeout(function() {
            if (confirm('Your session will expire soon. Do you want to stay logged in?')) {
                // Extend session
                fetch('extend_session.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        csrf_token: '<?php echo $csrf_token; ?>'
                    })
                });
            }
        }, 3000000); // 50 minutes
    </script>
</body>
</html> 