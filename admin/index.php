<?php
require_once '../config/init.php';

// Check if user is logged in as admin
if (!isset($_SESSION['admin_id']) || !isset($_SESSION['login_time'])) {
    header('Location: login.php');
    exit();
}

// Check session timeout
if (time() - $_SESSION['login_time'] > SESSION_TIMEOUT) {
    session_destroy();
    header('Location: login.php');
    exit();
}

$admin_id = $_SESSION['admin_id'];
$admin_username = $_SESSION['admin_username'];

// Get admin details
$stmt = $conn->prepare("SELECT id, username, email, role FROM admin_users WHERE id = ?");
$stmt->bind_param("i", $admin_id);
$stmt->execute();
$admin = $stmt->get_result()->fetch_assoc();
$stmt->close();

// Get statistics
$stats = [];

// Total users
$stmt = $conn->prepare("SELECT COUNT(*) as total FROM users");
$stmt->execute();
$stats['total_users'] = $stmt->get_result()->fetch_assoc()['total'];
$stmt->close();

// Active sessions
$stmt = $conn->prepare("SELECT COUNT(*) as total FROM user_sessions WHERE is_active = TRUE");
$stmt->execute();
$stats['active_sessions'] = $stmt->get_result()->fetch_assoc()['total'];
$stmt->close();

// Recent login attempts
$stmt = $conn->prepare("SELECT COUNT(*) as total FROM login_logs WHERE attempt_time > DATE_SUB(NOW(), INTERVAL 24 HOUR)");
$stmt->execute();
$stats['recent_logins'] = $stmt->get_result()->fetch_assoc()['total'];
$stmt->close();

// Failed login attempts
$stmt = $conn->prepare("SELECT COUNT(*) as total FROM login_logs WHERE success = FALSE AND attempt_time > DATE_SUB(NOW(), INTERVAL 24 HOUR)");
$stmt->execute();
$stats['failed_logins'] = $stmt->get_result()->fetch_assoc()['total'];
$stmt->close();

// Get recent security events
$stmt = $conn->prepare("SELECT * FROM login_logs ORDER BY attempt_time DESC LIMIT 10");
$stmt->execute();
$recent_events = $stmt->get_result();
$stmt->close();

// Get locked accounts
$stmt = $conn->prepare("SELECT id, username, email, login_attempts, account_locked_until FROM users WHERE account_locked = TRUE");
$stmt->execute();
$locked_accounts = $stmt->get_result();
$stmt->close();

// Handle logout
if (isset($_POST['logout']) && verify_csrf_token($_POST['csrf_token'])) {
    // Clear admin session
    session_destroy();
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
    <meta name="description" content="SecureAuth - Admin Panel">
    <meta name="robots" content="noindex, nofollow">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.css">
    <link rel="shortcut icon" href="https://cdn-icons-png.flaticon.com/512/295/295128.png">
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <title>SecureAuth - Admin Panel</title>
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
        .stat-card {
            background: linear-gradient(135deg, #009688 0%, #00796B 100%);
            color: white;
            border-radius: 15px;
            padding: 20px;
            margin-bottom: 20px;
        }
        .event-item {
            padding: 10px;
            border-left: 3px solid #009688;
            margin-bottom: 10px;
            background: rgba(0, 150, 136, 0.1);
            border-radius: 5px;
        }
        .locked-account {
            background: rgba(220, 53, 69, 0.1);
            border-left: 4px solid #dc3545;
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 5px;
        }
    </style>
</head>

<body>
    <!-- Navigation -->
    <nav class="navbar navbar-expand-lg navbar-dark">
        <div class="container">
            <a class="navbar-brand" href="#">
                <i class="fa fa-shield"></i> SecureAuth Admin
            </a>
            <div class="navbar-nav ms-auto">
                <span class="navbar-text me-3">
                    Admin: <strong><?php echo htmlspecialchars($admin_username); ?></strong>
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
        <!-- Statistics Cards -->
        <div class="row mb-4">
            <div class="col-md-3">
                <div class="stat-card text-center">
                    <i class="fa fa-users" style="font-size: 2rem;"></i>
                    <h3><?php echo $stats['total_users']; ?></h3>
                    <p>Total Users</p>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stat-card text-center">
                    <i class="fa fa-desktop" style="font-size: 2rem;"></i>
                    <h3><?php echo $stats['active_sessions']; ?></h3>
                    <p>Active Sessions</p>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stat-card text-center">
                    <i class="fa fa-sign-in" style="font-size: 2rem;"></i>
                    <h3><?php echo $stats['recent_logins']; ?></h3>
                    <p>Recent Logins (24h)</p>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stat-card text-center">
                    <i class="fa fa-exclamation-triangle" style="font-size: 2rem;"></i>
                    <h3><?php echo $stats['failed_logins']; ?></h3>
                    <p>Failed Logins (24h)</p>
                </div>
            </div>
        </div>

        <div class="row">
            <!-- Recent Security Events -->
            <div class="col-md-8 mb-4">
                <div class="card">
                    <div class="card-header">
                        <h5><i class="fa fa-history"></i> Recent Security Events</h5>
                    </div>
                    <div class="card-body">
                        <?php if ($recent_events->num_rows > 0): ?>
                            <?php while ($event = $recent_events->fetch_assoc()): ?>
                                <div class="event-item">
                                    <div class="d-flex justify-content-between align-items-center">
                                        <div>
                                            <strong><?php echo htmlspecialchars($event['email']); ?></strong><br>
                                            <small class="text-muted">
                                                <?php echo date('M j, Y g:i A', strtotime($event['attempt_time'])); ?>
                                            </small>
                                        </div>
                                        <span class="badge <?php echo $event['success'] ? 'bg-success' : 'bg-danger'; ?>">
                                            <?php echo $event['success'] ? 'SUCCESS' : 'FAILED'; ?>
                                        </span>
                                    </div>
                                    <small class="text-muted">IP: <?php echo htmlspecialchars($event['ip_address']); ?></small>
                                </div>
                            <?php endwhile; ?>
                        <?php else: ?>
                            <p class="text-muted">No recent security events</p>
                        <?php endif; ?>
                    </div>
                </div>
            </div>

            <!-- Locked Accounts -->
            <div class="col-md-4 mb-4">
                <div class="card">
                    <div class="card-header">
                        <h5><i class="fa fa-lock"></i> Locked Accounts</h5>
                    </div>
                    <div class="card-body">
                        <?php if ($locked_accounts->num_rows > 0): ?>
                            <?php while ($account = $locked_accounts->fetch_assoc()): ?>
                                <div class="locked-account">
                                    <div class="d-flex justify-content-between align-items-center">
                                        <div>
                                            <strong><?php echo htmlspecialchars($account['username']); ?></strong><br>
                                            <small class="text-muted"><?php echo htmlspecialchars($account['email']); ?></small>
                                        </div>
                                        <span class="badge bg-danger">LOCKED</span>
                                    </div>
                                    <small class="text-muted">
                                        Attempts: <?php echo $account['login_attempts']; ?><br>
                                        Locked until: <?php echo date('M j, Y g:i A', strtotime($account['account_locked_until'])); ?>
                                    </small>
                                </div>
                            <?php endwhile; ?>
                        <?php else: ?>
                            <p class="text-muted">No locked accounts</p>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>

        <!-- Security Chart -->
        <div class="row">
            <div class="col-12">
                <div class="card">
                    <div class="card-header">
                        <h5><i class="fa fa-chart-line"></i> Security Activity (Last 7 Days)</h5>
                    </div>
                    <div class="card-body">
                        <canvas id="securityChart" width="400" height="200"></canvas>
                    </div>
                </div>
            </div>
        </div>

        <!-- Quick Actions -->
        <div class="row mt-4">
            <div class="col-12">
                <div class="card">
                    <div class="card-header">
                        <h5><i class="fa fa-cogs"></i> Quick Actions</h5>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-3 mb-3">
                                <a href="users.php" class="btn btn-primary w-100">
                                    <i class="fa fa-users"></i> Manage Users
                                </a>
                            </div>
                            <div class="col-md-3 mb-3">
                                <a href="logs.php" class="btn btn-info w-100">
                                    <i class="fa fa-list"></i> View All Logs
                                </a>
                            </div>
                            <div class="col-md-3 mb-3">
                                <a href="settings.php" class="btn btn-warning w-100">
                                    <i class="fa fa-cog"></i> System Settings
                                </a>
                            </div>
                            <div class="col-md-3 mb-3">
                                <a href="backup.php" class="btn btn-success w-100">
                                    <i class="fa fa-download"></i> Backup Data
                                </a>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Security Activity Chart
        const ctx = document.getElementById('securityChart').getContext('2d');
        const securityChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
                datasets: [{
                    label: 'Successful Logins',
                    data: [12, 19, 15, 25, 22, 18, 24],
                    borderColor: '#28a745',
                    backgroundColor: 'rgba(40, 167, 69, 0.1)',
                    tension: 0.4
                }, {
                    label: 'Failed Logins',
                    data: [3, 5, 2, 8, 4, 6, 3],
                    borderColor: '#dc3545',
                    backgroundColor: 'rgba(220, 53, 69, 0.1)',
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'top',
                    },
                    title: {
                        display: true,
                        text: 'Login Activity'
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });

        // Auto-refresh data every 30 seconds
        setInterval(function() {
            location.reload();
        }, 30000);
    </script>
</body>
</html> 