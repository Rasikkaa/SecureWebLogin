<?php
require_once '../config/init.php';

// Add this line to allow Google reCAPTCHA scripts
header("Content-Security-Policy: script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://code.jquery.com https://www.google.com https://www.gstatic.com;");

$message = "";
$toastClass = "";

// Check if admin is already logged in
if (isset($_SESSION['admin_id']) && isset($_SESSION['login_time'])) {
    header('Location: index.php');
    exit();
}

$recaptcha_site_key = "6LeCbJkrAAAAAHoJBlULHFl5uuS_pAkBYLL0yze4";
$recaptcha_secret_key = "6LeCbJkrAAAAAPZ0k1Ywb-ZVNgAdShbrHCmuQXLB";

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Verify CSRF token
    if (!isset($_POST['csrf_token']) || !verify_csrf_token($_POST['csrf_token'])) {
        $message = "Invalid request. Please try again.";
        $toastClass = "danger";
        log_security_event("ADMIN_CSRF_ATTEMPT", "Failed CSRF validation");
    } else {
        // Verify reCAPTCHA
        $recaptcha_response = $_POST['g-recaptcha-response'] ?? '';
        if (empty($recaptcha_response)) {
            $message = "Please complete the reCAPTCHA verification.";
            $toastClass = "warning";
        } else {
            $verify = file_get_contents(
                "https://www.google.com/recaptcha/api/siteverify?secret=" . $recaptcha_secret_key . "&response=" . $recaptcha_response . "&remoteip=" . $_SERVER['REMOTE_ADDR']
            );
            $captcha_success = json_decode($verify);
            if (!$captcha_success->success) {
                $message = "reCAPTCHA verification failed. Please try again.";
                $toastClass = "danger";
                log_security_event("ADMIN_RECAPTCHA_FAILED", "IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
            } else {
                $username = sanitize_input($_POST['username']);
                $password = $_POST['password'];
                $ip_address = $_SERVER['REMOTE_ADDR'] ?? 'unknown';

                // Validate input
                if (empty($username) || empty($password)) {
                    $message = "Please fill in all fields";
                    $toastClass = "warning";
                } else {
                    // Check rate limiting for admin login
                    if (!check_rate_limit($ip_address, 'admin_login', 20, 900)) {
                        $message = "Too many login attempts. Please try again in 15 minutes.";
                        $toastClass = "danger";
                        log_security_event("ADMIN_RATE_LIMIT_EXCEEDED", "IP: $ip_address");
                    } else {
                        // Get admin data
                        $stmt = $conn->prepare("SELECT id, username, email, password_hash, role FROM admin_users WHERE username = ?");
                        $stmt->bind_param("s", $username);
                        $stmt->execute();
                        $result = $stmt->get_result();

                        if ($result->num_rows > 0) {
                            $admin = $result->fetch_assoc();
                            
                            // Verify password
                            if (verify_password($password, $admin['password_hash'])) {
                                // Successful admin login
                                session_regenerate_id(true);
                                
                                $_SESSION['admin_id'] = $admin['id'];
                                $_SESSION['admin_username'] = $admin['username'];
                                $_SESSION['admin_role'] = $admin['role'];
                                $_SESSION['login_time'] = time();
                                $_SESSION['ip_address'] = $ip_address;
                                $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
                                
                                // Log successful admin login
                                log_security_event("ADMIN_LOGIN_SUCCESS", "Admin: $username");
                                
                                header('Location: index.php');
                                exit();
                            } else {
                                // Failed admin login
                                $message = "Invalid username or password";
                                $toastClass = "danger";
                                log_security_event("ADMIN_LOGIN_FAILED", "Admin: $username");
                            }
                        } else {
                            // Admin not found - don't reveal this information
                            $message = "Invalid username or password";
                            $toastClass = "danger";
                            log_security_event("ADMIN_NOT_FOUND", "Username: $username");
                        }
                        $stmt->close();
                    }
                }
            }
        }
    }

    $conn->close();
}

// Generate CSRF token
$csrf_token = generate_csrf_token();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="SecureAuth - Admin Login">
    <meta name="robots" content="noindex, nofollow">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.css">
    <link rel="shortcut icon" href="https://cdn-icons-png.flaticon.com/512/295/295128.png">
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/js/bootstrap.bundle.min.js"></script>
    <title>SecureAuth - Admin Login</title>
    <style>
        body {
            background: linear-gradient(135deg, #009688 0%, #00796B 100%);
            min-height: 100vh;
        }
        .card {
            border: none;
            border-radius: 15px;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.1);
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
            padding: 12px 30px;
            font-weight: 600;
        }
        .form-control {
            border-radius: 10px;
            border: 2px solid #e9ecef;
            padding: 12px 15px;
        }
        .form-control:focus {
            border-color: #009688;
            box-shadow: 0 0 0 0.2rem rgba(0, 150, 136, 0.25);
        }
        .security-info {
            background: rgba(255, 255, 255, 0.1);
            border-radius: 10px;
            padding: 15px;
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header text-center">
                        <h3><i class="fa fa-user-secret"></i> Admin Login</h3>
                        <p class="mb-0">SecureAuth Administration Panel</p>
                    </div>
                    <div class="card-body p-4">
                        <form method="POST" id="adminLoginForm">
                            <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                            <div class="mb-3">
                                <label for="username" class="form-label">
                                    <i class="fa fa-user"></i> Admin Username
                                </label>
                                <input type="text" name="username" id="username" class="form-control" 
                                       required autocomplete="username" placeholder="Enter admin username">
                            </div>
                            <div class="mb-3">
                                <label for="password" class="form-label">
                                    <i class="fa fa-lock"></i> Admin Password
                                </label>
                                <div class="input-group">
                                    <input type="password" name="password" id="password" class="form-control" 
                                           required autocomplete="current-password" placeholder="Enter admin password">
                                    <button class="btn btn-outline-secondary" type="button" id="togglePassword">
                                        <i class="fa fa-eye"></i>
                                    </button>
                                </div>
                            </div>
                            <div class="mb-3 form-check">
                                <input type="checkbox" class="form-check-input" id="rememberMe">
                                <label class="form-check-label" for="rememberMe">
                                    Remember me for 30 days
                                </label>
                            </div>
                            <!-- Google reCAPTCHA widget -->
                            <div class="mb-3">
                                <div class="g-recaptcha" data-sitekey="<?php echo $recaptcha_site_key; ?>"></div>
                            </div>
                            <div class="d-grid">
                                <button type="submit" class="btn btn-primary btn-lg">
                                    <i class="fa fa-sign-in"></i> Admin Login
                                </button>
                            </div>
                        </form>
                        <div class="text-center mt-4">
                            <p class="mb-0">
                                <a href="../pages/login.php" class="text-decoration-none">
                                    <i class="fa fa-arrow-left"></i> Back to User Login
                                </a>
                            </p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <!-- Toast Notification -->
    <?php if ($message): ?>
    <div class="toast-container position-fixed bottom-0 end-0 p-3">
        <div class="toast show" role="alert" aria-live="assertive" aria-atomic="true">
            <div class="toast-header">
                <strong class="me-auto">SecureAuth Admin</strong>
                <button type="button" class="btn-close" data-bs-dismiss="toast"></button>
            </div>
            <div class="toast-body text-<?php echo $toastClass; ?>">
                <?php echo htmlspecialchars($message); ?>
            </div>
        </div>
    </div>
    <?php endif; ?>
    <script src="https://www.google.com/recaptcha/api.js" async defer></script>
    <script>
        // Password visibility toggle
        document.getElementById('togglePassword').addEventListener('click', function() {
            const password = document.getElementById('password');
            const icon = this.querySelector('i');
            if (password.type === 'password') {
                password.type = 'text';
                icon.classList.remove('fa-eye');
                icon.classList.add('fa-eye-slash');
            } else {
                password.type = 'password';
                icon.classList.remove('fa-eye-slash');
                icon.classList.add('fa-eye');
            }
        });
        // Form validation
        document.getElementById('adminLoginForm').addEventListener('submit', function(e) {
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            if (!username || !password) {
                e.preventDefault();
                alert('Please fill in all fields');
                return false;
            }
        });
        // Auto-hide toast after 5 seconds
        setTimeout(function() {
            const toasts = document.querySelectorAll('.toast');
            toasts.forEach(toast => {
                const bsToast = new bootstrap.Toast(toast);
                bsToast.hide();
            });
        }, 5000);
    </script>
</body>
</html> 