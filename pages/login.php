<?php
require_once '../config/init.php';

// --- Set Content Security Policy header (add this in your init.php or at the top here) ---
header("Content-Security-Policy: script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://code.jquery.com https://www.google.com https://www.gstatic.com;");

// --- Your reCAPTCHA keys ---
$recaptcha_site_key = "6LeCbJkrAAAAAHoJBlULHFl5uuS_pAkBYLL0yze4";
$recaptcha_secret_key = "6LeCbJkrAAAAAPZ0k1Ywb-ZVNgAdShbrHCmuQXLB";

$message = "";
$toastClass = "";

// Check if admin is already logged in
if (isset($_SESSION['admin_id']) && isset($_SESSION['login_time'])) {
    if (time() - $_SESSION['login_time'] > SESSION_TIMEOUT) {
        session_destroy();
    } else {
        header('Location: login.php');
        exit();
    }
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Verify CSRF token
    if (!isset($_POST['csrf_token']) || !verify_csrf_token($_POST['csrf_token'])) {
        $message = "Invalid request. Please try again.";
        $toastClass = "danger";
        log_security_event("CSRF_ATTEMPT", "Failed CSRF validation");
    } else {
        // Verify reCAPTCHA
        $recaptcha_response = $_POST['g-recaptcha-response'] ?? '';
        if (empty($recaptcha_response)) {
            $message = "Please complete the reCAPTCHA verification.";
            $toastClass = "warning";
        } else {
            // Verify with Google
            $verify = file_get_contents(
                "https://www.google.com/recaptcha/api/siteverify?secret=" . $recaptcha_secret_key . "&response=" . $recaptcha_response . "&remoteip=" . $_SERVER['REMOTE_ADDR']
            );
            $captcha_success = json_decode($verify);

            if (!$captcha_success->success) {
                $message = "reCAPTCHA verification failed. Please try again.";
                $toastClass = "danger";
                log_security_event("RECAPTCHA_FAILED", "IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
            } else {
                // reCAPTCHA passed, proceed with login
                $email = sanitize_input($_POST['email']);
                $password = $_POST['password'];
                $ip_address = $_SERVER['REMOTE_ADDR'] ?? 'unknown';

                // Validate input
                if (empty($email) || empty($password)) {
                    $message = "Please fill in all fields";
                    $toastClass = "warning";
                } elseif (!validate_email($email)) {
                    $message = "Please enter a valid email address";
                    $toastClass = "warning";
                } else {
                    // Check rate limiting
                    if (!check_rate_limit($ip_address, 'login', 5, 300)) {
                        $message = "Too many login attempts. Please try again in 5 minutes.";
                        $toastClass = "danger";
                        log_security_event("RATE_LIMIT_EXCEEDED", "IP: $ip_address");
                    } else {
                        // Get user data
                        $stmt = $conn->prepare("SELECT id, username, email, password_hash, login_attempts, account_locked, account_locked_until FROM users WHERE email = ?");
                        $stmt->bind_param("s", $email);
                        $stmt->execute();
                        $result = $stmt->get_result();

                        if ($result->num_rows > 0) {
                            $user = $result->fetch_assoc();
                            // Check if account is locked
                            if ($user['account_locked'] && $user['account_locked_until'] > date('Y-m-d H:i:s')) {
                                $message = "Account is temporarily locked due to too many failed attempts. Please try again later.";
                                $toastClass = "danger";
                                log_security_event($email, "Account locked");
                            } else {
                                // Verify password
                                if (verify_password($password, $user['password_hash'])) {
                                    // Successful login
                                    reset_login_attempts($email);
                                    create_secure_session($user['id'], $user['username']);
                                    log_security_event($email, "SUCCESS");
                                    header('Location: dashboard.php');
                                    exit();
                                } else {
                                    // Failed login
                                    increment_login_attempts($email);
                                    // Check if account should be locked
                                    $stmt = $conn->prepare("SELECT login_attempts FROM users WHERE email = ?");
                                    $stmt->bind_param("s", $email);
                                    $stmt->execute();
                                    $attempt_result = $stmt->get_result();
                                    $attempt_data = $attempt_result->fetch_assoc();
                                    $stmt->close();
                                    if ($attempt_data['login_attempts'] >= MAX_LOGIN_ATTEMPTS) {
                                        lock_account($email);
                                        $message = "Account locked due to too many failed attempts. Please try again in 15 minutes.";
                                        $toastClass = "danger";
                                    } else {
                                        $remaining_attempts = MAX_LOGIN_ATTEMPTS - $attempt_data['login_attempts'];
                                        $message = "Invalid email or password. {$remaining_attempts} attempts remaining.";
                                        $toastClass = "danger";
                                    }
                                    log_security_event($email, "FAILED");
                                }
                            }
                        } else {
                            // User not found - don't reveal this information
                            $message = "Invalid email or password";
                            $toastClass = "danger";
                            log_security_event($email, "USER_NOT_FOUND");
                        }
                        $stmt->close();
                    }
                }
            }
        }
    }
}

$csrf_token = generate_csrf_token();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="SecureAuth - Secure User Authentication System">
    <meta name="robots" content="noindex, nofollow">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.css">
    <link rel="shortcut icon" href="https://cdn-icons-png.flaticon.com/512/295/295128.png">
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/js/bootstrap.bundle.min.js"></script>
    <title>SecureAuth - Login</title>
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
                        <h3><i class="fa fa-shield"></i> SecureAuth Login</h3>
                        <p class="mb-0">Secure User Authentication System</p>
                    </div>
                    <div class="card-body p-4">
                        <form method="POST" id="loginForm">
                            <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                            <div class="mb-3">
                                <label for="email" class="form-label">
                                    <i class="fa fa-envelope"></i> Email Address
                                </label>
                                <input type="email" name="email" id="email" class="form-control" 
                                       required autocomplete="email" placeholder="Enter your email">
                            </div>
                            <div class="mb-3">
                                <label for="password" class="form-label">
                                    <i class="fa fa-lock"></i> Password
                                </label>
                                <div class="input-group">
                                    <input type="password" name="password" id="password" class="form-control" 
                                           required autocomplete="current-password" placeholder="Enter your password">
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
                                    <i class="fa fa-sign-in"></i> Secure Login
                                </button>
                            </div>
                        </form>
                        <div class="text-center mt-4">
                            <p class="mb-2">Don't have an account? 
                                <a href="register.php" class="text-decoration-none fw-bold">Register here</a>
                            </p>
                            <p class="mb-0">
                                <a href="resetpassword.php" class="text-decoration-none">Forgot Password?</a>
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
                <strong class="me-auto">SecureAuth</strong>
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
        document.getElementById('loginForm').addEventListener('submit', function(e) {
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;
            if (!email || !password) {
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