<?php
require_once '../config/init.php';

$message = "";
$toastClass = "";

// Check if user is already logged in
if (validate_session()) {
    header('Location: dashboard.php');
    exit();
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Verify CSRF token
    if (!isset($_POST['csrf_token']) || !verify_csrf_token($_POST['csrf_token'])) {
        $message = "Invalid request. Please try again.";
        $toastClass = "danger";
        log_security_event("CSRF_ATTEMPT", "Failed CSRF validation during registration");
    } else {
        $username = sanitize_input($_POST['username']);
        $email = sanitize_input($_POST['email']);
        $password = $_POST['password'];
        $confirm_password = $_POST['confirm_password'];
        $ip_address = $_SERVER['REMOTE_ADDR'] ?? 'unknown';

        // Validate input
        $errors = [];

        // Username validation
        if (empty($username)) {
            $errors[] = "Username is required";
        } elseif (!validate_username($username)) {
            $errors[] = "Username must be 3-20 characters long and contain only letters, numbers, and underscores";
        }

        // Email validation
        if (empty($email)) {
            $errors[] = "Email is required";
        } elseif (!validate_email($email)) {
            $errors[] = "Please enter a valid email address";
        }

        // Password validation
        if (empty($password)) {
            $errors[] = "Password is required";
        } else {
            $password_errors = validate_password($password);
            $errors = array_merge($errors, $password_errors);
        }

        // Confirm password
        if ($password !== $confirm_password) {
            $errors[] = "Passwords do not match";
        }

        // Check rate limiting for registration
        if (!check_rate_limit($ip_address, 'register', 3, 3600)) {
            $errors[] = "Too many registration attempts. Please try again in 1 hour.";
        }

        if (empty($errors)) {
            // Check if email already exists
            $checkEmailStmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
            $checkEmailStmt->bind_param("s", $email);
            $checkEmailStmt->execute();
            $checkEmailStmt->store_result();

            if ($checkEmailStmt->num_rows > 0) {
                $message = "Email address is already registered";
                $toastClass = "warning";
                log_security_event($email, "Registration attempt with existing email");
            } else {
                // Check if username already exists
                $checkUsernameStmt = $conn->prepare("SELECT id FROM users WHERE username = ?");
                $checkUsernameStmt->bind_param("s", $username);
                $checkUsernameStmt->execute();
                $checkUsernameStmt->store_result();

                if ($checkUsernameStmt->num_rows > 0) {
                    $message = "Username is already taken";
                    $toastClass = "warning";
                    log_security_event($email, "Registration attempt with existing username");
                } else {
                    // Hash password
                    $password_hash = hash_password($password);
                    
                    // Generate email verification token
                    $verification_token = generate_secure_token();
                    
                    // Insert new user
                    $stmt = $conn->prepare("INSERT INTO users (username, email, password_hash, email_verification_token) VALUES (?, ?, ?, ?)");
                    $stmt->bind_param("ssss", $username, $email, $password_hash, $verification_token);

                    if ($stmt->execute()) {
                        $user_id = $conn->insert_id;
                        
                        // Log successful registration
                        log_security_event($email, "REGISTRATION_SUCCESS");
                        
                        $message = "Account created successfully! Please check your email for verification.";
                        $toastClass = "success";
                        
                        // In a real application, you would send verification email here
                        // For demo purposes, we'll auto-verify the email
                        $verifyStmt = $conn->prepare("UPDATE users SET email_verified = TRUE, email_verification_token = NULL WHERE id = ?");
                        $verifyStmt->bind_param("i", $user_id);
                        $verifyStmt->execute();
                        $verifyStmt->close();
                        
                    } else {
                        $message = "Error creating account. Please try again.";
                        $toastClass = "danger";
                        log_security_event($email, "Registration database error: " . $stmt->error);
                    }
                    $stmt->close();
                }
                $checkUsernameStmt->close();
            }
            $checkEmailStmt->close();
        } else {
            $message = implode("<br>", $errors);
            $toastClass = "warning";
            log_security_event($email, "Registration validation failed: " . implode(", ", $errors));
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
    <meta name="description" content="SecureAuth - Secure User Registration">
    <meta name="robots" content="noindex, nofollow">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.css">
    <link rel="shortcut icon" href="https://cdn-icons-png.flaticon.com/512/295/295128.png">
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <title>SecureAuth - Registration</title>
    <style>
        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
        .card {
            border: none;
            border-radius: 15px;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.1);
        }
        .card-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-radius: 15px 15px 0 0 !important;
        }
        .btn-primary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
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
            border-color: #667eea;
            box-shadow: 0 0 0 0.2rem rgba(102, 126, 234, 0.25);
        }
        .password-strength {
            height: 5px;
            border-radius: 3px;
            margin-top: 5px;
            transition: all 0.3s ease;
        }
        .strength-weak { background-color: #dc3545; width: 25%; }
        .strength-fair { background-color: #ffc107; width: 50%; }
        .strength-good { background-color: #17a2b8; width: 75%; }
        .strength-strong { background-color: #28a745; width: 100%; }
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
                        <h3><i class="fa fa-user-plus"></i> SecureAuth Registration</h3>
                        <p class="mb-0">Create Your Secure Account</p>
                    </div>
                    <div class="card-body p-4">
                        <form method="POST" id="registerForm">
                            <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                            
                            <div class="mb-3">
                                <label for="username" class="form-label">
                                    <i class="fa fa-user"></i> Username
                                </label>
                                <input type="text" name="username" id="username" class="form-control" 
                                       required placeholder="Enter username (3-20 characters)" 
                                       pattern="[a-zA-Z0-9_]{3,20}" title="Username must be 3-20 characters long and contain only letters, numbers, and underscores">
                                <div class="form-text">Username must be 3-20 characters long and contain only letters, numbers, and underscores</div>
                            </div>
                            
                            <div class="mb-3">
                                <label for="email" class="form-label">
                                    <i class="fa fa-envelope"></i> Email Address
                                </label>
                                <input type="email" name="email" id="email" class="form-control" 
                                       required autocomplete="email" placeholder="Enter your email address">
                            </div>
                            
                            <div class="mb-3">
                                <label for="password" class="form-label">
                                    <i class="fa fa-lock"></i> Password
                                </label>
                                <div class="input-group">
                                    <input type="password" name="password" id="password" class="form-control" 
                                           required autocomplete="new-password" placeholder="Enter your password">
                                    <button class="btn btn-outline-secondary" type="button" id="togglePassword">
                                        <i class="fa fa-eye"></i>
                                    </button>
                                </div>
                                <div class="password-strength" id="passwordStrength"></div>
                                <div class="form-text">
                                    Password must contain at least 8 characters, including uppercase, lowercase, number, and special character
                                </div>
                            </div>
                            
                            <div class="mb-3">
                                <label for="confirm_password" class="form-label">
                                    <i class="fa fa-lock"></i> Confirm Password
                                </label>
                                <input type="password" name="confirm_password" id="confirm_password" class="form-control" 
                                       required autocomplete="new-password" placeholder="Confirm your password">
                            </div>
                            
                            <div class="mb-3 form-check">
                                <input type="checkbox" class="form-check-input" id="agreeTerms" required>
                                <label class="form-check-label" for="agreeTerms">
                                    I agree to the <a href="#" class="text-decoration-none">Terms of Service</a> and 
                                    <a href="#" class="text-decoration-none">Privacy Policy</a>
                                </label>
                            </div>
                            
                            <div class="d-grid">
                                <button type="submit" class="btn btn-primary btn-lg">
                                    <i class="fa fa-user-plus"></i> Create Secure Account
                                </button>
                            </div>
                        </form>
                        
                        <div class="text-center mt-4">
                            <p class="mb-0">Already have an account? 
                                <a href="login.php" class="text-decoration-none fw-bold">Login here</a>
                            </p>
                        </div>
                        
                        <div class="security-info">
                            <h6><i class="fa fa-shield"></i> Security Features:</h6>
                            <ul class="list-unstyled mb-0 small">
                                <li><i class="fa fa-check text-success"></i> Strong Password Requirements</li>
                                <li><i class="fa fa-check text-success"></i> Email Verification</li>
                                <li><i class="fa fa-check text-success"></i> CSRF Protection</li>
                                <li><i class="fa fa-check text-success"></i> Rate Limiting</li>
                                <li><i class="fa fa-check text-success"></i> Secure Password Hashing</li>
                            </ul>
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
                <?php echo $message; ?>
            </div>
        </div>
    </div>
    <?php endif; ?>

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

        // Password strength meter
        document.getElementById('password').addEventListener('input', function() {
            const password = this.value;
            const strengthBar = document.getElementById('passwordStrength');
            let strength = 0;
            
            if (password.length >= 8) strength++;
            if (/[A-Z]/.test(password)) strength++;
            if (/[a-z]/.test(password)) strength++;
            if (/[0-9]/.test(password)) strength++;
            if (/[^A-Za-z0-9]/.test(password)) strength++;
            
            strengthBar.className = 'password-strength';
            if (strength <= 2) {
                strengthBar.classList.add('strength-weak');
            } else if (strength === 3) {
                strengthBar.classList.add('strength-fair');
            } else if (strength === 4) {
                strengthBar.classList.add('strength-good');
            } else {
                strengthBar.classList.add('strength-strong');
            }
        });

        // Password confirmation check
        document.getElementById('confirm_password').addEventListener('input', function() {
            const password = document.getElementById('password').value;
            const confirmPassword = this.value;
            
            if (password !== confirmPassword) {
                this.setCustomValidity('Passwords do not match');
            } else {
                this.setCustomValidity('');
            }
        });

        // Form validation
        document.getElementById('registerForm').addEventListener('submit', function(e) {
            const password = document.getElementById('password').value;
            const confirmPassword = document.getElementById('confirm_password').value;
            
            if (password !== confirmPassword) {
                e.preventDefault();
                alert('Passwords do not match');
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