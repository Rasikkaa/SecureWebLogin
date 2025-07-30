<?php
require_once '../config/init.php';

$message = "";
$toastClass = "";

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Verify CSRF token
    if (!isset($_POST['csrf_token']) || !verify_csrf_token($_POST['csrf_token'])) {
        $message = "Invalid request. Please try again.";
        $toastClass = "danger";
        log_security_event("CSRF_ATTEMPT", "Failed CSRF validation during password reset");
    } else {
        if (isset($_POST['request_reset'])) {
            // Step 1: Request password reset
            $email = sanitize_input($_POST['email']);
            
            if (empty($email) || !validate_email($email)) {
                $message = "Please enter a valid email address";
                $toastClass = "warning";
            } else {
                // Check if user exists
                $stmt = $conn->prepare("SELECT id, username FROM users WHERE email = ?");
                $stmt->bind_param("s", $email);
                $stmt->execute();
                $result = $stmt->get_result();
                
                if ($result->num_rows > 0) {
                    $user = $result->fetch_assoc();
                    
                    // Generate reset token
                    $reset_token = generate_secure_token();
                    $expires = date('Y-m-d H:i:s', time() + 3600); // 1 hour
                    
                    // Store reset token
                    $updateStmt = $conn->prepare("UPDATE users SET reset_token = ?, reset_token_expires = ? WHERE email = ?");
                    $updateStmt->bind_param("sss", $reset_token, $expires, $email);
                    
                    if ($updateStmt->execute()) {
                        $message = "Password reset instructions have been sent to your email address.";
                        $toastClass = "success";
                        log_security_event($email, "PASSWORD_RESET_REQUESTED");
                        
                        // In a real application, send email here
                        // For demo purposes, we'll show the token
                        $message .= " (Demo: Reset token is $reset_token)";
                    } else {
                        $message = "Error processing request. Please try again.";
                        $toastClass = "danger";
                    }
                    $updateStmt->close();
                } else {
                    // Don't reveal if email exists or not
                    $message = "If the email address exists in our system, you will receive reset instructions.";
                    $toastClass = "info";
                    log_security_event($email, "PASSWORD_RESET_EMAIL_NOT_FOUND");
                }
                $stmt->close();
            }
        } elseif (isset($_POST['reset_password'])) {
            // Step 2: Reset password with token
            $token = sanitize_input($_POST['token']);
            $new_password = $_POST['new_password'];
            $confirm_password = $_POST['confirm_password'];
            
            if (empty($token) || empty($new_password) || empty($confirm_password)) {
                $message = "Please fill in all fields";
                $toastClass = "warning";
            } elseif ($new_password !== $confirm_password) {
                $message = "Passwords do not match";
                $toastClass = "warning";
            } else {
                // Validate password strength
                $password_errors = validate_password($new_password);
                if (!empty($password_errors)) {
                    $message = implode("<br>", $password_errors);
                    $toastClass = "warning";
                } else {
                    // Verify token
                    $stmt = $conn->prepare("SELECT id, email FROM users WHERE reset_token = ? AND reset_token_expires > NOW()");
                    $stmt->bind_param("s", $token);
                    $stmt->execute();
                    $result = $stmt->get_result();
                    
                    if ($result->num_rows > 0) {
                        $user = $result->fetch_assoc();
                        
                        // Hash new password
                        $password_hash = hash_password($new_password);
                        
                        // Update password and clear token
                        $updateStmt = $conn->prepare("UPDATE users SET password_hash = ?, reset_token = NULL, reset_token_expires = NULL WHERE id = ?");
                        $updateStmt->bind_param("si", $password_hash, $user['id']);
                        
                        if ($updateStmt->execute()) {
                            $message = "Password has been reset successfully. You can now login with your new password.";
                            $toastClass = "success";
                            log_security_event($user['email'], "PASSWORD_RESET_SUCCESS");
                            
                            // Redirect to login after 3 seconds
                            header("refresh:3;url=login.php");
                        } else {
                            $message = "Error resetting password. Please try again.";
                            $toastClass = "danger";
                        }
                        $updateStmt->close();
                    } else {
                        $message = "Invalid or expired reset token. Please request a new one.";
                        $toastClass = "danger";
                        log_security_event("INVALID_RESET_TOKEN", "Token: $token");
                    }
                    $stmt->close();
                }
            }
        }
    }
    $conn->close();
}

$csrf_token = generate_csrf_token();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="SecureAuth - Password Reset">
    <meta name="robots" content="noindex, nofollow">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.css">
    <link rel="shortcut icon" href="https://cdn-icons-png.flaticon.com/512/295/295128.png">
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/js/bootstrap.bundle.min.js"></script>
    <title>SecureAuth - Password Reset</title>
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
    </style>
</head>

<body>
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header text-center">
                        <h3><i class="fa fa-key"></i> Password Reset</h3>
                        <p class="mb-0">SecureAuth Password Recovery</p>
                    </div>
                    <div class="card-body p-4">
                        
                        <!-- Step 1: Request Reset -->
                        <div id="step1">
                            <h5 class="mb-3">Step 1: Request Password Reset</h5>
                            <form method="POST" id="requestResetForm">
                                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                
                                <div class="mb-3">
                                    <label for="email" class="form-label">
                                        <i class="fa fa-envelope"></i> Email Address
                                    </label>
                                    <input type="email" name="email" id="email" class="form-control" 
                                           required placeholder="Enter your registered email address">
                                </div>
                                
                                <div class="d-grid">
                                    <button type="submit" name="request_reset" class="btn btn-primary btn-lg">
                                        <i class="fa fa-paper-plane"></i> Send Reset Instructions
                                    </button>
                                </div>
                            </form>
                        </div>
                        
                        <!-- Step 2: Reset Password -->
                        <div id="step2" style="display: none;">
                            <h5 class="mb-3">Step 2: Reset Your Password</h5>
                            <form method="POST" id="resetPasswordForm">
                                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                
                                <div class="mb-3">
                                    <label for="token" class="form-label">
                                        <i class="fa fa-key"></i> Reset Token
                                    </label>
                                    <input type="text" name="token" id="token" class="form-control" 
                                           required placeholder="Enter the reset token from your email">
                                </div>
                                
                                <div class="mb-3">
                                    <label for="new_password" class="form-label">
                                        <i class="fa fa-lock"></i> New Password
                                    </label>
                                    <div class="input-group">
                                        <input type="password" name="new_password" id="new_password" class="form-control" 
                                               required placeholder="Enter new password">
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
                                        <i class="fa fa-lock"></i> Confirm New Password
                                    </label>
                                    <input type="password" name="confirm_password" id="confirm_password" class="form-control" 
                                           required placeholder="Confirm new password">
                                </div>
                                
                                <div class="d-grid">
                                    <button type="submit" name="reset_password" class="btn btn-primary btn-lg">
                                        <i class="fa fa-check"></i> Reset Password
                                    </button>
                                </div>
                            </form>
                        </div>
                        
                        <div class="text-center mt-4">
                            <p class="mb-0">
                                <a href="login.php" class="text-decoration-none">
                                    <i class="fa fa-arrow-left"></i> Back to Login
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
            const password = document.getElementById('new_password');
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
        document.getElementById('new_password').addEventListener('input', function() {
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

        // Show step 2 if token is provided
        const urlParams = new URLSearchParams(window.location.search);
        if (urlParams.get('token')) {
            document.getElementById('step1').style.display = 'none';
            document.getElementById('step2').style.display = 'block';
            document.getElementById('token').value = urlParams.get('token');
        }

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