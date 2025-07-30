# 🔐 SecureAuth - Secure User Authentication System

A comprehensive and secure web application authentication system built with PHP, featuring advanced security measures and modern UI design.

## 🚀 Features

### ✅ **Core Authentication**
- **Secure User Registration** with email validation
- **Advanced Login System** with password hashing
- **Session Management** with automatic timeout
- **Password Reset** functionality
- **User Dashboard** with activity monitoring

### 🛡️ **Security Implementations**

#### **Input Validation & Sanitization**
- Server-side and client-side validation
- Input sanitization to prevent XSS attacks
- Email format validation
- Username format validation (3-20 characters, alphanumeric + underscore)

#### **Password Security**
- **Argon2id** password hashing (industry standard)
- Strong password requirements:
  - Minimum 8 characters
  - At least one uppercase letter
  - At least one lowercase letter
  - At least one number
  - At least one special character
- Password strength meter
- Secure password confirmation

#### **Session Security**
- **HttpOnly** cookies
- **Secure** cookie flag
- **SameSite** cookie attribute
- Session regeneration on login
- Session timeout (1 hour)
- IP address validation
- User agent tracking

#### **Protection Against Common Attacks**

##### **SQL Injection Protection**
- Prepared statements for all database queries
- Parameterized queries
- Input sanitization

##### **Cross-Site Scripting (XSS) Protection**
- Input sanitization with `htmlspecialchars()`
- Content Security Policy headers
- Output encoding

##### **Cross-Site Request Forgery (CSRF) Protection**
- CSRF tokens on all forms
- Token validation on form submission
- Secure token generation

##### **Brute Force Attack Protection**
- Rate limiting (5 attempts per 5 minutes)
- Account lockout after 5 failed attempts
- 15-minute lockout duration
- IP-based rate limiting

##### **Session Fixation Protection**
- Session ID regeneration on login
- Secure session management

#### **Security Headers**
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Content-Security-Policy` headers

### 📊 **Admin Panel**
- **Security Monitoring** dashboard
- **User Management** interface
- **Login Activity** tracking
- **Locked Accounts** monitoring
- **System Statistics** and charts
- **Security Event** logging

### 🎨 **Modern UI/UX**
- **Responsive Design** with Bootstrap 5
- **Gradient Backgrounds** and modern styling
- **Interactive Elements** with JavaScript
- **Toast Notifications** for user feedback
- **Password Visibility Toggle**
- **Loading States** and animations

## 🛠️ **Installation**

### **Prerequisites**
- PHP 7.4 or higher
- MySQL 5.7 or higher
- Web server (Apache/Nginx)
- XAMPP/WAMP/MAMP (for local development)

### **Setup Instructions**

1. **Clone/Download the Project**
   ```bash
   git clone https://github.com/yourusername/secureauth.git
   cd secureauth
   ```

2. **Database Setup**
   - Start your MySQL server
   - Create a new database named `secureauth`
   - Import the `database_setup.sql` file:
   ```bash
   mysql -u root -p secureauth < database_setup.sql
   ```

3. **Configuration**
   - Update database credentials in `database/db_connect.php`
   - Configure email settings in `config/security.php` (optional)
   - Set up your web server to point to the project directory

4. **Default Admin Account**
   - Username: `admin`
   - Password: `admin123`
   - **Important**: Change the default password after first login!

5. **Access the Application**
   - User Login: `http://localhost/secureauth/`
   - Admin Panel: `http://localhost/secureauth/admin/`

## 📁 **Project Structure**

```
secureauth/
├── admin/                 # Admin panel files
│   ├── index.php         # Admin dashboard
│   └── login.php         # Admin login
├── config/               # Configuration files
│   └── security.php      # Security settings and functions
├── database/             # Database files
│   └── db_connect.php    # Database connection
├── pages/                # User pages
│   ├── login.php         # User login
│   ├── register.php      # User registration
│   ├── dashboard.php     # User dashboard
│   ├── logout.php        # Logout functionality
│   ├── resetpassword.php # Password reset
│   └── check_email.php   # Email verification
├── database_setup.sql    # Database schema
├── index.php             # Main entry point
└── README.md            # This file
```

## 🔧 **Configuration**

### **Database Configuration**
Edit `database/db_connect.php`:
```php
$servername = "localhost";
$username = "your_db_username";
$password = "your_db_password";
$dbname = "secureauth";
```

### **Security Settings**
Edit `config/security.php`:
```php
// Session timeout (in seconds)
define('SESSION_TIMEOUT', 3600);

// Maximum login attempts
define('MAX_LOGIN_ATTEMPTS', 5);

// Lockout duration (in seconds)
define('LOCKOUT_DURATION', 900);

// Minimum password length
define('PASSWORD_MIN_LENGTH', 8);
```

### **Email Configuration** (Optional)
For email verification features, update the email settings in `config/security.php`:
```php
define('SMTP_HOST', 'smtp.gmail.com');
define('SMTP_PORT', 587);
define('SMTP_USERNAME', 'your-email@gmail.com');
define('SMTP_PASSWORD', 'your-app-password');
```

## 🛡️ **Security Features Explained**

### **1. Password Hashing**
Uses Argon2id, the most secure password hashing algorithm:
```php
function hash_password($password) {
    return password_hash($password, PASSWORD_ARGON2ID, [
        'memory_cost' => 65536,
        'time_cost' => 4,
        'threads' => 3
    ]);
}
```

### **2. CSRF Protection**
Every form includes a CSRF token:
```php
<input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
```

### **3. Rate Limiting**
Prevents brute force attacks:
```php
if (!check_rate_limit($ip_address, 'login', 5, 300)) {
    // Block access
}
```

### **4. Session Security**
Secure session configuration:
```php
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 1);
ini_set('session.cookie_samesite', 'Strict');
```

## 📊 **Database Schema**

### **Users Table**
- `id` - Primary key
- `username` - Unique username
- `email` - Unique email address
- `password_hash` - Hashed password
- `email_verified` - Email verification status
- `login_attempts` - Failed login counter
- `account_locked` - Account lock status
- `created_at` - Registration timestamp

### **User Sessions Table**
- `id` - Primary key
- `user_id` - Foreign key to users
- `session_id` - Unique session identifier
- `ip_address` - Client IP address
- `user_agent` - Browser information
- `expires_at` - Session expiration time

### **Login Logs Table**
- `id` - Primary key
- `user_id` - Foreign key to users
- `email` - Email used in attempt
- `ip_address` - Client IP address
- `success` - Login success status
- `attempt_time` - Timestamp of attempt

## 🚨 **Security Best Practices**

### **For Developers**
1. **Never store passwords in plain text**
2. **Always use prepared statements**
3. **Validate and sanitize all inputs**
4. **Implement proper session management**
5. **Use HTTPS in production**
6. **Regular security audits**

### **For Users**
1. **Use strong, unique passwords**
2. **Enable two-factor authentication when available**
3. **Logout from shared computers**
4. **Monitor login activity regularly**
5. **Report suspicious activity**

## 🔍 **Testing Security Features**

### **SQL Injection Test**
Try entering `' OR '1'='1` in login fields - should be blocked.

### **XSS Test**
Try entering `<script>alert('XSS')</script>` - should be sanitized.

### **CSRF Test**
Try submitting forms without CSRF tokens - should be rejected.

### **Brute Force Test**
Try multiple failed login attempts - account should be locked.

## 📈 **Performance Optimization**

- **Database Indexing** on frequently queried columns
- **Session Cleanup** for expired sessions
- **Log Rotation** for security logs
- **Caching** for static content
- **CDN** for external resources

## 🐛 **Troubleshooting**

### **Common Issues**

1. **Database Connection Error**
   - Check database credentials
   - Ensure MySQL server is running
   - Verify database exists

2. **Session Issues**
   - Check PHP session configuration
   - Verify file permissions
   - Clear browser cookies

3. **Email Not Working**
   - Configure SMTP settings
   - Check email credentials
   - Verify port settings

## 📝 **License**

This project is licensed under the MIT License - see the LICENSE file for details.

## 🤝 **Contributing**

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📞 **Support**

For support and questions:
- Create an issue on GitHub
- Email: support@secureauth.com
- Documentation: [Wiki](https://github.com/yourusername/secureauth/wiki)

## 🔄 **Updates & Maintenance**

- **Regular Security Updates**
- **Database Maintenance**
- **Log Monitoring**
- **Backup Procedures**
- **Performance Monitoring**

---

**⚠️ Important Security Notice:**
This system implements industry-standard security practices, but security is an ongoing process. Regular updates and monitoring are essential for maintaining security.

**🔒 Remember:** Always change default passwords and keep your system updated! 