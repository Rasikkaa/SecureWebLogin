# 🔐 CredGuard – Secure Web Application for User Authentication

CredGuard is a secure, PHP-MySQL-based web application that demonstrates core authentication mechanisms and defense against common web vulnerabilities. It includes a clean login and sign-up system, administrative controls, and robust backend security, making it ideal for learning and deployment in security-aware web development environments.

---

## 📌 Table of Contents

* [Features](#features)
* [Security Measures](#security-measures)
* [Technologies Used](#technologies-used)
* [Project Structure](#project-structure)
* [Installation & Setup](#installation--setup)
* [Default Admin Credentials](#default-admin-credentials)
* [Security Testing](#security-testing)
* [Troubleshooting](#troubleshooting)
* [Future Enhancements](#future-enhancements)
* [Author](#author)
* [License](#license)

---

## ✅ Features

### 👥 User System

* User registration with input validation
* Login system with hashed passwords
* Forgot password/reset functionality
* Session-based authentication
* Role-based access: Admin & User

### 🛠 Admin Panel

* View all registered users
* Delete or manage user accounts
* Protected routes accessible only to admins

---

## 🛡️ Security Measures

CredGuard follows OWASP guidelines and implements:

* **Input Validation & Sanitization:** Prevents Cross-site Scripting (XSS)
* **Prepared Statements (PDO):** Protects against SQL Injection
* **Password Hashing:** Uses `password_hash()` (bcrypt or Argon2)
* **CSRF Protection:** Token-based CSRF defense on sensitive forms
* **Session Management:** Regenerates session IDs on login; sets session timeout
* **Secure Cookies:** HTTPOnly and Secure flags
* **Brute Force Protection:** Lockout after repeated failed attempts
* **Error Handling:** Detailed errors hidden from users

---

## 🧰 Technologies Used

| Technology          | Purpose        |
| ------------------- | -------------- |
| PHP (v7.4+)         | Backend Logic  |
| MySQL               | Database       |
| HTML, CSS, JS       | Frontend       |
| Bootstrap 5         | UI Components  |
| PHP Sessions        | Authentication |
| Prepared Statements | SQL Security   |

---

## 📁 Project Structure

```
CredGuard/
├── admin/                 # Admin dashboard & actions
├── config/                # DB config & security utils
├── pages/                 # login, register, dashboard etc.
├── database_setup.sql     # SQL file to create schema
├── db_connect.php         # DB connection logic
├── index.php              # Default route
└── README.md              # Project documentation
```

---

## ⚙️ Installation & Setup

### 🖥️ Requirements

* PHP 7.4 or above
* MySQL 5.7 or above
* Apache/Nginx (XAMPP or WAMP recommended)

### 📦 Setup Steps

1. Clone or download the repository
2. Import the database:

   * Open phpMyAdmin
   * Create a DB: `secureauth`
   * Import `database_setup.sql` file
3. Update `db_connect.php` with your DB credentials
4. Launch app in browser:

   ```
   http://localhost/CredGuard/
   ```

---

## 🧑‍💼 Default Admin Credentials

| Role  | Username | Password |
| ----- | -------- | -------- |
| Admin | admin    | admin123 |

> ⚠️ Note: Change admin credentials immediately after first login.

---

## 🧪 Security Testing

| Test Scenario      | Sample Input                | Expected Behavior          |
| ------------------ | --------------------------- | -------------------------- |
| SQL Injection      | `' OR '1'='1`               | Query blocked              |
| XSS Injection      | `<script>alert(1)</script>` | Escaped or removed         |
| CSRF Token Missing | POST without token          | Rejected with error        |
| Brute Force Login  | 5+ failed login attempts    | Account temporarily locked |

---

## ❗ Troubleshooting

* Blank screen? Enable error reporting in `php.ini`
* Database connection error? Check `db_connect.php` credentials
* Session issues? Ensure `session_start()` and writable temp folder
* Admin panel inaccessible? Login with admin credentials only

---

## 🧩 Future Enhancements

* 2FA (Two-Factor Authentication)
* CAPTCHA integration during login/registration
* Email verification on sign-up
* Password strength meter
* Activity logging and audit trail

---

## 👨‍💻 Author

**Rasi P**
