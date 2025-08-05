## 🔐 CredGuard – Secure Web Application for User Authentication

**CredGuard** is a secure and modern web application built with PHP and MySQL, designed to demonstrate robust authentication mechanisms and security best practices. It features a login and sign-up system with protection against common web vulnerabilities.

---

## 🚀 Features

### 🔑 Core Authentication

* Secure user registration with input validation
* Login system with hashed passwords
* Password reset functionality
* User session management
* Admin panel with user management

### 🛡️ Security Highlights

* **Input Validation & Sanitization** (to prevent XSS)
* **SQL Injection Protection** using prepared statements
* **Password Hashing** using Argon2id
* **CSRF Protection** with tokens
* **Session Security** with regeneration and timeout
* **Brute Force Protection** via rate limiting and account lockout
* **Secure HTTP Headers** and cookie flags

### 🎨 UI/UX

* Responsive design (Bootstrap 5)
* Modern interface with form validation, alerts, and animations
* User-friendly dashboard for users and admins

---

## 📁 Project Structure

```
CredGuard/
├── admin/                 # Admin dashboard & tools
├── config/                # Configuration & security functions
├── database/              # Database connection
├── pages/                 # Login, Register, Dashboard, etc.
├── database_setup.sql     # SQL schema file
├── index.php              # Landing page
└── README.md              # Documentation (this file)
```

---

## ⚙️ Installation

### Requirements

* PHP 7.4+
* MySQL 5.7+
* Apache/Nginx (or XAMPP/WAMP)

### Setup Steps

1. Clone or download the project:

   ```bash
   git clone https://github.com/yourusername/credguard.git
   cd credguard
   ```

2. Import the database:

   * Create a MySQL database named `secureauth`
   * Import `database_setup.sql`

3. Configure database connection:

   * Edit `database/db_connect.php` with your DB credentials

4. Launch in browser:

   * Access via `http://localhost/credguard/`

---

## 🔐 Default Admin Credentials

> ⚠️ **Important:** Change this after first login.

* **Username:** `admin`
* **Password:** `admin123`

---

## 🧪 Security Testing

| Test                          | Expected Behavior              |
| ----------------------------- | ------------------------------ |
| SQL Injection (`' OR 1=1`)    | Blocked (prepared statements)  |
| XSS Script Injection          | Sanitized (`htmlspecialchars`) |
| CSRF (missing token)          | Rejected form submission       |
| Brute Force (multiple logins) | Locked after 5 failed attempts |

---

## 📌 Notes

* Built for academic demonstration of secure web development
* Uses industry-standard techniques, but **not production-hardened**
* Modular code for easy customization

---


## 👨‍💻 Author

**Rasi P** 

