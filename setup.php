<?php
// ============================================================
// SETUP SCRIPT - Run this ONCE in your browser after importing
// database.sql to create the platform admin account
// URL: http://localhost/threat_intel/setup.php
// DELETE this file after running it!
// ============================================================

$host = 'localhost';
$dbname = 'threat_intel_db';
$user = 'root';
$pass = '2879o288i6@Ee';

$conn = new mysqli($host, $user, $pass, $dbname);
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

$email = 'admin@platform.com';
$password = 'Admin@123';
$hash = password_hash($password, PASSWORD_BCRYPT);

// Check if already exists
$check = $conn->prepare("SELECT id FROM users WHERE email = ?");
$check->bind_param("s", $email);
$check->execute();
$check->store_result();

if ($check->num_rows > 0) {
    echo "<h2 style='color:orange;font-family:Arial'>Platform admin already exists. Setup not needed.</h2>";
} else {
    $stmt = $conn->prepare("INSERT INTO users (org_id, full_name, email, password_hash, role) VALUES (NULL, 'Platform Administrator', ?, ?, 'platform_admin')");
    $stmt->bind_param("ss", $email, $hash);
    if ($stmt->execute()) {
        echo "<h2 style='color:green;font-family:Arial'>✓ Setup complete!</h2>";
        echo "<p style='font-family:Arial'>Platform admin created.<br><br>";
        echo "<strong>Login:</strong> admin@platform.com<br>";
        echo "<strong>Password:</strong> Admin@123</p>";
        echo "<p style='font-family:Arial;color:red'><strong>DELETE this setup.php file now for security!</strong></p>";
        echo "<p><a href='index.php' style='font-family:Arial'>→ Go to Login</a></p>";
    } else {
        echo "<h2 style='color:red;font-family:Arial'>Error: " . $stmt->error . "</h2>";
    }
}

$conn->close();
?>
