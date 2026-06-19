<?php
$db_host = 'localhost';
$db_user = 'root';
$db_pass = '2879o288i6@Ee';
$db_name = 'threat_intel_db';
$conn = new mysqli($db_host, $db_user, $db_pass, $db_name);
if ($conn->connect_error) {
    die("<div style='font-family:Arial;padding:20px;color:red;'>Database connection failed: " . $conn->connect_error . "</div>");
}
$conn->set_charset("utf8mb4");
?>