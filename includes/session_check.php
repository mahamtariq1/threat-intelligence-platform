<?php
// Call this at top of every protected page
// Usage: require_role(['org_admin', 'expert']);

function require_role($allowed_roles) {
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
    if (!isset($_SESSION['user_id'])) {
        header("Location: /threat_intel/auth/login.php");
        exit();
    }
    if (!in_array($_SESSION['role'], $allowed_roles)) {
        header("Location: /threat_intel/auth/login.php");
        exit();
    }
}

function is_logged_in() {
    if (session_status() === PHP_SESSION_NONE) session_start();
    return isset($_SESSION['user_id']);
}
?>
