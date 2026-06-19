<?php
if (session_status() === PHP_SESSION_NONE) session_start();
$role      = $_SESSION['role'] ?? '';
$full_name = $_SESSION['full_name'] ?? '';

$alert_count = 0;
if ($role === 'org_admin' && isset($_SESSION['org_id'])) {
    require_once __DIR__ . '/db.php';
    $stmt = $conn->prepare("SELECT COUNT(*) FROM alerts WHERE org_id = ? AND is_read = 0");
    $stmt->bind_param("i", $_SESSION['org_id']);
    $stmt->execute();
    $stmt->bind_result($alert_count);
    $stmt->fetch();
    $stmt->close();
}

// Get initials for avatar
$initials = '';
$parts = explode(' ', $full_name);
foreach ($parts as $p) $initials .= strtoupper(substr($p, 0, 1));
$initials = substr($initials, 0, 2);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= isset($page_title) ? htmlspecialchars($page_title) . ' — ' : '' ?>ThreatIntel Platform</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/bootstrap-icons.css" rel="stylesheet">
    <link href="/threat_intel/assets/style.css" rel="stylesheet">
</head>
<body>

<nav class="navbar navbar-expand-lg">
    <div class="container-fluid px-0">
        <a class="navbar-brand" href="#">ThreatIntel<span style="color:var(--teal-bright);">.</span></a>
        <button class="navbar-toggler border-0" type="button" data-bs-toggle="collapse" data-bs-target="#navMain">
            <span style="color:var(--muted);font-size:20px;">&#9776;</span>
        </button>
        <div class="collapse navbar-collapse" id="navMain">
            <ul class="navbar-nav mx-auto">

                <?php if ($role === 'employee'): ?>
                <li class="nav-item"><a class="nav-link" href="/threat_intel/employee/dashboard.php">Dashboard</a></li>
                <li class="nav-item"><a class="nav-link" href="/threat_intel/employee/file_complaint.php">File Complaint</a></li>
                <li class="nav-item"><a class="nav-link" href="/threat_intel/employee/my_cases.php">My Cases</a></li>

                <?php elseif ($role === 'expert'): ?>
                <li class="nav-item"><a class="nav-link" href="/threat_intel/expert/dashboard.php">Dashboard</a></li>
                <li class="nav-item"><a class="nav-link" href="/threat_intel/expert/my_cases.php">Assigned Cases</a></li>

                <?php elseif ($role === 'org_admin'): ?>
                <li class="nav-item"><a class="nav-link" href="/threat_intel/org-admin/dashboard.php">Dashboard</a></li>
                <li class="nav-item"><a class="nav-link" href="/threat_intel/org-admin/cases.php">All Cases</a></li>
                <li class="nav-item"><a class="nav-link" href="/threat_intel/org-admin/users.php">Users</a></li>
                <li class="nav-item">
                    <a class="nav-link" href="/threat_intel/org-admin/alerts.php">
                        Alerts
                        <?php if ($alert_count > 0): ?>
                        <span class="badge bg-danger ms-1"><?= $alert_count ?></span>
                        <?php endif; ?>
                    </a>
                </li>

                <?php elseif ($role === 'platform_admin'): ?>
                <li class="nav-item"><a class="nav-link" href="/threat_intel/admin/dashboard.php">Dashboard</a></li>
                <li class="nav-item"><a class="nav-link" href="/threat_intel/admin/organizations.php">Organizations</a></li>
                <li class="nav-item"><a class="nav-link" href="/threat_intel/admin/iocs.php">Global IOCs</a></li>
                <li class="nav-item"><a class="nav-link" href="/threat_intel/admin/rules.php">Scoring Rules</a></li>
                <?php endif; ?>

            </ul>
            <ul class="navbar-nav ms-auto align-items-center">
                <li class="nav-item dropdown">
                    <a class="nav-link dropdown-toggle d-flex align-items-center gap-2 pe-0" href="#" data-bs-toggle="dropdown">
                        <span style="width:32px;height:32px;border-radius:50%;background:var(--teal);display:inline-flex;align-items:center;justify-content:center;font-size:12px;font-weight:700;color:#fff;flex-shrink:0;">
                            <?= $initials ?: '?' ?>
                        </span>
                        <span style="font-size:13px;color:var(--text);"><?= htmlspecialchars($full_name) ?></span>
                    </a>
                    <ul class="dropdown-menu dropdown-menu-end">
                        <li>
                            <span class="dropdown-item disabled" style="font-size:11px;color:var(--muted2) !important;text-transform:uppercase;letter-spacing:0.4px;">
                                <?= str_replace('_', ' ', $role) ?>
                            </span>
                        </li>
                        <li><hr class="dropdown-divider" style="border-color:var(--border);margin:4px 0;"></li>
                        <li><a class="dropdown-item" style="color:#f87171 !important;" href="/threat_intel/auth/logout.php">Logout</a></li>
                    </ul>
                </li>
            </ul>
        </div>
    </div>
</nav>

<div class="container-fluid py-4">
