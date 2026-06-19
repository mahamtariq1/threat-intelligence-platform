<?php
session_start();
require_once '../includes/db.php';
$error = ''; $success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $org_name  = trim($_POST['org_name'] ?? '');
    $org_type  = trim($_POST['org_type'] ?? '');
    $country   = trim($_POST['country'] ?? '');
    $full_name = trim($_POST['full_name'] ?? '');
    $email     = trim($_POST['email'] ?? '');
    $password  = $_POST['password'] ?? '';
    $confirm   = $_POST['confirm_password'] ?? '';
    if (!$org_name || !$org_type || !$country || !$full_name || !$email || !$password) {
        $error = 'All fields are required.';
    } elseif ($password !== $confirm) {
        $error = 'Passwords do not match.';
    } elseif (strlen($password) < 6) {
        $error = 'Password must be at least 6 characters.';
    } else {
        $chk = $conn->prepare("SELECT id FROM users WHERE email = ?");
        $chk->bind_param("s", $email); $chk->execute(); $chk->store_result();
        if ($chk->num_rows > 0) {
            $error = 'An account with this email already exists.';
        } else {
            $stmt = $conn->prepare("INSERT INTO organizations (name, email, type, country) VALUES (?, ?, ?, ?)");
            $stmt->bind_param("ssss", $org_name, $email, $org_type, $country); $stmt->execute();
            $org_id = $conn->insert_id;
            $hash = password_hash($password, PASSWORD_BCRYPT);
            $u = $conn->prepare("INSERT INTO users (org_id, full_name, email, password_hash, role) VALUES (?, ?, ?, ?, 'org_admin')");
            $u->bind_param("isss", $org_id, $full_name, $email, $hash); $u->execute();
            $success = 'Organization registered successfully!';
        }
    }
}
$org_types = ['Government','Financial','Healthcare','Education','Technology','Retail','Manufacturing','Other'];
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register — ThreatIntel Platform</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Syne:wght@400;700;800&family=DM+Sans:wght@300;400;500&display=swap" rel="stylesheet">
    <style>
        :root { --bg:#1e2736; --surface:#0f1520; --surface2:#141a28; --border:#1c2535; --border2:#21303f; --teal:#0d9488; --teal-bright:#14b8a6; --text:#e2e8f0; --muted:#64748b; --muted2:#3d4f63; }
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'DM Sans', sans-serif; background: var(--bg); min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 30px 20px; }
        .split-card { display: flex; width: 100%; max-width: 960px; min-height: 580px; border-radius: 20px; overflow: hidden; border: 0.5px solid var(--border2); }
        .split-left { flex: 0.75; background: var(--surface); padding: 36px; display: flex; flex-direction: column; justify-content: space-between; position: relative; overflow: hidden; border-right: 0.5px solid var(--border); }
        .brand { font-family: 'Syne', sans-serif; font-weight: 800; font-size: 20px; color: var(--text); }
        .brand span { color: var(--teal-bright); }
        .blob { position: absolute; border-radius: 50%; }
        .blob1 { width: 240px; height: 240px; top: 50px; left: -60px; border: 1px solid rgba(13,148,136,0.2); }
        .blob2 { width: 170px; height: 170px; bottom: 80px; right: 10px; border: 1px solid rgba(13,148,136,0.15); }
        .blob3 { width: 120px; height: 120px; bottom: 30px; left: 40px; border: 1px solid rgba(13,148,136,0.08); }
        .welcome { font-family: 'Syne', sans-serif; font-weight: 800; font-size: 34px; color: var(--text); line-height: 1.05; letter-spacing: -1px; position: relative; z-index: 2; }
        .tagline { font-size: 12px; color: var(--muted); margin-top: 10px; line-height: 1.6; position: relative; z-index: 2; }
        .split-right { flex: 1; background: var(--surface); padding: 40px 44px; overflow-y: auto; }
        .reg-title { font-family: 'Syne', sans-serif; font-weight: 800; font-size: 24px; color: var(--text); margin-bottom: 24px; letter-spacing: -0.5px; }
        .section-lbl { font-size: 11px; font-weight: 600; color: var(--teal-bright); text-transform: uppercase; letter-spacing: 0.8px; margin: 20px 0 14px; padding-bottom: 8px; border-bottom: 0.5px solid var(--border); }
        .section-lbl:first-of-type { margin-top: 0; }
        .form-row { display: grid; gap: 12px; margin-bottom: 12px; }
        .form-row.two { grid-template-columns: 1fr 1fr; }
        .form-row.one { grid-template-columns: 1fr; }
        .fgroup label { display: block; font-size: 11px; font-weight: 500; color: var(--muted); text-transform: uppercase; letter-spacing: 0.4px; margin-bottom: 6px; }
        .fgroup input, .fgroup select { width: 100%; background: var(--surface2); border: 0.5px solid var(--border2); border-radius: 9px; padding: 11px 14px; font-size: 13px; font-family: 'DM Sans', sans-serif; color: var(--text); outline: none; transition: border-color 0.15s; appearance: none; }
        .fgroup input:focus, .fgroup select:focus { border-color: var(--teal-bright); }
        .fgroup input::placeholder { color: var(--muted2); }
        .fgroup select option { background: var(--surface2); }
        .btn-register { width: 100%; background: var(--teal); color: #fff; border: none; border-radius: 11px; padding: 13px; font-family: 'Syne', sans-serif; font-weight: 700; font-size: 14px; cursor: pointer; margin-top: 20px; transition: background 0.15s; }
        .btn-register:hover { background: #0a7a70; }
        .back-link { display: block; text-align: center; margin-top: 16px; font-size: 12px; color: var(--muted); text-decoration: none; }
        .back-link:hover { color: var(--teal-bright); }
        .error-box { background: rgba(239,68,68,0.1); border: 0.5px solid rgba(239,68,68,0.3); color: #f87171; border-radius: 10px; padding: 10px 14px; font-size: 13px; margin-bottom: 16px; }
        .success-box { background: rgba(13,148,136,0.1); border: 0.5px solid rgba(13,148,136,0.3); color: var(--teal-bright); border-radius: 10px; padding: 10px 14px; font-size: 13px; margin-bottom: 16px; }
        @media (max-width: 640px) { .split-left { display: none; } .form-row.two { grid-template-columns: 1fr; } }
    </style>
</head>
<body>
<div class="split-card">
    <div class="split-left">
        <div class="brand">ThreatIntel<span>.</span></div>
        <div class="blob blob1"></div>
        <div class="blob blob2"></div>
        <div class="blob blob3"></div>
        <div>
            <div class="welcome">Join the<br>Network.</div>
            <div class="tagline">Register your organization to start reporting incidents and sharing threat intelligence across the platform.</div>
        </div>
    </div>
    <div class="split-right">
        <div class="reg-title">Register Organization</div>
        <?php if ($error): ?><div class="error-box"><?= htmlspecialchars($error) ?></div><?php endif; ?>
        <?php if ($success): ?><div class="success-box"><?= htmlspecialchars($success) ?> <a href="/threat_intel/auth/login.php" style="color:var(--teal-bright);">Log in →</a></div><?php endif; ?>
        <form method="POST" novalidate>
            <div class="section-lbl">Organization Details</div>
            <div class="form-row two">
                <div class="fgroup"><label>Organization Name</label><input type="text" name="org_name" required placeholder="e.g. National Bank" value="<?= htmlspecialchars($_POST['org_name'] ?? '') ?>"></div>
                <div class="fgroup"><label>Type</label>
                    <select name="org_type" required>
                        <option value="">Select type...</option>
                        <?php foreach ($org_types as $t): ?><option value="<?= $t ?>" <?= ($_POST['org_type'] ?? '') === $t ? 'selected' : '' ?>><?= $t ?></option><?php endforeach; ?>
                    </select>
                </div>
            </div>
            <div class="form-row one">
                <div class="fgroup"><label>Country</label><input type="text" name="country" required placeholder="e.g. Pakistan" value="<?= htmlspecialchars($_POST['country'] ?? '') ?>"></div>
            </div>
            <div class="section-lbl">Admin Account</div>
            <div class="form-row one">
                <div class="fgroup"><label>Full Name</label><input type="text" name="full_name" required placeholder="e.g. Sara Ahmed" value="<?= htmlspecialchars($_POST['full_name'] ?? '') ?>"></div>
            </div>
            <div class="form-row one">
                <div class="fgroup"><label>Email Address</label><input type="email" name="email" required placeholder="you@organization.com" value="<?= htmlspecialchars($_POST['email'] ?? '') ?>"></div>
            </div>
            <div class="form-row two">
                <div class="fgroup"><label>Password</label><input type="password" name="password" required placeholder="Min. 6 characters"></div>
                <div class="fgroup"><label>Confirm Password</label><input type="password" name="confirm_password" required placeholder="Repeat password"></div>
            </div>
            <button type="submit" class="btn-register">Register Organization</button>
        </form>
        <a href="/threat_intel/auth/login.php" class="back-link">← Already have an account? Log in</a>
    </div>
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
