<?php
session_start();
if (isset($_SESSION['user_id'])) {
    $role = $_SESSION['role'];
    if ($role === 'platform_admin') header("Location: /threat_intel/admin/dashboard.php");
    elseif ($role === 'org_admin')  header("Location: /threat_intel/org-admin/dashboard.php");
    elseif ($role === 'expert')     header("Location: /threat_intel/expert/dashboard.php");
    else                            header("Location: /threat_intel/employee/dashboard.php");
    exit();
}
require_once '../includes/db.php';
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email    = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    if (!$email || !$password) {
        $error = 'Please enter both email and password.';
    } else {
        $stmt = $conn->prepare("SELECT u.id, u.full_name, u.password_hash, u.role, u.is_active, u.org_id, o.is_active as org_active FROM users u LEFT JOIN organizations o ON u.org_id = o.id WHERE u.email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $user = $stmt->get_result()->fetch_assoc();
        if (!$user || !password_verify($password, $user['password_hash'])) {
            $error = 'Invalid email or password.';
        } elseif (!$user['is_active']) {
            $error = 'Your account has been deactivated.';
        } elseif ($user['org_id'] && $user['org_active'] == 0) {
            $error = 'Your organization has been deactivated.';
        } else {
            session_regenerate_id(true);
            $_SESSION['user_id']   = $user['id'];
            $_SESSION['full_name'] = $user['full_name'];
            $_SESSION['role']      = $user['role'];
            $_SESSION['org_id']    = $user['org_id'];
            if ($user['role'] === 'platform_admin') header("Location: /threat_intel/admin/dashboard.php");
            elseif ($user['role'] === 'org_admin')  header("Location: /threat_intel/org-admin/dashboard.php");
            elseif ($user['role'] === 'expert')     header("Location: /threat_intel/expert/dashboard.php");
            else                                    header("Location: /threat_intel/employee/dashboard.php");
            exit();
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login — ThreatIntel Platform</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Syne:wght@400;700;800&family=DM+Sans:wght@300;400;500&display=swap" rel="stylesheet">
    <style>
        :root { --bg:#1e2736; --surface:#0f1520; --surface2:#141a28; --border:#1c2535; --border2:#21303f; --teal:#0d9488; --teal-bright:#14b8a6; --text:#e2e8f0; --muted:#64748b; --muted2:#3d4f63; }
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'DM Sans', sans-serif; background: var(--bg); min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }
        .split-card { display: flex; width: 100%; max-width: 880px; min-height: 520px; border-radius: 20px; overflow: hidden; border: 0.5px solid var(--border2); }
        .split-left { flex: 1.1; background: var(--surface); padding: 36px; display: flex; flex-direction: column; justify-content: space-between; position: relative; overflow: hidden; border-right: 0.5px solid var(--border); }
        .brand { font-family: 'Syne', sans-serif; font-weight: 800; font-size: 20px; color: var(--text); }
        .brand span { color: var(--teal-bright); }
        .blob { position: absolute; border-radius: 50%; }
        .blob1 { width: 260px; height: 260px; top: 40px; left: -70px; border: 1px solid rgba(13,148,136,0.2); }
        .blob2 { width: 190px; height: 190px; top: 170px; left: 30px; border: 1px solid rgba(13,148,136,0.12); }
        .blob3 { width: 150px; height: 150px; bottom: 60px; right: 10px; border: 1px solid rgba(13,148,136,0.18); }
        .blob4 { width: 100px; height: 100px; bottom: 20px; left: 50px; border: 1px solid rgba(13,148,136,0.08); }
        .welcome { font-family: 'Syne', sans-serif; font-weight: 800; font-size: 40px; color: var(--text); line-height: 1.05; letter-spacing: -1.5px; position: relative; z-index: 2; }
        .tagline { font-size: 12px; color: var(--muted); margin-top: 10px; position: relative; z-index: 2; }
        .split-right { flex: 1; background: var(--surface); padding: 52px 44px; display: flex; flex-direction: column; justify-content: center; }
        .login-title { font-family: 'Syne', sans-serif; font-weight: 800; font-size: 28px; color: var(--text); margin-bottom: 30px; letter-spacing: -0.5px; }
        .field { position: relative; margin-bottom: 14px; }
        .field svg { position: absolute; left: 14px; top: 50%; transform: translateY(-50%); opacity: 0.3; }
        .field input { width: 100%; background: var(--surface2); border: 0.5px solid var(--border2); border-radius: 10px; padding: 13px 16px 13px 42px; font-size: 14px; font-family: 'DM Sans', sans-serif; color: var(--text); outline: none; transition: border-color 0.15s; }
        .field input:focus { border-color: var(--teal-bright); }
        .field input::placeholder { color: var(--muted2); }
        .row-opts { display: flex; justify-content: space-between; align-items: center; margin: 6px 0 22px; }
        .remember { display: flex; align-items: center; gap: 8px; font-size: 12px; color: var(--muted); }
        .remember input { accent-color: var(--teal); }
        .forgot { font-size: 12px; color: var(--muted); text-decoration: none; }
        .forgot:hover { color: var(--teal-bright); }
        .btn-login { width: 100%; background: var(--teal); color: #fff; border: none; border-radius: 11px; padding: 14px; font-family: 'Syne', sans-serif; font-weight: 700; font-size: 15px; cursor: pointer; transition: background 0.15s; }
        .btn-login:hover { background: #0a7a70; }
        .divider { display: flex; align-items: center; gap: 12px; margin: 18px 0; }
        .divider div { flex: 1; height: 0.5px; background: var(--border2); }
        .divider span { font-size: 12px; color: var(--muted); }
        .btn-signup { width: 100%; background: transparent; border: 0.5px solid var(--border2); color: var(--text); border-radius: 11px; padding: 13px; font-size: 14px; font-family: 'DM Sans', sans-serif; cursor: pointer; text-align: center; text-decoration: none; display: block; transition: all 0.15s; }
        .btn-signup:hover { border-color: var(--teal-bright); color: var(--teal-bright); }
        .error-box { background: rgba(239,68,68,0.1); border: 0.5px solid rgba(239,68,68,0.3); color: #f87171; border-radius: 10px; padding: 10px 14px; font-size: 13px; margin-bottom: 18px; }
        @media (max-width: 600px) { .split-left { display: none; } .split-card { max-width: 420px; } }
    </style>
</head>
<body>
<div class="split-card">
    <div class="split-left">
        <div class="brand">ThreatIntel<span>.</span></div>
        <div class="blob blob1"></div>
        <div class="blob blob2"></div>
        <div class="blob blob3"></div>
        <div class="blob blob4"></div>
        <div>
            <div class="welcome">Welcome<br>Back!</div>
            <div class="tagline">Collaborative Cyber Incident Response Platform</div>
        </div>
    </div>
    <div class="split-right">
        <div class="login-title">Log in</div>
        <?php if ($error): ?><div class="error-box"><?= htmlspecialchars($error) ?></div><?php endif; ?>
        <form method="POST" novalidate>
            <div class="field">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                <input type="email" name="email" placeholder="Email address" required value="<?= htmlspecialchars($_POST['email'] ?? '') ?>">
            </div>
            <div class="field">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                <input type="password" name="password" placeholder="Password" required>
            </div>
            <div class="row-opts">
                <label class="remember"><input type="checkbox" name="remember"> Remember Me</label>
                <a href="#" class="forgot">Forgot Password?</a>
            </div>
            <button type="submit" class="btn-login">Log in</button>
        </form>
        <div class="divider"><div></div><span>Or</span><div></div></div>
        <a href="/threat_intel/auth/register.php" class="btn-signup">Sign up</a>
    </div>
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
