<?php
require_once '../includes/session_check.php';
require_role(['org_admin']);
require_once '../includes/db.php';
$page_title = 'User Management';
$oid = $_SESSION['org_id'];
$uid = $_SESSION['user_id'];
$success = ''; $error = '';

// Handle create user
if ($_SERVER['REQUEST_METHOD']==='POST' && isset($_POST['action'])) {
    if ($_POST['action']==='create') {
        $name  = trim($_POST['full_name'] ?? '');
        $email = trim($_POST['email'] ?? '');
        $pass  = $_POST['password'] ?? '';
        $role  = $_POST['role'] ?? '';
        if (!$name||!$email||!$pass||!in_array($role,['employee','expert'])) {
            $error = 'All fields are required and role must be employee or expert.';
        } else {
            $chk = $conn->prepare("SELECT id FROM users WHERE email=?"); $chk->bind_param("s",$email); $chk->execute(); $chk->store_result();
            if ($chk->num_rows>0) { $error = 'Email already registered.'; }
            else {
                $hash = password_hash($pass, PASSWORD_BCRYPT);
                $ins = $conn->prepare("INSERT INTO users (org_id, full_name, email, password_hash, role) VALUES (?,?,?,?,?)");
                $ins->bind_param("issss",$oid,$name,$email,$hash,$role); $ins->execute();
                $success = "User '$name' created successfully as $role.";
            }
        }
    } elseif ($_POST['action']==='toggle') {
        $toggle_id = intval($_POST['user_id']);
        $new_status = intval($_POST['new_status']);
        // Cannot deactivate self
        if ($toggle_id !== $uid) {
            $upd = $conn->prepare("UPDATE users SET is_active=? WHERE id=? AND org_id=?");
            $upd->bind_param("iii",$new_status,$toggle_id,$oid); $upd->execute();
            $success = "User status updated.";
        } else { $error = "You cannot deactivate your own account."; }
    }
}

$users_q = $conn->prepare("SELECT id, full_name, email, role, is_active, created_at FROM users WHERE org_id=? ORDER BY role, full_name");
$users_q->bind_param("i",$oid); $users_q->execute(); $users = $users_q->get_result()->fetch_all(MYSQLI_ASSOC);

include '../includes/header.php';
?>
<h4 class="page-title"><i class="bi bi-people me-2"></i>User Management</h4>
<?php if($success): ?><div class="alert alert-success alert-dismissible fade show"><?= htmlspecialchars($success) ?><button type="button" class="btn-close" data-bs-dismiss="alert"></button></div><?php endif; ?>
<?php if($error): ?><div class="alert alert-danger"><?= htmlspecialchars($error) ?></div><?php endif; ?>

<div class="row">
<div class="col-lg-4 mb-4">
    <div class="card">
        <div class="card-header bg-success text-white"><i class="bi bi-person-plus me-1"></i>Add New User</div>
        <div class="card-body">
            <form method="POST">
                <input type="hidden" name="action" value="create">
                <div class="mb-2">
                    <label class="form-label fw-semibold small">Full Name</label>
                    <input type="text" name="full_name" class="form-control form-control-sm" required>
                </div>
                <div class="mb-2">
                    <label class="form-label fw-semibold small">Email</label>
                    <input type="email" name="email" class="form-control form-control-sm" required>
                </div>
                <div class="mb-2">
                    <label class="form-label fw-semibold small">Password</label>
                    <input type="password" name="password" class="form-control form-control-sm" required minlength="6">
                </div>
                <div class="mb-3">
                    <label class="form-label fw-semibold small">Role</label>
                    <select name="role" class="form-select form-select-sm" required>
                        <option value="">Select role...</option>
                        <option value="employee">Employee</option>
                        <option value="expert">Cybersecurity Expert</option>
                    </select>
                </div>
                <button class="btn btn-success btn-sm w-100"><i class="bi bi-person-plus me-1"></i>Create User</button>
            </form>
        </div>
    </div>
</div>

<div class="col-lg-8">
    <div class="card">
        <div class="card-header bg-primary text-white"><i class="bi bi-people me-1"></i>Organization Users (<?= count($users) ?>)</div>
        <div class="card-body p-0">
            <table class="table table-hover mb-0">
                <thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Status</th><th>Since</th><th>Action</th></tr></thead>
                <tbody>
                <?php foreach($users as $u): ?>
                <tr>
                    <td><?= htmlspecialchars($u['full_name']) ?> <?= $u['id']===$uid?'<span class="badge bg-primary">You</span>':'' ?></td>
                    <td><?= htmlspecialchars($u['email']) ?></td>
                    <td><span class="badge bg-info text-dark"><?= htmlspecialchars(str_replace('_',' ',$u['role'])) ?></span></td>
                    <td><?= $u['is_active'] ? '<span class="badge bg-success">Active</span>' : '<span class="badge bg-secondary">Inactive</span>' ?></td>
                    <td><?= date('d M Y', strtotime($u['created_at'])) ?></td>
                    <td>
                        <?php if ($u['id']!==$uid): ?>
                        <form method="POST" class="d-inline">
                            <input type="hidden" name="action" value="toggle">
                            <input type="hidden" name="user_id" value="<?= $u['id'] ?>">
                            <input type="hidden" name="new_status" value="<?= $u['is_active']?0:1 ?>">
                            <button class="btn btn-sm <?= $u['is_active']?'btn-outline-danger':'btn-outline-success' ?>"><?= $u['is_active']?'Deactivate':'Activate' ?></button>
                        </form>
                        <?php endif; ?>
                    </td>
                </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>
</div>
</div>
<?php include '../includes/footer.php'; ?>
