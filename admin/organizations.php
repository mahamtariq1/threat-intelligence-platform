<?php
require_once '../includes/session_check.php';
require_role(['platform_admin']);
require_once '../includes/db.php';
$page_title = 'Organizations';
$success = '';

if ($_SERVER['REQUEST_METHOD']==='POST' && isset($_POST['toggle_org'])) {
    $oid = intval($_POST['org_id']);
    $new = intval($_POST['new_status']);
    $upd = $conn->prepare("UPDATE organizations SET is_active=? WHERE id=?");
    $upd->bind_param("ii",$new,$oid); $upd->execute();
    $success = "Organization status updated.";
}

$orgs = $conn->query("SELECT o.id, o.name, o.email, o.type, o.country, o.is_active, o.created_at, COUNT(DISTINCT u.id) as user_count, COUNT(DISTINCT c.id) as case_count FROM organizations o LEFT JOIN users u ON o.id=u.org_id AND u.role!='platform_admin' LEFT JOIN cases c ON o.id=c.org_id GROUP BY o.id ORDER BY o.created_at DESC")->fetch_all(MYSQLI_ASSOC);

include '../includes/header.php';
?>
<h4 class="page-title"><i class="bi bi-building me-2"></i>Registered Organizations (<?= count($orgs) ?>)</h4>
<?php if($success): ?><div class="alert alert-success alert-dismissible fade show"><?= htmlspecialchars($success) ?><button type="button" class="btn-close" data-bs-dismiss="alert"></button></div><?php endif; ?>

<div class="card">
    <div class="card-body p-0">
        <table class="table table-hover mb-0">
            <thead><tr><th>#</th><th>Organization</th><th>Email</th><th>Type</th><th>Country</th><th>Users</th><th>Cases</th><th>Status</th><th>Registered</th><th>Action</th></tr></thead>
            <tbody>
            <?php foreach($orgs as $o): ?>
            <tr>
                <td><?= $o['id'] ?></td>
                <td><strong><?= htmlspecialchars($o['name']) ?></strong></td>
                <td><?= htmlspecialchars($o['email']) ?></td>
                <td><?= htmlspecialchars($o['type']) ?></td>
                <td><?= htmlspecialchars($o['country']) ?></td>
                <td><?= $o['user_count'] ?></td>
                <td><?= $o['case_count'] ?></td>
                <td><?= $o['is_active'] ? '<span class="badge bg-success">Active</span>' : '<span class="badge bg-secondary">Inactive</span>' ?></td>
                <td><?= date('d M Y', strtotime($o['created_at'])) ?></td>
                <td>
                    <form method="POST" class="d-inline">
                        <input type="hidden" name="toggle_org" value="1">
                        <input type="hidden" name="org_id" value="<?= $o['id'] ?>">
                        <input type="hidden" name="new_status" value="<?= $o['is_active']?0:1 ?>">
                        <button class="btn btn-sm <?= $o['is_active']?'btn-outline-danger':'btn-outline-success' ?>"><?= $o['is_active']?'Deactivate':'Activate' ?></button>
                    </form>
                </td>
            </tr>
            <?php endforeach; ?>
            <?php if(!$orgs): ?><tr><td colspan="10" class="text-center text-muted py-4">No organizations registered yet.</td></tr><?php endif; ?>
            </tbody>
        </table>
    </div>
</div>
<?php include '../includes/footer.php'; ?>
