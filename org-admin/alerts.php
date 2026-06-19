<?php
require_once '../includes/session_check.php';
require_role(['org_admin']);
require_once '../includes/db.php';
$page_title = 'Threat Alerts';
$oid = $_SESSION['org_id'];

// Mark alert as read
if ($_SERVER['REQUEST_METHOD']==='POST' && isset($_POST['mark_read'])) {
    $aid = intval($_POST['alert_id']);
    $upd = $conn->prepare("UPDATE alerts SET is_read=1 WHERE id=? AND org_id=?");
    $upd->bind_param("ii",$aid,$oid); $upd->execute();
}

// Mark all read
if (isset($_POST['mark_all_read'])) {
    $conn->prepare("UPDATE alerts SET is_read=1 WHERE org_id=?")->bind_param("i",$oid);
    $upd = $conn->prepare("UPDATE alerts SET is_read=1 WHERE org_id=?");
    $upd->bind_param("i",$oid); $upd->execute();
}

$show_read = isset($_GET['show_read']);
$sql = "SELECT a.id, a.message, a.is_read, a.created_at, i.ioc_value, i.ioc_type, i.times_seen, a.case_id FROM alerts a JOIN iocs i ON a.ioc_id=i.id WHERE a.org_id=?";
if (!$show_read) $sql .= " AND a.is_read=0";
$sql .= " ORDER BY a.created_at DESC";
$stmt = $conn->prepare($sql); $stmt->bind_param("i",$oid); $stmt->execute();
$alerts = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);

$stmt2 = $conn->prepare("SELECT COUNT(*) FROM alerts WHERE org_id=? AND is_read=0");
$stmt2->bind_param("i",$oid); $stmt2->execute(); $stmt2->bind_result($unread_count); $stmt2->fetch(); $stmt2->close();

include '../includes/header.php';
?>
<div class="d-flex justify-content-between align-items-center mb-3">
    <h4 class="page-title mb-0"><i class="bi bi-bell me-2"></i>Threat Alerts <?php if($unread_count): ?><span class="badge bg-danger"><?= $unread_count ?> unread</span><?php endif; ?></h4>
    <div class="d-flex gap-2">
        <?php if ($unread_count): ?>
        <form method="POST" class="d-inline"><button name="mark_all_read" class="btn btn-outline-secondary btn-sm"><i class="bi bi-check-all me-1"></i>Mark All Read</button></form>
        <?php endif; ?>
        <a href="?<?= $show_read ? '' : 'show_read=1' ?>" class="btn btn-outline-primary btn-sm"><?= $show_read ? 'Show Unread Only' : 'Show All (incl. Read)' ?></a>
    </div>
</div>

<?php if (!$alerts): ?>
<div class="alert alert-info"><i class="bi bi-info-circle me-2"></i>No <?= $show_read?'':'unread ' ?>alerts. Your organization has not been matched to any cross-organization IOCs yet.</div>
<?php else: ?>
<div class="card">
    <div class="card-body p-0">
        <table class="table table-hover mb-0">
            <thead><tr><th>IOC</th><th>Type</th><th>Seen</th><th>Message</th><th>Source Case</th><th>Date</th><th>Status</th><th></th></tr></thead>
            <tbody>
            <?php foreach($alerts as $a): ?>
            <tr class="<?= !$a['is_read']?'table-warning':'' ?>">
                <td><code style="font-size:0.8rem"><?= htmlspecialchars($a['ioc_value']) ?></code></td>
                <td><span class="badge bg-secondary"><?= $a['ioc_type'] ?></span></td>
                <td><?= $a['times_seen'] ?>x</td>
                <td class="small"><?= htmlspecialchars($a['message']) ?></td>
                <td><a href="/threat_intel/org-admin/case_detail.php?id=<?= $a['case_id'] ?>" class="small">#<?= $a['case_id'] ?></a></td>
                <td class="small"><?= date('d M Y H:i', strtotime($a['created_at'])) ?></td>
                <td><?= $a['is_read']?'<span class="badge bg-secondary">Read</span>':'<span class="badge bg-warning text-dark">Unread</span>' ?></td>
                <td>
                    <?php if(!$a['is_read']): ?>
                    <form method="POST" class="d-inline"><input type="hidden" name="alert_id" value="<?= $a['id'] ?>"><button name="mark_read" class="btn btn-sm btn-outline-success"><i class="bi bi-check"></i></button></form>
                    <?php endif; ?>
                </td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>
<?php endif; ?>
<?php include '../includes/footer.php'; ?>
