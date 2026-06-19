<?php
require_once '../includes/session_check.php';
require_role(['org_admin']);
require_once '../includes/db.php';
$page_title = 'Org Admin Dashboard';
$oid = $_SESSION['org_id'];

// Stats
$stmt = $conn->prepare("SELECT COUNT(*) FROM cases WHERE org_id = ?"); $stmt->bind_param("i",$oid); $stmt->execute(); $stmt->bind_result($total); $stmt->fetch(); $stmt->close();
$stmt = $conn->prepare("SELECT COUNT(*) FROM cases WHERE org_id = ? AND status='open'"); $stmt->bind_param("i",$oid); $stmt->execute(); $stmt->bind_result($open); $stmt->fetch(); $stmt->close();
$stmt = $conn->prepare("SELECT COUNT(*) FROM cases WHERE org_id = ? AND status='in_progress'"); $stmt->bind_param("i",$oid); $stmt->execute(); $stmt->bind_result($inprog); $stmt->fetch(); $stmt->close();
$stmt = $conn->prepare("SELECT COUNT(*) FROM cases WHERE org_id = ? AND severity='Critical'"); $stmt->bind_param("i",$oid); $stmt->execute(); $stmt->bind_result($critical); $stmt->fetch(); $stmt->close();
$stmt = $conn->prepare("SELECT COUNT(*) FROM alerts WHERE org_id = ? AND is_read=0"); $stmt->bind_param("i",$oid); $stmt->execute(); $stmt->bind_result($unread_alerts); $stmt->fetch(); $stmt->close();
$stmt = $conn->prepare("SELECT COUNT(*) FROM users WHERE org_id = ? AND is_active=1"); $stmt->bind_param("i",$oid); $stmt->execute(); $stmt->bind_result($users); $stmt->fetch(); $stmt->close();

// Severity breakdown
$sev_q = $conn->prepare("SELECT severity, COUNT(*) as cnt FROM cases WHERE org_id = ? GROUP BY severity");
$sev_q->bind_param("i",$oid); $sev_q->execute(); $sev_rows = $sev_q->get_result()->fetch_all(MYSQLI_ASSOC);
$sev_map = array_column($sev_rows, 'cnt', 'severity');

// Recent cases
$recent = $conn->prepare("SELECT c.id, c.title, c.severity, c.status, c.created_at, u.full_name as reporter FROM cases c JOIN users u ON c.reported_by=u.id WHERE c.org_id=? ORDER BY c.created_at DESC LIMIT 6");
$recent->bind_param("i",$oid); $recent->execute(); $cases = $recent->get_result();

// Recent alerts
$alerts_q = $conn->prepare("SELECT a.id, a.message, a.created_at, i.ioc_value FROM alerts a JOIN iocs i ON a.ioc_id=i.id WHERE a.org_id=? AND a.is_read=0 ORDER BY a.created_at DESC LIMIT 4");
$alerts_q->bind_param("i",$oid); $alerts_q->execute(); $alerts = $alerts_q->get_result()->fetch_all(MYSQLI_ASSOC);

include '../includes/header.php';
?>
<h4 class="page-title"><i class="bi bi-house me-2"></i>Organization Dashboard</h4>

<div class="row mb-4">
    <div class="col-md-2"><div class="stat-card bg-primary"><div class="stat-number"><?= $total ?></div><div class="stat-label">Total Cases</div></div></div>
    <div class="col-md-2"><div class="stat-card bg-warning text-dark"><div class="stat-number"><?= $open ?></div><div class="stat-label">Open</div></div></div>
    <div class="col-md-2"><div class="stat-card bg-info"><div class="stat-number"><?= $inprog ?></div><div class="stat-label">In Progress</div></div></div>
    <div class="col-md-2"><div class="stat-card bg-danger"><div class="stat-number"><?= $critical ?></div><div class="stat-label">Critical</div></div></div>
    <div class="col-md-2"><div class="stat-card bg-dark position-relative"><div class="stat-number"><?= $unread_alerts ?></div><div class="stat-label">Unread Alerts</div></div></div>
    <div class="col-md-2"><div class="stat-card bg-success"><div class="stat-number"><?= $users ?></div><div class="stat-label">Active Users</div></div></div>
</div>

<div class="row">
<div class="col-lg-8">
    <div class="card mb-4">
        <div class="card-header bg-primary text-white d-flex justify-content-between">
            <span><i class="bi bi-folder me-2"></i>Recent Cases</span>
            <a href="/threat_intel/org-admin/cases.php" class="btn btn-sm btn-light">View All</a>
        </div>
        <div class="card-body p-0">
            <table class="table table-hover mb-0">
                <thead><tr><th>#</th><th>Title</th><th>Severity</th><th>Status</th><th>Reporter</th><th>Date</th><th></th></tr></thead>
                <tbody>
                <?php $cnt=0; while($c=$cases->fetch_assoc()): $cnt++; ?>
                <tr>
                    <td><?= $c['id'] ?></td>
                    <td><?= htmlspecialchars($c['title']) ?></td>
                    <td><span class="severity-badge severity-<?= $c['severity'] ?>"><?= $c['severity'] ?></span></td>
                    <td><span class="badge bg-secondary"><?= str_replace('_',' ',$c['status']) ?></span></td>
                    <td><?= htmlspecialchars($c['reporter']) ?></td>
                    <td><?= date('d M Y', strtotime($c['created_at'])) ?></td>
                    <td><a href="/threat_intel/org-admin/case_detail.php?id=<?= $c['id'] ?>" class="btn btn-sm btn-outline-primary">Manage</a></td>
                </tr>
                <?php endwhile; if($cnt===0): ?><tr><td colspan="7" class="text-center text-muted py-3">No cases yet.</td></tr><?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>
</div>

<div class="col-lg-4">
    <!-- Severity Breakdown -->
    <div class="card mb-4">
        <div class="card-header bg-warning text-dark"><i class="bi bi-bar-chart me-1"></i>Severity Breakdown</div>
        <div class="card-body">
            <?php foreach(['Critical'=>'danger','High'=>'warning','Medium'=>'info','Low'=>'success'] as $sev=>$col): ?>
            <div class="d-flex justify-content-between align-items-center mb-2">
                <span class="severity-badge severity-<?= $sev ?>"><?= $sev ?></span>
                <span class="badge bg-<?= $col ?> fs-6"><?= $sev_map[$sev] ?? 0 ?></span>
            </div>
            <?php endforeach; ?>
        </div>
    </div>

    <!-- Unread Alerts -->
    <div class="card mb-4">
        <div class="card-header bg-danger text-white d-flex justify-content-between">
            <span><i class="bi bi-bell me-1"></i>Unread Alerts</span>
            <a href="/threat_intel/org-admin/alerts.php" class="btn btn-sm btn-light">View All</a>
        </div>
        <div class="card-body p-2">
            <?php if ($alerts): ?>
            <?php foreach($alerts as $al): ?>
            <div class="border rounded p-2 mb-2 small bg-light">
                <i class="bi bi-exclamation-triangle text-danger me-1"></i>
                IOC: <code><?= htmlspecialchars($al['ioc_value']) ?></code><br>
                <span class="text-muted"><?= date('d M H:i', strtotime($al['created_at'])) ?></span>
            </div>
            <?php endforeach; ?>
            <?php else: ?><p class="text-muted text-center mb-0 small py-2">No unread alerts.</p><?php endif; ?>
        </div>
    </div>
</div>
</div>
<?php include '../includes/footer.php'; ?>
