<?php
require_once '../includes/session_check.php';
require_role(['employee']);
require_once '../includes/db.php';
$page_title = 'Dashboard';

$uid = $_SESSION['user_id'];
$oid = $_SESSION['org_id'];

$stmt = $conn->prepare("SELECT COUNT(*) FROM cases WHERE reported_by = ?"); $stmt->bind_param("i",$uid); $stmt->execute(); $stmt->bind_result($total_cases); $stmt->fetch(); $stmt->close();
$stmt = $conn->prepare("SELECT COUNT(*) FROM cases WHERE reported_by = ? AND status = 'open'"); $stmt->bind_param("i",$uid); $stmt->execute(); $stmt->bind_result($open_cases); $stmt->fetch(); $stmt->close();
$stmt = $conn->prepare("SELECT COUNT(*) FROM cases WHERE reported_by = ? AND status = 'resolved'"); $stmt->bind_param("i",$uid); $stmt->execute(); $stmt->bind_result($resolved_cases); $stmt->fetch(); $stmt->close();

$recent = $conn->prepare("SELECT c.id, c.title, c.severity, c.status, c.created_at FROM cases c WHERE c.reported_by = ? ORDER BY c.created_at DESC LIMIT 5");
$recent->bind_param("i",$uid); $recent->execute(); $cases = $recent->get_result();

include '../includes/header.php';
?>
<h4 class="page-title"><i class="bi bi-house me-2"></i>Employee Dashboard</h4>
<div class="row mb-4">
    <div class="col-md-4"><div class="stat-card bg-primary"><div class="stat-number"><?= $total_cases ?></div><div class="stat-label"><i class="bi bi-folder me-1"></i>Total Cases Filed</div></div></div>
    <div class="col-md-4"><div class="stat-card bg-warning text-dark"><div class="stat-number"><?= $open_cases ?></div><div class="stat-label"><i class="bi bi-clock me-1"></i>Open Cases</div></div></div>
    <div class="col-md-4"><div class="stat-card bg-success"><div class="stat-number"><?= $resolved_cases ?></div><div class="stat-label"><i class="bi bi-check-circle me-1"></i>Resolved Cases</div></div></div>
</div>

<div class="card">
    <div class="card-header bg-primary text-white d-flex justify-content-between align-items-center">
        <span><i class="bi bi-clock-history me-2"></i>Recent Cases</span>
        <a href="/threat_intel/employee/file_complaint.php" class="btn btn-sm btn-light"><i class="bi bi-plus-circle me-1"></i>File New Complaint</a>
    </div>
    <div class="card-body p-0">
        <table class="table table-hover mb-0">
            <thead><tr><th>#</th><th>Title</th><th>Severity</th><th>Status</th><th>Date</th><th></th></tr></thead>
            <tbody>
            <?php while($c = $cases->fetch_assoc()): ?>
            <tr>
                <td><?= $c['id'] ?></td>
                <td><?= htmlspecialchars($c['title']) ?></td>
                <td><span class="severity-badge severity-<?= $c['severity'] ?>"><?= $c['severity'] ?></span></td>
                <td><span class="badge bg-secondary"><?= str_replace('_',' ',$c['status']) ?></span></td>
                <td><?= date('d M Y', strtotime($c['created_at'])) ?></td>
                <td><a href="/threat_intel/employee/case_view.php?id=<?= $c['id'] ?>" class="btn btn-sm btn-outline-primary">View</a></td>
            </tr>
            <?php endwhile; ?>
            <?php if ($total_cases == 0): ?><tr><td colspan="6" class="text-center text-muted py-4">No cases yet. <a href="/threat_intel/employee/file_complaint.php">File your first complaint.</a></td></tr><?php endif; ?>
            </tbody>
        </table>
    </div>
</div>
<?php include '../includes/footer.php'; ?>
