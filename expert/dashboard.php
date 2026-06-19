<?php
require_once '../includes/session_check.php';
require_role(['expert']);
require_once '../includes/db.php';
$page_title = 'Expert Dashboard';
$uid = $_SESSION['user_id'];

$stmt = $conn->prepare("SELECT COUNT(*) FROM cases WHERE assigned_to = ?"); $stmt->bind_param("i",$uid); $stmt->execute(); $stmt->bind_result($total); $stmt->fetch(); $stmt->close();
$stmt = $conn->prepare("SELECT COUNT(*) FROM cases WHERE assigned_to = ? AND status = 'open'"); $stmt->bind_param("i",$uid); $stmt->execute(); $stmt->bind_result($open); $stmt->fetch(); $stmt->close();
$stmt = $conn->prepare("SELECT COUNT(*) FROM cases WHERE assigned_to = ? AND status = 'in_progress'"); $stmt->bind_param("i",$uid); $stmt->execute(); $stmt->bind_result($inprog); $stmt->fetch(); $stmt->close();
$stmt = $conn->prepare("SELECT COUNT(*) FROM cases WHERE assigned_to = ? AND status = 'resolved'"); $stmt->bind_param("i",$uid); $stmt->execute(); $stmt->bind_result($resolved); $stmt->fetch(); $stmt->close();

$recent = $conn->prepare("SELECT c.id, c.title, c.severity, c.status, c.created_at FROM cases c WHERE c.assigned_to = ? ORDER BY c.updated_at DESC LIMIT 6");
$recent->bind_param("i",$uid); $recent->execute(); $cases = $recent->get_result();

include '../includes/header.php';
?>
<h4 class="page-title"><i class="bi bi-house me-2"></i>Expert Dashboard</h4>
<div class="row mb-4">
    <div class="col-md-3"><div class="stat-card bg-primary"><div class="stat-number"><?= $total ?></div><div class="stat-label"><i class="bi bi-folder me-1"></i>Assigned Cases</div></div></div>
    <div class="col-md-3"><div class="stat-card bg-warning text-dark"><div class="stat-number"><?= $open ?></div><div class="stat-label"><i class="bi bi-clock me-1"></i>Open</div></div></div>
    <div class="col-md-3"><div class="stat-card bg-info"><div class="stat-number"><?= $inprog ?></div><div class="stat-label"><i class="bi bi-arrow-repeat me-1"></i>In Progress</div></div></div>
    <div class="col-md-3"><div class="stat-card bg-success"><div class="stat-number"><?= $resolved ?></div><div class="stat-label"><i class="bi bi-check-circle me-1"></i>Resolved</div></div></div>
</div>

<div class="card">
    <div class="card-header bg-primary text-white d-flex justify-content-between align-items-center">
        <span><i class="bi bi-clock-history me-2"></i>Recent Assigned Cases</span>
        <a href="/threat_intel/expert/my_cases.php" class="btn btn-sm btn-light">View All</a>
    </div>
    <div class="card-body p-0">
        <table class="table table-hover mb-0">
            <thead><tr><th>#</th><th>Title</th><th>Severity</th><th>Status</th><th>Date</th><th></th></tr></thead>
            <tbody>
            <?php $count=0; while($c = $cases->fetch_assoc()): $count++; ?>
            <tr>
                <td><?= $c['id'] ?></td>
                <td><?= htmlspecialchars($c['title']) ?></td>
                <td><span class="severity-badge severity-<?= $c['severity'] ?>"><?= $c['severity'] ?></span></td>
                <td><span class="badge bg-secondary"><?= str_replace('_',' ',$c['status']) ?></span></td>
                <td><?= date('d M Y', strtotime($c['created_at'])) ?></td>
                <td><a href="/threat_intel/expert/case_detail.php?id=<?= $c['id'] ?>" class="btn btn-sm btn-outline-primary">Investigate</a></td>
            </tr>
            <?php endwhile; if($count===0): ?>
            <tr><td colspan="6" class="text-center text-muted py-4">No cases assigned to you yet.</td></tr>
            <?php endif; ?>
            </tbody>
        </table>
    </div>
</div>
<?php include '../includes/footer.php'; ?>
