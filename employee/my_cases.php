<?php
require_once '../includes/session_check.php';
require_role(['employee']);
require_once '../includes/db.php';
$page_title = 'My Cases';
$uid = $_SESSION['user_id'];

$cases = $conn->prepare("SELECT c.id, c.title, c.attack_type, c.severity, c.status, c.severity_score, c.created_at, u.full_name as expert FROM cases c LEFT JOIN users u ON c.assigned_to = u.id WHERE c.reported_by = ? ORDER BY c.created_at DESC");
$cases->bind_param("i", $uid); $cases->execute(); $result = $cases->get_result();

include '../includes/header.php';
?>
<div class="d-flex justify-content-between align-items-center mb-4">
    <h4 class="page-title mb-0"><i class="bi bi-folder me-2"></i>My Cases</h4>
    <a href="/threat_intel/employee/file_complaint.php" class="btn btn-primary"><i class="bi bi-plus-circle me-1"></i>File New Complaint</a>
</div>
<div class="card">
    <div class="card-body p-0">
        <table class="table table-hover mb-0">
            <thead><tr><th>#</th><th>Title</th><th>Attack Type</th><th>Severity</th><th>Score</th><th>Status</th><th>Assigned To</th><th>Date</th><th></th></tr></thead>
            <tbody>
            <?php $count = 0; while($c = $result->fetch_assoc()): $count++; ?>
            <tr>
                <td><?= $c['id'] ?></td>
                <td><?= htmlspecialchars($c['title']) ?></td>
                <td><?= htmlspecialchars($c['attack_type']) ?></td>
                <td><span class="severity-badge severity-<?= $c['severity'] ?>"><?= $c['severity'] ?></span></td>
                <td><?= $c['severity_score'] ?></td>
                <td><span class="badge bg-secondary"><?= str_replace('_',' ',$c['status']) ?></span></td>
                <td><?= $c['expert'] ? htmlspecialchars($c['expert']) : '<span class="text-muted">Unassigned</span>' ?></td>
                <td><?= date('d M Y', strtotime($c['created_at'])) ?></td>
                <td><a href="/threat_intel/employee/case_view.php?id=<?= $c['id'] ?>" class="btn btn-sm btn-outline-primary">View</a></td>
            </tr>
            <?php endwhile; ?>
            <?php if ($count === 0): ?><tr><td colspan="9" class="text-center text-muted py-4">No cases filed yet. <a href="/threat_intel/employee/file_complaint.php">File your first complaint.</a></td></tr><?php endif; ?>
            </tbody>
        </table>
    </div>
</div>
<?php include '../includes/footer.php'; ?>
