<?php
require_once '../includes/session_check.php';
require_role(['expert']);
require_once '../includes/db.php';
$page_title = 'Assigned Cases';
$uid = $_SESSION['user_id'];

$filter = $_GET['status'] ?? '';
$sql = "SELECT c.id, c.title, c.attack_type, c.severity, c.severity_score, c.status, c.created_at, u.full_name as reporter FROM cases c JOIN users u ON c.reported_by = u.id WHERE c.assigned_to = ?";
if ($filter) $sql .= " AND c.status = '" . $conn->real_escape_string($filter) . "'";
$sql .= " ORDER BY c.updated_at DESC";
$stmt = $conn->prepare($sql); $stmt->bind_param("i",$uid); $stmt->execute(); $result = $stmt->get_result();

include '../includes/header.php';
?>
<div class="d-flex justify-content-between align-items-center mb-4">
    <h4 class="page-title mb-0"><i class="bi bi-folder me-2"></i>My Assigned Cases</h4>
    <div class="btn-group">
        <a href="?" class="btn btn-sm <?= !$filter ? 'btn-primary' : 'btn-outline-primary' ?>">All</a>
        <a href="?status=open" class="btn btn-sm <?= $filter==='open' ? 'btn-warning' : 'btn-outline-warning' ?>">Open</a>
        <a href="?status=in_progress" class="btn btn-sm <?= $filter==='in_progress' ? 'btn-info' : 'btn-outline-info' ?>">In Progress</a>
        <a href="?status=resolved" class="btn btn-sm <?= $filter==='resolved' ? 'btn-success' : 'btn-outline-success' ?>">Resolved</a>
    </div>
</div>
<div class="card">
    <div class="card-body p-0">
        <table class="table table-hover mb-0">
            <thead><tr><th>#</th><th>Title</th><th>Attack Type</th><th>Severity</th><th>Score</th><th>Status</th><th>Reporter</th><th>Date</th><th></th></tr></thead>
            <tbody>
            <?php $count=0; while($c=$result->fetch_assoc()): $count++; ?>
            <tr>
                <td><?= $c['id'] ?></td>
                <td><?= htmlspecialchars($c['title']) ?></td>
                <td><?= htmlspecialchars($c['attack_type']) ?></td>
                <td><span class="severity-badge severity-<?= $c['severity'] ?>"><?= $c['severity'] ?></span></td>
                <td><?= $c['severity_score'] ?></td>
                <td><span class="badge bg-secondary"><?= str_replace('_',' ',$c['status']) ?></span></td>
                <td><?= htmlspecialchars($c['reporter']) ?></td>
                <td><?= date('d M Y', strtotime($c['created_at'])) ?></td>
                <td><a href="/threat_intel/expert/case_detail.php?id=<?= $c['id'] ?>" class="btn btn-sm btn-outline-primary">Investigate</a></td>
            </tr>
            <?php endwhile; if($count===0): ?>
            <tr><td colspan="9" class="text-center text-muted py-4">No cases found.</td></tr>
            <?php endif; ?>
            </tbody>
        </table>
    </div>
</div>
<?php include '../includes/footer.php'; ?>
