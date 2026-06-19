<?php
require_once '../includes/session_check.php';
require_role(['employee']);
require_once '../includes/db.php';
$page_title = 'Case Details';

$case_id = intval($_GET['id'] ?? 0);
$uid = $_SESSION['user_id'];

$stmt = $conn->prepare("SELECT c.*, u.full_name as expert_name, m.name as mitre_name, m.tactic as mitre_tactic, m.technique_id as mitre_tid FROM cases c LEFT JOIN users u ON c.assigned_to = u.id LEFT JOIN mitre_techniques m ON c.mitre_technique_id = m.id WHERE c.id = ? AND c.reported_by = ?");
$stmt->bind_param("ii", $case_id, $uid);
$stmt->execute();
$case = $stmt->get_result()->fetch_assoc();

if (!$case) { header("Location: /threat_intel/employee/my_cases.php"); exit(); }

$iocs_q = $conn->prepare("SELECT DISTINCT i.ioc_value, i.ioc_type FROM ioc_sightings s JOIN iocs i ON s.ioc_id = i.id WHERE s.case_id = ?");
$iocs_q->bind_param("i", $case_id); $iocs_q->execute(); $iocs = $iocs_q->get_result();

$logs_q = $conn->prepare("SELECT l.action, l.details, l.created_at, u.full_name FROM case_logs l LEFT JOIN users u ON l.user_id = u.id WHERE l.case_id = ? ORDER BY l.created_at ASC");
$logs_q->bind_param("i", $case_id); $logs_q->execute(); $logs = $logs_q->get_result();

include '../includes/header.php';
if (isset($_GET['new'])): ?>
<div class="alert alert-success"><i class="bi bi-check-circle me-2"></i>Your complaint has been submitted and analyzed. Severity assigned: <strong><?= $case['severity'] ?></strong>.</div>
<?php endif; ?>
<h4 class="page-title"><i class="bi bi-folder me-2"></i>Case #<?= $case_id ?> — <?= htmlspecialchars($case['title']) ?></h4>

<div class="row">
<div class="col-lg-4 mb-4">
    <div class="card h-100">
        <div class="card-header bg-primary text-white"><i class="bi bi-info-circle me-1"></i> Case Info</div>
        <div class="card-body">
            <table class="table table-sm table-borderless mb-0">
                <tr><th>Status</th><td><span class="badge bg-secondary"><?= str_replace('_',' ',$case['status']) ?></span></td></tr>
                <tr><th>Severity</th><td><span class="severity-badge severity-<?= $case['severity'] ?>"><?= $case['severity'] ?></span></td></tr>
                <tr><th>Score</th><td><?= $case['severity_score'] ?></td></tr>
                <tr><th>Attack Type</th><td><?= htmlspecialchars($case['attack_type']) ?></td></tr>
                <tr><th>Assigned To</th><td><?= $case['expert_name'] ? htmlspecialchars($case['expert_name']) : '<span class="text-muted">Unassigned</span>' ?></td></tr>
                <tr><th>Filed</th><td><?= date('d M Y H:i', strtotime($case['created_at'])) ?></td></tr>
            </table>
        </div>
    </div>
</div>
<div class="col-lg-8 mb-4">
    <div class="card">
        <div class="card-header bg-primary text-white"><i class="bi bi-file-text me-1"></i> Description</div>
        <div class="card-body"><p class="mb-0"><?= nl2br(htmlspecialchars($case['description'])) ?></p></div>
    </div>
    <?php if ($case['mitre_name']): ?>
    <div class="card mt-3">
        <div class="card-header bg-warning text-dark"><i class="bi bi-diagram-3 me-1"></i> MITRE ATT&CK Mapping</div>
        <div class="card-body">
            <span class="badge bg-dark me-2"><?= htmlspecialchars($case['mitre_tid']) ?></span>
            <strong><?= htmlspecialchars($case['mitre_name']) ?></strong><br>
            <small class="text-muted">Tactic: <?= htmlspecialchars($case['mitre_tactic']) ?></small>
        </div>
    </div>
    <?php endif; ?>
</div>
</div>

<?php $ioc_rows = $iocs->fetch_all(MYSQLI_ASSOC); if ($ioc_rows): ?>
<div class="card mb-4">
    <div class="card-header bg-danger text-white"><i class="bi bi-exclamation-triangle me-1"></i> Extracted IOCs (<?= count($ioc_rows) ?>)</div>
    <div class="card-body"><?php foreach ($ioc_rows as $ioc): ?><span class="ioc-tag"><span class="text-muted"><?= $ioc['ioc_type'] ?>:</span> <?= htmlspecialchars($ioc['ioc_value']) ?></span><?php endforeach; ?></div>
</div>
<?php endif; ?>

<div class="card">
    <div class="card-header bg-secondary text-white"><i class="bi bi-journal-text me-1"></i> Case Activity</div>
    <div class="card-body">
        <?php while($log = $logs->fetch_assoc()): ?>
        <div class="audit-log-item">
            <strong><?= htmlspecialchars(str_replace('_',' ', $log['action'])) ?></strong>
            <?php if ($log['full_name']): ?> &mdash; <?= htmlspecialchars($log['full_name']) ?><?php endif; ?>
            <br><small class="text-muted"><?= date('d M Y H:i', strtotime($log['created_at'])) ?></small>
            <?php if ($log['details']): ?><br><span class="text-secondary"><?= htmlspecialchars($log['details']) ?></span><?php endif; ?>
        </div>
        <?php endwhile; ?>
    </div>
</div>
<?php include '../includes/footer.php'; ?>
