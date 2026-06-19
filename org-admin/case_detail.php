<?php
require_once '../includes/session_check.php';
require_role(['org_admin']);
require_once '../includes/db.php';
$page_title = 'Case Detail';
$oid = $_SESSION['org_id'];
$uid = $_SESSION['user_id'];
$case_id = intval($_GET['id'] ?? 0);
$success = ''; $error = '';

// Fetch case - must belong to this org
$stmt = $conn->prepare("SELECT c.*, u.full_name as reporter, e.full_name as expert_name, m.name as mitre_name, m.tactic as mitre_tactic, m.technique_id as mitre_tid FROM cases c JOIN users u ON c.reported_by=u.id LEFT JOIN users e ON c.assigned_to=e.id LEFT JOIN mitre_techniques m ON c.mitre_technique_id=m.id WHERE c.id=? AND c.org_id=?");
$stmt->bind_param("ii",$case_id,$oid); $stmt->execute();
$case = $stmt->get_result()->fetch_assoc();
if (!$case) { header("Location: /threat_intel/org-admin/cases.php"); exit(); }

// Handle assign expert
if ($_SERVER['REQUEST_METHOD']==='POST' && isset($_POST['assign_expert'])) {
    $expert_id = intval($_POST['expert_id']);
    // Verify expert belongs to this org
    $chk = $conn->prepare("SELECT id, full_name FROM users WHERE id=? AND org_id=? AND role='expert' AND is_active=1");
    $chk->bind_param("ii",$expert_id,$oid); $chk->execute();
    $expert = $chk->get_result()->fetch_assoc();
    if ($expert) {
        $upd = $conn->prepare("UPDATE cases SET assigned_to=? WHERE id=?");
        $upd->bind_param("ii",$expert_id,$case_id); $upd->execute();
        $log = $conn->prepare("INSERT INTO case_logs (case_id, user_id, action, details) VALUES (?,?,'expert_assigned',?)");
        $detail = "Case assigned to expert: " . $expert['full_name'];
        $log->bind_param("iis",$case_id,$uid,$detail); $log->execute();
        $case['expert_name'] = $expert['full_name'];
        $case['assigned_to'] = $expert_id;
        $success = "Case assigned to " . htmlspecialchars($expert['full_name']);
    } else { $error = "Invalid expert selection."; }
}

// Experts in org
$experts_q = $conn->prepare("SELECT id, full_name FROM users WHERE org_id=? AND role='expert' AND is_active=1 ORDER BY full_name");
$experts_q->bind_param("i",$oid); $experts_q->execute(); $experts = $experts_q->get_result()->fetch_all(MYSQLI_ASSOC);

// IOCs, rules, logs
$iocs_q = $conn->prepare("SELECT DISTINCT i.ioc_value, i.ioc_type, i.times_seen, i.is_confirmed FROM ioc_sightings s JOIN iocs i ON s.ioc_id=i.id WHERE s.case_id=?");
$iocs_q->bind_param("i",$case_id); $iocs_q->execute(); $iocs = $iocs_q->get_result()->fetch_all(MYSQLI_ASSOC);

$rules_q = $conn->prepare("SELECT r.name, l.score_added, l.matched_value FROM rule_match_logs l JOIN severity_rules r ON l.rule_id=r.id WHERE l.case_id=? ORDER BY l.score_added DESC");
$rules_q->bind_param("i",$case_id); $rules_q->execute(); $rules = $rules_q->get_result()->fetch_all(MYSQLI_ASSOC);

$logs_q = $conn->prepare("SELECT l.action, l.details, l.created_at, u.full_name FROM case_logs l LEFT JOIN users u ON l.user_id=u.id WHERE l.case_id=? ORDER BY l.created_at ASC");
$logs_q->bind_param("i",$case_id); $logs_q->execute(); $logs = $logs_q->get_result()->fetch_all(MYSQLI_ASSOC);

include '../includes/header.php';
?>
<?php if($success): ?><div class="alert alert-success alert-dismissible fade show"><?= $success ?><button type="button" class="btn-close" data-bs-dismiss="alert"></button></div><?php endif; ?>
<?php if($error): ?><div class="alert alert-danger"><?= $error ?></div><?php endif; ?>

<div class="d-flex justify-content-between align-items-center mb-3">
    <h4 class="page-title mb-0"><i class="bi bi-folder me-2"></i>Case #<?= $case_id ?> — <?= htmlspecialchars($case['title']) ?></h4>
    <div>
        <a href="/threat_intel/expert/report.php?id=<?= $case_id ?>" class="btn btn-outline-dark btn-sm" target="_blank"><i class="bi bi-printer me-1"></i>Print Report</a>
        <a href="/threat_intel/org-admin/cases.php" class="btn btn-outline-secondary btn-sm"><i class="bi bi-arrow-left me-1"></i>Back</a>
    </div>
</div>

<div class="row">
<div class="col-lg-4">
    <div class="card mb-3">
        <div class="card-header bg-primary text-white"><i class="bi bi-info-circle me-1"></i>Case Info</div>
        <div class="card-body">
            <table class="table table-sm table-borderless mb-0 small">
                <tr><th>Attack Type</th><td><?= htmlspecialchars($case['attack_type']) ?></td></tr>
                <tr><th>Reporter</th><td><?= htmlspecialchars($case['reporter']) ?></td></tr>
                <tr><th>Severity</th><td><span class="severity-badge severity-<?= $case['severity'] ?>"><?= $case['severity'] ?></span></td></tr>
                <tr><th>Score</th><td><strong><?= $case['severity_score'] ?></strong></td></tr>
                <tr><th>Status</th><td><span class="badge bg-secondary"><?= str_replace('_',' ',$case['status']) ?></span></td></tr>
                <tr><th>Filed</th><td><?= date('d M Y H:i', strtotime($case['created_at'])) ?></td></tr>
                <tr><th>Assigned To</th><td><?= $case['expert_name'] ? htmlspecialchars($case['expert_name']) : '<span class="text-muted">Unassigned</span>' ?></td></tr>
            </table>
        </div>
    </div>

    <!-- Assign Expert -->
    <div class="card mb-3">
        <div class="card-header bg-success text-white"><i class="bi bi-person-check me-1"></i>Assign Expert</div>
        <div class="card-body">
            <?php if ($experts): ?>
            <form method="POST">
                <select name="expert_id" class="form-select form-select-sm mb-2" required>
                    <option value="">-- Select Expert --</option>
                    <?php foreach($experts as $e): ?>
                    <option value="<?= $e['id'] ?>" <?= $case['assigned_to']==$e['id']?'selected':'' ?>><?= htmlspecialchars($e['full_name']) ?></option>
                    <?php endforeach; ?>
                </select>
                <button name="assign_expert" class="btn btn-success btn-sm w-100">Assign</button>
            </form>
            <?php else: ?>
            <p class="text-muted small mb-0">No experts in your organization. <a href="/threat_intel/org-admin/users.php">Add experts first.</a></p>
            <?php endif; ?>
        </div>
    </div>

    <?php if ($case['mitre_name']): ?>
    <div class="card mb-3">
        <div class="card-header bg-dark text-white"><i class="bi bi-diagram-3 me-1"></i>MITRE ATT&CK</div>
        <div class="card-body small">
            <span class="badge bg-secondary"><?= htmlspecialchars($case['mitre_tid']) ?></span>
            <strong class="ms-1"><?= htmlspecialchars($case['mitre_name']) ?></strong><br>
            <span class="text-muted">Tactic: <?= htmlspecialchars($case['mitre_tactic']) ?></span>
        </div>
    </div>
    <?php endif; ?>
</div>

<div class="col-lg-8">
    <div class="card mb-3">
        <div class="card-header bg-primary text-white"><i class="bi bi-file-text me-1"></i>Incident Description</div>
        <div class="card-body"><p class="small mb-0"><?= nl2br(htmlspecialchars($case['description'])) ?></p></div>
    </div>

    <?php if ($iocs): ?>
    <div class="card mb-3">
        <div class="card-header bg-danger text-white"><i class="bi bi-bug me-1"></i>Extracted IOCs (<?= count($iocs) ?>)</div>
        <div class="card-body">
            <?php foreach($iocs as $ioc): ?>
            <span class="ioc-tag">
                <span class="badge bg-secondary me-1" style="font-size:0.65rem"><?= $ioc['ioc_type'] ?></span>
                <?= htmlspecialchars($ioc['ioc_value']) ?>
                <?php if($ioc['is_confirmed']): ?> <i class="bi bi-exclamation-triangle text-danger" title="Confirmed malicious"></i><?php endif; ?>
            </span>
            <?php endforeach; ?>
        </div>
    </div>
    <?php endif; ?>

    <?php if ($rules): ?>
    <div class="card mb-3">
        <div class="card-header bg-warning text-dark"><i class="bi bi-sliders me-1"></i>Rule Matches (Score: <?= $case['severity_score'] ?>)</div>
        <div class="card-body">
            <?php foreach($rules as $r): ?>
            <div class="rule-match-row">
                <strong><?= htmlspecialchars($r['name']) ?></strong>
                <span class="badge bg-danger float-end">+<?= $r['score_added'] ?> pts</span><br>
                <small class="text-muted">Matched: <code><?= htmlspecialchars($r['matched_value']) ?></code></small>
            </div>
            <?php endforeach; ?>
        </div>
    </div>
    <?php endif; ?>

    <div class="card">
        <div class="card-header bg-secondary text-white"><i class="bi bi-journal-text me-1"></i>Case Audit Trail</div>
        <div class="card-body" style="max-height:280px;overflow-y:auto;">
            <?php foreach($logs as $log): ?>
            <div class="audit-log-item">
                <strong><?= htmlspecialchars(ucwords(str_replace('_',' ',$log['action']))) ?></strong>
                <?php if($log['full_name']): ?> — <em><?= htmlspecialchars($log['full_name']) ?></em><?php endif; ?>
                <span class="float-end text-muted" style="font-size:0.78rem"><?= date('d M Y H:i', strtotime($log['created_at'])) ?></span>
                <?php if($log['details']): ?><br><span class="text-secondary small"><?= htmlspecialchars($log['details']) ?></span><?php endif; ?>
            </div>
            <?php endforeach; ?>
        </div>
    </div>
</div>
</div>
<?php include '../includes/footer.php'; ?>
