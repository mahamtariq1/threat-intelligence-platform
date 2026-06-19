<?php
require_once '../includes/session_check.php';
require_role(['platform_admin']);
require_once '../includes/db.php';
$page_title = 'Scoring Rules';
$success = ''; $error = '';

if ($_SERVER['REQUEST_METHOD']==='POST') {
    $action = $_POST['action'] ?? '';

    if ($action === 'create') {
        $name    = trim($_POST['name'] ?? '');
        $keyword = trim($_POST['condition_keyword'] ?? '');
        $score   = intval($_POST['score_add'] ?? 0);
        $mitre   = intval($_POST['mitre_technique_id'] ?? 0) ?: null;
        if (!$name || !$keyword || $score < 1) {
            $error = 'Name, keyword, and a valid score are required.';
        } else {
            $ins = $conn->prepare("INSERT INTO severity_rules (name, condition_keyword, score_add, mitre_technique_id) VALUES (?,?,?,?)");
            $ins->bind_param("ssii",$name,$keyword,$score,$mitre); $ins->execute();
            $success = "Rule '$name' created successfully.";
        }
    } elseif ($action === 'toggle') {
        $rid = intval($_POST['rule_id']); $new = intval($_POST['new_status']);
        $upd = $conn->prepare("UPDATE severity_rules SET is_active=? WHERE id=?");
        $upd->bind_param("ii",$new,$rid); $upd->execute();
        $success = "Rule status updated.";
    } elseif ($action === 'update') {
        $rid   = intval($_POST['rule_id']);
        $score = intval($_POST['score_add'] ?? 0);
        $mitre = intval($_POST['mitre_technique_id'] ?? 0) ?: null;
        if ($score < 1) { $error = 'Score must be at least 1.'; }
        else {
            $upd = $conn->prepare("UPDATE severity_rules SET score_add=?, mitre_technique_id=? WHERE id=?");
            $upd->bind_param("iii",$score,$mitre,$rid); $upd->execute();
            $success = "Rule updated.";
        }
    }
}

$rules = $conn->query("SELECT r.*, m.name as mitre_name, m.technique_id as mitre_tid FROM severity_rules r LEFT JOIN mitre_techniques m ON r.mitre_technique_id=m.id ORDER BY r.is_active DESC, r.score_add DESC")->fetch_all(MYSQLI_ASSOC);
$mitres = $conn->query("SELECT id, technique_id, name FROM mitre_techniques ORDER BY technique_id")->fetch_all(MYSQLI_ASSOC);

include '../includes/header.php';
?>
<h4 class="page-title"><i class="bi bi-sliders me-2"></i>Severity Scoring Rules</h4>
<?php if($success): ?><div class="alert alert-success alert-dismissible fade show"><?= htmlspecialchars($success) ?><button type="button" class="btn-close" data-bs-dismiss="alert"></button></div><?php endif; ?>
<?php if($error): ?><div class="alert alert-danger"><?= htmlspecialchars($error) ?></div><?php endif; ?>

<div class="row">
<div class="col-lg-4 mb-4">
    <div class="card">
        <div class="card-header bg-success text-white"><i class="bi bi-plus-circle me-1"></i>Add New Rule</div>
        <div class="card-body">
            <form method="POST">
                <input type="hidden" name="action" value="create">
                <div class="mb-2">
                    <label class="form-label fw-semibold small">Rule Name</label>
                    <input type="text" name="name" class="form-control form-control-sm" placeholder="e.g. Ransomware Detected" required>
                </div>
                <div class="mb-2">
                    <label class="form-label fw-semibold small">Condition Keyword</label>
                    <input type="text" name="condition_keyword" class="form-control form-control-sm" placeholder="e.g. ransomware" required>
                    <div class="form-text" style="font-size:0.75rem">Matched against case description (case-insensitive)</div>
                </div>
                <div class="mb-2">
                    <label class="form-label fw-semibold small">Score Points</label>
                    <input type="number" name="score_add" class="form-control form-control-sm" min="1" max="100" placeholder="10" required>
                </div>
                <div class="mb-3">
                    <label class="form-label fw-semibold small">MITRE Technique (optional)</label>
                    <select name="mitre_technique_id" class="form-select form-select-sm">
                        <option value="">-- None --</option>
                        <?php foreach($mitres as $m): ?>
                        <option value="<?= $m['id'] ?>"><?= htmlspecialchars($m['technique_id'].' — '.$m['name']) ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <button class="btn btn-success btn-sm w-100"><i class="bi bi-plus-circle me-1"></i>Add Rule</button>
            </form>
        </div>
    </div>
</div>

<div class="col-lg-8">
    <div class="card">
        <div class="card-header bg-primary text-white"><i class="bi bi-list-check me-1"></i>All Rules (<?= count($rules) ?>)</div>
        <div class="card-body p-0">
            <table class="table table-hover mb-0 small">
                <thead><tr><th>#</th><th>Name</th><th>Keyword</th><th>Score</th><th>MITRE</th><th>Status</th><th>Actions</th></tr></thead>
                <tbody>
                <?php foreach($rules as $r): ?>
                <tr class="<?= !$r['is_active']?'table-secondary':'' ?>">
                    <td><?= $r['id'] ?></td>
                    <td><?= htmlspecialchars($r['name']) ?></td>
                    <td><code><?= htmlspecialchars($r['condition_keyword']) ?></code></td>
                    <td>
                        <form method="POST" class="d-inline">
                            <input type="hidden" name="action" value="update">
                            <input type="hidden" name="rule_id" value="<?= $r['id'] ?>">
                            <div class="input-group input-group-sm" style="width:120px">
                                <input type="number" name="score_add" class="form-control form-control-sm" value="<?= $r['score_add'] ?>" min="1" max="100" style="width:60px">
                                <button class="btn btn-outline-primary btn-sm" title="Save score">✓</button>
                            </div>
                        </form>
                    </td>
                    <td><?= $r['mitre_tid'] ? '<span class="badge bg-dark">'.htmlspecialchars($r['mitre_tid']).'</span>' : '<span class="text-muted">—</span>' ?></td>
                    <td><?= $r['is_active'] ? '<span class="badge bg-success">Active</span>' : '<span class="badge bg-secondary">Disabled</span>' ?></td>
                    <td>
                        <form method="POST" class="d-inline">
                            <input type="hidden" name="action" value="toggle">
                            <input type="hidden" name="rule_id" value="<?= $r['id'] ?>">
                            <input type="hidden" name="new_status" value="<?= $r['is_active']?0:1 ?>">
                            <button class="btn btn-sm <?= $r['is_active']?'btn-outline-warning':'btn-outline-success' ?>"><?= $r['is_active']?'Disable':'Enable' ?></button>
                        </form>
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
