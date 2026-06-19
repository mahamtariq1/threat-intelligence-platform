<?php
require_once '../includes/session_check.php';
require_role(['org_admin']);
require_once '../includes/db.php';
$page_title = 'All Cases';
$oid = $_SESSION['org_id'];

$filter_status = $_GET['status'] ?? '';
$filter_sev    = $_GET['severity'] ?? '';
$search        = $_GET['q'] ?? '';

$sql = "SELECT c.id, c.title, c.attack_type, c.severity, c.severity_score, c.status, c.created_at, u.full_name as reporter, e.full_name as expert FROM cases c JOIN users u ON c.reported_by=u.id LEFT JOIN users e ON c.assigned_to=e.id WHERE c.org_id=?";
$params = [$oid]; $types = "i";
if ($filter_status) { $sql .= " AND c.status=?"; $params[]=$filter_status; $types.="s"; }
if ($filter_sev)    { $sql .= " AND c.severity=?"; $params[]=$filter_sev; $types.="s"; }
if ($search)        { $sql .= " AND c.title LIKE ?"; $params[]="%$search%"; $types.="s"; }
$sql .= " ORDER BY c.created_at DESC";

$stmt = $conn->prepare($sql);
$stmt->bind_param($types, ...$params);
$stmt->execute(); $result = $stmt->get_result();

include '../includes/header.php';
?>
<div class="d-flex justify-content-between align-items-center mb-3">
    <h4 class="page-title mb-0"><i class="bi bi-folder me-2"></i>All Cases</h4>
</div>

<!-- Filters -->
<div class="card mb-3">
    <div class="card-body py-2">
        <form method="GET" class="row g-2 align-items-end">
            <div class="col-md-4"><input type="text" name="q" class="form-control form-control-sm" placeholder="Search by title..." value="<?= htmlspecialchars($search) ?>"></div>
            <div class="col-md-3">
                <select name="status" class="form-select form-select-sm">
                    <option value="">All Statuses</option>
                    <?php foreach(['open','in_progress','resolved','closed'] as $s): ?>
                    <option value="<?=$s?>" <?=$filter_status===$s?'selected':''?>><?= ucfirst(str_replace('_',' ',$s)) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="col-md-2">
                <select name="severity" class="form-select form-select-sm">
                    <option value="">All Severities</option>
                    <?php foreach(['Low','Medium','High','Critical'] as $s): ?>
                    <option value="<?=$s?>" <?=$filter_sev===$s?'selected':''?>><?=$s?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="col-md-2"><button class="btn btn-primary btn-sm w-100">Filter</button></div>
            <div class="col-md-1"><a href="cases.php" class="btn btn-outline-secondary btn-sm w-100">Reset</a></div>
        </form>
    </div>
</div>

<div class="card">
    <div class="card-body p-0">
        <table class="table table-hover mb-0">
            <thead><tr><th>#</th><th>Title</th><th>Type</th><th>Severity</th><th>Score</th><th>Status</th><th>Reporter</th><th>Expert</th><th>Date</th><th></th></tr></thead>
            <tbody>
            <?php $cnt=0; while($c=$result->fetch_assoc()): $cnt++; ?>
            <tr>
                <td><?= $c['id'] ?></td>
                <td><?= htmlspecialchars($c['title']) ?></td>
                <td><?= htmlspecialchars($c['attack_type']) ?></td>
                <td><span class="severity-badge severity-<?= $c['severity'] ?>"><?= $c['severity'] ?></span></td>
                <td><?= $c['severity_score'] ?></td>
                <td><span class="badge bg-secondary"><?= str_replace('_',' ',$c['status']) ?></span></td>
                <td><?= htmlspecialchars($c['reporter']) ?></td>
                <td><?= $c['expert'] ? htmlspecialchars($c['expert']) : '<span class="text-muted small">Unassigned</span>' ?></td>
                <td><?= date('d M Y', strtotime($c['created_at'])) ?></td>
                <td><a href="/threat_intel/org-admin/case_detail.php?id=<?= $c['id'] ?>" class="btn btn-sm btn-outline-primary">Manage</a></td>
            </tr>
            <?php endwhile; if($cnt===0): ?><tr><td colspan="10" class="text-center text-muted py-4">No cases found.</td></tr><?php endif; ?>
            </tbody>
        </table>
    </div>
</div>
<?php include '../includes/footer.php'; ?>
