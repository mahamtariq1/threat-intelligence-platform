<?php
require_once '../includes/session_check.php';
require_role(['platform_admin']);
require_once '../includes/db.php';
$page_title = 'Global IOC Database';
$success = '';

if ($_SERVER['REQUEST_METHOD']==='POST' && isset($_POST['confirm_ioc'])) {
    $ioc_id = intval($_POST['ioc_id']);
    $upd = $conn->prepare("UPDATE iocs SET is_confirmed=1 WHERE id=?");
    $upd->bind_param("i",$ioc_id); $upd->execute();
    $success = "IOC marked as confirmed malicious.";
}

$filter_type = $_GET['type'] ?? '';
$search = $_GET['q'] ?? '';
$sql = "SELECT * FROM iocs WHERE 1=1";
if ($filter_type) $sql .= " AND ioc_type='" . $conn->real_escape_string($filter_type) . "'";
if ($search)      $sql .= " AND ioc_value LIKE '%" . $conn->real_escape_string($search) . "%'";
$sql .= " ORDER BY times_seen DESC, last_seen DESC";
$iocs = $conn->query($sql)->fetch_all(MYSQLI_ASSOC);

include '../includes/header.php';
?>
<h4 class="page-title"><i class="bi bi-globe me-2"></i>Global IOC Database (<?= count($iocs) ?>)</h4>
<?php if($success): ?><div class="alert alert-success alert-dismissible fade show"><?= htmlspecialchars($success) ?><button type="button" class="btn-close" data-bs-dismiss="alert"></button></div><?php endif; ?>

<!-- Filters -->
<div class="card mb-3">
    <div class="card-body py-2">
        <form method="GET" class="row g-2 align-items-end">
            <div class="col-md-5"><input type="text" name="q" class="form-control form-control-sm" placeholder="Search IOC value..." value="<?= htmlspecialchars($search) ?>"></div>
            <div class="col-md-3">
                <select name="type" class="form-select form-select-sm">
                    <option value="">All Types</option>
                    <?php foreach(['ip','domain','url','email','md5','sha256'] as $t): ?>
                    <option value="<?=$t?>" <?=$filter_type===$t?'selected':''?>><?= strtoupper($t) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="col-md-2"><button class="btn btn-primary btn-sm w-100">Filter</button></div>
            <div class="col-md-2"><a href="iocs.php" class="btn btn-outline-secondary btn-sm w-100">Reset</a></div>
        </form>
    </div>
</div>

<div class="card">
    <div class="card-body p-0">
        <table class="table table-hover mb-0">
            <thead><tr><th>#</th><th>IOC Value</th><th>Type</th><th>Times Seen</th><th>Reputation</th><th>Confirmed</th><th>First Seen</th><th>Last Seen</th><th>Action</th></tr></thead>
            <tbody>
            <?php foreach($iocs as $ioc): ?>
            <tr>
                <td><?= $ioc['id'] ?></td>
                <td><code style="font-size:0.8rem"><?= htmlspecialchars($ioc['ioc_value']) ?></code></td>
                <td><span class="badge bg-secondary"><?= strtoupper($ioc['ioc_type']) ?></span></td>
                <td><span class="badge bg-<?= $ioc['times_seen']>5?'danger':($ioc['times_seen']>2?'warning text-dark':'secondary') ?>"><?= $ioc['times_seen'] ?>x</span></td>
                <td><?= $ioc['reputation_score'] ?></td>
                <td><?= $ioc['is_confirmed'] ? '<span class="badge bg-danger"><i class="bi bi-exclamation-triangle me-1"></i>Confirmed</span>' : '<span class="badge bg-light text-dark">Unconfirmed</span>' ?></td>
                <td class="small"><?= date('d M Y', strtotime($ioc['first_seen'])) ?></td>
                <td class="small"><?= date('d M Y H:i', strtotime($ioc['last_seen'])) ?></td>
                <td>
                    <?php if(!$ioc['is_confirmed']): ?>
                    <form method="POST" class="d-inline">
                        <input type="hidden" name="ioc_id" value="<?= $ioc['id'] ?>">
                        <button name="confirm_ioc" class="btn btn-sm btn-outline-danger" onclick="return confirm('Mark this IOC as confirmed malicious?')"><i class="bi bi-exclamation-triangle"></i> Confirm</button>
                    </form>
                    <?php else: ?>
                    <span class="text-muted small">Confirmed</span>
                    <?php endif; ?>
                </td>
            </tr>
            <?php endforeach; ?>
            <?php if(!$iocs): ?><tr><td colspan="9" class="text-center text-muted py-4">No IOCs in the global database yet.</td></tr><?php endif; ?>
            </tbody>
        </table>
    </div>
</div>
<?php include '../includes/footer.php'; ?>
