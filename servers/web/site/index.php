<?php
$db = new mysqli('localhost', 'heros', 'HeroPass2026!', 'heros', 0, '/run/mysqld/mysqld.sock');
$heroes = [];
if ($db->connect_error) {
    $db_status = "Database offline";
} else {
    $db_status = "Connected";
    $result = $db->query("SELECT * FROM heroes ORDER BY id");
    while ($row = $result->fetch_assoc()) {
        $heroes[] = $row;
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Heros | Quantum Bytz</title>
<style>
:root { --bg: #0d1117; --card: #161b22; --border: #30363d; --text: #e6edf3; --muted: #8b949e; --blue: #58a6ff; --green: #3fb950; --purple: #bc8cff; }
* { box-sizing: border-box; margin: 0; padding: 0; }
body { background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; }
.header { text-align: center; padding: 60px 20px 40px; background: linear-gradient(135deg, #0d1117 0%, #1c1c2e 100%); border-bottom: 1px solid var(--border); }
.header h1 { font-size: 36px; margin-bottom: 8px; }
.header h1 span { color: var(--blue); }
.header p { color: var(--muted); font-size: 16px; }
.status { display: inline-block; padding: 4px 12px; border-radius: 12px; font-size: 12px; margin-top: 12px; }
.status-ok { background: rgba(63,185,80,0.15); color: var(--green); }
.container { max-width: 1000px; margin: 0 auto; padding: 40px 20px; }
.grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 16px; }
.card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 24px; transition: border-color 0.2s; }
.card:hover { border-color: var(--blue); }
.card h3 { font-size: 18px; margin-bottom: 8px; }
.card .power { color: var(--purple); font-size: 14px; margin-bottom: 6px; }
.card .team { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; }
.footer { text-align: center; padding: 40px; color: var(--muted); font-size: 13px; border-top: 1px solid var(--border); margin-top: 40px; }
.info { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 16px; margin-bottom: 24px; font-size: 13px; color: var(--muted); }
.info strong { color: var(--text); }
</style>
</head>
<body>

<div class="header">
    <h1>Heros<span>.quantumbytz</span>.com</h1>
    <p>Guardians of the Quantum Network</p>
    <div class="status status-ok">Database: <?= htmlspecialchars($db_status) ?> | Heroes: <?= count($heroes) ?></div>
</div>

<div class="container">
    <div class="info">
        <strong>Server:</strong> <?= htmlspecialchars(gethostname()) ?> |
        <strong>IP:</strong> <?= htmlspecialchars($_SERVER['SERVER_ADDR'] ?? 'N/A') ?> |
        <strong>PHP:</strong> <?= phpversion() ?> |
        <strong>Protected by:</strong> Cerberix Firewall AI Firewall
    </div>

    <div class="grid">
    <?php foreach ($heroes as $hero): ?>
        <div class="card">
            <h3><?= htmlspecialchars($hero['name']) ?></h3>
            <div class="power"><?= htmlspecialchars($hero['power']) ?></div>
            <div class="team">Team <?= htmlspecialchars($hero['team']) ?></div>
        </div>
    <?php endforeach; ?>
    </div>
</div>

<div class="footer">
    &copy; 2026 Quantum Bytz | Protected by Cerberix Firewall
</div>

</body>
</html>
