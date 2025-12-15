<?php
// Headers de segurança
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' cdnjs.cloudflare.com; font-src cdnjs.cloudflare.com; img-src 'self' data:;");

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Inclui o sistema de autenticação local
require_once 'local_auth.php';

// Verifica se o usuário está logado
requireLogin();

// Carregar configuração e funções
global $config;
if (!isset($config)) {
    $config = include(__DIR__ . '/config.php');
}

// === POST: inserir/editar/excluir senha manual ===
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Sanitizar dados de entrada
    $postData = sanitizeRequestData($_POST, ['csrf_token', 'manual_password', 'computer', 'delete_manual_password']);
    
    // Verificar token CSRF
    if (!isset($postData['csrf_token']) || !validarTokenCsrf($postData['csrf_token'])) {
        die("Token CSRF inválido!");
    }
    
    $conn = new mysqli(
        $config['host'],
        $config['user'],
        $config['password'],
        $config['dbname']
    );
    if ($conn->connect_error) {
        die("Erro na conexão: " . $conn->connect_error);
    }

    // Inserir ou atualizar senha manual
    if (!empty($postData['manual_password']) && !empty($postData['computer'])) {
        $computerName = sanitizeInput($postData['computer'], 'string');
        $manualPassword = sanitizeInput($postData['manual_password'], 'string');
        
        // Garantir colunas de timestamp na tabela de senhas manuais
        $conn->query("CREATE TABLE IF NOT EXISTS ComputerManualPasswords (ComputerName VARCHAR(255) PRIMARY KEY, ManualPassword TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP)");

        $stmt = $conn->prepare("\n            INSERT INTO ComputerManualPasswords (ComputerName, ManualPassword)\n            VALUES (?, ?)\n            ON DUPLICATE KEY UPDATE ManualPassword = VALUES(ManualPassword), updated_at = NOW()\n        ");
        $stmt->bind_param('ss', $computerName, $manualPassword);
        $stmt->execute();
        $stmt->close();
    }

    // Excluir senha manual
    if (isset($postData['delete_manual_password'], $postData['computer'])) {
        $computerName = sanitizeInput($postData['computer'], 'string');
        $stmt = $conn->prepare("DELETE FROM ComputerManualPasswords WHERE ComputerName = ?");
        $stmt->bind_param('s', $computerName);
        $stmt->execute();
        $stmt->close();
    }

    $conn->close();
    header("Location: view_laps.php?" . $_SERVER['QUERY_STRING']);
    exit();
}

// === GET: configuração da listagem ===
$conn = new mysqli(
    $config['host'],
    $config['user'],
    $config['password'],
    $config['dbname']
);
if ($conn->connect_error) {
    die("Erro na conexão: " . $conn->connect_error);
}

// Desktop: limpeza automática de senhas manuais obsoletas
if (!($isMobile ?? false)) {
    $conn->query("CREATE TABLE IF NOT EXISTS ComputerManualPasswords (ComputerName VARCHAR(255) PRIMARY KEY, ManualPassword TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP)");
    $cleanupSql = "DELETE m FROM ComputerManualPasswords m INNER JOIN Passwords p ON p.ComputerName = m.ComputerName WHERE p.ExpirationTimestamp IS NOT NULL AND m.created_at IS NOT NULL AND p.ExpirationTimestamp > m.created_at";
    $conn->query($cleanupSql);
}

// Sanitizar parâmetros GET
$getData = sanitizeRequestData($_GET, ['computername', 'show_null_passwords', 'show_old_passwords', 'orderby', 'orderdir', 'filter']);

$computerNameFilter = sanitizeInput($getData['computername'] ?? '', 'string');
$showNull = isset($getData['show_null_passwords']);
$showOld  = isset($getData['show_old_passwords']);
$filter = sanitizeInput($getData['filter'] ?? '', 'string');

// Detectar dispositivo móvel
$ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
$isMobile = preg_match('/Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i', $ua);

$allowedCols = ['ComputerName','Password','ExpirationTimestamp','ManualPassword'];
$orderBy  = in_array($getData['orderby'] ?? '', $allowedCols) ? $getData['orderby'] : 'ComputerName';
$orderDir = ($getData['orderdir'] ?? '') === 'DESC' ? 'DESC' : 'ASC';

// Para senhas manuais, usar uma consulta diferente
if ($filter === 'manual') {
    $sql = "
        SELECT 
            COALESCE(p.ComputerName, m.ComputerName) as ComputerName,
            p.Password,
            p.ExpirationTimestamp,
            m.ManualPassword
        FROM ComputerManualPasswords m
        LEFT JOIN Passwords p ON m.ComputerName = p.ComputerName
    ";
} else {
    $table = $showNull ? 'null_passwords' : ($showOld ? 'old_passwords' : 'Passwords');
    
    $sql = "
        SELECT p.ComputerName, p.Password, p.ExpirationTimestamp, m.ManualPassword
        FROM {$table} p
        LEFT JOIN ComputerManualPasswords m ON p.ComputerName = m.ComputerName
    ";
}

$params = []; $types = '';
$whereConditions = [];

// Filtros baseados no parâmetro filter
switch ($filter) {
    case 'expire_today': $whereConditions[] = "p.ExpirationTimestamp = CURDATE()"; break;
    case 'expire_30_days': $whereConditions[] = "p.ExpirationTimestamp BETWEEN CURDATE() AND DATE_ADD(CURDATE(), INTERVAL 30 DAY)"; break;
    case 'expired': $whereConditions[] = "p.ExpirationTimestamp < CURDATE()"; break;
    case 'expired_6_months': $whereConditions[] = "p.ExpirationTimestamp < DATE_SUB(CURDATE(), INTERVAL 6 MONTH)"; break;
    case 'expired_1_year': $whereConditions[] = "p.ExpirationTimestamp < DATE_SUB(CURDATE(), INTERVAL 1 YEAR)"; break;
    case 'manual': $whereConditions[] = "m.ManualPassword IS NOT NULL"; break;
    case 'updated_today': $whereConditions[] = "EXISTS (SELECT 1 FROM old_passwords o WHERE o.ComputerName = p.ComputerName AND DATE(o.created_at) = CURDATE())"; break;
}

// Filtro por nome do computador
if ($computerNameFilter !== '') {
    $baseTable = ($filter === 'manual') ? 'm' : 'p';
    $whereConditions[] = "$baseTable.ComputerName LIKE ?";
    $types = 's';
    $params[] = "%{$computerNameFilter}%";
}

// Aplicar condições WHERE
if (!empty($whereConditions)) {
    $sql .= " WHERE " . implode(' AND ', $whereConditions);
}

$sql .= " ORDER BY {$orderBy} {$orderDir}";

$rows = [];
if (!($isMobile && $computerNameFilter === '')) {
    $stmt = $conn->prepare($sql);
    if ($types) {
        $stmt->bind_param($types, ...$params);
    }
    $stmt->execute();
    $rows = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
    $stmt->close();
}
$conn->close();

function toggle($d) { return $d === 'ASC' ? 'DESC' : 'ASC'; }

// Determinar nome do filtro ativo
$filterNameMap = [
    'expire_today' => 'Expira Hoje',
    'expire_30_days' => 'Expirando em 30 dias',
    'expired' => 'Senhas Expiradas',
    'expired_6_months' => 'Expiradas há 6+ meses',
    'expired_1_year' => 'Expiradas há 1+ ano',
    'manual' => 'Senhas Manuais',
    'updated_today' => 'Alteradas Hoje',
    'null' => 'Senhas Nulas'
];
$filterName = $filterNameMap[$filter] ?? '';

$version = file_exists('version.txt') ? trim(file_get_contents('version.txt')) : '1.0.0';
$lastUpdate = 'N/A';
$logFile = '/var/log/ldap-up.log';
if (file_exists($logFile)) {
    $lines = file($logFile, FILE_IGNORE_NEW_LINES|FILE_SKIP_EMPTY_LINES);
    if ($lines && preg_match('/\[(.*?)\]/', end($lines), $m)) {
        $lastUpdate = $m[1];
    }
}
?>
<!DOCTYPE html>
<html lang="pt-br">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Gerenciador LAPS</title>
  <link rel="icon" href="./img/fav.png" type="image/x-icon">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
  <link rel="stylesheet" href="style.css">
</head>
<body>
  <button class="theme-toggle" onclick="toggleTheme()" title="Alternar tema">
    <i class="fas fa-moon"></i>
  </button>
  <div id="toast" class="toast" aria-live="polite" aria-atomic="true"></div>
  <div class="container">
    <header class="header">
      <div class="title">
        <div class="title-left">
          <img src="./img/lap.png" class="logo" alt="LAPS" onclick="alert('Versão: <?= $version ?>')">
          <h1 class="custom-title"><?= $isMobile ? 'GSLaps' : 'Gerenciador de Senhas LAPS' ?></h1>
        </div>
        <div class="user-section-title desktop-only">
          <div class="user-info-title">
            <i class="fas fa-user"></i> 
            <a href="profile.php" class="user-profile-link" title="Ver perfil">
              <?= htmlspecialchars($_SESSION['username'] ?? 'N/A') ?>
            </a>
          </div>
          <div class="user-actions">
            <button onclick="window.location.href='api_keys.php'" class="btn api-btn" title="Gerenciar Chaves de API">
              <i class="fas fa-key"></i> API
            </button>
            <button onclick="logout()" class="btn logout-btn" title="Sair do sistema">
              <i class="fas fa-sign-out-alt"></i>
            </button>
          </div>
        </div>
      </div>
      <div class="status-bar desktop-only">
        <div class="update-status">
          <i class="fas fa-clock"></i> Atualizado: <?= htmlspecialchars($lastUpdate) ?>
        </div>
        <div class="status-buttons">
          <button onclick="window.location.href='dashboard.php'" class="btn refresh-btn">
            <i class="fas fa-chart-bar"></i> Dashboard
          </button>
          <button onclick="updateData(event)" class="btn refresh-btn">
            <i class="fas fa-sync-alt"></i> Atualizar
          </button>
        </div>
      </div>
      <form method="get" class="search-form">
        <div class="form-group">
          <input type="text" name="computername" class="search-input" value="<?= htmlspecialchars($computerNameFilter) ?>" placeholder="Nome do computador">
          <div class="filters desktop-only">
            <label class="filter-option">
              <input type="checkbox" name="show_old_passwords" <?= $showOld ? 'checked' : '' ?>> Senhas Antigas
            </label>
          </div>
          <button type="submit" class="btn search-btn">
            <i class="fas fa-search"></i> Buscar
          </button>
        </div>
      </form>
    </header>
    
    <?php if ($filterName): ?>
    <div class="filter-indicator">
      <i class="fas fa-filter"></i>
      <span>Filtro ativo: <strong><?= htmlspecialchars($filterName) ?></strong></span>
      <a href="view_laps.php" class="clear-filter">
        <i class="fas fa-times"></i> Limpar filtro
      </a>
    </div>
    <?php endif; ?>
    
    <main class="main-content">
      <?php if ($rows): ?>
        <!-- Alfabeto Guia -->
        <div class="alphabet-guide" id="alphabetGuide">
          <div class="alphabet-title">
            <span>Guia de Caracteres:</span>
            <button type="button" class="alphabet-toggle-btn" onclick="toggleAlphabetGuide()" title="Mostrar/Esconder guia">
              <i class="fas fa-chevron-up" id="alphabetToggleIcon"></i>
            </button>
          </div>
          <div class="alphabet-chars">
            <span class="char-group">
              <span class="char-label">Números:</span>
              <span class="char-item">0</span>
              <span class="char-item">1</span>
              <span class="char-item">2</span>
              <span class="char-item">3</span>
              <span class="char-item">4</span>
              <span class="char-item">5</span>
              <span class="char-item">6</span>
              <span class="char-item">7</span>
              <span class="char-item">8</span>
              <span class="char-item">9</span>
            </span>
            <span class="char-group">
              <span class="char-label">Letras Maiúsculas:</span>
              <span class="char-item">A</span>
              <span class="char-item">B</span>
              <span class="char-item">C</span>
              <span class="char-item">D</span>
              <span class="char-item">E</span>
              <span class="char-item">F</span>
              <span class="char-item">G</span>
              <span class="char-item">H</span>
              <span class="char-item highlight">I</span>
              <span class="char-item">J</span>
              <span class="char-item">K</span>
              <span class="char-item">L</span>
              <span class="char-item">M</span>
              <span class="char-item">N</span>
              <span class="char-item highlight">O</span>
              <span class="char-item">P</span>
              <span class="char-item">Q</span>
              <span class="char-item">R</span>
              <span class="char-item">S</span>
              <span class="char-item">T</span>
              <span class="char-item">U</span>
              <span class="char-item">V</span>
              <span class="char-item">W</span>
              <span class="char-item">X</span>
              <span class="char-item">Y</span>
              <span class="char-item">Z</span>
            </span>
            <span class="char-group">
              <span class="char-label">Letras Minúsculas:</span>
              <span class="char-item">a</span>
              <span class="char-item">b</span>
              <span class="char-item">c</span>
              <span class="char-item">d</span>
              <span class="char-item">e</span>
              <span class="char-item">f</span>
              <span class="char-item">g</span>
              <span class="char-item">h</span>
              <span class="char-item highlight">i</span>
              <span class="char-item highlight">l</span>
              <span class="char-item">j</span>
              <span class="char-item">k</span>
              <span class="char-item">m</span>
              <span class="char-item">n</span>
              <span class="char-item highlight">o</span>
              <span class="char-item">p</span>
              <span class="char-item">q</span>
              <span class="char-item">r</span>
              <span class="char-item">s</span>
              <span class="char-item">t</span>
              <span class="char-item">u</span>
              <span class="char-item">v</span>
              <span class="char-item">w</span>
              <span class="char-item">x</span>
              <span class="char-item">y</span>
              <span class="char-item">z</span>
            </span>
          </div>
          <div class="alphabet-note">
            <i class="fas fa-info-circle"></i>
            <span>Caracteres destacados podem ser confundidos: <strong>0 (zero), O (ó maiúsculo), o (ó minúsculo)</strong> e <strong>1 (um), I (i maiúsculo), i (i minúsculo), l (L minúsculo)</strong></span>
          </div>
        </div>
        
        <table class="results-table desktop-only">
          <thead>
            <tr>
              <?php foreach ($allowedCols as $col): 
                $qs = http_build_query(array_merge($_GET, ['orderby' => $col, 'orderdir' => toggle($orderDir)]));
              ?>
                <th>
                  <a href="?<?= $qs ?>" class="<?= $orderBy === $col ? 'active' : '' ?>">
                    <?= htmlspecialchars($col) ?>
                    <?php if ($orderBy === $col): ?>
                      <i class="fas fa-sort-<?= $orderDir === 'ASC' ? 'up' : 'down' ?>"></i>
                    <?php endif; ?>
                  </a>
                </th>
              <?php endforeach; ?>
              <th>Ações</th>
            </tr>
          </thead>
          <tbody>
            <?php foreach ($rows as $r): ?>
              <tr>
                <td><?= htmlspecialchars($r['ComputerName'] ?? '') ?></td>
                <td>
                  <div class="password-container">
                    <div class="password-text"><?= htmlspecialchars($r['Password'] ?? '') ?></div>
                    <button class="toggle-password-btn" onclick="togglePassword(this)">
                      <i class="far fa-eye"></i>
                    </button>
                    <button class="copy-btn" onclick="copyToClipboard('<?= htmlspecialchars($r['Password'] ?? '') ?>')">
                      <i class="far fa-copy"></i>
                    </button>
                    <a href="<?= htmlspecialchars(rtrim($config['glpi_url'], '/')) ?>/front/computer.php?is_deleted=0&as_map=0&browse=0&criteria%5B0%5D%5Blink%5D=AND&criteria%5B0%5D%5Bfield%5D=view&criteria%5B0%5D%5Bsearchtype%5D=contains&criteria%5B0%5D%5Bvalue%5D=<?= urlencode($r['ComputerName']) ?>&itemtype=Computer&start=0" 
                      class="btn glpi-btn" target="_blank" title="Ver no GLPI">
                      <i class="fa fa-desktop" aria-hidden="true"></i>
                    </a>
                  </div>
                </td>
                <td>
                  <?php 
                    $exp = $r['ExpirationTimestamp'] ?? '';
                    $statusClass = '';
                    $title = '';
                    if ($exp) {
                      $today = new DateTime(date('Y-m-d'));
                      $expDt = new DateTime((new DateTime($exp))->format('Y-m-d'));
                      $diff = (int)$today->diff($expDt)->format('%r%a');
                      if ($diff < 0) {
                        $statusClass = 'status-expired';
                      } elseif ($diff === 7) {
                        $statusClass = 'status-ok';
                      } elseif ($diff >= 0 && $diff < 7) {
                        $statusClass = 'status-warn';
                      }
                      $title = ($diff < 0) ? 'Expirada' : ($diff.' dias');
                    }
                  ?>
                  <span class="status-pill <?= $statusClass ?>" title="<?= htmlspecialchars($title) ?>"><?= htmlspecialchars($exp) ?></span>
                </td>
                <td>
                  <?php if ($r['ManualPassword'] !== null): ?>
                    <div class="password-container">
                      <div class="password-text manual"><?= htmlspecialchars($r['ManualPassword']) ?></div>
                    </div>
                  <?php else: ?>
                    <span class="text-muted">—</span>
                  <?php endif; ?>
                </td>
                <td>
                  <div style="display: flex; gap: 6px; align-items: center; justify-content: flex-end;">
                    <?php if ($r['ManualPassword'] !== null): ?>
                      <button class="toggle-password-btn" data-target=".password-text.manual" onclick="togglePassword(this)" title="Visualizar Senha Manual">
                        <i class="far fa-eye"></i>
                      </button>
                      <button class="copy-btn" onclick="copyToClipboard('<?= htmlspecialchars($r['ManualPassword']) ?>')" title="Copiar Senha Manual">
                        <i class="far fa-copy"></i>
                      </button>
                      <button class="icon-btn" onclick="editPasswordForm('<?= htmlspecialchars($r['ComputerName'] ?? '') ?>')" title="Editar Senha Manual">
                        <i class="fas fa-edit"></i>
                      </button>
                      <button class="icon-btn" onclick="deletePasswordForm('<?= htmlspecialchars($r['ComputerName'] ?? '') ?>')" title="Excluir Senha Manual">
                        <i class="fas fa-trash-alt"></i>
                      </button>
                    <?php else: ?>
                      <button class="toggle-password-btn" data-target=".password-text.manual" style="opacity: 0.3; cursor: not-allowed;" disabled title="Visualizar Senha Manual">
                        <i class="far fa-eye"></i>
                      </button>
                      <button class="copy-btn" style="opacity: 0.3; cursor: not-allowed;" disabled title="Copiar Senha Manual">
                        <i class="far fa-copy"></i>
                      </button>
                      <button class="icon-btn" onclick="editPasswordForm('<?= htmlspecialchars($r['ComputerName'] ?? '') ?>')" title="Adicionar Senha Manual">
                        <i class="fas fa-plus"></i>
                      </button>
                      <button class="icon-btn" style="opacity: 0.3; cursor: not-allowed;" disabled>
                        <i class="fas fa-trash-alt"></i>
                      </button>
                    <?php endif; ?>
                  </div>
                </td>
              </tr>
            <?php endforeach; ?>
          </tbody>
        </table>
      <?php else: ?>
        <?php if (!($isMobile && $computerNameFilter === '')): ?>
        <div class="empty-state">
          <i class="fas fa-info-circle"></i> Nenhum registro encontrado.
        </div>
        <?php endif; ?>
      <?php endif; ?>

      <?php if ($rows): ?>
      <div class="results-cards mobile-only">
        <?php foreach ($rows as $r): ?>
          <div class="pc-card">
            <div class="pc-card-row">
              <span class="pc-label"><i class="fas fa-desktop"></i></span>
              <span class="pc-value"><?= htmlspecialchars($r['ComputerName'] ?? '') ?></span>
            </div>
            <div class="pc-card-row">
              <span class="pc-label"><i class="fas fa-key"></i></span>
              <div class="pc-actions">
                <span class="pc-password <?= ($r['Password'] ?? '') !== '' ? '' : 'empty' ?>"><?= htmlspecialchars($r['Password'] ?? '') ?></span>
                <button class="toggle-password-btn" onclick="togglePassword(this)"><i class="far fa-eye"></i></button>
                <button class="copy-btn" onclick="copyToClipboard('<?= htmlspecialchars($r['Password'] ?? '') ?>')"><i class="far fa-copy"></i></button>
              </div>
            </div>
            <div class="pc-card-row">
              <span class="pc-label"><i class="fas fa-calendar-day"></i></span>
              <?php 
                $exp = $r['ExpirationTimestamp'] ?? '';
                $statusClass = '';
                $title = '';
                if ($exp) {
                  $today = new DateTime(date('Y-m-d'));
                  $expDt = new DateTime((new DateTime($exp))->format('Y-m-d'));
                  $diff = (int)$today->diff($expDt)->format('%r%a');
                  if ($diff < 0) {
                    $statusClass = 'status-expired';
                  } elseif ($diff === 7) {
                    $statusClass = 'status-ok';
                  } elseif ($diff >= 0 && $diff < 7) {
                    $statusClass = 'status-warn';
                  }
                  $title = ($diff < 0) ? 'Expirada' : ($diff.' dias');
                }
              ?>
              <span class="status-pill <?= $statusClass ?>" title="<?= htmlspecialchars($title) ?>"><?= htmlspecialchars($exp) ?></span>
            </div>
            <div class="pc-card-row">
              <span class="pc-label"><i class="fas fa-pen"></i></span>
              <div class="pc-actions">
                <span class="pc-password manual <?= ($r['ManualPassword'] ?? '') !== '' ? '' : 'empty' ?>"><?= htmlspecialchars($r['ManualPassword'] ?? '') ?></span>
                <?php if ($r['ManualPassword'] !== null): ?>
                  <button class="toggle-password-btn" data-target=".pc-password.manual" onclick="togglePassword(this)"><i class="far fa-eye"></i></button>
                  <button class="copy-btn" onclick="copyToClipboard('<?= htmlspecialchars($r['ManualPassword']) ?>')"><i class="far fa-copy"></i></button>
                <?php else: ?>
                  <button class="toggle-password-btn" data-target=".pc-password.manual" style="opacity:0.3;cursor:not-allowed;" disabled><i class="far fa-eye"></i></button>
                  <button class="copy-btn" style="opacity:0.3;cursor:not-allowed;" disabled><i class="far fa-copy"></i></button>
                <?php endif; ?>
              </div>
            </div>
            <div class="pc-card-row desktop-only">
              <a href="<?= htmlspecialchars(rtrim($config['glpi_url'], '/')) ?>/front/computer.php?is_deleted=0&as_map=0&browse=0&criteria%5B0%5D%5Blink%5D=AND&criteria%5B0%5D%5Bfield%5D=view&criteria%5B0%5D%5Bsearchtype%5D=contains&criteria%5B0%5D%5Bvalue%5D=<?= urlencode($r['ComputerName']) ?>&itemtype=Computer&start=0" 
                 class="btn glpi-btn" target="_blank" title="Ver no GLPI">
                <i class="fa fa-desktop" aria-hidden="true"></i> GLPI
              </a>
            </div>
          </div>
        <?php endforeach; ?>
      </div>
      <?php endif; ?>
    </main>
  </div>

  <script>
    // Função para alternar o tema
    function toggleTheme() {
        const body = document.body;
        const currentTheme = body.getAttribute('data-theme');
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
        body.setAttribute('data-theme', newTheme);
        localStorage.setItem('theme', newTheme);
        const icon = document.querySelector('.theme-toggle i');
        icon.className = newTheme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
    }

    // Carregar tema salvo
    document.addEventListener('DOMContentLoaded', () => {
        const savedTheme = localStorage.getItem('theme') || 'light';
        document.body.setAttribute('data-theme', savedTheme);
        const icon = document.querySelector('.theme-toggle i');
        icon.className = savedTheme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
        adjustMobileHeader();
    });
    
    function togglePassword(button) {
      const targetSelector = button.getAttribute('data-target');
      let passwordText = null;
      if (targetSelector) {
        const scope = button.closest('tr') || button.closest('.pc-card') || document;
        passwordText = scope.querySelector(targetSelector);
      }
      if (!passwordText) {
        const container = button.closest('.password-container') || button.closest('.pc-actions');
        passwordText = container ? (container.querySelector('.password-text') || container.querySelector('.pc-password')) : null;
      }
      if (!passwordText) {
        const scope = button.closest('tr') || button.closest('.pc-card');
        if (scope) {
          passwordText = scope.querySelector('.password-text') || scope.querySelector('.pc-password');
        }
      }
      if (!passwordText) return;
      const icon = button.querySelector('i');
      passwordText.classList.toggle('visible');
      if (icon) {
        icon.className = passwordText.classList.contains('visible') ? 'far fa-eye-slash' : 'far fa-eye';
      }
    }

    function updateData(event) {
        const btn = event.currentTarget;
        const originalText = btn.innerHTML;
        let pollingInterval;

        function startPolling() {
            console.log("Iniciando verificação de status (polling)...");
            pollingInterval = setInterval(() => {
                fetch('check_status.php')
                    .then(response => response.json())
                    .then(data => {
                        console.log("Status recebido:", data);
                        if (data.status === 'completed' || data.status === 'error') {
                            clearInterval(pollingInterval);
                            console.log("Polling finalizado. Recarregando...");
                            btn.innerHTML = `<i class="fas fa-check-circle"></i> Concluído`;
                            setTimeout(() => {
                                location.reload();
                            }, 1500);
                        }
                    })
                    .catch(error => {
                        console.error("Erro no polling:", error);
                        clearInterval(pollingInterval);
                        btn.innerHTML = originalText;
                        btn.disabled = false;
                    });
            }, 5000);
        }

        btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Atualizando...';
        btn.disabled = true;

        fetch('update_laps.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: 'csrf_token=<?= gerarTokenCsrf() ?>'
        })
        .then(response => response.text())
        .then(text => {
            console.log("Resposta do 'update_laps.php':", text);
            if (text.includes("iniciado em segundo plano")) {
                startPolling();
            } else {
                alert("Erro ao iniciar o processo de atualização: " + text);
                btn.innerHTML = originalText;
                btn.disabled = false;
            }
        })
        .catch(error => {
            console.error("Erro ao chamar 'update_laps.php':", error);
            alert("Erro de comunicação ao tentar iniciar a atualização.");
            btn.innerHTML = originalText;
            btn.disabled = false;
        });
    }

    // Funções para gerenciar senhas manuais via formulário
    function editPasswordForm(computer){
      const pass = prompt('Nova senha manual para ' + computer + ':');
      if (pass === null) return;
      
      const form = document.createElement('form');
      form.method = 'POST';
      form.action = window.location.href; // Submete para a própria página
      
      form.innerHTML = `
        <input type="hidden" name="computer" value="${computer}">
        <input type="hidden" name="manual_password" value="${pass}">
        <input type="hidden" name="csrf_token" value="<?= gerarTokenCsrf() ?>">
      `;
      
      document.body.appendChild(form);
      form.submit();
    }

    function deletePasswordForm(computer){
      if (!confirm('Tem certeza que deseja excluir a senha manual de ' + computer + '?')) return;
      
      const form = document.createElement('form');
      form.method = 'POST';
      form.action = window.location.href;
      
      form.innerHTML = `
        <input type="hidden" name="computer" value="${computer}">
        <input type="hidden" name="delete_manual_password" value="1">
        <input type="hidden" name="csrf_token" value="<?= gerarTokenCsrf() ?>">
      `;
      
      document.body.appendChild(form);
      form.submit();
    }

    function showToast(message){
      const t = document.getElementById('toast');
      if (!t) return;
      t.textContent = message;
      t.classList.add('show');
      setTimeout(() => t.classList.remove('show'), 2000);
    }
    function copyToClipboard(txt){
      navigator.clipboard.writeText(txt)
        .then(() => showToast('Copiado'))
        .catch(() => showToast('Erro ao copiar'))
    }

    function toggleAlphabetGuide() {
      const guide = document.getElementById('alphabetGuide');
      const icon = document.getElementById('alphabetToggleIcon');
      
      guide.classList.toggle('collapsed');
      
      if (guide.classList.contains('collapsed')) {
        icon.className = 'fas fa-chevron-down';
      } else {
        icon.className = 'fas fa-chevron-up';
      }
      
      // Salvar estado no localStorage
      localStorage.setItem('alphabetGuideCollapsed', guide.classList.contains('collapsed'));
    }

    // Restaurar estado do guia ao carregar a página
    document.addEventListener('DOMContentLoaded', function() {
      const isCollapsed = localStorage.getItem('alphabetGuideCollapsed') === 'true';
      const guide = document.getElementById('alphabetGuide');
      const icon = document.getElementById('alphabetToggleIcon');
      
      if (isCollapsed) {
        guide.classList.add('collapsed');
        icon.className = 'fas fa-chevron-down';
      }
    });

    function logout(){
      if (confirm('Deseja realmente sair do sistema?')) {
        window.location.href = 'logout.php';
      }
    }
  </script>
</body>
</html>
<script>
  function debounce(fn, ms){ let t; return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); }; }
  document.addEventListener('DOMContentLoaded', () => {
    const input = document.querySelector('.search-input');
    const form = document.querySelector('.search-form');
    const submitDebounced = debounce(() => { if (input && input.value.trim() !== '') { showLoadingSkeleton(); form.submit(); } }, 350);
    if (input) { input.addEventListener('input', submitDebounced); }
    if (form) { form.addEventListener('submit', () => { showLoadingSkeleton(); adjustMobileHeader(); }); }
  });
  function showLoadingSkeleton(){
    const main = document.querySelector('.main-content');
    if (!main) return;
    const overlay = document.createElement('div');
    overlay.className = 'skeleton-overlay';
    for (let i=0;i<6;i++){ const s = document.createElement('div'); s.className = 'skeleton-card'; overlay.appendChild(s); }
    main.innerHTML = '';
    main.appendChild(overlay);
  }
  function adjustMobileHeader(){
    if (!window.matchMedia('(max-width: 768px)').matches) return;
    const header = document.querySelector('.header');
    if (!header) return;
    const h = header.offsetHeight;
    document.documentElement.style.setProperty('--mobile-header-h', h + 'px');
  }
  window.addEventListener('resize', adjustMobileHeader);
</script>
