<?php
// Headers de segurança
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' cdnjs.cloudflare.com cdn.jsdelivr.net; font-src cdnjs.cloudflare.com; img-src 'self' data:;");

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Inclui o sistema de autenticação local
require_once 'local_auth.php';

// Verifica se o usuário está logado
requireLogin();

// === CONEXÃO COM BANCO DE DADOS ===
global $config;
if (!isset($config)) {
    $config = include(__DIR__ . '/config.php');
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

// === CONSULTAS PARA DASHBOARD ===

// 1. Total de computadores
$totalComputers = $conn->query("SELECT COUNT(*) as total FROM Passwords")->fetch_assoc()['total'];

// 2. Senhas que expiram hoje
$expireToday = $conn->query("
    SELECT COUNT(*) as total 
    FROM Passwords 
    WHERE ExpirationTimestamp = CURDATE()
")->fetch_assoc()['total'];

// 3. Senhas que expiram nos próximos 30 dias
$recentPasswords = $conn->query("
    SELECT COUNT(*) as total 
    FROM Passwords 
    WHERE ExpirationTimestamp BETWEEN CURDATE() AND DATE_ADD(CURDATE(), INTERVAL 30 DAY)
")->fetch_assoc()['total'];

// 3. Senhas que expiram entre 30 dias e 6 meses
$sixMonthsPasswords = $conn->query("
    SELECT COUNT(*) as total 
    FROM Passwords 
    WHERE ExpirationTimestamp BETWEEN DATE_ADD(CURDATE(), INTERVAL 30 DAY) AND DATE_ADD(CURDATE(), INTERVAL 6 MONTH)
")->fetch_assoc()['total'];

// 4. Senhas que expiram em mais de 6 meses
$oneYearPasswords = $conn->query("
    SELECT COUNT(*) as total 
    FROM Passwords 
    WHERE ExpirationTimestamp > DATE_ADD(CURDATE(), INTERVAL 6 MONTH)
")->fetch_assoc()['total'];

// 5. Senhas já expiradas (todas as que expiraram antes de hoje)
$expiredPasswords = $conn->query("
    SELECT COUNT(*) as total 
    FROM Passwords 
    WHERE ExpirationTimestamp < CURDATE()
")->fetch_assoc()['total'];

// 6. Senhas expiradas há mais de 6 meses
$expiredSixMonths = $conn->query("
    SELECT COUNT(*) as total 
    FROM Passwords 
    WHERE ExpirationTimestamp < DATE_SUB(CURDATE(), INTERVAL 6 MONTH)
")->fetch_assoc()['total'];

// 7. Senhas expiradas há mais de 1 ano
$expiredOneYear = $conn->query("
    SELECT COUNT(*) as total 
    FROM Passwords 
    WHERE ExpirationTimestamp < DATE_SUB(CURDATE(), INTERVAL 1 YEAR)
")->fetch_assoc()['total'];

// 5. Senhas que expiram nos próximos 30 dias
$expiringSoon = $conn->query("
    SELECT COUNT(*) as total 
    FROM Passwords 
    WHERE ExpirationTimestamp BETWEEN CURDATE() AND DATE_ADD(CURDATE(), INTERVAL 30 DAY)
")->fetch_assoc()['total'];

// 6. Senhas manuais
$manualPasswords = $conn->query("
    SELECT COUNT(*) as total 
    FROM ComputerManualPasswords
")->fetch_assoc()['total'];

// 7. Senhas nulas
$nullPasswords = $conn->query("
    SELECT COUNT(*) as total 
    FROM null_passwords
")->fetch_assoc()['total'];

// 8. Computadores alterados HOJE (baseado na nova lógica otimizada)
$updatedToday = $conn->query("
    SELECT COUNT(*) as total 
    FROM Passwords p
    WHERE EXISTS (SELECT 1 FROM old_passwords o WHERE o.ComputerName = p.ComputerName AND DATE(o.created_at) = CURDATE())
")->fetch_assoc()['total'];

// 8. Dados para gráfico de linha - computadores alterados por dia (últimos 30 dias)
$dailyData = [];
for ($i = 29; $i >= 0; $i--) {
    $date = date('Y-m-d', strtotime("-$i days"));
    $dayName = date('d/m', strtotime("-$i days"));
    
    $result = $conn->query("
        SELECT COUNT(*) as total 
        FROM Passwords 
        WHERE DATE(updated_at) = '$date'
    ")->fetch_assoc();
    
    $dailyData[] = [
        'day' => $dayName,
        'count' => (int)$result['total']
    ];
}

// 9. Dados para gráfico de pizza - distribuição por status
$statusData = [
    ['label' => 'Ativas', 'value' => $totalComputers - $nullPasswords, 'color' => '#2ca444'],
    ['label' => 'Nulas', 'value' => $nullPasswords, 'color' => '#3b82f6'],
    ['label' => 'Manuais', 'value' => $manualPasswords, 'color' => '#f59e0b']
];

// 10. Dados para gráfico de barras - senhas por faixa de tempo
$timeRangeData = [
    ['label' => 'Expira Hoje', 'value' => $expireToday, 'color' => '#3b82f6'],
    ['label' => 'Expira em 30 dias', 'value' => $recentPasswords, 'color' => '#2ca444'],
    ['label' => 'Expiradas', 'value' => $expiredPasswords, 'color' => '#f59e0b'],
    ['label' => 'Expiradas 6+ meses', 'value' => $expiredSixMonths, 'color' => '#8b5cf6'],
    ['label' => 'Expiradas 1+ ano', 'value' => $expiredOneYear, 'color' => '#6366f1']
];

$conn->close();

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
    <title>Dashboard LAPS</title>
    <link rel="icon" href="./img/fav.png" type="image/x-icon">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="style.css">
    <link rel="stylesheet" href="dashboard.css">
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <button class="theme-toggle" onclick="toggleTheme()" title="Alternar tema">
        <i class="fas fa-moon"></i>
    </button>
    
    <div class="dashboard-container">
        <header class="header">
            <div class="title">
                <div class="title-left">
                    <img src="./img/lap.png" class="logo" alt="LAPS" onclick="alert('Versão: <?= $version ?>')">
                    <h1 class="custom-title">Dashboard LAPS</h1>
                </div>
                <div class="user-section-title">
                    <div class="user-info-title">
                        <i class="fas fa-user"></i> 
                        <a href="profile.php" class="user-profile-link" title="Ver perfil">
                            <?= htmlspecialchars($_SESSION['username'] ?? 'N/A') ?>
                        </a>
                    </div>
                    <button onclick="logout()" class="btn logout-btn" title="Sair do sistema">
                        <i class="fas fa-sign-out-alt"></i>
                    </button>
                </div>
            </div>
            <div class="status-bar">
                <div class="update-status">
                    <i class="fas fa-clock"></i> Atualizado: <?= htmlspecialchars($lastUpdate) ?>
                </div>
                <div class="status-buttons">
                    <button onclick="window.location.href='view_laps.php'" class="btn refresh-btn">
                        <i class="fas fa-list"></i> Ver Senhas
                    </button>
                    <button onclick="updateData(event)" class="btn refresh-btn">
                        <i class="fas fa-sync-alt"></i> Atualizar
                    </button>
                    
                </div>
            </div>
        </header>

        



                <!-- Cards de Estatísticas -->
        <div class="stats-grid">
            <a href="view_laps.php" class="stat-card-link">
                <div class="stat-card">
                    <i class="fas fa-desktop stat-icon"></i>
                    <div class="stat-value"><?= number_format($totalComputers) ?></div>
                    <div class="stat-label">Total de Computadores</div>
                </div>
            </a>
            
            <a href="view_laps.php?filter=expire_today" class="stat-card-link">
                <div class="stat-card <?= $expireToday > 0 ? 'danger' : '' ?>">
                    <i class="fas fa-calendar-day stat-icon"></i>
                    <div class="stat-value"><?= number_format($expireToday) ?></div>
                    <div class="stat-label">Expira Hoje</div>
                </div>
            </a>
            

            
            <a href="view_laps.php?filter=expired" class="stat-card-link">
                <div class="stat-card <?= $expiredPasswords > 0 ? 'danger' : '' ?>">
                    <i class="fas fa-times-circle stat-icon"></i>
                    <div class="stat-value"><?= number_format($expiredPasswords) ?></div>
                    <div class="stat-label">Senhas Expiradas</div>
                </div>
            </a>
            
            <a href="view_laps.php?filter=expired_6_months" class="stat-card-link">
                <div class="stat-card <?= $expiredSixMonths > 0 ? 'danger' : '' ?>">
                    <i class="fas fa-exclamation-triangle stat-icon"></i>
                    <div class="stat-value"><?= number_format($expiredSixMonths) ?></div>
                    <div class="stat-label">Expiradas há 6+ meses</div>
                </div>
            </a>
            
            <a href="view_laps.php?filter=expired_1_year" class="stat-card-link">
                <div class="stat-card <?= $expiredOneYear > 0 ? 'danger' : '' ?>">
                    <i class="fas fa-exclamation-circle stat-icon"></i>
                    <div class="stat-value"><?= number_format($expiredOneYear) ?></div>
                    <div class="stat-label">Expiradas há 1+ ano</div>
                </div>
            </a>
            
            <a href="view_laps.php?filter=manual" class="stat-card-link">
                <div class="stat-card">
                    <i class="fas fa-key stat-icon"></i>
                    <div class="stat-value"><?= number_format($manualPasswords) ?></div>
                    <div class="stat-label">Senhas Manuais</div>
                </div>
            </a>
            
            <a href="view_laps.php?filter=updated_today" class="stat-card-link">
                <div class="stat-card <?= $updatedToday > 0 ? 'success' : '' ?>">
                    <i class="fas fa-sync-alt stat-icon"></i>
                    <div class="stat-value"><?= number_format($updatedToday) ?></div>
                    <div class="stat-label">Alteradas Hoje</div>
                </div>
            </a>
            
            <a href="view_laps.php?computername=&show_null_passwords=on" class="stat-card-link">
                <div class="stat-card <?= $nullPasswords > 0 ? 'warning' : '' ?>">
                    <i class="fas fa-ban stat-icon"></i>
                    <div class="stat-value"><?= number_format($nullPasswords) ?></div>
                    <div class="stat-label">Senhas Nulas</div>
                </div>
            </a>
        </div>

        <!-- Gráficos -->
        <div class="charts-grid">
            <!-- Gráfico de Linha - Computadores Alterados por Dia -->
            <div class="chart-container">
                <div class="chart-title">Computadores Alterados por Dia</div>
                <div class="chart-canvas">
                    <canvas id="dailyChart"></canvas>
                </div>
            </div>

            

            <!-- Gráfico de Barras - Senhas por Faixa de Tempo -->
            <div class="chart-container">
                <div class="chart-title">Senhas por Data de Expiração</div>
                <div class="chart-canvas">
                    <canvas id="timeRangeChart"></canvas>
                </div>
            </div>

            <!-- Gráfico de Doughnut - Visão Geral -->
            <div class="chart-container">
                <div class="chart-title">Distribuição por Status</div>
                <div class="chart-canvas">
                    <canvas id="overviewChart"></canvas>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Configuração do tema
        function toggleTheme() {
            const body = document.body;
            const currentTheme = body.getAttribute('data-theme');
            const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
            body.setAttribute('data-theme', newTheme);
            localStorage.setItem('theme', newTheme);
            
            // Atualizar ícone
            const icon = document.querySelector('.theme-toggle i');
            icon.className = newTheme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
            
            // Recarregar gráficos com novo tema
            updateChartsTheme();
        }

        // Carregar tema salvo
        const savedTheme = localStorage.getItem('theme') || 'light';
        document.body.setAttribute('data-theme', savedTheme);
        const icon = document.querySelector('.theme-toggle i');
        icon.className = savedTheme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';

        // Configuração do Chart.js
        Chart.defaults.color = getComputedStyle(document.body).getPropertyValue('--text-color');
        Chart.defaults.borderColor = getComputedStyle(document.body).getPropertyValue('--card-border');

                 // Dados dos gráficos
         const dailyData = <?= json_encode($dailyData) ?>;
         const timeRangeData = <?= json_encode($timeRangeData) ?>;

        // Gráfico de linha - Computadores alterados por dia
        const dailyCtx = document.getElementById('dailyChart').getContext('2d');
        const dailyChart = new Chart(dailyCtx, {
            type: 'line',
            data: {
                labels: dailyData.map(item => item.day),
                datasets: [{
                    label: 'Computadores Alterados',
                    data: dailyData.map(item => item.count),
                    borderColor: '#2ca444',
                    backgroundColor: 'rgba(44, 164, 68, 0.1)',
                    borderWidth: 3,
                    fill: true,
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            stepSize: 1
                        }
                    }
                }
            }
        });

        

        // Gráfico de barras - Senhas por faixa de tempo
        const timeRangeCtx = document.getElementById('timeRangeChart').getContext('2d');
        const timeRangeChart = new Chart(timeRangeCtx, {
            type: 'bar',
            data: {
                labels: timeRangeData.map(item => item.label),
                datasets: [{
                    label: 'Quantidade',
                    data: timeRangeData.map(item => item.value),
                    backgroundColor: timeRangeData.map(item => item.color),
                    borderWidth: 0,
                    borderRadius: 8
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            stepSize: 1
                        }
                    }
                }
            }
        });

        // Gráfico de doughnut - Visão geral
        const overviewCtx = document.getElementById('overviewChart').getContext('2d');
        const overviewChart = new Chart(overviewCtx, {
            type: 'doughnut',
            data: {
                labels: ['Expira Hoje', 'Expirando em 30 dias', 'Expiradas', 'Nulas'],
                datasets: [{
                    data: [
                        <?= $expireToday ?>,
                        <?= $recentPasswords ?>,
                        <?= $expiredPasswords ?>,
                        <?= $nullPasswords ?>
                    ],
                                         backgroundColor: ['#3b82f6', '#2ca444', '#f59e0b', '#8b5cf6'],
                    borderWidth: 2,
                    borderColor: getComputedStyle(document.body).getPropertyValue('--card-bg')
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });

        // Função para atualizar tema dos gráficos
        function updateChartsTheme() {
            const textColor = getComputedStyle(document.body).getPropertyValue('--text-color');
            const borderColor = getComputedStyle(document.body).getPropertyValue('--card-border');
            
                         // Atualizar cores dos gráficos
             [dailyChart, timeRangeChart, overviewChart].forEach(chart => {
                if (chart.options.scales) {
                    chart.options.scales.x.grid.color = borderColor;
                    chart.options.scales.y.grid.color = borderColor;
                }
                chart.update();
            });
        }

        // Função de logout
        function logout() {
            if (confirm('Deseja realmente sair do sistema?')) {
                window.location.href = 'logout.php';
            }
        }

        // Função de atualização
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
                            // Atualiza a mensagem do botão para dar feedback
                            btn.innerHTML = `<i class="fas fa-spinner fa-spin"></i> ${data.message || 'Atualizando...'}`;
                            
                            if (data.status === 'completed' || data.status === 'error') {
                                clearInterval(pollingInterval);
                                console.log("Polling finalizado. Status:", data.status);
                                
                                let finalMessage = data.status === 'completed' 
                                    ? '<i class="fas fa-check-circle"></i> Atualização Concluída!' 
                                    : '<i class="fas fa-times-circle"></i> Falha na Atualização';

                                btn.innerHTML = finalMessage;
                                
                                // Recarrega a página após um breve delay para o usuário ver a mensagem final.
                                setTimeout(() => {
                                    location.reload();
                                }, 2000);
                            }
                        })
                        .catch(error => {
                            console.error("Erro no polling:", error);
                            clearInterval(pollingInterval);
                            btn.innerHTML = originalText;
                            btn.disabled = false;
                        });
                }, 5000); // Verifica a cada 5 segundos
            }

            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Iniciando...';
            btn.disabled = true;

            // Chama o script para iniciar o processo em segundo plano
            fetch('update_laps.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: 'csrf_token=<?= gerarTokenCsrf() ?>'
            })
            .then(response => response.text())
            .then(text => {
                console.log("Resposta do 'update_laps.php':", text);
                if (text.includes("iniciado em segundo plano")) {
                    // Se o processo foi iniciado com sucesso, começa a verificar o status.
                    startPolling();
                } else {
                    // Se houve um erro ao iniciar, reverte o botão.
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
    </script>
</body>
</html> 
