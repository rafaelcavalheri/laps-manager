<?php
// Verifica se o usuário está logado
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Verifica se o usuário tem acesso à configuração LDAP
require_once 'local_auth.php';

// Proteção CSRF
if (!function_exists('gerarTokenCsrf')) {
    function gerarTokenCsrf() {
        if (empty($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        }
        return $_SESSION['csrf_token'];
    }
}

if (!function_exists('validarTokenCsrf')) {
    function validarTokenCsrf($token) {
        return hash_equals($_SESSION['csrf_token'] ?? '', $token);
    }
}

function requireLdapConfigAccess() {
    // Permite acesso para admins locais
    if (isAdmin()) {
        return;
    }
    
    // Permite acesso para usuários LDAP autenticados
    if (isset($_SESSION['auth_type']) && $_SESSION['auth_type'] === 'ldap') {
        return;
    }
    
    // Redireciona para login se não tiver acesso
    header("Location: login.php");
    exit();
}

requireLdapConfigAccess();

// Carregar configurações atuais
$currentConfig = [
    'DB_NAME' => getenv('DB_NAME') ?: 'laps',
    'DB_USER' => getenv('DB_USER') ?: 'root',
    'DB_PASS' => getenv('DB_PASSWORD') ?: '',
    'DB_HOST' => getenv('DB_HOST') ?: 'db',
    'LDAP_SERVER' => '',
    'LDAP_USER' => '',
    'LDAP_BASE' => '',
    'LDAP_PASSWORD' => ''
];

$configFile = __DIR__ . '/ldap_settings.php';

if (file_exists($configFile)) {
    // Definir constante de segurança antes de incluir (se não estiver definida)
    if (!defined('SECURE_ACCESS')) {
        define('SECURE_ACCESS', true);
    }
    require_once $configFile;
    
    // Verificar se as variáveis foram definidas e não estão vazias
    if (isset($dbName) && !empty($dbName)) $currentConfig['DB_NAME'] = $dbName;
    if (isset($dbUser) && !empty($dbUser)) $currentConfig['DB_USER'] = $dbUser;
    if (isset($dbPass) && !empty($dbPass)) $currentConfig['DB_PASS'] = $dbPass;
    if (isset($dbHost) && !empty($dbHost)) $currentConfig['DB_HOST'] = $dbHost;
    if (isset($ldapServer) && !empty($ldapServer)) $currentConfig['LDAP_SERVER'] = $ldapServer;
    if (isset($ldapUser) && !empty($ldapUser)) $currentConfig['LDAP_USER'] = $ldapUser;
    if (isset($ldapBase) && !empty($ldapBase)) $currentConfig['LDAP_BASE'] = $ldapBase;
    if (isset($ldapPassword) && !empty($ldapPassword)) $currentConfig['LDAP_PASSWORD'] = $ldapPassword;
}

// Função para atualizar as configurações
function updateConfig($newConfig) {
    $configFile = __DIR__ . '/ldap_settings.php';
    
    // Criar conteúdo do arquivo de configuração
    $configContent = "<?php\n";
    $configContent .= "// Configurações LDAP - Gerado automaticamente\n";
    $configContent .= "// Última atualização: " . date('Y-m-d H:i:s') . "\n\n";
    $configContent .= "// Configurações do MySQL\n";
    $configContent .= "\$dbName = '" . addslashes($newConfig['DB_NAME']) . "';\n";
    $configContent .= "\$dbUser = '" . addslashes($newConfig['DB_USER']) . "';\n";
    $configContent .= "\$dbPass = '" . addslashes($newConfig['DB_PASS']) . "';\n";
    $configContent .= "\$dbHost = '" . addslashes($newConfig['DB_HOST']) . "';\n\n";
    $configContent .= "// Configurações do LDAP\n";
    $configContent .= "\$ldapServer = '" . addslashes($newConfig['LDAP_SERVER']) . "';\n";
    $configContent .= "\$ldapUser = '" . addslashes($newConfig['LDAP_USER']) . "';\n";
    $configContent .= "\$ldapBase = '" . addslashes($newConfig['LDAP_BASE']) . "';\n";
    $configContent .= "\$ldapPassword = '" . addslashes($newConfig['LDAP_PASSWORD']) . "';\n";
    
    // Salvar diretamente no arquivo
    if (file_put_contents($configFile, $configContent)) {
        return true;
    } else {
        error_log("LDAP Config: Falha ao salvar arquivo de configuração $configFile");
        return false;
    }
}

// Variáveis para mensagens
$sucesso = '';
$erro = '';
$testResult = null;

// Processar formulário
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Verificar token CSRF
    if (!isset($_POST['csrf_token']) || !validarTokenCsrf($_POST['csrf_token'])) {
        die("Token CSRF inválido!");
    }
    $newConfig = [
        'DB_NAME' => trim($_POST['DB_NAME'] ?? ''),
        'DB_USER' => trim($_POST['DB_USER'] ?? ''),
        'DB_PASS' => trim($_POST['DB_PASS'] ?? ''),
        'DB_HOST' => trim($_POST['DB_HOST'] ?? ''),
        'LDAP_SERVER' => trim($_POST['LDAP_SERVER'] ?? ''),
        'LDAP_USER' => trim($_POST['LDAP_USER'] ?? ''),
        'LDAP_BASE' => trim($_POST['LDAP_BASE'] ?? ''),
        'LDAP_PASSWORD' => trim($_POST['LDAP_PASSWORD'] ?? '')
    ];
    
    // Atualizar configuração atual com os valores do formulário
    $currentConfig = array_merge($currentConfig, $newConfig);
    
    // Validar campos obrigatórios baseado no tipo de ação
    $missingFields = [];
    
    if (isset($_POST['test_db_connection'])) {
        // Debug: verificar se estamos realmente no teste do banco
        error_log("DEBUG: Testando banco de dados");
        
        // Validar apenas campos do banco de dados
        $dbFields = ['DB_NAME', 'DB_USER', 'DB_PASS', 'DB_HOST'];
        $missingFields = []; // Reset array para este teste específico
        
        foreach ($dbFields as $field) {
            if (empty($newConfig[$field])) {
                $missingFields[] = $field;
            }
        }
        
        error_log("DEBUG: Campos faltando para banco: " . implode(', ', $missingFields));
        
        if (!empty($missingFields)) {
            $erro = "Para testar o banco de dados, os seguintes campos são obrigatórios: " . implode(', ', $missingFields);
        } else {
            // Se não há campos faltando, prosseguir com o teste
            try {
                // Testar conexão com o banco de dados
                $mysqli = new mysqli(
                    $newConfig['DB_HOST'],
                    $newConfig['DB_USER'],
                    $newConfig['DB_PASS'],
                    $newConfig['DB_NAME']
                );
                
                if ($mysqli->connect_error) {
                    throw new Exception("Erro na conexão com o banco: " . $mysqli->connect_error);
                }
                
                // Testar se consegue executar uma query simples
                $result = $mysqli->query("SELECT 1 as test");
                if (!$result) {
                    throw new Exception("Erro ao executar query de teste: " . $mysqli->error);
                }
                
                $testResult = [
                    'success' => true,
                    'message' => "Conexão com o banco de dados estabelecida com sucesso! Host: {$newConfig['DB_HOST']}, Banco: {$newConfig['DB_NAME']}, Usuário: {$newConfig['DB_USER']}"
                ];
                $mysqli->close();
                
            } catch (Exception $e) {
                $testResult = [
                    'success' => false,
                    'message' => "Erro: " . $e->getMessage()
                ];
            }
        }
    } elseif (isset($_POST['test_connection'])) {
        // Debug: verificar se estamos realmente no teste do LDAP
        error_log("DEBUG: Testando LDAP");
        
        // Validar apenas campos do LDAP
        $ldapFields = ['LDAP_SERVER', 'LDAP_USER', 'LDAP_BASE', 'LDAP_PASSWORD'];
        $missingFields = []; // Reset array para este teste específico
        
        foreach ($ldapFields as $field) {
            if (empty($newConfig[$field])) {
                $missingFields[] = $field;
            }
        }
        
        error_log("DEBUG: Campos faltando para LDAP: " . implode(', ', $missingFields));
        
        if (!empty($missingFields)) {
            $erro = "Para testar o LDAP, os seguintes campos são obrigatórios: " . implode(', ', $missingFields);
        } else {
            // Se não há campos faltando, prosseguir com o teste
            try {
                // Testar conexão LDAP
                $ldapConn = ldap_connect($newConfig['LDAP_SERVER']);
                if (!$ldapConn) {
                    throw new Exception("Não foi possível conectar ao servidor LDAP.");
                }
                
                ldap_set_option($ldapConn, LDAP_OPT_PROTOCOL_VERSION, 3);
                ldap_set_option($ldapConn, LDAP_OPT_REFERRALS, 0);
                
                // Tentar bind com as credenciais fornecidas
                if (!@ldap_bind($ldapConn, $newConfig['LDAP_USER'], $newConfig['LDAP_PASSWORD'])) {
                    throw new Exception("Falha na autenticação LDAP. Verifique usuário e senha.");
                }
                
                $testResult = [
                    'success' => true,
                    'message' => "Conexão com o servidor LDAP estabelecida com sucesso!"
                ];
                ldap_unbind($ldapConn);
                
            } catch (Exception $e) {
                $testResult = [
                    'success' => false,
                    'message' => "Erro: " . $e->getMessage()
                ];
            }
        }
    } else {
        // Para salvar, validar todos os campos
        $requiredFields = ['DB_NAME', 'DB_USER', 'DB_PASS', 'DB_HOST', 'LDAP_SERVER', 'LDAP_USER', 'LDAP_BASE', 'LDAP_PASSWORD'];
        foreach ($requiredFields as $field) {
            if (empty($newConfig[$field])) {
                $missingFields[] = $field;
            }
        }
        if (!empty($missingFields)) {
            $erro = "Os seguintes campos são obrigatórios: " . implode(', ', $missingFields);
        }
    }
    
    if (empty($missingFields) && !isset($_POST['test_db_connection']) && !isset($_POST['test_connection'])) {
        // Apenas para salvar configurações (quando não é teste)
        try {
            if (updateConfig($newConfig)) {
                $sucesso = "Configurações LDAP salvas com sucesso!";
                $currentConfig = $newConfig;
            } else {
                throw new Exception("Não foi possível salvar as configurações.");
            }
        } catch (Exception $e) {
            $erro = "Erro: " . $e->getMessage();
        }
    }
}

$version = file_exists('version.txt') ? trim(file_get_contents('version.txt')) : '1.0.0';
?>
<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Configurações - LAPS</title>
    <link rel="icon" href="./fav.png" type="image/x-icon">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="style.css">
    <style>
        .config-section {
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: var(--radius);
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            box-shadow: 0 4px 6px -1px var(--shadow-color);
        }
        
        .config-section h3 {
            color: var(--text-color);
            margin-bottom: 1rem;
            font-size: 1.3rem;
            font-weight: 600;
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding-bottom: 0.75rem;
            border-bottom: 2px solid var(--card-border);
        }
        
        .section-title-content {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .section-test-button {
            padding: 0.4rem 0.8rem;
            font-size: 0.8rem;
            border: none;
            border-radius: var(--radius);
            font-weight: 500;
            cursor: pointer;
            transition: all var(--transition-fast);
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 0.3rem;
            box-shadow: 0 1px 3px 0 var(--shadow-color);
            min-width: auto;
            justify-content: center;
        }
        
        .section-test-button:hover {
            box-shadow: 0 2px 4px -1px var(--shadow-color);
        }
        
        .section-test-button.btn-secondary {
            background: #6b7280;
            color: white;
        }
        
        .section-test-button.btn-secondary:hover {
            background: #4b5563;
        }
        
        .form-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 1rem;
            margin-bottom: 1rem;
        }
        
        .form-group {
            margin-bottom: 0;
            position: relative;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 600;
            color: var(--text-color);
            font-size: 0.9rem;
            letter-spacing: 0.025em;
        }
        
        .form-group input {
            width: 100%;
            padding: 0.6rem 1rem;
            border: 2px solid var(--input-border);
            border-radius: var(--radius);
            font-size: 0.95rem;
            background: var(--input-bg);
            color: var(--text-color);
            transition: all var(--transition-fast);
            box-shadow: 0 1px 3px 0 var(--shadow-color);
        }
        
        .form-group input:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(44, 164, 68, 0.1), 0 4px 6px -1px var(--shadow-color);
            transform: translateY(-1px);
        }
        
        .form-group input:hover {
            border-color: var(--primary);
            box-shadow: 0 2px 4px -1px var(--shadow-color);
        }
        
        .form-group small {
            color: var(--text-color);
            opacity: 0.7;
            font-size: 0.8rem;
            margin-top: 0.3rem;
            display: block;
            line-height: 1.3;
        }
        
        .section-actions {
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 1rem;
            background: linear-gradient(135deg, var(--bg-color) 0%, rgba(44, 164, 68, 0.05) 100%);
            border-radius: var(--radius);
            border: 1px solid var(--card-border);
            margin-top: 1rem;
        }
        
                 .header-actions {
             display: flex;
             gap: 1rem;
             align-items: center;
         }
         
         .header-actions .btn {
             padding: 0.6rem 1.2rem;
             font-size: 0.85rem;
             min-width: auto;
             width: 80px;
             height: 36px;
             justify-content: center;
             align-items: center;
             display: inline-flex;
         }
         
                 .main-actions {
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 1rem;
            padding: 1.5rem 1rem;
            background: linear-gradient(135deg, var(--card-bg) 0%, rgba(44, 164, 68, 0.02) 100%);
            border-radius: var(--radius);
            border: 2px solid var(--card-border);
            margin-top: 1rem;
            box-shadow: 0 4px 6px -1px var(--shadow-color);
        }
        
        .btn {
             padding: 0.75rem 1.5rem;
            border: none;
             border-radius: var(--radius);
             font-size: 0.9rem;
             font-weight: 600;
            cursor: pointer;
             transition: all var(--transition-fast);
             text-decoration: none;
             display: inline-flex;
             align-items: center;
             gap: 0.5rem;
             box-shadow: 0 2px 4px -1px var(--shadow-color);
             min-width: 120px;
             justify-content: center;
         }
        
                 .btn:hover {
             box-shadow: 0 4px 8px -2px var(--shadow-color);
         }
        
        .btn-primary {
             background: var(--primary);
            color: white;
        }
         
         .btn-primary:hover {
             background: #22c55e;
         }
         
        .btn-secondary {
             background: #6b7280;
             color: white;
         }
         
         .btn-secondary:hover {
             background: #4b5563;
         }
         
         .btn-info {
             background: var(--info);
            color: white;
        }
         
         .btn-info:hover {
             background: #0891b2;
        }
        
        .alert {
            padding: 1rem 1.5rem;
            margin-bottom: 1rem;
            border-radius: var(--radius);
            border-left: 4px solid;
            font-weight: 500;
            box-shadow: 0 2px 4px -1px var(--shadow-color);
        }
        
        .alert-success {
            background: rgba(44, 164, 68, 0.1);
            color: var(--success);
            border-left-color: var(--success);
        }
        
        .alert-danger {
            background: rgba(239, 68, 68, 0.1);
            color: var(--danger);
            border-left-color: var(--danger);
        }
        
        .test-result {
            padding: 1rem 1.5rem;
            margin-bottom: 1rem;
            border-radius: var(--radius);
            font-weight: 500;
            border-left: 4px solid;
            box-shadow: 0 2px 4px -1px var(--shadow-color);
        }
        
        .test-success {
            background: rgba(6, 182, 212, 0.1);
            color: var(--info);
            border-left-color: var(--info);
        }
        
        .test-error {
            background: rgba(239, 68, 68, 0.1);
            color: var(--danger);
            border-left-color: var(--danger);
        }
        
        .form-row {
            display: flex;
            gap: 2rem;
            margin-bottom: 2rem;
        }
        
        .form-row .form-group {
            flex: 1;
        }
        
                 @media (max-width: 1024px) {
             .form-grid {
                 grid-template-columns: 1fr;
                 gap: 1.5rem;
             }
             
             .form-row {
                 flex-direction: column;
                 gap: 1.5rem;
        }
             
             .main-actions {
                 flex-direction: column;
                 gap: 1rem;
             }
             
             .btn {
                 width: 100%;
                 min-width: auto;
             }
             
             .header-actions {
                 flex-direction: column;
                 gap: 0.5rem;
             }
             
             .header-actions .btn {
                 width: 100%;
             }
         }
        
        @media (max-width: 768px) {
            .config-section {
                padding: 1.5rem;
            }
            
            .form-grid {
                gap: 1rem;
            }
            
            .section-actions,
            .main-actions {
                padding: 1.5rem;
            }
        }
    </style>
</head>
<body>
    <button class="theme-toggle" onclick="toggleTheme()" title="Alternar tema">
        <i class="fas fa-moon"></i>
    </button>
    
    <div class="container" style="padding: 1rem;">
        <header class="header" style="padding: 1rem; margin-bottom: 1rem;">
            <div class="title">
                <div class="title-left">
                    <img src="lap.png" class="logo" alt="LAPS" onclick="alert('Versão: <?= $version ?>')">
                    <h1 class="custom-title">Configuração LDAP</h1>
                </div>
                <div class="header-actions">
                    <a href="view_laps.php" class="btn btn-secondary">
                        <i class="fas fa-arrow-left"></i> Voltar
                    </a>
                    <button type="submit" form="ldap-config-form" class="btn btn-primary">
                        <i class="fas fa-save"></i> Salvar
                    </button>
                </div>
            </div>
        </header>
        
        <?php if ($sucesso): ?>
            <div class="alert alert-success">
                <i class="fas fa-check-circle"></i> <?= htmlspecialchars($sucesso) ?>
            </div>
        <?php endif; ?>

        <?php if ($erro): ?>
            <div class="alert alert-danger">
                <i class="fas fa-exclamation-circle"></i> <?= htmlspecialchars($erro) ?>
            </div>
        <?php endif; ?>

        <?php if ($testResult): ?>
            <div class="test-result <?= $testResult['success'] ? 'test-success' : 'test-error' ?>">
                <i class="fas fa-<?= $testResult['success'] ? 'check-circle' : 'exclamation-circle' ?>"></i>
                <?= htmlspecialchars($testResult['message']) ?>
            </div>
        <?php endif; ?>

        <form method="POST" action="" id="ldap-config-form">
            <input type="hidden" name="csrf_token" value="<?= gerarTokenCsrf() ?>">
            <div class="config-section">
                <h3>
                    <div class="section-title-content">
                        <i class="fas fa-database"></i> Configurações do MySQL
                    </div>
                    <button type="submit" name="test_db_connection" class="section-test-button btn-secondary">
                        <i class="fas fa-plug"></i> Testar Banco
                    </button>
                </h3>
                
                <div class="form-grid">
                <div class="form-group">
                        <label for="DB_NAME">Nome do Banco de Dados</label>
                    <input type="text" id="DB_NAME" name="DB_NAME" 
                           value="<?= htmlspecialchars($currentConfig['DB_NAME']) ?>" required>
                    <small>Nome do banco de dados LAPS</small>
                </div>

                <div class="form-group">
                        <label for="DB_USER">Usuário do Banco</label>
                    <input type="text" id="DB_USER" name="DB_USER" 
                               value="<?= htmlspecialchars($currentConfig['DB_USER'] ?? 'root') ?>" required>
                        <small>Usuário do banco de dados (configurado no .env)</small>
                </div>

                <div class="form-group">
                        <label for="DB_PASS">Senha do Banco</label>
                    <input type="password" id="DB_PASS" name="DB_PASS" 
                           value="<?= htmlspecialchars($currentConfig['DB_PASS'] ?? '') ?>" required>
                    <small>Senha do usuário do banco de dados</small>
                </div>

                <div class="form-group">
                        <label for="DB_HOST">Host do Banco</label>
                    <input type="text" id="DB_HOST" name="DB_HOST" 
                           value="<?= htmlspecialchars($currentConfig['DB_HOST'] ?? '') ?>" required>
                    <small>Endereço do servidor MySQL (ex: localhost, db, 192.168.1.100)</small>
                </div>
            </div>
            </div>

            <div class="config-section">
                <h3>
                    <div class="section-title-content">
                        <i class="fas fa-shield-alt"></i> Configurações do LDAP
                    </div>
                    <button type="submit" name="test_connection" class="section-test-button btn-secondary">
                        <i class="fas fa-network-wired"></i> Testar LDAP
                    </button>
                </h3>
                
                <div class="form-grid">
                                <div class="form-group">
                        <label for="LDAP_SERVER">Servidor LDAP</label>
                    <input type="text" id="LDAP_SERVER" name="LDAP_SERVER" 
                           value="<?= htmlspecialchars($currentConfig['LDAP_SERVER'] ?? '') ?>">
                    <small>URL do servidor LDAP (ex: ldap://192.168.10.224)</small>
                </div>

                <div class="form-group">
                        <label for="LDAP_USER">Usuário LDAP</label>
                    <input type="text" id="LDAP_USER" name="LDAP_USER" 
                               value="<?= htmlspecialchars($currentConfig['LDAP_USER'] ?? '') ?>">
                        <small>DN do usuário LDAP (ex: CN=user,OU=IT,DC=domain,DC=local)</small>
                </div>

                <div class="form-group">
                        <label for="LDAP_BASE">Base DN</label>
                    <input type="text" id="LDAP_BASE" name="LDAP_BASE" 
                           value="<?= htmlspecialchars($currentConfig['LDAP_BASE'] ?? '') ?>">
                    <small>Base DN para busca (ex: dc=domain,dc=local)</small>
                </div>

                <div class="form-group">
                        <label for="LDAP_PASSWORD">Senha LDAP</label>
                    <input type="password" id="LDAP_PASSWORD" name="LDAP_PASSWORD" 
                           value="<?= htmlspecialchars($currentConfig['LDAP_PASSWORD'] ?? '') ?>">
                    <small>Senha do usuário LDAP</small>
                    </div>
                </div>
            </div>
        </form>
    </div>

    <script>
        function toggleTheme() {
            const body = document.body;
            const themeToggle = document.querySelector('.theme-toggle i');
            
            const currentTheme = body.getAttribute('data-theme');
            
            if (currentTheme === 'dark') {
                body.removeAttribute('data-theme');
                themeToggle.classList.remove('fa-sun');
                themeToggle.classList.add('fa-moon');
                localStorage.setItem('theme', 'light');
            } else {
                body.setAttribute('data-theme', 'dark');
                themeToggle.classList.remove('fa-moon');
                themeToggle.classList.add('fa-sun');
                localStorage.setItem('theme', 'dark');
            }
        }

        function loadTheme() {
            const savedTheme = localStorage.getItem('theme');
            const themeToggle = document.querySelector('.theme-toggle i');
            
            if (savedTheme === 'dark') {
                document.body.setAttribute('data-theme', 'dark');
                themeToggle.classList.remove('fa-moon');
                themeToggle.classList.add('fa-sun');
            }
        }

        loadTheme();
    </script>
</body>
</html> 