<?php

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Headers de segurança
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;");

// Incluindo o arquivo de configuração
$config = include __DIR__ . '/config.php';

// Função para implementar rate limiting
function checkRateLimit($ip, $username, $maxAttempts = 5, $lockoutTime = 900) {
    $lockoutFile = sys_get_temp_dir() . '/laps_login_attempts.json';
    $attempts = [];

    if (file_exists($lockoutFile)) {
        $attempts = json_decode(file_get_contents($lockoutFile), true) ?: [];
    }

    $currentTime = time();
    $key = $ip . '_' . $username;

    // Limpar tentativas antigas
    foreach ($attempts as $attemptKey => $attempt) {
        if ($currentTime - $attempt['time'] > $lockoutTime) {
            unset($attempts[$attemptKey]);
        }
    }

    // Verificar se está bloqueado
    if (isset($attempts[$key])) {
        if ($attempts[$key]['count'] >= $maxAttempts) {
            $timeRemaining = $lockoutTime - ($currentTime - $attempts[$key]['time']);
            if ($timeRemaining > 0) {
                return [
                    'blocked' => true,
                    'timeRemaining' => $timeRemaining,
                    'message' => "Muitas tentativas de login. Tente novamente em " . ceil($timeRemaining / 60) . " minutos."
                ];
            } else {
                // Reset após o tempo de bloqueio
                unset($attempts[$key]);
            }
        }
    }

    return ['blocked' => false];
}

function recordLoginAttempt($ip, $username, $success = false) {
    $lockoutFile = sys_get_temp_dir() . '/laps_login_attempts.json';
    $attempts = [];

    if (file_exists($lockoutFile)) {
        $attempts = json_decode(file_get_contents($lockoutFile), true) ?: [];
    }

    $currentTime = time();
    $key = $ip . '_' . $username;

    if ($success) {
        // Reset tentativas em caso de sucesso
        unset($attempts[$key]);
    } else {
        // Registrar tentativa falhada
        if (!isset($attempts[$key])) {
            $attempts[$key] = ['count' => 0, 'time' => $currentTime];
        }
        $attempts[$key]['count']++;
        $attempts[$key]['time'] = $currentTime;
    }

    // Salvar tentativas
    file_put_contents($lockoutFile, json_encode($attempts));

    // Log de segurança
    $logMessage = sprintf(
        "SECURITY: Login attempt - IP: %s, User: %s, Success: %s, Time: %s",
        $ip,
        $username,
        $success ? 'YES' : 'NO',
        date('Y-m-d H:i:s')
    );
    error_log($logMessage);
}

// Verificar se as configurações foram carregadas corretamente
if (empty($config['password'])) {
    error_log("Erro: Senha do banco de dados não configurada");
    die("Erro de configuração: Senha do banco de dados não definida. Verifique as variáveis de ambiente.");
}

// Conexão ao banco de dados (para outras funcionalidades)

try {
$conn = new mysqli($config['host'], $config['user'], $config['password'], $config['dbname']);

// Verifique a conexão
if ($conn->connect_error) {
        error_log("Erro de conexão MySQL: " . $conn->connect_error);
        die("Falha na conexão com o banco de dados: " . $conn->connect_error);
    }
} catch (Exception $e) {
    error_log("Exceção na conexão MySQL: " . $e->getMessage());
    die("Erro ao conectar com o banco de dados: " . $e->getMessage());
}


// Verifique se o formulário foi enviado
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Sanitizar dados de entrada
    $postData = sanitizeRequestData($_POST, ['username', 'password', 'auth_type']);
    $username = sanitizeInput($postData['username'] ?? '', 'username');
    $password = $postData['password'] ?? ''; // Senha não deve ser sanitizada para hash
    $auth_type = sanitizeInput($postData['auth_type'] ?? 'ldap', 'string');

    // Obter IP do usuário
    $userIP = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['HTTP_X_REAL_IP'] ?? $_SERVER['REMOTE_ADDR'] ?? 'unknown';

    // Verificar rate limiting
    $rateLimitCheck = checkRateLimit($userIP, $username);
    if ($rateLimitCheck['blocked']) {
        $error = $rateLimitCheck['message'];
    } else {



        if ($auth_type === 'local') {
            // Autenticação local
            require_once 'local_auth.php';

            if (authenticateLocalUser($username, $password)) {
                // Login local bem-sucedido
                recordLoginAttempt($userIP, $username, true);
                header("Location: dashboard.php");
                exit();
            } else {
                recordLoginAttempt($userIP, $username, false);
                $error = "Usuário ou senha inválidos";
            }
        } else {
            // Autenticação LDAP
            require_once 'auth_functions.php';

            $authResult = authenticateADUser($username, $password, $config);

            if ($authResult === true) {
                // Login LDAP bem-sucedido
                recordLoginAttempt($userIP, $username, true);
                $_SESSION['username'] = $username;
                $_SESSION['authenticated'] = true;
                $_SESSION['auth_type'] = 'ldap';
                header("Location: dashboard.php");
                exit();
            } else {
                // Mensagem de erro
                recordLoginAttempt($userIP, $username, false);
                $error = is_array($authResult) ? "Credenciais inválidas" : $authResult;
            }
        }
    }
}


$conn->close();

?>


<!DOCTYPE html>

<html lang="pt-br">

<head>

    <meta charset="UTF-8">

    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>LAPS Manager</title>

    <link rel="icon" href="./img/fav.png" type="image/x-icon">

    <style>

        body {

            font-family: system-ui;

            background-color: #f4f4f4;

            display: flex;

            justify-content: center;

            align-items: center;

            height: 100vh;

            margin: 0;

        }

        .login-container {

            background-color: white;

            padding: 30px;

            border-radius: 10px;

            box-shadow: 0 0 15px rgba(0, 0, 0, 0.1);

            text-align: center;

            max-width: 260px;

            width: 100%;

        }

        .logo {

            max-width: 250px;

            margin-bottom: 20px;

        }

        h2 {

            margin-bottom: 20px;

            color: #727272;

        }

        label {

            display: block;

            margin-bottom: 2px;

            font-weight: 400;

            text-align: left;

            color: #727272;

        }

        input[type="text"], input[type="password"] {

            width: 100%;

            padding: 12px;

            margin-bottom: 20px;

            border: 1px solid #ccc;

            border-radius: 4px;

            box-sizing: border-box;

        }

        input[type="submit"] {

            width: 100%;

            background-color: #28a745;

            color: white;

            border: none;

            padding: 12px;

            border-radius: 4px;

            cursor: pointer;

            font-size: 16px;

        }

        input[type="submit"]:hover {

            background-color: #218838;

        }

        .error {

            color: red;

            margin-bottom: 20px;

        }

        .auth-selector {

            margin-bottom: 20px;

        }

        .auth-selector select {

            width: 100%;

            padding: 12px;

            border: 1px solid #ccc;

            border-radius: 4px;

            background-color: white;

            font-size: 14px;

            cursor: pointer;

            appearance: none;

            -webkit-appearance: none;

            -moz-appearance: none;

            background-image: url("data:image/svg+xml;charset=UTF-8,%3csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3e%3cpolyline points='6,9 12,15 18,9'%3e%3c/polyline%3e%3c/svg%3e");

            background-repeat: no-repeat;

            background-position: right 12px center;

            background-size: 16px;

            padding-right: 40px;

        }

        .auth-selector select:focus {

            outline: none;

            border-color: #28a745;

            box-shadow: 0 0 0 2px rgba(40, 167, 69, 0.2);

        }

        .auth-selector select option {

            padding: 8px;

        }

    </style>

</head>

<body>

    <div class="login-container">

        <img src="./img/laps.png" alt="Logo" class="logo">

        <?php

        // Exibe mensagem de erro, se houver

        if (!empty($error)) {

            echo '<p class="error">' . htmlspecialchars($error) . '</p>';

        } elseif (isset($_GET['error'])) {

            echo '<p class="error">' . htmlspecialchars($_GET['error']) . '</p>';

        }

        ?>


        <form action="index.php" method="POST">

            <label for="auth_type">Tipo de Autenticação:</label>
            <div class="auth-selector">
                <select id="auth_type" name="auth_type" required>
                    <option value="ldap">Rede</option>
                    <option value="local">Local</option>
                </select>
            </div>

            <label for="username">Usuário:</label>
            <input type="text" id="username" name="username" required>

            <label for="password">Senha:</label>
            <input type="password" id="password" name="password" required>

            <input type="submit" value="Entrar">
        </form>

    </div>

</body>

</html>
