<?php
// api.php - API REST para integração com GLPI

// Headers de segurança
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Content-Security-Policy: default-src 'self';");
header("Content-Type: application/json");

// Permitir apenas métodos GET e POST
$allowedMethods = ['GET', 'POST'];
if (!in_array($_SERVER['REQUEST_METHOD'], $allowedMethods)) {
    http_response_code(405);
    echo json_encode(['error' => 'Método não permitido']);
    exit();
}

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Inclui o sistema de autenticação local
require_once 'local_auth.php';

// Carregar configuração
global $config;
if (!isset($config)) {
    $config = include(__DIR__ . '/config.php');
}

/**
 * Função para autenticar via API Key ou sessão
 */
function authenticateRequest() {
    global $config;
    
    // Verificar se há uma sessão ativa
    if (isset($_SESSION['authenticated']) && $_SESSION['authenticated'] === true) {
        return true;
    }
    
    // Verificar API Key no header
    $headers = getallheaders();
    $apiKey = $headers['X-API-Key'] ?? $_GET['api_key'] ?? $_POST['api_key'] ?? null;
    
    if (!$apiKey) {
        return false;
    }
    
    // Conectar ao banco para verificar a API Key
    $conn = new mysqli(
        $config['host'],
        $config['user'],
        $config['password'],
        $config['dbname']
    );
    
    if ($conn->connect_error) {
        return false;
    }
    
    // Verificar se a API Key existe e está ativa
    $stmt = $conn->prepare("SELECT id, name, is_active FROM api_keys WHERE api_key = ? AND is_active = 1");
    $stmt->bind_param('s', $apiKey);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows === 1) {
        $apiData = $result->fetch_assoc();
        // Log da utilização da API
        $logStmt = $conn->prepare("INSERT INTO api_logs (api_key_id, endpoint, ip_address, user_agent, created_at) VALUES (?, ?, ?, ?, NOW())");
        $endpoint = $_SERVER['REQUEST_URI'];
        $ipAddress = $_SERVER['REMOTE_ADDR'];
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $logStmt->bind_param('isss', $apiData['id'], $endpoint, $ipAddress, $userAgent);
        $logStmt->execute();
        $logStmt->close();
        
        $stmt->close();
        $conn->close();
        return true;
    }
    
    $stmt->close();
    $conn->close();
    return false;
}

/**
 * Função para buscar senha de um computador
 */
function getComputerPassword($computerName) {
    global $config;
    
    $conn = new mysqli(
        $config['host'],
        $config['user'],
        $config['password'],
        $config['dbname']
    );
    
    if ($conn->connect_error) {
        return ['error' => 'Erro na conexão com o banco de dados'];
    }
    
    // Buscar senha do computador (incluindo senhas manuais)
    $stmt = $conn->prepare("
        SELECT 
            COALESCE(p.ComputerName, m.ComputerName) as ComputerName,
            COALESCE(m.ManualPassword, p.Password) as Password,
            p.ExpirationTimestamp,
            CASE 
                WHEN m.ManualPassword IS NOT NULL THEN 'manual'
                WHEN p.Password IS NOT NULL THEN 'laps'
                ELSE 'none'
            END as PasswordType,
            CASE 
                WHEN p.ExpirationTimestamp IS NULL THEN NULL
                WHEN p.ExpirationTimestamp < NOW() THEN 'expired'
                WHEN p.ExpirationTimestamp < DATE_ADD(NOW(), INTERVAL 7 DAY) THEN 'expiring_soon'
                ELSE 'valid'
            END as Status
        FROM (
            SELECT ? as ComputerName
        ) c
        LEFT JOIN Passwords p ON c.ComputerName = p.ComputerName
        LEFT JOIN ComputerManualPasswords m ON c.ComputerName = m.ComputerName
    ");
    
    $stmt->bind_param('s', $computerName);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows === 0) {
        $stmt->close();
        $conn->close();
        return ['error' => 'Computador não encontrado'];
    }
    
    $data = $result->fetch_assoc();
    $stmt->close();
    $conn->close();
    
    // Não retornar a senha se não houver nenhuma
    if ($data['PasswordType'] === 'none') {
        return [
            'computer_name' => $data['ComputerName'],
            'password_type' => 'none',
            'status' => 'no_password',
            'message' => 'Nenhuma senha encontrada para este computador'
        ];
    }
    
    return [
        'computer_name' => $data['ComputerName'],
        'password' => $data['Password'],
        'password_type' => $data['PasswordType'],
        'expiration_timestamp' => $data['ExpirationTimestamp'],
        'status' => $data['Status'] ?? 'unknown'
    ];
}

/**
 * Função para listar computadores
 */
function listComputers($limit = 100, $offset = 0, $search = '') {
    global $config;
    
    $conn = new mysqli(
        $config['host'],
        $config['user'],
        $config['password'],
        $config['dbname']
    );
    
    if ($conn->connect_error) {
        return ['error' => 'Erro na conexão com o banco de dados'];
    }
    
    $whereClause = '';
    $params = [];
    $types = '';
    
    if (!empty($search)) {
        $whereClause = 'WHERE p.ComputerName LIKE ?';
        $params[] = "%{$search}%";
        $types = 's';
    }
    
    $sql = "
        SELECT 
            p.ComputerName,
            CASE 
                WHEN m.ManualPassword IS NOT NULL THEN 'manual'
                WHEN p.Password IS NOT NULL THEN 'laps'
                ELSE 'none'
            END as PasswordType,
            p.ExpirationTimestamp,
            CASE 
                WHEN p.ExpirationTimestamp IS NULL THEN NULL
                WHEN p.ExpirationTimestamp < NOW() THEN 'expired'
                WHEN p.ExpirationTimestamp < DATE_ADD(NOW(), INTERVAL 7 DAY) THEN 'expiring_soon'
                ELSE 'valid'
            END as Status
        FROM Passwords p
        LEFT JOIN ComputerManualPasswords m ON p.ComputerName = m.ComputerName
        {$whereClause}
        ORDER BY p.ComputerName
        LIMIT ? OFFSET ?
    ";
    
    $params[] = $limit;
    $params[] = $offset;
    $types .= 'ii';
    
    $stmt = $conn->prepare($sql);
    $stmt->bind_param($types, ...$params);
    $stmt->execute();
    $result = $stmt->get_result();
    
    $computers = [];
    while ($row = $result->fetch_assoc()) {
        $computers[] = $row;
    }
    
    $stmt->close();
    $conn->close();
    
    return [
        'computers' => $computers,
        'total' => count($computers),
        'limit' => $limit,
        'offset' => $offset
    ];
}

// Verificar autenticação
if (!authenticateRequest()) {
    http_response_code(401);
    echo json_encode(['error' => 'Não autorizado. API Key necessária.']);
    exit();
}

// Roteamento da API
$action = $_GET['action'] ?? $_POST['action'] ?? 'help';

switch ($action) {
    case 'get_password':
        $computerName = $_GET['computer'] ?? $_POST['computer'] ?? '';
        if (empty($computerName)) {
            http_response_code(400);
            echo json_encode(['error' => 'Nome do computador é obrigatório']);
            break;
        }
        
        $result = getComputerPassword($computerName);
        if (isset($result['error'])) {
            http_response_code(404);
        }
        echo json_encode($result);
        break;
        
    case 'list_computers':
        $limit = min(100, max(1, intval($_GET['limit'] ?? $_POST['limit'] ?? 50)));
        $offset = max(0, intval($_GET['offset'] ?? $_POST['offset'] ?? 0));
        $search = $_GET['search'] ?? $_POST['search'] ?? '';
        
        $result = listComputers($limit, $offset, $search);
        echo json_encode($result);
        break;
        
    case 'status':
        echo json_encode([
            'status' => 'ok',
            'version' => file_exists('version.txt') ? trim(file_get_contents('version.txt')) : '1.0.0',
            'timestamp' => date('Y-m-d H:i:s')
        ]);
        break;
        
    case 'help':
    default:
        echo json_encode([
            'message' => 'API LAPS para integração com GLPI',
            'endpoints' => [
                'get_password' => 'GET/POST ?action=get_password&computer=NOME_COMPUTADOR',
                'list_computers' => 'GET/POST ?action=list_computers&limit=50&offset=0&search=termo',
                'status' => 'GET/POST ?action=status'
            ],
            'authentication' => 'Requer API Key no header X-API-Key ou parâmetro api_key',
            'version' => file_exists('version.txt') ? trim(file_get_contents('version.txt')) : '1.0.0'
        ]);
        break;
}
?>