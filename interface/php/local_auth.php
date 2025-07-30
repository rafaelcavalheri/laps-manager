<?php
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Função para verificar se o usuário está logado (LDAP ou local)
function isLoggedIn() {
    return isset($_SESSION['username']) && !empty($_SESSION['username']);
}

// Função para verificar se o usuário é admin
function isAdmin() {
    return isset($_SESSION['role']) && $_SESSION['role'] === 'admin';
}

// Função para autenticar usuário local
function authenticateLocalUser($username, $password) {
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
        return false;
    }

    // Buscar usuário local
    $stmt = $conn->prepare("SELECT id, username, password_hash, role, full_name, is_active FROM local_users WHERE username = ? AND is_active = 1");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows === 1) {
        $user = $result->fetch_assoc();

        // Verificar senha
        if (password_verify($password, $user['password_hash'])) {
            // Atualizar último login
            $updateStmt = $conn->prepare("UPDATE local_users SET last_login = CURRENT_TIMESTAMP WHERE id = ?");
            $updateStmt->bind_param("i", $user['id']);
            $updateStmt->execute();

            // Definir sessão
            $_SESSION['username'] = $user['username'];
            $_SESSION['role'] = $user['role'];
            $_SESSION['full_name'] = $user['full_name'];
            $_SESSION['auth_type'] = 'local';
            $_SESSION['authenticated'] = true;

            $stmt->close();
            $conn->close();
            return true;
        }
    }

    $stmt->close();
    $conn->close();
    return false;
}

// Função para criar hash de senha
function createPasswordHash($password) {
    return password_hash($password, PASSWORD_BCRYPT);
}

// Função para verificar se o usuário existe localmente
function userExistsLocally($username) {
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
        return false;
    }

    $stmt = $conn->prepare("SELECT id FROM local_users WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $result = $stmt->get_result();
    $exists = $result->num_rows > 0;

    $stmt->close();
    $conn->close();
    return $exists;
}

// Função para criar usuário local
function createLocalUser($username, $password, $email = null, $full_name = null, $role = 'user') {
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
        return false;
    }

    $password_hash = createPasswordHash($password);

    $stmt = $conn->prepare("INSERT INTO local_users (username, password_hash, email, full_name, role) VALUES (?, ?, ?, ?, ?)");
    $stmt->bind_param("sssss", $username, $password_hash, $email, $full_name, $role);
    $success = $stmt->execute();

    $stmt->close();
    $conn->close();
    return $success;
}

// Função para logout
function logout() {
    session_destroy();
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
}

// Função para redirecionar se não estiver logado
function requireLogin() {
    if (!isLoggedIn()) {
        header("Location: index.php?error=not_logged_in");
        exit();
    }
}

// Função para redirecionar se não for admin
function requireAdmin() {
    requireLogin();
    if (!isAdmin()) {
        header("Location: dashboard.php?error=access_denied");
        exit();
    }
}