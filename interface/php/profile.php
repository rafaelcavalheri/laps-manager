<?php
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Headers de segurança
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' cdnjs.cloudflare.com; font-src cdnjs.cloudflare.com;");

// Inclui o sistema de autenticação local
require_once 'local_auth.php';

// Carregar configuração (inclui funções CSRF)
global $config;
if (!isset($config)) {
    $config = include(__DIR__ . '/config.php');
}

// Verifica se o usuário está logado
requireLogin();

// Verificação adicional de segurança
if (!isset($_SESSION['username']) || empty($_SESSION['username'])) {
    header("Location: index.php?error=not_logged_in");
    exit();
}

// Verificar tempo de sessão (8 horas)
$sessionTimeout = 8 * 60 * 60; // 8 horas em segundos
if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity'] > $sessionTimeout)) {
    session_destroy();
    header("Location: index.php?error=session_expired");
    exit();
}
$_SESSION['last_activity'] = time();

// Inicializar contador de tentativas se não existir
if (!isset($_SESSION['password_attempts'])) {
    $_SESSION['password_attempts'] = 0;
    $_SESSION['last_attempt_time'] = 0;
}

$message = '';
$error = '';

// Processar alteração de senha
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Rate limiting: máximo 5 tentativas por 15 minutos
    $maxAttempts = 5;
    $lockoutTime = 15 * 60; // 15 minutos

    if ($_SESSION['password_attempts'] >= $maxAttempts) {
        $timeSinceLastAttempt = time() - $_SESSION['last_attempt_time'];
        if ($timeSinceLastAttempt < $lockoutTime) {
            $remainingTime = $lockoutTime - $timeSinceLastAttempt;
            $error = "Muitas tentativas. Tente novamente em " . ceil($remainingTime / 60) . " minutos.";

            // Log da tentativa bloqueada
            error_log("SECURITY: Password change blocked for user " . ($_SESSION['username'] ?? 'unknown') . " - Rate limit exceeded");
        } else {
            // Reset do contador após o tempo de bloqueio
            $_SESSION['password_attempts'] = 0;
        }
    }

    if (empty($error)) {
        // Verificar se o usuário está logado antes de processar
        if (!isset($_SESSION['username']) || empty($_SESSION['username'])) {
            $error = "Usuário não está logado corretamente. Por favor, faça login novamente.";
        } else {

        // Verificar token CSRF
        if (!isset($_POST['csrf_token']) || !validarTokenCsrf($_POST['csrf_token'])) {
            $error = "Token CSRF inválido!";
            error_log("SECURITY: CSRF token validation failed for user " . ($_SESSION['username'] ?? 'unknown'));
        } else {
            // Sanitizar entradas
            $currentPassword = trim($_POST['current_password'] ?? '');
            $newPassword = trim($_POST['new_password'] ?? '');
            $confirmPassword = trim($_POST['confirm_password'] ?? '');

            // Validar se é usuário local
            if (!isset($_SESSION['auth_type']) || $_SESSION['auth_type'] !== 'local') {
                $error = "Alteração de senha disponível apenas para usuários locais.";
            } else {
                // Validar campos
                if (empty($currentPassword) || empty($newPassword) || empty($confirmPassword)) {
                    $error = "Todos os campos são obrigatórios.";
                } elseif ($newPassword !== $confirmPassword) {
                    $error = "A nova senha e confirmação não coincidem.";
                } elseif (strlen($newPassword) < 8) {
                    $error = "A nova senha deve ter pelo menos 8 caracteres.";
                } elseif (!preg_match('/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/', $newPassword)) {
                    $error = "A nova senha deve conter pelo menos uma letra maiúscula, uma minúscula, um número e um caractere especial.";
                } elseif ($currentPassword === $newPassword) {
                    $error = "A nova senha deve ser diferente da senha atual.";
                } else {
                    // Verificar senha atual
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
                        $error = "Erro na conexão com o banco de dados.";
                    } else {
                        // Verificar se o usuário está logado
                        if (!isset($_SESSION['username']) || empty($_SESSION['username'])) {
                            $error = "Usuário não está logado corretamente.";
                        } else {
                            $stmt = $conn->prepare("SELECT username, password_hash FROM local_users WHERE username = ? AND is_active = 1");
                            $username = $_SESSION['username'] ?? '';
                            $stmt->bind_param("s", $username);
                            $stmt->execute();
                        $result = $stmt->get_result();

                        if ($result->num_rows === 1) {
                            $user = $result->fetch_assoc();

                            // Verificar senha atual
                            if (password_verify($currentPassword, $user['password_hash'])) {
                                // Atualizar senha
                                $newPasswordHash = password_hash($newPassword, PASSWORD_BCRYPT, ['cost' => 12]);
                                $updateStmt = $conn->prepare("UPDATE local_users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE username = ?");
                                $updateUsername = $_SESSION['username'] ?? '';
                                $updateStmt->bind_param("ss", $newPasswordHash, $updateUsername);

                                if ($updateStmt->execute()) {
                                    $message = "Senha alterada com sucesso!";

                                    // Reset do contador de tentativas
                                    $_SESSION['password_attempts'] = 0;

                                    // Log de sucesso
                                    error_log("SECURITY: Password changed successfully for user " . ($_SESSION['username'] ?? 'unknown') . " from IP " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
                                } else {
                                    $error = "Erro ao atualizar a senha.";
                                    error_log("ERROR: Failed to update password for user " . ($_SESSION['username'] ?? 'unknown'));
                                }
                                $updateStmt->close();
                            } else {
                                $error = "Senha atual incorreta.";

                                // Incrementar contador de tentativas
                                $_SESSION['password_attempts']++;
                                $_SESSION['last_attempt_time'] = time();

                                // Log de tentativa falhada
                                error_log("SECURITY: Failed password change attempt for user " . ($_SESSION['username'] ?? 'unknown') . " from IP " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown') . " - Attempt " . $_SESSION['password_attempts']);
                            }
                        } else {
                            $error = "Usuário não encontrado.";
                            error_log("SECURITY: User not found during password change: " . ($_SESSION['username'] ?? 'unknown'));
                        }
                        $stmt->close();
                        $conn->close();
                        }
                    }
                }
            }
        }
        }
    }
}

// Carregar informações do usuário
$userInfo = [
    'username' => $_SESSION['username'] ?? '',
    'full_name' => $_SESSION['full_name'] ?? '',
    'role' => $_SESSION['role'] ?? '',
    'auth_type' => $_SESSION['auth_type'] ?? ''
];
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Perfil do Usuário - LAPS</title>
    <link rel="stylesheet" href="style.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
</head>
<body>
    <div class="container">
        <header class="header">
            <div class="header-content">
                <div class="header-left">
                    <h1><i class="fas fa-user-circle"></i> Perfil do Usuário</h1>
                    <div class="user-info">
                        <span class="username"><?= htmlspecialchars($userInfo['username']) ?></span>
                    </div>
                </div>
                <div class="header-right">
                    <button onclick="window.location.href='dashboard.php'" class="btn back-btn">
                        <i class="fas fa-arrow-left"></i> Voltar
                    </button>
                </div>
            </div>
        </header>

        <main class="main-content">
            <?php if ($message): ?>
                <div class="alert success">
                    <i class="fas fa-check-circle"></i>
                    <?= htmlspecialchars($message) ?>
                </div>
            <?php endif; ?>

            <?php if ($error): ?>
                <div class="alert error">
                    <i class="fas fa-exclamation-circle"></i>
                    <?= htmlspecialchars($error) ?>
                </div>
            <?php endif; ?>

            <div class="profile-section">
                <h2><i class="fas fa-info-circle"></i> Informações do Usuário</h2>
                <div class="info-grid">
                    <div class="info-item">
                        <label>Nome de Usuário:</label>
                        <span><?= htmlspecialchars($userInfo['username']) ?></span>
                    </div>
                    <div class="info-item">
                        <label>Nome Completo:</label>
                        <span><?= htmlspecialchars($userInfo['full_name']) ?: 'Não informado' ?></span>
                    </div>

                    <div class="info-item">
                        <label>Tipo de Autenticação:</label>
                        <span class="auth-badge <?= $userInfo['auth_type'] ?>">
                            <?= $userInfo['auth_type'] === 'local' ? 'Local' : 'LDAP' ?>
                        </span>
                    </div>
                </div>
            </div>

            <?php if ($userInfo['auth_type'] === 'local'): ?>
            <div class="profile-section">
                <h2><i class="fas fa-key"></i> Alterar Senha</h2>
                <form method="POST" class="password-form">
                    <input type="hidden" name="csrf_token" value="<?= gerarTokenCsrf() ?>">

                    <div class="form-group">
                        <label for="current_password">Senha Atual:</label>
                        <div class="password-input-container">
                            <input type="password" id="current_password" name="current_password" required>
                            <button type="button" class="toggle-password" onclick="togglePasswordVisibility('current_password')">
                                <i class="far fa-eye"></i>
                            </button>
                        </div>
                    </div>

                    <div class="form-group">
                        <label for="new_password">Nova Senha:</label>
                        <div class="password-input-container">
                            <input type="password" id="new_password" name="new_password" required minlength="8" pattern="^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$">
                            <button type="button" class="toggle-password" onclick="togglePasswordVisibility('new_password')">
                                <i class="far fa-eye"></i>
                            </button>
                        </div>

                    </div>

                    <div class="form-group">
                        <label for="confirm_password">Confirmar Nova Senha:</label>
                        <div class="password-input-container">
                            <input type="password" id="confirm_password" name="confirm_password" required minlength="8">
                            <button type="button" class="toggle-password" onclick="togglePasswordVisibility('confirm_password')">
                                <i class="far fa-eye"></i>
                            </button>
                        </div>
                    </div>

                    <div class="form-actions">
                        <button type="submit" class="btn btn-primary">
                            <i class="fas fa-save"></i> Alterar Senha
                        </button>
                        <button type="reset" class="btn btn-secondary">
                            <i class="fas fa-undo"></i> Limpar
                        </button>
                    </div>
                </form>
            </div>
            <?php else: ?>
            <div class="profile-section">
                <div class="info-notice">
                    <i class="fas fa-info-circle"></i>
                    <p>Usuários autenticados via LDAP devem alterar suas senhas através do sistema de diretório ativo.</p>
                </div>
            </div>
            <?php endif; ?>
        </main>
    </div>

    <script>
        function togglePasswordVisibility(inputId) {
            const input = document.getElementById(inputId);
            const button = input.nextElementSibling;
            const icon = button.querySelector('i');

            if (input.type === 'password') {
                input.type = 'text';
                icon.classList.remove('fa-eye');
                icon.classList.add('fa-eye-slash');
            } else {
                input.type = 'password';
                icon.classList.remove('fa-eye-slash');
                icon.classList.add('fa-eye');
            }
        }

        function logout() {
            if (confirm('Deseja realmente sair do sistema?')) {
                window.location.href = 'logout.php';
            }
        }

        // Aguardar o DOM estar completamente carregado
        document.addEventListener('DOMContentLoaded', function() {
            // Validar confirmação de senha em tempo real
            const confirmPasswordField = document.getElementById('confirm_password');
            const newPasswordField = document.getElementById('new_password');
            
            if (confirmPasswordField) {
                confirmPasswordField.addEventListener('input', function() {
                    const newPassword = newPasswordField ? newPasswordField.value : '';
                    const confirmPassword = this.value;

                    if (confirmPassword && newPassword !== confirmPassword) {
                        this.setCustomValidity('As senhas não coincidem');
                    } else {
                        this.setCustomValidity('');
                    }
                });
            }

            // Validar força da senha em tempo real
            if (newPasswordField) {
                newPasswordField.addEventListener('input', function() {
                    const password = this.value;
                    const hasLower = /[a-z]/.test(password);
                    const hasUpper = /[A-Z]/.test(password);
                    const hasNumber = /\d/.test(password);
                    const hasSpecial = /[@$!%*?&]/.test(password);
                    const isLongEnough = password.length >= 8;

                    let message = '';
                    if (!isLongEnough) message += 'Mínimo 8 caracteres. ';
                    if (!hasLower) message += 'Uma letra minúscula. ';
                    if (!hasUpper) message += 'Uma letra maiúscula. ';
                    if (!hasNumber) message += 'Um número. ';
                    if (!hasSpecial) message += 'Um caractere especial (@$!%*?&). ';

                    this.setCustomValidity(message);
                });
            }
        });
    </script>
</body>
</html>