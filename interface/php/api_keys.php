<?php
session_start();
require_once 'config.php';
require_once 'local_auth.php';

// Verificar se o usuário está logado
if (!isLoggedIn()) {
    header('Location: index.php');
    exit;
}

// Função para gerar uma nova API key
function generateApiKey() {
    return bin2hex(random_bytes(32));
}

// Conectar ao banco de dados
try {
    $conn = new mysqli(
        $config['host'],
        $config['user'],
        $config['password'],
        $config['dbname']
    );
    
    if ($conn->connect_error) {
        throw new Exception("Erro de conexão: " . $conn->connect_error);
    }
    
    // Criar tabela api_keys se não existir
    $createTableQuery = "
        CREATE TABLE IF NOT EXISTS api_keys (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            api_key VARCHAR(64) NOT NULL UNIQUE,
            is_active BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            last_used_at TIMESTAMP NULL,
            permissions TEXT NULL,
            ip_whitelist TEXT NULL,
            expires_at TIMESTAMP NULL,
            INDEX idx_api_key (api_key),
            INDEX idx_is_active (is_active),
            INDEX idx_expires_at (expires_at)
        )
    ";
    
    $conn->query($createTableQuery);
    
    // Criar tabela api_logs se não existir
    $createLogsTableQuery = "
        CREATE TABLE IF NOT EXISTS api_logs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            api_key_id INT,
            endpoint VARCHAR(255),
            ip_address VARCHAR(45),
            user_agent TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (api_key_id) REFERENCES api_keys(id) ON DELETE CASCADE,
            INDEX idx_api_key_id (api_key_id),
            INDEX idx_created_at (created_at)
        )
    ";
    
    $conn->query($createLogsTableQuery);
    
} catch (Exception $e) {
    $error = "Erro ao conectar com o banco de dados: " . $e->getMessage();
}

// Processar ações
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['action'])) {
        switch ($_POST['action']) {
            case 'create':
                $name = trim($_POST['name'] ?? '');
                if (!empty($name)) {
                    $apiKey = generateApiKey();
                    
                    $stmt = $conn->prepare("INSERT INTO api_keys (name, api_key) VALUES (?, ?)");
                    $stmt->bind_param("ss", $name, $apiKey);
                    
                    if ($stmt->execute()) {
                        $success = "Chave de API criada com sucesso!";
                        $newApiKey = $apiKey;
                    } else {
                        $error = "Erro ao criar chave de API: " . $stmt->error;
                    }
                    $stmt->close();
                }
                break;
                
            case 'toggle':
                $id = intval($_POST['id'] ?? 0);
                if ($id > 0) {
                    $stmt = $conn->prepare("UPDATE api_keys SET is_active = NOT is_active WHERE id = ?");
                    $stmt->bind_param("i", $id);
                    
                    if ($stmt->execute()) {
                        $success = "Status da chave alterado com sucesso!";
                    } else {
                        $error = "Erro ao alterar status da chave: " . $stmt->error;
                    }
                    $stmt->close();
                }
                break;
                
            case 'delete':
                $id = intval($_POST['id'] ?? 0);
                if ($id > 0) {
                    $stmt = $conn->prepare("DELETE FROM api_keys WHERE id = ?");
                    $stmt->bind_param("i", $id);
                    
                    if ($stmt->execute()) {
                        $success = "Chave de API excluída com sucesso!";
                    } else {
                        $error = "Erro ao excluir chave de API: " . $stmt->error;
                    }
                    $stmt->close();
                }
                break;
        }
    }
}

// Buscar todas as chaves de API
$apiKeys = [];
if (isset($conn)) {
    $result = $conn->query("SELECT id, name, api_key, is_active, created_at, last_used_at FROM api_keys ORDER BY created_at DESC");
    if ($result) {
        $apiKeys = $result->fetch_all(MYSQLI_ASSOC);
    }
}

?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Gerenciar Chaves de API - LAPS</title>
    <link rel="stylesheet" href="style.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="title-section">
                <h1 class="custom-title"><i class="fas fa-key"></i> Gerenciar Chaves de API</h1>
            </div>
            <div class="user-section-title">
                <div class="user-info-title">
                    <i class="fas fa-user"></i> 
                    <a href="profile.php" class="user-profile-link" title="Ver perfil">
                        <?= htmlspecialchars($_SESSION['username'] ?? 'N/A') ?>
                    </a>
                </div>
                <button onclick="window.location.href='view_laps.php'" class="btn" title="Voltar">
                    <i class="fas fa-arrow-left"></i>
                </button>
            </div>
        </div>

        <?php if (isset($error)): ?>
            <div class="alert alert-error">
                <i class="fas fa-exclamation-triangle"></i>
                <?= htmlspecialchars($error) ?>
            </div>
        <?php endif; ?>

        <?php if (isset($success)): ?>
            <div class="alert alert-success">
                <i class="fas fa-check-circle"></i>
                <?= htmlspecialchars($success) ?>
                <?php if (isset($newApiKey)): ?>
                    <div class="new-api-key">
                        <strong>Nova Chave de API:</strong>
                        <code id="newApiKey"><?= htmlspecialchars($newApiKey) ?></code>
                        <button onclick="copyToClipboard('newApiKey')" class="btn btn-small" title="Copiar">
                            <i class="fas fa-copy"></i>
                        </button>
                    </div>
                    <p><small><i class="fas fa-info-circle"></i> Guarde esta chave em local seguro. Ela não será exibida novamente.</small></p>
                <?php endif; ?>
            </div>
        <?php endif; ?>

        <div class="api-keys-section">
            <div class="section-header">
                <h2><i class="fas fa-plus"></i> Criar Nova Chave de API</h2>
            </div>
            
            <form method="POST" class="api-form">
                <input type="hidden" name="action" value="create">
                <div class="form-group">
                    <label for="name">Nome da Chave:</label>
                    <input type="text" id="name" name="name" required placeholder="Ex: Integração GLPI">
                </div>
                <button type="submit" class="btn btn-primary">
                    <i class="fas fa-plus"></i> Criar Chave
                </button>
            </form>
        </div>

        <div class="api-keys-section">
            <div class="section-header">
                <h2><i class="fas fa-list"></i> Chaves de API Existentes</h2>
            </div>
            
            <?php if (empty($apiKeys)): ?>
                <div class="no-data">
                    <i class="fas fa-key"></i>
                    <p>Nenhuma chave de API encontrada.</p>
                </div>
            <?php else: ?>
                <div class="api-keys-table">
                    <table>
                        <thead>
                            <tr>
                                <th>Nome</th>
                                <th>Chave</th>
                                <th>Status</th>
                                <th>Criado em</th>
                                <th>Último uso</th>
                                <th>Ações</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($apiKeys as $key): ?>
                                <tr>
                                    <td><?= htmlspecialchars($key['name']) ?></td>
                                    <td>
                                        <code class="api-key-display" id="key_<?= $key['id'] ?>">
                                            <?= substr($key['api_key'], 0, 8) ?>...<?= substr($key['api_key'], -8) ?>
                                        </code>
                                        <button onclick="showFullKey(<?= $key['id'] ?>, '<?= htmlspecialchars($key['api_key']) ?>')" 
                                                class="btn btn-small" title="Ver chave completa">
                                            <i class="fas fa-eye"></i>
                                        </button>
                                    </td>
                                    <td>
                                        <span class="status-badge <?= $key['is_active'] ? 'active' : 'inactive' ?>">
                                            <?= $key['is_active'] ? 'Ativa' : 'Inativa' ?>
                                        </span>
                                    </td>
                                    <td><?= date('d/m/Y H:i', strtotime($key['created_at'])) ?></td>
                                    <td><?= $key['last_used_at'] ? date('d/m/Y H:i', strtotime($key['last_used_at'])) : 'Nunca' ?></td>
                                    <td class="actions">
                                        <form method="POST" style="display: inline;">
                                            <input type="hidden" name="action" value="toggle">
                                            <input type="hidden" name="id" value="<?= $key['id'] ?>">
                                            <button type="submit" class="btn btn-small" 
                                                    title="<?= $key['is_active'] ? 'Desativar' : 'Ativar' ?>">
                                                <i class="fas <?= $key['is_active'] ? 'fa-pause' : 'fa-play' ?>"></i>
                                            </button>
                                        </form>
                                        <form method="POST" style="display: inline;" 
                                              onsubmit="return confirm('Tem certeza que deseja excluir esta chave?')">
                                            <input type="hidden" name="action" value="delete">
                                            <input type="hidden" name="id" value="<?= $key['id'] ?>">
                                            <button type="submit" class="btn btn-small btn-danger" title="Excluir">
                                                <i class="fas fa-trash"></i>
                                            </button>
                                        </form>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            <?php endif; ?>
        </div>
    </div>

    <script>
        function copyToClipboard(elementId) {
            const element = document.getElementById(elementId);
            const text = element.textContent;
            
            navigator.clipboard.writeText(text).then(function() {
                // Feedback visual
                const originalText = element.innerHTML;
                element.innerHTML = '<i class="fas fa-check"></i> Copiado!';
                setTimeout(() => {
                    element.innerHTML = originalText;
                }, 2000);
            });
        }
        
        function showFullKey(keyId, fullKey) {
            const element = document.getElementById('key_' + keyId);
            const isShowing = element.dataset.showing === 'true';
            
            if (isShowing) {
                element.innerHTML = fullKey.substring(0, 8) + '...' + fullKey.substring(fullKey.length - 8);
                element.dataset.showing = 'false';
            } else {
                element.innerHTML = fullKey + ' <button onclick="copyToClipboard(\'key_' + keyId + '\')" class="btn btn-small" title="Copiar"><i class="fas fa-copy"></i></button>';
                element.dataset.showing = 'true';
            }
        }
    </script>
</body>
</html>