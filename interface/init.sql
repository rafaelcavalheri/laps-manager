-- Script de inicialização do banco de dados LAPS
-- Cria as tabelas necessárias para o sistema

USE laps;

-- Tabela principal de senhas
CREATE TABLE IF NOT EXISTS Passwords (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ComputerName VARCHAR(255) NOT NULL UNIQUE,
    Password VARCHAR(255),
    ExpirationTimestamp DATE,
    export_date DATE,
    ManualPassword VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_computer_name (ComputerName),
    INDEX idx_export_date (export_date)
);

-- Tabela de senhas antigas (histórico)
CREATE TABLE IF NOT EXISTS old_passwords (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ComputerName VARCHAR(255) NOT NULL,
    Password VARCHAR(255),
    ExpirationTimestamp DATE,
    ManualPassword VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_computer_name (ComputerName),
    INDEX idx_created_at (created_at)
);

-- Tabela de computadores sem senha (null passwords)
CREATE TABLE IF NOT EXISTS null_passwords (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ComputerName VARCHAR(255) NOT NULL UNIQUE,
    Password VARCHAR(255),
    ExpirationTimestamp DATE,
    ManualPassword VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_computer_name (ComputerName)
);

-- Tabela de senhas manuais
CREATE TABLE IF NOT EXISTS ComputerManualPasswords (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ComputerName VARCHAR(255) NOT NULL UNIQUE,
    ManualPassword VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_computer_name (ComputerName)
);

-- Tabela temporária para processamento
CREATE TABLE IF NOT EXISTS TempPasswords (
    ComputerName VARCHAR(255),
    Password VARCHAR(255),
    ExpirationTimestamp DATE,
    INDEX idx_computer_name (ComputerName)
);

-- Inserir alguns dados de exemplo para teste (opcional)
INSERT IGNORE INTO null_passwords (ComputerName, Password) VALUES 
('TESTE-001', NULL),
('TESTE-002', NULL),
('TESTE-003', NULL);

-- Inserir dados de exemplo na tabela principal
INSERT IGNORE INTO Passwords (ComputerName, Password, ExpirationTimestamp, export_date) VALUES 
('EXEMPLO-001', 'Senha123!', '2024-12-31', CURDATE()),
('EXEMPLO-002', 'Admin456@', '2024-12-31', CURDATE());

-- Tabela de usuários locais
CREATE TABLE IF NOT EXISTS local_users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    email VARCHAR(255),
    full_name VARCHAR(255),
    role ENUM('admin', 'user') DEFAULT 'user',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL,
    INDEX idx_username (username),
    INDEX idx_role (role),
    INDEX idx_is_active (is_active)
);

-- Inserir usuário admin local (senha: admin)
INSERT IGNORE INTO local_users (username, password_hash, email, full_name, role) VALUES 
('admin', '$2a$12$.ntwFWSA.pFnHyU6qNgqIuYy6RFOguEju4CCsItZ8QTArmDtc4nNG', 'admin@laps.local', 'Administrador Local', 'admin');

-- Criar usuário personalizado se especificado no .env
-- Este comando será executado dinamicamente pelo Dockerfile
-- CREATE USER IF NOT EXISTS '${DB_USER}'@'%' IDENTIFIED BY '${DB_PASSWORD}';
-- GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'%';
-- FLUSH PRIVILEGES;

COMMIT; 