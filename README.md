# Gerenciador de Senhas LAPS

Sistema de gerenciamento de senhas LAPS (Local Administrator Password Solution).

## 📋 Apresentação

O Gerenciador de Senhas LAPS é uma aplicação web desenvolvida para centralizar e gerenciar as senhas de administrador local de todos os computadores da rede. O sistema integra-se ao Active Directory (LDAP) para sincronizar automaticamente as senhas LAPS e fornece uma interface intuitiva para visualização, gerenciamento e monitoramento.

## 🎯 Funcionalidades Principais

### 📊 Dashboard Interativo
- **Gráficos Visuais**: Gráficos de linha, barras, pizza e doughnut com estatísticas em tempo real
- **Cards de Métricas**: 8 cards clicáveis com informações importantes:
  - Total de computadores
  - Senhas que expiram hoje
  - Senhas expiradas
  - Senhas antigas (6+ meses e 1+ ano)
  - Senhas manuais
  - Senhas alteradas hoje
  - Computadores sem senha
- **Sistema de Alertas**: Notificações visuais para situações críticas
- **Navegação Intuitiva**: Cards clicáveis abrem visualizações filtradas

### 🔍 Visualização e Filtros
- **Tabela Principal**: Lista completa de senhas LAPS com todas as informações
- **Filtros Avançados**:
  - Senhas ativas (padrão)
  - Senhas nulas (computadores sem senha)
  - Senhas antigas (histórico)
  - Senhas que expiram hoje
  - Senhas alteradas hoje
- **Busca Inteligente**: Pesquisa por nome do computador
- **Ordenação**: Ordenação por qualquer coluna da tabela

### 🔧 Gerenciamento de Senhas
- **Senhas Automáticas**: Sincronização automática com o Active Directory
- **Senhas Manuais**: Adição, edição e exclusão de senhas manuais
- **Cópia Rápida**: Botão para copiar senhas para clipboard
- **Validação**: Verificação de integridade dos dados

### 🔄 Sincronização Automática
- **Integração LDAP**: Conexão direta com o Active Directory
- **Atualização em Tempo Real**: Botão "Atualizar" para sincronizar dados
- **Processamento Inteligente**: Sincroniza apenas computadores com alterações
- **Feedback Visual**: Status em tempo real do processo de atualização

### 🔒 Segurança
- **Autenticação**: Sistema de login seguro
- **Sessões Protegidas**: Controle de acesso por sessão
- **Tokens CSRF**: Proteção contra ataques cross-site
- **Sanitização**: Tratamento seguro de dados de entrada
- **Logout Seguro**: Destruição completa de sessões

## 🚀 Como Usar

### 1. Acesso ao Sistema
- **URL**: Acesse a aplicação através do navegador
- **Credenciais Padrão**:
  - Usuário: `admin`
  - Senha: `Laps@Admin`
- **⚠️ Importante**: Altere a senha padrão imediatamente após o primeiro login

### 2. Dashboard
- **Acesso**: Clique em "Dashboard" na página principal
- **Navegação**: Clique em qualquer card para ver dados específicos
- **Tema**: Use o botão de tema para alternar entre claro/escuro
- **Atualização**: Use o botão "Atualizar" para sincronizar dados

### 3. Visualização de Senhas
- **Tabela Principal**: Visualize todas as senhas LAPS
- **Filtros**: Use os checkboxes para filtrar por tipo de senha
- **Busca**: Digite o nome do computador na caixa de busca
- **Ordenação**: Clique nos cabeçalhos das colunas para ordenar

### 4. Gerenciamento
- **Copiar Senha**: Clique no ícone de cópia ao lado da senha
- **Adicionar Manual**: Clique no ícone "+" para adicionar senha manual
- **Editar**: Clique no ícone de edição para modificar senha manual
- **Excluir**: Clique no ícone "🗑️" para remover senha manual

### 5. Atualização de Dados
- **Sincronização**: Clique em "Atualizar" para sincronizar com o LDAP
- **Status**: Acompanhe o progresso em tempo real
- **Conclusão**: A página recarrega automaticamente com dados atualizados

## 🏗️ Arquitetura

### Estrutura de Diretórios
```
laps/
├── interface/           # Interface web principal
│   ├── PHP/            # Arquivos PHP da aplicação
│   ├── SCRIPTS/        # Scripts de sincronização
│   └── nginx/          # Configuração do servidor web
├── .env                # Configurações do ambiente
├── docker-compose.yml  # Orquestração de containers
└── README.md          # Este arquivo
```

### Tecnologias Utilizadas
- **Backend**: PHP 8.1
- **Banco de Dados**: MySQL 8.0
- **Servidor Web**: Nginx
- **Containerização**: Docker
- **Frontend**: HTML5, CSS3, JavaScript
- **Gráficos**: Chart.js
- **Ícones**: Font Awesome

### Integração
- **Active Directory**: Sincronização automática via LDAP
- **GLPI**: Integração para gestão de ativos (configurável via GLPI_URL)
- **Banco de Dados**: Armazenamento seguro de senhas e histórico

## 🔧 Configuração

### Variáveis de Ambiente
O sistema utiliza um arquivo `.env` para todas as configurações:

```env
# Configurações do Banco de Dados
DB_HOST=localhost
DB_NAME=laps_db
DB_USER=laps_user
DB_PASS=sua_senha

# Configurações LDAP
LDAP_SERVER=ldap://seu-servidor
LDAP_BASE_DN=DC=exemplo,DC=com
LDAP_USER=usuario_ldap
LDAP_PASS=senha_ldap

# Configurações GLPI
GLPI_URL=https://glpi.exemplo.com

# Grupos permitidos para acesso (separados por vírgula)
LDAP_ALLOWED_GROUPS=Domain Admins
```

### Configuração do GLPI
O sistema integra-se ao GLPI para permitir visualização dos computadores no sistema de gestão de ativos. Para configurar:

1. **URL do GLPI**: Configure a variável `GLPI_URL` no arquivo `.env`
2. **Exemplo**: `GLPI_URL=https://glpi.sua-empresa.com`
3. **Funcionalidade**: O botão "Ver no GLPI" na tabela de senhas abrirá o computador correspondente no GLPI

### Configuração de Grupos Permitidos
O sistema verifica se o usuário pertence aos grupos configurados no Active Directory. Para configurar:

1. **Grupos Permitidos**: Configure a variável `LDAP_ALLOWED_GROUPS` no arquivo `.env`
2. **Exemplo**: `LDAP_ALLOWED_GROUPS=Domain Admins,Administradores,TI`
3. **Funcionalidade**: Apenas usuários dos grupos especificados poderão fazer login no sistema

### Deploy com Docker
```bash
# Clone o repositório
git clone [url-do-repositorio]

# Configure o arquivo .env
cp exemplo.env .env
# Edite o arquivo .env com suas configurações

# Execute com Docker Compose
docker-compose up -d
```

## 📈 Monitoramento

### Estatísticas Disponíveis
- **Total de Computadores**: Contagem geral de registros
- **Senhas por Status**: Distribuição entre ativas, nulas e manuais
- **Histórico de Alterações**: Senhas modificadas por período
- **Alertas de Expiração**: Senhas que expiram em breve
- **Performance**: Tempo de sincronização e processamento

### Logs e Debug
- **Logs de Sincronização**: Arquivo `ldap-up.log` com detalhes do processo
- **Script de Estatísticas**: `ldap-stats.sh` para análise detalhada
- **Monitoramento em Tempo Real**: Status visual na interface

## 🛡️ Segurança

### Medidas Implementadas
- **Autenticação Segura**: Sistema de login com validação
- **Proteção CSRF**: Tokens para prevenir ataques cross-site
- **Sanitização de Dados**: Tratamento seguro de entradas
- **Sessões Protegidas**: Controle de acesso por sessão
- **Headers de Segurança**: CSP, XSS Protection, Frame Options
- **Logout Seguro**: Destruição completa de sessões e cookies

### Boas Práticas
- **Senhas Fortes**: Exigência de complexidade mínima
- **Alteração Obrigatória**: Força troca da senha padrão
- **Controle de Acesso**: Verificação de autenticação em todas as páginas
- **Auditoria**: Registro de ações importantes

## 🎨 Interface e UX

### Design Responsivo
- **Layout Adaptável**: Funciona em desktop, tablet e mobile
- **Tema Claro/Escuro**: Alternância automática com persistência
- **Ícones Intuitivos**: Font Awesome para melhor usabilidade
- **Animações Suaves**: Transições CSS para melhor experiência

### Experiência do Usuário
- **Feedback Visual**: Estados de loading e confirmações
- **Navegação Clara**: Estrutura intuitiva e fácil de usar
- **Acessibilidade**: Contraste adequado e navegação por teclado
- **Performance**: Carregamento rápido e operações eficientes


