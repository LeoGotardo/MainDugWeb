// server-enhanced.js - Backend API completo com recursos adicionais

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { Pool } = require('pg');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Configuração do PostgreSQL
const pool = new Pool({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT || 5432,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false,
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 2000,
});

// Middlewares de segurança
app.use(helmet());
app.use(cors({
    origin: process.env.CORS_ORIGIN || ['http://localhost:*', 'chrome-extension://*'],
    credentials: true
}));
app.use(express.json({ limit: '10mb' }));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: 100, // limite de requisições
    message: 'Muitas requisições deste IP, tente novamente mais tarde.'
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5, // máximo 5 tentativas de login
    skipSuccessfulRequests: true
});

app.use('/api/', limiter);
app.use('/api/auth/login', authLimiter);
app.use('/api/auth/register', authLimiter);

// Chave de criptografia para senhas
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex');
const IV_LENGTH = 16;

// Funções de criptografia
function encrypt(text) {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(
        'aes-256-cbc',
        Buffer.from(ENCRYPTION_KEY, 'hex'),
        iv
    );
    
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(text) {
    const textParts = text.split(':');
    const iv = Buffer.from(textParts.shift(), 'hex');
    const encryptedText = Buffer.from(textParts.join(':'), 'hex');
    
    const decipher = crypto.createDecipheriv(
        'aes-256-cbc',
        Buffer.from(ENCRYPTION_KEY, 'hex'),
        iv
    );
    
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    
    return decrypted.toString();
}

// Middleware de autenticação
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'Token não fornecido' });
    }
    
    jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key', (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Token inválido ou expirado' });
        }
        req.user = user;
        next();
    });
}

// Middleware de validação
function handleValidationErrors(req, res, next) {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    next();
}

// Inicializar banco de dados
async function initDatabase() {
    try {
        // Criar tabela de usuários
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                name VARCHAR(255),
                two_factor_enabled BOOLEAN DEFAULT FALSE,
                two_factor_secret VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                is_premium BOOLEAN DEFAULT FALSE,
                storage_used INTEGER DEFAULT 0,
                max_passwords INTEGER DEFAULT 100
            )
        `);
        
        // Criar tabela de senhas
        await pool.query(`
            CREATE TABLE IF NOT EXISTS passwords (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                site VARCHAR(255) NOT NULL,
                url TEXT,
                username VARCHAR(255) NOT NULL,
                encrypted_password TEXT NOT NULL,
                notes TEXT,
                category VARCHAR(100),
                favorite BOOLEAN DEFAULT FALSE,
                password_strength INTEGER,
                last_used TIMESTAMP,
                usage_count INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                UNIQUE(user_id, site, username)
            )
        `);
        
        // Criar tabela de logs de segurança
        await pool.query(`
            CREATE TABLE IF NOT EXISTS security_logs (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                action VARCHAR(100) NOT NULL,
                ip_address INET,
                user_agent TEXT,
                success BOOLEAN,
                details JSONB,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        // Criar tabela de senhas compartilhadas
        await pool.query(`
            CREATE TABLE IF NOT EXISTS shared_passwords (
                id SERIAL PRIMARY KEY,
                password_id INTEGER REFERENCES passwords(id) ON DELETE CASCADE,
                shared_by INTEGER REFERENCES users(id),
                shared_with_email VARCHAR(255),
                permission VARCHAR(50) DEFAULT 'view',
                expires_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        // Criar tabela de categorias personalizadas
        await pool.query(`
            CREATE TABLE IF NOT EXISTS categories (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                name VARCHAR(100) NOT NULL,
                color VARCHAR(7),
                icon VARCHAR(50),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, name)
            )
        `);
        
        // Criar índices para melhor performance
        await pool.query(`
            CREATE INDEX IF NOT EXISTS idx_passwords_user_id ON passwords(user_id);
            CREATE INDEX IF NOT EXISTS idx_passwords_site ON passwords(site);
            CREATE INDEX IF NOT EXISTS idx_passwords_favorite ON passwords(favorite);
            CREATE INDEX IF NOT EXISTS idx_security_logs_user_id ON security_logs(user_id);
            CREATE INDEX IF NOT EXISTS idx_shared_passwords_shared_with ON shared_passwords(shared_with_email);
        `);
        
        console.log('✅ Banco de dados inicializado com sucesso');
    } catch (error) {
        console.error('❌ Erro ao inicializar banco de dados:', error);
        process.exit(1);
    }
}

// Função para log de segurança
async function logSecurityEvent(userId, action, success, req, details = {}) {
    try {
        await pool.query(
            `INSERT INTO security_logs (user_id, action, ip_address, user_agent, success, details) 
             VALUES ($1, $2, $3, $4, $5, $6)`,
            [
                userId,
                action,
                req.ip || req.connection.remoteAddress,
                req.headers['user-agent'],
                success,
                JSON.stringify(details)
            ]
        );
    } catch (error) {
        console.error('Erro ao registrar log de segurança:', error);
    }
}

// Função para calcular força da senha
function calculatePasswordStrength(password) {
    let strength = 0;
    
    if (password.length >= 8) strength += 1;
    if (password.length >= 12) strength += 1;
    if (password.length >= 16) strength += 1;
    if (/[a-z]/.test(password)) strength += 1;
    if (/[A-Z]/.test(password)) strength += 1;
    if (/[0-9]/.test(password)) strength += 1;
    if (/[^a-zA-Z0-9]/.test(password)) strength += 1;
    
    return Math.min(Math.floor((strength / 7) * 5), 5); // Retorna de 0 a 5
}

// ROTAS DE AUTENTICAÇÃO

// Registro com validação
app.post('/api/auth/register', [
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 6 }).withMessage('A senha deve ter pelo menos 6 caracteres'),
    body('name').optional().trim().escape(),
    handleValidationErrors
], async (req, res) => {
    const { email, password, name } = req.body;
    
    try {
        // Verificar se o usuário já existe
        const userExists = await pool.query(
            'SELECT id FROM users WHERE email = $1',
            [email]
        );
        
        if (userExists.rows.length > 0) {
            await logSecurityEvent(null, 'REGISTER_ATTEMPT_DUPLICATE', false, req, { email });
            return res.status(400).json({ error: 'Este email já está cadastrado' });
        }
        
        // Hash da senha
        const passwordHash = await bcrypt.hash(password, 12);
        
        // Criar usuário
        const result = await pool.query(
            'INSERT INTO users (email, password_hash, name) VALUES ($1, $2, $3) RETURNING id, email',
            [email, passwordHash, name]
        );
        
        await logSecurityEvent(result.rows[0].id, 'REGISTER_SUCCESS', true, req);
        
        res.status(201).json({
            message: 'Usuário criado com sucesso',
            userId: result.rows[0].id
        });
    } catch (error) {
        console.error('Erro ao registrar usuário:', error);
        res.status(500).json({ error: 'Erro ao criar usuário' });
    }
});

// Login com validação
app.post('/api/auth/login', [
    body('email').isEmail().normalizeEmail(),
    body('password').notEmpty(),
    handleValidationErrors
], async (req, res) => {
    const { email, password } = req.body;
    
    try {
        // Buscar usuário
        const result = await pool.query(
            'SELECT id, email, password_hash, name, two_factor_enabled FROM users WHERE email = $1',
            [email]
        );
        
        if (result.rows.length === 0) {
            await logSecurityEvent(null, 'LOGIN_FAILED_USER_NOT_FOUND', false, req, { email });
            return res.status(401).json({ error: 'Credenciais inválidas' });
        }
        
        const user = result.rows[0];
        
        // Verificar senha
        const validPassword = await bcrypt.compare(password, user.password_hash);
        
        if (!validPassword) {
            await logSecurityEvent(user.id, 'LOGIN_FAILED_WRONG_PASSWORD', false, req);
            return res.status(401).json({ error: 'Credenciais inválidas' });
        }
        
        // Atualizar último login
        await pool.query(
            'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1',
            [user.id]
        );
        
        // Gerar token JWT
        const token = jwt.sign(
            { 
                userId: user.id, 
                email: user.email,
                name: user.name 
            },
            process.env.JWT_SECRET || 'your-secret-key',
            { expiresIn: '7d' }
        );
        
        await logSecurityEvent(user.id, 'LOGIN_SUCCESS', true, req);
        
        res.json({
            message: 'Login realizado com sucesso',
            token,
            userId: user.id,
            user: {
                email: user.email,
                name: user.name,
                twoFactorEnabled: user.two_factor_enabled
            }
        });
    } catch (error) {
        console.error('Erro ao fazer login:', error);
        res.status(500).json({ error: 'Erro ao fazer login' });
    }
});

// Logout (registrar evento)
app.post('/api/auth/logout', authenticateToken, async (req, res) => {
    await logSecurityEvent(req.user.userId, 'LOGOUT', true, req);
    res.json({ message: 'Logout realizado com sucesso' });
});

// Verificar token
app.get('/api/auth/verify', authenticateToken, (req, res) => {
    res.json({ valid: true, user: req.user });
});

// Alterar senha
app.post('/api/auth/change-password', [
    authenticateToken,
    body('currentPassword').notEmpty(),
    body('newPassword').isLength({ min: 6 }),
    handleValidationErrors
], async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    
    try {
        // Buscar senha atual
        const result = await pool.query(
            'SELECT password_hash FROM users WHERE id = $1',
            [req.user.userId]
        );
        
        // Verificar senha atual
        const validPassword = await bcrypt.compare(currentPassword, result.rows[0].password_hash);
        
        if (!validPassword) {
            await logSecurityEvent(req.user.userId, 'CHANGE_PASSWORD_FAILED', false, req);
            return res.status(401).json({ error: 'Senha atual incorreta' });
        }
        
        // Hash da nova senha
        const newPasswordHash = await bcrypt.hash(newPassword, 12);
        
        // Atualizar senha
        await pool.query(
            'UPDATE users SET password_hash = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2',
            [newPasswordHash, req.user.userId]
        );
        
        await logSecurityEvent(req.user.userId, 'CHANGE_PASSWORD_SUCCESS', true, req);
        
        res.json({ message: 'Senha alterada com sucesso' });
    } catch (error) {
        console.error('Erro ao alterar senha:', error);
        res.status(500).json({ error: 'Erro ao alterar senha' });
    }
});

// ROTAS DE SENHAS

// Listar senhas com filtros
app.get('/api/passwords', authenticateToken, async (req, res) => {
    const { category, favorite, search, sort = 'site' } = req.query;
    
    try {
        let query = `
            SELECT id, site, url, username, notes, category, favorite, 
                   password_strength, last_used, usage_count, created_at, updated_at 
            FROM passwords 
            WHERE user_id = $1
        `;
        const params = [req.user.userId];
        let paramCount = 1;
        
        if (category) {
            paramCount++;
            query += ` AND category = $${paramCount}`;
            params.push(category);
        }
        
        if (favorite === 'true') {
            query += ` AND favorite = true`;
        }
        
        if (search) {
            paramCount++;
            query += ` AND (site ILIKE $${paramCount} OR username ILIKE $${paramCount} OR notes ILIKE $${paramCount})`;
            params.push(`%${search}%`);
        }
        
        // Ordenação
        const validSorts = ['site', 'username', 'created_at', 'updated_at', 'last_used', 'usage_count'];
        const sortField = validSorts.includes(sort) ? sort : 'site';
        query += ` ORDER BY ${sortField}`;
        
        const result = await pool.query(query, params);
        
        res.json(result.rows);
    } catch (error) {
        console.error('Erro ao listar senhas:', error);
        res.status(500).json({ error: 'Erro ao listar senhas' });
    }
});

// Buscar senha específica
app.get('/api/passwords/:id', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT id, site, url, username, notes, category, favorite, 
                    password_strength, last_used, usage_count, created_at, updated_at 
             FROM passwords 
             WHERE id = $1 AND user_id = $2`,
            [req.params.id, req.user.userId]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Senha não encontrada' });
        }
        
        res.json(result.rows[0]);
    } catch (error) {
        console.error('Erro ao buscar senha:', error);
        res.status(500).json({ error: 'Erro ao buscar senha' });
    }
});

// Adicionar ou atualizar senha com validação completa
app.post('/api/passwords', [
    authenticateToken,
    body('site').notEmpty().trim(),
    body('username').notEmpty().trim(),
    body('password').notEmpty(),
    body('url').optional().isURL(),
    body('notes').optional().trim(),
    body('category').optional().trim(),
    body('favorite').optional().isBoolean(),
    handleValidationErrors
], async (req, res) => {
    const { site, url, username, password, notes, category, favorite } = req.body;
    
    try {
        // Verificar limite de senhas do usuário
        const countResult = await pool.query(
            'SELECT COUNT(*) as count, max_passwords FROM passwords p JOIN users u ON p.user_id = u.id WHERE u.id = $1 GROUP BY u.max_passwords',
            [req.user.userId]
        );
        
        if (countResult.rows.length > 0) {
            const { count, max_passwords } = countResult.rows[0];
            if (parseInt(count) >= max_passwords) {
                return res.status(403).json({ 
                    error: `Limite de ${max_passwords} senhas atingido. Considere fazer upgrade para premium.` 
                });
            }
        }
        
        // Criptografar senha
        const encryptedPassword = encrypt(password);
        const passwordStrength = calculatePasswordStrength(password);
        
        // Verificar se já existe
        const existing = await pool.query(
            'SELECT id FROM passwords WHERE user_id = $1 AND site = $2 AND username = $3',
            [req.user.userId, site, username]
        );
        
        let result;
        
        if (existing.rows.length > 0) {
            // Atualizar senha existente
            result = await pool.query(
                `UPDATE passwords 
                 SET encrypted_password = $1, url = $2, notes = $3, category = $4, 
                     favorite = $5, password_strength = $6, updated_at = CURRENT_TIMESTAMP 
                 WHERE id = $7 
                 RETURNING id`,
                [encryptedPassword, url, notes, category, favorite || false, passwordStrength, existing.rows[0].id]
            );
            
            await logSecurityEvent(req.user.userId, 'PASSWORD_UPDATED', true, req, { passwordId: existing.rows[0].id });
        } else {
            // Criar nova senha
            result = await pool.query(
                `INSERT INTO passwords (user_id, site, url, username, encrypted_password, notes, category, favorite, password_strength) 
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) 
                 RETURNING id`,
                [req.user.userId, site, url, username, encryptedPassword, notes, category, favorite || false, passwordStrength]
            );
            
            await logSecurityEvent(req.user.userId, 'PASSWORD_CREATED', true, req, { passwordId: result.rows[0].id });
        }
        
        res.status(existing.rows.length > 0 ? 200 : 201).json({
            message: existing.rows.length > 0 ? 'Senha atualizada' : 'Senha salva',
            passwordId: result.rows[0].id,
            passwordStrength
        });
    } catch (error) {
        console.error('Erro ao salvar senha:', error);
        res.status(500).json({ error: 'Erro ao salvar senha' });
    }
});

// Descriptografar senha e registrar uso
app.get('/api/passwords/:id/decrypt', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT encrypted_password FROM passwords WHERE id = $1 AND user_id = $2',
            [req.params.id, req.user.userId]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Senha não encontrada' });
        }
        
        // Atualizar estatísticas de uso
        await pool.query(
            'UPDATE passwords SET last_used = CURRENT_TIMESTAMP, usage_count = usage_count + 1 WHERE id = $1',
            [req.params.id]
        );
        
        const decryptedPassword = decrypt(result.rows[0].encrypted_password);
        
        await logSecurityEvent(req.user.userId, 'PASSWORD_ACCESSED', true, req, { passwordId: req.params.id });
        
        res.json({ password: decryptedPassword });
    } catch (error) {
        console.error('Erro ao descriptografar senha:', error);
        res.status(500).json({ error: 'Erro ao descriptografar senha' });
    }
});

// Deletar senha
app.delete('/api/passwords/:id', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            'DELETE FROM passwords WHERE id = $1 AND user_id = $2 RETURNING id, site',
            [req.params.id, req.user.userId]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Senha não encontrada' });
        }
        
        await logSecurityEvent(req.user.userId, 'PASSWORD_DELETED', true, req, { 
            passwordId: req.params.id,
            site: result.rows[0].site 
        });
        
        res.json({ message: 'Senha excluída com sucesso' });
    } catch (error) {
        console.error('Erro ao deletar senha:', error);
        res.status(500).json({ error: 'Erro ao deletar senha' });
    }
});

// Favoritar/desfavoritar senha
app.patch('/api/passwords/:id/favorite', authenticateToken, async (req, res) => {
    const { favorite } = req.body;
    
    try {
        const result = await pool.query(
            'UPDATE passwords SET favorite = $1 WHERE id = $2 AND user_id = $3 RETURNING id',
            [favorite, req.params.id, req.user.userId]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Senha não encontrada' });
        }
        
        res.json({ message: favorite ? 'Adicionado aos favoritos' : 'Removido dos favoritos' });
    } catch (error) {
        console.error('Erro ao atualizar favorito:', error);
        res.status(500).json({ error: 'Erro ao atualizar favorito' });
    }
});

// ROTAS DE CATEGORIAS

// Listar categorias
app.get('/api/categories', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT id, name, color, icon FROM categories WHERE user_id = $1 ORDER BY name',
            [req.user.userId]
        );
        
        res.json(result.rows);
    } catch (error) {
        console.error('Erro ao listar categorias:', error);
        res.status(500).json({ error: 'Erro ao listar categorias' });
    }
});

// Criar categoria
app.post('/api/categories', [
    authenticateToken,
    body('name').notEmpty().trim(),
    body('color').optional().matches(/^#[0-9A-F]{6}$/i),
    body('icon').optional().trim(),
    handleValidationErrors
], async (req, res) => {
    const { name, color, icon } = req.body;
    
    try {
        const result = await pool.query(
            'INSERT INTO categories (user_id, name, color, icon) VALUES ($1, $2, $3, $4) RETURNING id',
            [req.user.userId, name, color, icon]
        );
        
        res.status(201).json({
            message: 'Categoria criada',
            categoryId: result.rows[0].id
        });
    } catch (error) {
        if (error.constraint === 'categories_user_id_name_key') {
            return res.status(400).json({ error: 'Categoria já existe' });
        }
        console.error('Erro ao criar categoria:', error);
        res.status(500).json({ error: 'Erro ao criar categoria' });
    }
});

// ROTAS DE COMPARTILHAMENTO

// Compartilhar senha
app.post('/api/passwords/:id/share', [
    authenticateToken,
    body('email').isEmail().normalizeEmail(),
    body('permission').isIn(['view', 'edit']),
    body('expiresIn').optional().isInt({ min: 1, max: 30 }),
    handleValidationErrors
], async (req, res) => {
    const { email, permission, expiresIn } = req.body;
    const passwordId = req.params.id;
    
    try {
        // Verificar se a senha pertence ao usuário
        const passwordCheck = await pool.query(
            'SELECT id FROM passwords WHERE id = $1 AND user_id = $2',
            [passwordId, req.user.userId]
        );
        
        if (passwordCheck.rows.length === 0) {
            return res.status(404).json({ error: 'Senha não encontrada' });
        }
        
        // Calcular data de expiração
        const expiresAt = expiresIn ? 
            new Date(Date.now() + expiresIn * 24 * 60 * 60 * 1000) : 
            null;
        
        // Criar compartilhamento
        const result = await pool.query(
            `INSERT INTO shared_passwords (password_id, shared_by, shared_with_email, permission, expires_at) 
             VALUES ($1, $2, $3, $4, $5) RETURNING id`,
            [passwordId, req.user.userId, email, permission, expiresAt]
        );
        
        await logSecurityEvent(req.user.userId, 'PASSWORD_SHARED', true, req, { 
            passwordId,
            sharedWith: email,
            permission
        });
        
        res.status(201).json({
            message: 'Senha compartilhada com sucesso',
            shareId: result.rows[0].id
        });
    } catch (error) {
        console.error('Erro ao compartilhar senha:', error);
        res.status(500).json({ error: 'Erro ao compartilhar senha' });
    }
});

// ROTAS DE ESTATÍSTICAS

// Dashboard com estatísticas
app.get('/api/dashboard', authenticateToken, async (req, res) => {
    try {
        // Total de senhas
        const totalPasswords = await pool.query(
            'SELECT COUNT(*) as count FROM passwords WHERE user_id = $1',
            [req.user.userId]
        );
        
        // Senhas fracas
        const weakPasswords = await pool.query(
            'SELECT COUNT(*) as count FROM passwords WHERE user_id = $1 AND password_strength < 3',
            [req.user.userId]
        );
        
        // Senhas duplicadas (mesmo username e senha criptografada)
        const duplicatePasswords = await pool.query(
            `SELECT COUNT(*) as count FROM (
                SELECT encrypted_password, COUNT(*) 
                FROM passwords 
                WHERE user_id = $1 
                GROUP BY encrypted_password 
                HAVING COUNT(*) > 1
            ) as duplicates`,
            [req.user.userId]
        );
        
        // Senhas mais usadas
        const mostUsedPasswords = await pool.query(
            'SELECT site, username, usage_count FROM passwords WHERE user_id = $1 ORDER BY usage_count DESC LIMIT 5',
            [req.user.userId]
        );
        
        // Atividade recente
        const recentActivity = await pool.query(
            'SELECT action, success, created_at FROM security_logs WHERE user_id = $1 ORDER BY created_at DESC LIMIT 10',
            [req.user.userId]
        );
        
        res.json({
            stats: {
                totalPasswords: parseInt(totalPasswords.rows[0].count),
                weakPasswords: parseInt(weakPasswords.rows[0].count),
                duplicatePasswords: parseInt(duplicatePasswords.rows[0].count)
            },
            mostUsedPasswords: mostUsedPasswords.rows,
            recentActivity: recentActivity.rows
        });
    } catch (error) {
        console.error('Erro ao buscar dashboard:', error);
        res.status(500).json({ error: 'Erro ao buscar estatísticas' });
    }
});

// ROTAS DE EXPORTAÇÃO/IMPORTAÇÃO

// Exportar senhas (múltiplos formatos)
app.get('/api/passwords/export/:format', authenticateToken, async (req, res) => {
    const format = req.params.format;
    
    try {
        const result = await pool.query(
            'SELECT site, url, username, notes, category FROM passwords WHERE user_id = $1 ORDER BY site',
            [req.user.userId]
        );
        
        await logSecurityEvent(req.user.userId, 'PASSWORDS_EXPORTED', true, req, { format });
        
        if (format === 'csv') {
            // Exportar como CSV
            let csv = 'Site,URL,Username,Notes,Category\n';
            
            result.rows.forEach(row => {
                csv += `"${row.site}","${row.url || ''}","${row.username}","${row.notes || ''}","${row.category || ''}"\n`;
            });
            
            res.setHeader('Content-Type', 'text/csv');
            res.setHeader('Content-Disposition', 'attachment; filename="passwords.csv"');
            res.send(csv);
            
        } else if (format === 'json') {
            // Exportar como JSON
            res.setHeader('Content-Type', 'application/json');
            res.setHeader('Content-Disposition', 'attachment; filename="passwords.json"');
            res.json({
                exported_at: new Date().toISOString(),
                count: result.rows.length,
                passwords: result.rows
            });
            
        } else if (format === 'bitwarden') {
            // Formato compatível com Bitwarden
            const bitwardenFormat = {
                encrypted: false,
                folders: [],
                items: result.rows.map(row => ({
                    id: crypto.randomUUID(),
                    organizationId: null,
                    folderId: null,
                    type: 1,
                    name: row.site,
                    notes: row.notes,
                    favorite: false,
                    login: {
                        uris: [{ match: null, uri: row.url }],
                        username: row.username,
                        password: null // Não incluímos senhas descriptografadas na exportação
                    },
                    collectionIds: [],
                    reprompt: 0
                }))
            };
            
            res.setHeader('Content-Type', 'application/json');
            res.setHeader('Content-Disposition', 'attachment; filename="passwords_bitwarden.json"');
            res.json(bitwardenFormat);
            
        } else {
            res.status(400).json({ error: 'Formato não suportado. Use: csv, json ou bitwarden' });
        }