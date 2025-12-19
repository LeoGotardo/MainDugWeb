#!/usr/bin/env node

/**
 * Script para gerar chaves de segurança para MainDug API
 * 
 * Uso: node generate-keys.js
 */

const crypto = require('crypto');

console.log('\n╔══════════════════════════════════════════════════════╗');
console.log('║  GERADOR DE CHAVES - MAINDUG API                     ║');
console.log('╚══════════════════════════════════════════════════════╝\n');

// Gerar JWT Secret (32 bytes = 64 caracteres hex)
const jwtSecret = crypto.randomBytes(32).toString('hex');

// Gerar Encryption Key (32 bytes = 64 caracteres hex)
const encryptionKey = crypto.randomBytes(32).toString('hex');

console.log('📋 COPIE ESTAS CHAVES PARA SEU ARQUIVO .env:\n');
console.log('─────────────────────────────────────────────────────\n');

console.log('# JWT Secret (para autenticação)');
console.log(`JWT_SECRET=${jwtSecret}\n`);

console.log('# Encryption Key (para criptografia de senhas)');
console.log(`ENCRYPTION_KEY=${encryptionKey}\n`);

console.log('─────────────────────────────────────────────────────\n');

console.log('⚠️  IMPORTANTE:');
console.log('   • Nunca compartilhe estas chaves');
console.log('   • Use chaves diferentes para desenvolvimento e produção');
console.log('   • Guarde estas chaves em local seguro');
console.log('   • Não commite o arquivo .env no Git\n');

console.log('✅ Chaves geradas com sucesso!\n');

// Opcionalmente, criar arquivo .env se não existir
const fs = require('fs');
const path = require('path');

const envPath = path.join(__dirname, '.env');
const envExamplePath = path.join(__dirname, '.env.example');

if (!fs.existsSync(envPath)) {
    console.log('📝 Arquivo .env não encontrado. Deseja criar? (s/n)');
    
    const readline = require('readline');
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });
    
    rl.question('> ', (answer) => {
        if (answer.toLowerCase() === 's' || answer.toLowerCase() === 'sim') {
            let envContent = '';
            
            // Tentar ler .env.example como template
            if (fs.existsSync(envExamplePath)) {
                envContent = fs.readFileSync(envExamplePath, 'utf8');
                
                // Substituir chaves
                envContent = envContent.replace(
                    /JWT_SECRET=.*/,
                    `JWT_SECRET=${jwtSecret}`
                );
                envContent = envContent.replace(
                    /ENCRYPTION_KEY=.*/,
                    `ENCRYPTION_KEY=${encryptionKey}`
                );
            } else {
                // Criar conteúdo básico
                envContent = `# Database
DB_HOST=localhost
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=sua_senha_aqui
DB_NAME=maindug_db
DB_SSL=false

# Server
PORT=5000
NODE_ENV=development

# Security
JWT_SECRET=${jwtSecret}
ENCRYPTION_KEY=${encryptionKey}

# CORS
CORS_ORIGIN=chrome-extension://*,http://localhost:*
`;
            }
            
            fs.writeFileSync(envPath, envContent);
            console.log('\n✅ Arquivo .env criado com sucesso!');
            console.log('⚠️  Lembre-se de configurar as credenciais do banco de dados.\n');
        } else {
            console.log('\n📋 Copie as chaves acima manualmente para seu arquivo .env\n');
        }
        
        rl.close();
    });
} else {
    console.log('ℹ️  Arquivo .env já existe.');
    console.log('   Para atualizar as chaves, edite o arquivo manualmente.\n');
}