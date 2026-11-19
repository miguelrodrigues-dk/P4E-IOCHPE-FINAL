// app.js
const express = require('express');
const path = require('path');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');
const app = express();

// Configurações do EJS e pastas públicas do projeto
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.disable('x-powered-by');
if (process.env.NODE_ENV === 'production' && !process.env.SESSION_SECRET) {
  throw new Error('Defina SESSION_SECRET no ambiente de produção antes de iniciar o P4E.');
}
app.use((req, res, next) => { res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('X-Frame-Options', 'DENY'); res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin'); next(); });
app.use(express.urlencoded({ extended: true, limit: '8mb' }));
app.use(express.json({ limit: '8mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// 1. PRIMEIRO: Inicializa a conexão com o arquivo database.db
const db = new sqlite3.Database(path.join(__dirname, 'database.db'), (err) => {
  if (err) console.error('Erro ao conectar ao SQLite:', err.message);
  else console.log('Banco de dados SQLite pronto e conectado (database.db)!');
});

// 2. SEGUNDO: Roda as configurações de tabelas e o administrador automático
db.serialize(() => {
  // Cria a tabela de usuários se ela não existir
  db.run(`
    CREATE TABLE IF NOT EXISTS usuarios (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      nome TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      senha TEXT NOT NULL,
      role TEXT DEFAULT 'comum',
      foto TEXT
    )
  `);

  // Compatibilidade com bancos criados antes da função de foto de perfil.
  db.all('PRAGMA table_info(usuarios)', (err, colunas) => {
    if (err) return console.error('Erro ao verificar tabela usuarios:', err.message);
    const possuiFoto = colunas.some(coluna => coluna.name === 'foto');
    if (!possuiFoto) {
      db.run('ALTER TABLE usuarios ADD COLUMN foto TEXT', (erroAlteracao) => {
        if (erroAlteracao) console.error('Erro ao adicionar coluna foto:', erroAlteracao.message);
      });
    }
  });

  // Conta administrativa inicial: configure ADMIN_EMAIL e ADMIN_PASSWORD no ambiente.
  // Se a conta ainda não existir, uma senha aleatória é gerada e exibida apenas no console.
  const adminEmail = process.env.ADMIN_EMAIL || 'admin@p4e.com';
  db.get('SELECT id FROM usuarios WHERE email = ?', [adminEmail], async (err, existente) => {
    if (err || existente) return;
    const senhaInicial = process.env.ADMIN_PASSWORD || crypto.randomBytes(18).toString('base64url');
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = await new Promise((resolve, reject) => crypto.scrypt(senhaInicial, salt, 64, (e, key) => e ? reject(e) : resolve(key.toString('hex'))));
    db.run("INSERT INTO usuarios (nome, email, senha, role) VALUES (?, ?, ?, 'admin')",
      ['Administrador P4E', adminEmail, `scrypt:${salt}:${hash}`], (insertErr) => {
        if (insertErr) console.error('Erro ao criar administrador:', insertErr.message);
        else console.log(`[P4E] Administrador criado: ${adminEmail}${process.env.ADMIN_PASSWORD ? '' : ` | senha inicial: ${senhaInicial}`}`);
      });
  });
});

// Tornar o banco global para usarmos nos arquivos de rotas
global.db = db;

// Configuração da Sessão (Expira após 20 minutos de inatividade)
app.use(session({
  secret: process.env.SESSION_SECRET || 'P4E-dev-secret-troque-esta-chave-antes-de-publicar-2026',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 20 * 60 * 1000, httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production' } // 20 minutos
}));

// Proteção básica contra envio de formulários originados em outros sites.
app.use((req, res, next) => {
  if (req.method !== 'POST') return next();
  const origem = req.get('origin');
  const referer = req.get('referer');
  const origemEsperada = `${req.protocol}://${req.get('host')}`;
  if (origem && origem !== origemEsperada) return res.status(403).send('Requisição bloqueada por segurança.');
  if (!origem && referer && !referer.startsWith(origemEsperada + '/')) return res.status(403).send('Requisição bloqueada por segurança.');
  next();
});

// Middleware global para injetar o usuário logado no Navbar
app.use((req, res, next) => {
  res.locals.usuario = req.session.usuario || null;
  next();
});

// Página pública de apresentação do P4E.
app.get('/', (req, res) => {
  if (req.session.usuario) return res.redirect('/eventos');
  res.render('sobre');
});

// Conectar as rotas do projeto
app.use('/eventos', require('./routes/eventoRoutes'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`P4E rodando com sucesso em http://localhost:${PORT}`);
});
