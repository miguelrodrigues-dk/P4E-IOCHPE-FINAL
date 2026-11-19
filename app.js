// app.js
const express = require('express');
const path = require('path');
const session = require('express-session');
const { createClient } = require('@libsql/client');
const crypto = require('crypto');
const app = express();

// Importante no Render para que o cookie 'secure' e o protocolo HTTPS funcionem corretamente
app.set('trust proxy', 1);

// Configurações do EJS e pastas públicas do projeto
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.disable('x-powered-by');
if (process.env.NODE_ENV === 'production' && !process.env.SESSION_SECRET) {
  throw new Error('Defina SESSION_SECRET no ambiente de produção antes de iniciar o P4E.');
}
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});
app.use(express.urlencoded({ extended: true, limit: '8mb' }));
app.use(express.json({ limit: '8mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// 1. Conexão com o Turso DB (com fallback local caso rode sem variáveis de ambiente)
const turso = createClient({
  url: process.env.TURSO_DATABASE_URL || 'file:database.db',
  authToken: process.env.TURSO_AUTH_TOKEN,
});

// Adaptador que mantém a compatibilidade com db.run, db.get e db.all nas rotas
const db = {
  run(sql, params, callback) {
    if (typeof params === 'function') {
      callback = params;
      params = [];
    }
    turso.execute({ sql, args: params || [] })
      .then((res) => {
        if (callback) {
          callback.call({
            lastID: res.lastInsertRowid ? Number(res.lastInsertRowid) : undefined,
            changes: res.rowsAffected
          }, null);
        }
      })
      .catch((err) => {
        if (callback) callback(err);
        else console.error('Erro no db.run (Turso):', err.message);
      });
  },

  get(sql, params, callback) {
    if (typeof params === 'function') {
      callback = params;
      params = [];
    }
    turso.execute({ sql, args: params || [] })
      .then((res) => {
        const row = res.rows.length > 0 ? { ...res.rows[0] } : undefined;
        if (callback) callback(null, row);
      })
      .catch((err) => {
        if (callback) callback(err);
        else console.error('Erro no db.get (Turso):', err.message);
      });
  },

  all(sql, params, callback) {
    if (typeof params === 'function') {
      callback = params;
      params = [];
    }
    turso.execute({ sql, args: params || [] })
      .then((res) => {
        const rows = res.rows.map(r => ({ ...r }));
        if (callback) callback(null, rows);
      })
      .catch((err) => {
        if (callback) callback(err);
        else console.error('Erro no db.all (Turso):', err.message);
      });
  }
};

// 2. Inicializa as tabelas e o administrador automático no Turso
async function inicializarBanco() {
  try {
    await turso.execute(`
      CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nome TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        senha TEXT NOT NULL,
        role TEXT DEFAULT 'comum',
        foto TEXT
      )
    `);

    // Verifica se a coluna 'foto' existe
    const info = await turso.execute('PRAGMA table_info(usuarios)');
    const possuiFoto = info.rows.some(coluna => coluna.name === 'foto');
    if (!possuiFoto) {
      await turso.execute('ALTER TABLE usuarios ADD COLUMN foto TEXT');
    }

    // Cria a conta administrativa inicial se não existir
    const adminEmail = process.env.ADMIN_EMAIL || 'admin@p4e.com';
    const existente = await turso.execute({
      sql: 'SELECT id FROM usuarios WHERE email = ?',
      args: [adminEmail]
    });

    if (existente.rows.length === 0) {
      const senhaInicial = process.env.ADMIN_PASSWORD || crypto.randomBytes(18).toString('base64url');
      const salt = crypto.randomBytes(16).toString('hex');
      const hash = await new Promise((resolve, reject) =>
        crypto.scrypt(senhaInicial, salt, 64, (e, key) => e ? reject(e) : resolve(key.toString('hex')))
      );

      await turso.execute({
        sql: "INSERT INTO usuarios (nome, email, senha, role) VALUES (?, ?, ?, 'admin')",
        args: ['Administrador P4E', adminEmail, `scrypt:${salt}:${hash}`]
      });
      console.log(`[P4E] Administrador criado no Turso: ${adminEmail}${process.env.ADMIN_PASSWORD ? '' : ` | senha inicial: ${senhaInicial}`}`);
    }

    console.log('Banco de dados Turso conectado e pronto!');
  } catch (err) {
    console.error('Erro ao inicializar o banco Turso:', err.message);
  }
}

inicializarBanco();

// Tornar o banco global para usarmos nos arquivos de rotas
global.db = db;

// Configuração da Sessão (Expira após 20 minutos de inatividade)
app.use(session({
  secret: process.env.SESSION_SECRET || 'P4E-dev-secret-troque-esta-chave-antes-de-publicar-2026',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 20 * 60 * 1000,
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production'
  }
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
  console.log(`P4E rodando com sucesso na porta ${PORT}`);
});
