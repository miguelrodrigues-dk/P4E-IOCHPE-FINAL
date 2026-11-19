const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { promisify } = require('util');
const scrypt = promisify(crypto.scrypt);

async function criarHash(senha) {
  const salt = crypto.randomBytes(16).toString('hex');
  const chave = await scrypt(senha, salt, 64);
  return `scrypt:${salt}:${chave.toString('hex')}`;
}
async function validarSenha(senha, armazenada) {
  if (!armazenada || !armazenada.startsWith('scrypt:')) return senha === armazenada;
  const partes = armazenada.split(':');
  const chave = await scrypt(senha, partes[1], 64);
  const esperada = Buffer.from(partes[2], 'hex');
  return esperada.length === chave.length && crypto.timingSafeEqual(esperada, chave);
}
async function salvarImagem(dataUrl) {
  if (!dataUrl) return null;
  const match = /^data:image\/(png|jpeg|jpg|webp|gif);base64,([A-Za-z0-9+/=]+)$/.exec(dataUrl);
  if (!match || dataUrl.length > 5_500_000) throw new Error('Imagem inválida. Use PNG, JPG, WEBP ou GIF de até 4 MB.');
  const buffer = Buffer.from(match[2], 'base64');
  if (!buffer.length || buffer.length > 4 * 1024 * 1024) throw new Error('A imagem deve ter no máximo 4 MB.');
  const ext = match[1] === 'jpeg' ? 'jpg' : match[1];
  const nome = `${crypto.randomUUID()}.${ext}`;
  const pasta = path.join(__dirname, '..', 'public', 'uploads');
  await fs.promises.mkdir(pasta, { recursive: true });
  await fs.promises.writeFile(path.join(pasta, nome), buffer, { flag: 'wx' });
  return `/uploads/${nome}`;
}

const eventosCompartilhados = new Map();
function chaveCompartilhados(email) {
  if (!eventosCompartilhados.has(email)) eventosCompartilhados.set(email, new Set());
  return eventosCompartilhados.get(email);
}
function podeVerEvento(evento, usuario) {
  if (!evento || !usuario) return false;
  if (!evento.privado || podeGerenciarEvento(evento, usuario)) return true;
  return chaveCompartilhados(usuario.email).has(evento.id);
}
const tentativasLogin = new Map();
function horariosValidos(inicio, fim) {
  const formato = /^([01]\d|2[0-3]):[0-5]\d$/;
  return formato.test(inicio || '') && formato.test(fim || '') && fim > inicio;
}

// Middlewares de Proteção de Acesso
function verificarAutenticacao(req, res, next) {
  if (!req.session.usuario) return res.redirect('/eventos/cadastro');
  next();
}

function verificarAdmin(req, res, next) {
  if (!req.session.usuario || req.session.usuario.role !== 'admin') {
    return res.status(403).send('Acesso Negado: Apenas administradores podem acessar esta página.');
  }
  next();
}

// Banco de dados em memória para os Eventos do projeto
const eventos = [
  {
    id: 1,
    nome: 'Festival de Música',
    categoria: 'Música',
    data: '15/11/2026',
    local: 'Parque Central',
    descricao: 'Uma noite com música ao vivo, artistas locais e muita energia.',
    imagem: 'https://images.unsplash.com/photo-1459749411175-04bf5292ceea?auto=format&fit=crop&w=1400&q=85',
    destaque: true,
    privado: false,
    criador_email: null,
    comentarios: [],
    convite: crypto.randomBytes(18).toString('hex')
  },
  {
    id: 2,
    nome: 'Noite de Gala',
    categoria: 'Social',
    data: '22/11/2026',
    local: 'Espaço Imperial',
    descricao: 'Uma celebração elegante para reunir pessoas e criar boas memórias.',
   imagem: 'https://images.unsplash.com/photo-1511795409834-ef04bbd61622?auto=format&fit=crop&w=1400&q=85',
    destaque: true,
    privado: false,
    criador_email: null,
    comentarios: [],
    convite: crypto.randomBytes(18).toString('hex')
  },
  {
    id: 3,
    nome: 'Feira Criativa',
    categoria: 'Cultura',
    data: '29/11/2026',
    local: 'Centro Cultural',
    descricao: 'Artesanato, gastronomia e projetos criativos em um só lugar.',
     imagem: 'https://images.unsplash.com/photo-1492684223066-81342ee5ff30?auto=format&fit=crop&w=1400&q=85',
    destaque: true,
    privado: false,
    criador_email: null,
    comentarios: [],
    convite: crypto.randomBytes(18).toString('hex')
  }
];

let proximoEventoId = 4;
let proximoComentarioId = 1;

function buscarEvento(id) {
  return eventos.find(evento => evento.id === Number(id));
}

function buscarComentario(evento, id) {
  return evento.comentarios.find(comentario => comentario.id === Number(id));
}

// Verifica se o usuário logado é Admin ou o criador do evento
function podeGerenciarEvento(evento, usuario) {
  if (!evento || !usuario) return false;
  if (usuario.role === 'admin') return true;
  return Boolean(evento.criador_email && evento.criador_email === usuario.email);
}

// ROTA: Exibir Formulário de Cadastro de Usuário
router.get('/cadastro', (req, res) => {
  if (req.session.usuario) return res.redirect('/eventos');
  res.render('Usuarios/cadastro');
});

// ROTA: Processar o Cadastro de Usuário Comum
router.post('/cadastro', async (req, res) => {
  const nome = (req.body.nome || '').trim();
  const email = (req.body.email || '').trim().toLowerCase();
  const senha = req.body.senha || '';
  if (nome.length < 2 || nome.length > 50 || !/^\S+@\S+\.\S+$/.test(email) || senha.length < 5 || senha.length > 128) {
    return res.status(400).send('Confira os dados. A senha precisa ter pelo menos 8 caracteres.');
  }
  try {
    const hash = await criarHash(senha);
    global.db.run("INSERT INTO usuarios (nome, email, senha, role) VALUES (?, ?, ?, 'comum')", [nome, email, hash], function(err) {
      if (err) return res.status(409).send('Não foi possível cadastrar. Esse e-mail pode já estar em uso.');
      req.session.regenerate((erroSessao) => {
        if (erroSessao) return res.status(500).send('Não foi possível iniciar sua sessão.');
        req.session.usuario = { id: this.lastID, nome, email, role: 'comum', foto: null };
        res.redirect('/eventos');
      });
    });
  } catch (erro) { res.status(500).send('Erro ao proteger a senha.'); }
});

// ROTA: Exibir Formulário de Login
router.get('/login', (req, res) => {
  res.render('Usuarios/login', { erro: null });
});

// ROTA: Autenticar Usuário no SQLite
router.post('/login', async (req, res) => {
  const email = (req.body.email || '').trim().toLowerCase();
  const senha = req.body.senha || '';
  const bloqueio = tentativasLogin.get(email);
  if (bloqueio && bloqueio.ate > Date.now()) return res.status(429).render('Usuarios/login', { erro: 'Muitas tentativas. Aguarde 5 minutos.' });
global.db.get('SELECT * FROM usuarios WHERE LOWER(TRIM(email)) = ?', [email], async (err, user) => {
    if (err || !user) { const t = tentativasLogin.get(email) || { total: 0 }; t.total++; if (t.total >= 5) { t.total = 0; t.ate = Date.now() + 5 * 60 * 1000; } tentativasLogin.set(email, t); return res.status(401).render('Usuarios/login', { erro: 'E-mail ou senha inválidos.' }); }
    try {
      const correta = await validarSenha(senha, user.senha);
      if (!correta) { const t = tentativasLogin.get(email) || { total: 0 }; t.total++; if (t.total >= 5) { t.total = 0; t.ate = Date.now() + 5 * 60 * 1000; } tentativasLogin.set(email, t); return res.status(401).render('Usuarios/login', { erro: 'E-mail ou senha inválidos.' }); }
      tentativasLogin.delete(email);
      if (!user.senha.startsWith('scrypt:')) {
        const hash = await criarHash(senha);
        global.db.run('UPDATE usuarios SET senha = ? WHERE id = ?', [hash, user.id]);
      }
      req.session.regenerate((erroSessao) => {
        if (erroSessao) return res.status(500).send('Não foi possível iniciar sua sessão.');
        req.session.usuario = { id: user.id, nome: user.nome, email: user.email, role: user.role, foto: user.foto || null };
        res.redirect('/eventos');
      });
    } catch (erro) { res.status(500).send('Erro ao autenticar.'); }
  });
});

// CONFIGURAÇÕES DA CONTA
router.get('/configuracoes', verificarAutenticacao, (req, res) => {
  global.db.get(
    'SELECT id, nome, email, role, foto FROM usuarios WHERE id = ?',
    [req.session.usuario.id],
    (err, conta) => {
      if (err || !conta) return res.status(500).send('Não foi possível carregar suas configurações.');
      res.render('Usuarios/configuracoes', {
        conta,
        mensagem: req.query.salvo ? 'Configurações salvas com sucesso!' : null,
        erro: req.query.erro === 'conta-protegida' ? 'A conta principal de administração não pode ser excluída.' : null
      });
    }
  );
});

router.post('/configuracoes', verificarAutenticacao, async (req, res) => {
  const nome = (req.body.nome || '').trim();
  let foto = null;
  try { foto = req.body.fotoUpload && req.body.fotoUpload.startsWith('data:image/') ? await salvarImagem(req.body.fotoUpload) : (req.body.removerFoto === 'on' ? null : (req.session.usuario.foto || null)); }
  catch (erro) { return res.status(400).send(erro.message); }

  if (nome.length < 2 || nome.length > 50) {
    return global.db.get(
      'SELECT id, nome, email, role, foto FROM usuarios WHERE id = ?',
      [req.session.usuario.id],
      (err, conta) => res.status(400).render('Usuarios/configuracoes', {
        conta, mensagem: null, erro: 'O nome precisa ter entre 2 e 50 caracteres.'
      })
    );
  }


  global.db.run(
    'UPDATE usuarios SET nome = ?, foto = ? WHERE id = ?',
    [nome, foto || null, req.session.usuario.id],
    function (err) {
      if (err) return res.status(500).send('Erro ao salvar as configurações.');
      req.session.usuario.nome = nome;
      req.session.usuario.foto = foto || null;
      res.redirect('/eventos/configuracoes?salvo=1');
    }
  );
});

// EXCLUIR A PRÓPRIA CONTA
router.post('/configuracoes/excluir', verificarAutenticacao, (req, res) => {
  const usuario = req.session.usuario;

  if (usuario.role === 'admin') {
    return res.redirect('/eventos/configuracoes?erro=conta-protegida');
  }

  eventos.forEach(evento => {
    evento.comentarios = evento.comentarios.filter(comentario => {
      if (comentario.autor_email === usuario.email) return false;
      comentario.respostas = (comentario.respostas || []).filter(resposta => resposta.autor_email !== usuario.email);
      return true;
    });
  });

  global.db.run('DELETE FROM usuarios WHERE id = ?', [usuario.id], function (err) {
    if (err) return res.status(500).send('Não foi possível excluir sua conta.');
    req.session.destroy(() => res.redirect('/eventos/cadastro?contaExcluida=1'));
  });
});

// ROTA: Destruir a sessão (Logout)
router.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/eventos/login');
});

// ROTA: Listar Usuários cadastrados (Exclusivo do Admin)
router.get('/admin/usuarios', verificarAutenticacao, verificarAdmin, (req, res) => {
  global.db.all("SELECT id, nome, email, role FROM usuarios", [], (err, rows) => {
    res.render('Usuarios/index', { listaUsuarios: rows });
  });
});

// --- ROTAS DO PROJETO PROTEGIDAS POR LOGIN ---

router.get('/', verificarAutenticacao, (req, res) => {
  const usuario = req.session.usuario;

  const eventosVisiveis = eventos.filter(evento => !evento.privado);
  const meusEventos = eventos.filter(evento => evento.criador_email === usuario.email || (usuario.role === 'admin' && evento.privado));
  const idsCompartilhados = chaveCompartilhados(usuario.email);
  const eventosSalvos = eventos.filter(evento => idsCompartilhados.has(evento.id));

  // Carrossel: NUNCA mostra eventos privados
  const destaques = eventos.filter(evento => !evento.privado && evento.destaque && evento.imagem);

  res.render('Eventos/index', { eventos: eventosVisiveis, meusEventos, eventosSalvos, destaques, paginaMeus: false });
});

router.get('/meus', verificarAutenticacao, (req, res) => {
  const usuario = req.session.usuario;
  const meusEventos = eventos.filter(evento => evento.criador_email === usuario.email);
  const eventosSalvos = eventos.filter(evento => chaveCompartilhados(usuario.email).has(evento.id));
  res.render('Eventos/index', { eventos: [], meusEventos, eventosSalvos, destaques: [], paginaMeus: true });
});

// Aceita convite privado e registra o evento na área "Meus eventos".
router.get('/convite/:token', verificarAutenticacao, (req, res) => {
  const evento = eventos.find(item => item.convite === req.params.token);
  if (!evento) return res.status(404).send('Link de convite inválido ou expirado.');
  chaveCompartilhados(req.session.usuario.email).add(evento.id);
  res.redirect('/eventos/' + evento.id);
});

router.post('/adicionar-link', verificarAutenticacao, (req, res) => {
  const link = (req.body.linkEvento || '').trim();
  let token = '';
  try { const u = new URL(link, 'http://p4e.local'); const partes = u.pathname.split('/').filter(Boolean); if (partes[0] === 'eventos' && partes[1] === 'convite') token = partes[2] || ''; } catch (_) {}
  const evento = eventos.find(item => item.convite === token);
  if (!evento) return res.redirect('/eventos?erro=' + encodeURIComponent('Esse link não é um convite P4E válido.'));
  chaveCompartilhados(req.session.usuario.email).add(evento.id);
  res.redirect('/eventos/meus');
});

router.get('/novo', verificarAutenticacao, (req, res) => {
  res.render('Eventos/form-cadastro', { titulo: 'Novo evento | P4E' });
});

router.post('/', verificarAutenticacao, async (req, res) => {
  const { nome, categoria, data, local, descricao, destaque, visibilidade, horario_inicio, horario_fim } = req.body;
  const isPrivado = visibilidade === 'privado';
  const isDestaque = !isPrivado && destaque === 'on';
 if (!horariosValidos(horario_inicio, horario_fim)) {
    return res.redirect('/eventos/novo?erro=' + encodeURIComponent('Informe horários válidos e o término deve ser depois do início.'));
}
  // Salva a imagem mesmo que o evento seja privado ou não esteja em destaque
  let imagem = '';
  try { imagem = req.body.imagemUpload && req.body.imagemUpload.startsWith('data:image/') ? await salvarImagem(req.body.imagemUpload) : ''; }
 catch (erro) {
    return res.redirect('/eventos/novo?erro=' + encodeURIComponent(erro.message));
}

  const novoEvento = {
    id: proximoEventoId++,
    nome,
    categoria,
    data,
    horario_inicio,
    horario_fim,
    local,
    descricao,
    imagem,
    destaque: isDestaque,
    privado: isPrivado,
    
    criador_email: req.session.usuario.email,
    comentarios: [],
    convite: crypto.randomBytes(18).toString('hex')
  };

  eventos.push(novoEvento);

  if (isPrivado) {
    return res.redirect('/eventos/' + novoEvento.id);
  }

  res.redirect('/eventos');
});

router.get('/:id', verificarAutenticacao, (req, res) => {
  const evento = buscarEvento(req.params.id);
  if (!evento) return res.status(404).send('Evento não encontrado.');
  if (!podeVerEvento(evento, req.session.usuario)) return res.status(403).send('Este evento é privado. Use o link de convite para adicioná-lo à sua lista.');

  const podeEditarExcluir = podeGerenciarEvento(evento, req.session.usuario);

  res.render('Eventos/detalhes', { evento, podeEditarExcluir });
});

// 🛠️ ROTAS DE EDIÇÃO E EXCLUSÃO DO EVENTO INTEIRO
router.get('/:id/editar', verificarAutenticacao, (req, res) => {
  const evento = buscarEvento(req.params.id);
  if (!evento) return res.status(404).send('Evento não encontrado.');

  if (!podeGerenciarEvento(evento, req.session.usuario)) {
    return res.redirect('/eventos/' + evento.id + '?erro=Acesso Proibido: Apenas o criador do evento ou o Admin podem editar!');
  }

  res.render('Eventos/editar-evento', { evento });
});

router.post('/:id/editar', verificarAutenticacao, async (req, res) => {
  const evento = buscarEvento(req.params.id);
  if (!evento) return res.status(404).send('Evento não encontrado.');

  if (!podeGerenciarEvento(evento, req.session.usuario)) {
    return res.redirect('/eventos/' + evento.id + '?erro=Acesso Proibido: Apenas o criador do evento ou o Admin podem editar!');
  }

  const { nome, categoria, data, local, descricao, destaque, visibilidade, horario_inicio, horario_fim } = req.body;
  const isPrivado = visibilidade === 'privado';
  const isDestaque = !isPrivado && destaque === 'on';
 if (!horariosValidos(horario_inicio, horario_fim)) {
    return res.redirect('/eventos/' + evento.id + '/editar?erro=' + encodeURIComponent('Informe horários válidos e o término deve ser depois do início.'));
}
  // Mantém/atualiza a imagem mesmo se o evento for privado
  let imagem = evento.imagem || '';
  try { if (req.body.imagemUpload && req.body.imagemUpload.startsWith('data:image/')) imagem = await salvarImagem(req.body.imagemUpload); }
 catch (erro) {
    return res.redirect('/eventos/' + evento.id + '/editar?erro=' + encodeURIComponent(erro.message));
}

  Object.assign(evento, {
    nome: nome.trim(),
    categoria,
    data: data.trim(),
    horario_inicio,
    horario_fim,
    local: local.trim(),
descricao: descricao.trim(),
privado: isPrivado,
destaque: isDestaque,
imagem
});
res.redirect('/eventos/' + evento.id);
});
// ROTA: Excluir um evento completo
router.post('/:id/excluir', verificarAutenticacao, (req, res) => {
const evento = buscarEvento(req.params.id);
if (!evento) return res.status(404).send('Evento não encontrado.');
if (!podeGerenciarEvento(evento, req.session.usuario)) {
return res.redirect('/eventos/' + evento.id + '?erro=Acesso Proibido: Apenas o criador do evento ou o Admin podem excluir!');
}
const indice = eventos.findIndex(item => item.id === evento.id);
eventos.splice(indice, 1);
res.redirect('/eventos');
});
// --- SEÇÃO DE COMENTÁRIOS ---
router.post('/:id/comentarios', verificarAutenticacao, (req, res) => {
const evento = buscarEvento(req.params.id);
if (!evento) return res.status(404).send('Evento não encontrado.');
const autorDigitado = (req.body.autor || '').trim();
const nomeAutor = autorDigitado || req.session.usuario.nome;
evento.comentarios.push({
id: proximoComentarioId++,
autor: nomeAutor,
autor_email: req.session.usuario.email,
autor_foto: req.session.usuario.foto || null,
texto: req.body.texto.trim(),
respostas: []
});
res.redirect('/eventos/' + evento.id + '#comentarios');
});
router.post('/:eventoId/comentarios/:comentarioId/editar', verificarAutenticacao, (req, res) => {
const evento = buscarEvento(req.params.eventoId);
if (!evento) return res.status(404).send('Evento não encontrado.');
const comentario = buscarComentario(evento, req.params.comentarioId);
if (!comentario) return res.status(404).send('Comentário não encontrado.');
if (comentario.autor_email !== req.session.usuario.email && req.session.usuario.role !== 'admin') {
return res.redirect('/eventos/' + evento.id + '?erro=Acesso Proibido: Apenas o autor ou o Admin podem editar este comentario!');
}
comentario.texto = req.body.texto.trim();
res.redirect('/eventos/' + evento.id + '#comentario-' + comentario.id);
});
router.post('/:eventoId/comentarios/:comentarioId/excluir', verificarAutenticacao, (req, res) => {
const evento = buscarEvento(req.params.eventoId);
if (!evento) return res.status(404).send('Evento não encontrado.');
const comentario = buscarComentario(evento, req.params.comentarioId);
if (!comentario) return res.status(404).send('Comentário não encontrado.');
if (comentario.autor_email !== req.session.usuario.email && req.session.usuario.role !== 'admin') {
return res.redirect('/eventos/' + evento.id + '?erro=Acesso Proibido: Voce nao tem permissao para excluir este comentario!');
}
evento.comentarios = evento.comentarios.filter(item => item.id !== comentario.id);
res.redirect('/eventos/' + evento.id + '#comentarios');
});
router.post('/:eventoId/comentarios/:comentarioId/respostas', verificarAutenticacao, (req, res) => {
const evento = buscarEvento(req.params.eventoId);
if (!evento) return res.status(404).send('Evento não encontrado.');
const comentario = buscarComentario(evento, req.params.comentarioId);
if (!comentario) return res.status(404).send('Comentário não encontrado.');
const autorDigitado = (req.body.autor || '').trim();
const nomeAutor = autorDigitado || req.session.usuario.nome;
const texto = (req.body.texto || '').trim();
if (!texto) {
return res.redirect('/eventos/' + evento.id + '?erro=A resposta não pode ficar vazia!');
}
comentario.respostas.push({
id: proximoComentarioId++,
autor: nomeAutor,
autor_email: req.session.usuario.email,
autor_foto: req.session.usuario.foto || null,
texto: texto
});
res.redirect('/eventos/' + evento.id + '#comentario-' + comentario.id);
});


module.exports = router;
