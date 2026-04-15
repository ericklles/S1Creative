const express      = require('express');
const cors         = require('cors');
const path         = require('path');
const fs           = require('fs');
const bcrypt       = require('bcryptjs');
const cookieParser = require('cookie-parser');
const { Users, Events } = require('./database');
const { signToken, requireAuth, requireAdmin } = require('./auth');

let YTDlpWrap;
try { YTDlpWrap = require('yt-dlp-wrap').default; } catch {}

const app  = express();
const PORT = process.env.PORT || 3000;
const DOWNLOAD_DIR = path.join(__dirname, 'downloads');
if (!fs.existsSync(DOWNLOAD_DIR)) fs.mkdirSync(DOWNLOAD_DIR, { recursive: true });

app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// ══════════════════════════════════════════════════
// AUTH
// ══════════════════════════════════════════════════
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Preencha todos os campos' });
  const user = Users.findByUsername(username.trim());
  if (!user || !user.active) return res.status(401).json({ error: 'Usuário ou senha incorretos' });
  if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: 'Usuário ou senha incorretos' });
  Users.updateLastLogin(user.id);
  Events.log(user.id, 'login');
  const token = signToken(user.id);
  res.cookie('token', token, { httpOnly: true, maxAge: 7*86400*1000, sameSite: 'lax' });
  res.json({ ok: true, role: user.role, username: user.username });
});

app.post('/api/auth/logout', requireAuth, (req, res) => {
  res.clearCookie('token');
  res.json({ ok: true });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  res.json({ id: req.user.id, username: req.user.username, role: req.user.role });
});

app.post('/api/auth/change-password', requireAuth, (req, res) => {
  const { current, newPass } = req.body;
  if (!current || !newPass) return res.status(400).json({ error: 'Campos obrigatórios' });
  if (!bcrypt.compareSync(current, req.user.password)) return res.status(401).json({ error: 'Senha atual incorreta' });
  Users.updatePassword(req.user.id, bcrypt.hashSync(newPass, 10));
  res.json({ ok: true });
});

// ══════════════════════════════════════════════════
// ADMIN
// ══════════════════════════════════════════════════
app.get('/api/admin/metrics', requireAdmin, (req, res) => {
  res.json({ summary: Events.summary(), daily: Events.daily(), recent: Events.recent(50) });
});

app.get('/api/admin/users', requireAdmin, (req, res) => res.json(Users.list()));

app.post('/api/admin/users', requireAdmin, (req, res) => {
  const { username, password, role = 'user' } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Campos obrigatórios' });
  if (Users.findByUsername(username)) return res.status(409).json({ error: 'Username já existe' });
  const result = Users.create(username, bcrypt.hashSync(password, 10), role);
  res.json({ ok: true, id: result.lastInsertRowid });
});

app.patch('/api/admin/users/:id', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  if (id === req.user.id) return res.status(400).json({ error: 'Não pode editar a si mesmo aqui' });
  const { active, password } = req.body;
  if (typeof active !== 'undefined') Users.setActive(id, active ? 1 : 0);
  if (password) Users.updatePassword(id, bcrypt.hashSync(password, 10));
  res.json({ ok: true });
});

app.delete('/api/admin/users/:id', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  if (id === req.user.id) return res.status(400).json({ error: 'Não pode deletar a si mesmo' });
  Users.delete(id);
  res.json({ ok: true });
});

app.get('/api/admin/user-events/:id', requireAdmin, (req, res) => {
  res.json(Events.byUser(Number(req.params.id)));
});

// ══════════════════════════════════════════════════
// TRACKING
// ══════════════════════════════════════════════════
app.post('/api/track', requireAuth, (req, res) => {
  const { type, meta } = req.body;
  const allowed = ['analysis','download','transcription','storyboard','api_call','protection'];
  if (!allowed.includes(type)) return res.status(400).json({ error: 'Tipo inválido' });
  Events.log(req.user.id, type, meta);
  res.json({ ok: true });
});

// ══════════════════════════════════════════════════
// YT-DLP
// ══════════════════════════════════════════════════
const QUALITY_FORMAT = {
  best:  'bestvideo[ext=mp4]+bestaudio[ext=m4a]/best[ext=mp4]/best',
  '1080':'bestvideo[height<=1080][ext=mp4]+bestaudio[ext=m4a]/best[height<=1080]/best',
  '720': 'bestvideo[height<=720][ext=mp4]+bestaudio[ext=m4a]/best[height<=720]/best',
  '480': 'bestvideo[height<=480][ext=mp4]+bestaudio[ext=m4a]/best[height<=480]/best',
};

function getYtDlpBin() {
  for (const c of ['/usr/local/bin/yt-dlp','/usr/bin/yt-dlp',path.join(__dirname,'yt-dlp')])
    if (fs.existsSync(c)) return c;
  return 'yt-dlp';
}

function fmtDur(s) {
  if (!s) return '—';
  const h=Math.floor(s/3600),m=Math.floor((s%3600)/60),sec=s%60;
  return h>0?`${h}:${String(m).padStart(2,'0')}:${String(sec).padStart(2,'0')}`:`${m}:${String(sec).padStart(2,'0')}`;
}

app.get('/api/info', requireAuth, async (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).json({ error: 'URL obrigatória' });
  if (!YTDlpWrap) return res.status(503).json({ error: 'yt-dlp não instalado' });
  try {
    const meta = await new YTDlpWrap(getYtDlpBin()).getVideoInfo(url);
    res.json({ title: meta.title||'Sem título', duration: fmtDur(meta.duration), thumbnail: meta.thumbnail||'', uploader: meta.uploader||'', platform: meta.extractor_key||'' });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/download-progress', requireAuth, (req, res) => {
  const { url, quality='best' } = req.query;
  if (!url) return res.status(400).end();

  res.setHeader('Content-Type','text/event-stream');
  res.setHeader('Cache-Control','no-cache');
  res.setHeader('Connection','keep-alive');
  const send = d => res.write(`data: ${JSON.stringify(d)}\n\n`);

  if (!YTDlpWrap) { send({ type:'error', message:'yt-dlp não instalado no servidor' }); return res.end(); }

  const filename = `video_${Date.now()}.mp4`;
  const outPath  = path.join(DOWNLOAD_DIR, filename);
  new YTDlpWrap(getYtDlpBin())
    .exec([url, '-f', QUALITY_FORMAT[quality]||QUALITY_FORMAT.best, '--merge-output-format','mp4', '-o', outPath, '--no-playlist','--newline'])
    .on('ytDlpEvent', (t,d) => { const m=d.match(/(\d+\.?\d*)%/); if(m) send({ type:'progress', percent:parseFloat(m[1]) }); })
    .on('error', e => { send({ type:'error', message:e.message }); res.end(); })
    .on('close', () => {
      Events.log(req.user.id, 'download', { url, quality });
      send({ type:'done' });
      setTimeout(() => { send({ type:'ready', url:`/api/file/${filename}` }); res.end(); }, 500);
    });
});

app.get('/api/file/:filename', requireAuth, (req, res) => {
  const fp = path.join(DOWNLOAD_DIR, req.params.filename);
  if (!fs.existsSync(fp)) return res.status(404).json({ error: 'Arquivo não encontrado' });
  res.download(fp, req.params.filename, () => fs.unlink(fp, ()=>{}));
});

// ══════════════════════════════════════════════════
// SPA routes
// ══════════════════════════════════════════════════
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// Limpeza de downloads antigos
setInterval(() => {
  fs.readdir(DOWNLOAD_DIR, (_,files) => {
    (files||[]).forEach(f => {
      const fp=path.join(DOWNLOAD_DIR,f);
      fs.stat(fp,(_,s)=>{ if(s&&Date.now()-s.mtimeMs>3600000) fs.unlink(fp,()=>{}); });
    });
  });
}, 600000);

app.listen(PORT, '0.0.0.0', () => console.log(`S1 Studios Tools :${PORT}`));
