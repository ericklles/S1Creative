const jwt    = require('jsonwebtoken');
const { Users } = require('./database');

const SECRET  = process.env.JWT_SECRET || 's1studios_jwt_secret_mude_em_producao';
const EXPIRES = '7d';

function signToken(userId) {
  return jwt.sign({ userId }, SECRET, { expiresIn: EXPIRES });
}

function verifyToken(token) {
  try { return jwt.verify(token, SECRET); }
  catch { return null; }
}

// FIX #8: requireAuth único, requireAdmin reutiliza sem chamar requireAuth novamente
function requireAuth(req, res, next) {
  const token = req.cookies?.token
    || (req.headers?.authorization || '').replace('Bearer ', '').trim()
    || null;

  if (!token) return res.status(401).json({ error: 'Não autenticado' });

  const payload = verifyToken(token);
  if (!payload) return res.status(401).json({ error: 'Token inválido ou expirado' });

  const user = Users.findById(payload.userId);
  if (!user)        return res.status(401).json({ error: 'Usuário não encontrado' });
  if (!user.active) return res.status(401).json({ error: 'Conta desativada' });

  req.user = user;
  next();
}

function requireAdmin(req, res, next) {
  // FIX #8: chama requireAuth inline sem duplicar lógica
  requireAuth(req, res, () => {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Acesso restrito a administradores' });
    }
    next();
  });
}

module.exports = { signToken, verifyToken, requireAuth, requireAdmin };
