const jwt = require('jsonwebtoken');
const { Users } = require('./database');

const SECRET = process.env.JWT_SECRET || 's1studios_secret_2025_change_in_production';
const EXPIRES = '7d';

function signToken(userId) {
  return jwt.sign({ userId }, SECRET, { expiresIn: EXPIRES });
}

function verifyToken(token) {
  try { return jwt.verify(token, SECRET); }
  catch { return null; }
}

// Middleware — requer login
function requireAuth(req, res, next) {
  const token = req.cookies?.token || req.headers?.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Não autenticado' });

  const payload = verifyToken(token);
  if (!payload) return res.status(401).json({ error: 'Token inválido' });

  const user = Users.findById(payload.userId);
  if (!user || !user.active) return res.status(401).json({ error: 'Usuário inativo' });

  req.user = user;
  next();
}

// Middleware — requer admin
function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Acesso negado' });
    next();
  });
}

module.exports = { signToken, verifyToken, requireAuth, requireAdmin };
