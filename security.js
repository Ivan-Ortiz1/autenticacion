import jwt from 'jsonwebtoken'
import rateLimit from 'express-rate-limit'
import csrf from 'csurf'
import { SECRET_JWT_KEY, REFRESH_SECRET, NODE_ENV } from './config.js'

export const loginRateLimiter = rateLimit({ //ver 
  windowMs: 15 * 60 * 1000, // 15 min
  max: 3,
  message: 'Demasiados intentos de login. Intenta más tarde.',
  standardHeaders: true, //manda los headers modernos (RateLimit-*).
  legacyHeaders: false //desactiva los headers viejos (X-RateLimit-*).
})
//token csrf
export const csrfProtection = csrf({ //ver
  cookie: {
    httpOnly: true,
    secure: NODE_ENV === 'production',
    sameSite: 'strict'
  }
})

export function generateAccessToken(payload) {
  return jwt.sign(payload, SECRET_JWT_KEY, { expiresIn: '15m' })
}

export function generateRefreshToken(payload) {
  return jwt.sign(payload, REFRESH_SECRET, { expiresIn: '7d' })
}

export function verifyAccessToken(token) {
  return jwt.verify(token, SECRET_JWT_KEY)
}

export function verifyRefreshToken(token) {
  return jwt.verify(token, REFRESH_SECRET)
}

export function authenticate(req, res, next) {
  const token = req.cookies.access_token

  if (!req.session) req.session = {} 

  if (!token) {
    req.session.user = null 
  }

  try {
    const data = verifyAccessToken(token)
    req.session.user = data
  } catch (err) {
    req.session.user = null // token inválido
  }

  next()
}

export function authorize(allowedRoles = []) { // Ver .map
  return (req, res, next) => {
    const user = req.session.user;
    if (!user || !allowedRoles.map(r => r.toLowerCase()).includes((user.role || '').toLowerCase())) {
      return res.render('acceso-denegado', { csrfToken: req.csrfToken() });
    }
    next();
  };
}
