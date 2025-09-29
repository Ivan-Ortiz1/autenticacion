import jwt from 'jsonwebtoken'
import rateLimit from 'express-rate-limit'
import csrf from 'csurf'
import { SECRET_JWT_KEY, REFRESH_SECRET, NODE_ENV } from './config.js'

export const loginRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 3,
  message: 'Demasiados intentos de login. Intenta más tarde.',
  standardHeaders: true,
  legacyHeaders: false
})

export const csrfProtection = csrf({
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
  req.session = { user: null }

  if (!token) return next()

  try {
    const data = verifyAccessToken(token)
    req.session.user = data
  } catch (err) {
    req.session.user = null
  }

  next()
}
