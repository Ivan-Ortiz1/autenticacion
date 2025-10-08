import express from 'express'
import jwt from 'jsonwebtoken'
import cookieParser from 'cookie-parser'
import session from 'express-session'
import SQLiteStore from 'connect-sqlite3'
import { PORT, SECRET_JWT_KEY } from './config.js'
import { UserRepository } from './user-repository.js'
import adminRoutes from './routes/admin.js'
import {
  csrfProtection,
  loginRateLimiter,
  authenticate,
  authorize,
  generateAccessToken,
  generateRefreshToken,
  verifyRefreshToken
} from './security.js'

const app = express()
app.set('view engine', 'ejs')

// Middlewares
app.use(express.json())
app.use(cookieParser())

// Sesiones persistentes con SQLite (modo cookie)
app.use(session({
  store: new (SQLiteStore(session))({ db: 'sessions.db', dir: './db' }),
  secret: SECRET_JWT_KEY,
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 1000 * 60 * 60 * 24, // 1 día
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  }
}))

// Rutas de admin
app.use('/admin', adminRoutes)

// Ruta raíz
app.get('/', csrfProtection, (req, res) => {
  const user = req.session.user || null
  const username = user ? user.username : null
  const role = user ? user.role : null

  res.render('index', { username, role, csrfToken: req.csrfToken() })
})

/**
 * LOGIN CON SESIONES (persistentes con cookies)
 * - Guarda usuario en req.session
 * - Devuelve cookies de sesión + tokens para renovar acceso
 */
app.post('/login-cookie', loginRateLimiter, csrfProtection, async (req, res) => {
  const { email, password } = req.body
  try {
    const user = await UserRepository.login({ email, password })

    // Guardamos al usuario en la sesión
    req.session.user = { id: user.id, username: user.username, email: user.email, role: user.role }

    const accessToken = generateAccessToken(req.session.user)
    const refreshToken = generateRefreshToken(req.session.user)

    res
      .cookie('access_token', accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 1000 * 60 * 15
      })
      .cookie('refresh_token', refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 1000 * 60 * 60 * 24 * 7
      })
      .send({ user, mode: 'cookie-session' })
  } catch (err) {
    res.status(401).send(err.message)
  }
})

/**
 * LOGIN CON JWT PURO (stateless)
 * - No usa sesiones ni cookies
 * - Devuelve tokens en JSON
 */
app.post('/login-jwt', loginRateLimiter, async (req, res) => {
  const { email, password } = req.body
  try {
    const user = await UserRepository.login({ email, password })

    const accessToken = generateAccessToken({ id: user.id, username: user.username, email: user.email, role: user.role })
    const refreshToken = generateRefreshToken({ id: user.id, username: user.username, email: user.email, role: user.role })

    res.send({
      user,
      mode: 'jwt-stateless',
      accessToken,
      refreshToken
    })
  } catch (err) {
    res.status(401).send(err.message)
  }
})

// Registro
app.post('/register', csrfProtection, async (req, res) => {
  const { username, email, password } = req.body
  try {
    const id = await UserRepository.create({ username, email, password })
    res.send({ id })
  } catch (err) {
    res.status(400).send(err.message)
  }
})

// Logout (solo aplica a sesiones persistentes)
app.post('/logout', csrfProtection, (req, res) => {
  req.session.destroy(err => {
    if (err) {
      console.error(err)
      return res.status(500).send('Error al cerrar sesión')
    }
    res.clearCookie('access_token')
    res.clearCookie('refresh_token')
    res.send({ message: 'Sesión cerrada (modo cookie)' })
  })
})

// Ruta protegida con sesiones persistentes
app.get('/protected-cookie', authenticate, csrfProtection, authorize(['admin']), (req, res) => {
  const user = req.session.user
  if (!user) return res.redirect('/')
  res.render('protected', { user, csrfToken: req.csrfToken() })
})

// Ruta protegida con JWT puro (stateless)
// Aquí no hay sesión, solo Authorization: Bearer <token>
app.get('/protected-jwt', (req, res) => {
  const authHeader = req.headers['authorization']
  const token = authHeader && authHeader.split(' ')[1]

  if (!token) return res.status(401).send('Token requerido')

  try {
    const user = jwt.verify(token, SECRET_JWT_KEY)
    res.send({ message: 'Acceso concedido (modo JWT)', user })
  } catch (err) {
    res.status(403).send('Token inválido o expirado')
  }
})

// Refresh token (modo cookie)
app.post('/refresh', csrfProtection, (req, res) => {
  const refreshToken = req.cookies.refresh_token
  if (!refreshToken) return res.status(401).send('No hay refresh token')

  try {
    const userData = verifyRefreshToken(refreshToken)
    const newAccessToken = generateAccessToken(userData)

    res.cookie('access_token', newAccessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 1000 * 60 * 15
    })

    res.send({ message: 'Token renovado' })
  } catch (err) {
    res.status(403).send('Refresh token inválido o expirado')
  }
})

// Refresh token (modo JWT stateless)
app.post('/refresh-jwt', (req, res) => {
  const { refreshToken } = req.body
  if (!refreshToken) return res.status(401).send('No hay refresh token')

  try {
    const userData = verifyRefreshToken(refreshToken)
    const newAccessToken = generateAccessToken(userData)

    res.send({ message: 'Token renovado (JWT)', accessToken: newAccessToken })
  } catch (err) {
    res.status(403).send('Refresh token inválido o expirado')
  }
})

// Servidor
app.listen(PORT, () => {
  console.log(`Servidor corriendo en: http://localhost:${PORT}`)
})
