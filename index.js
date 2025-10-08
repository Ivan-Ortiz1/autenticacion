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
  verifyRefreshToken,
  verifyAccessToken // <-- nuevo
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

// Endpoint para que el cliente (tras login JWT) pida al servidor poner el token en cookie
app.post('/set-jwt-cookie', express.json(), (req, res) => {
  const { accessToken, refreshToken } = req.body
  if (!accessToken) return res.status(400).send('accessToken requerido')

  try {
    const userData = verifyAccessToken(accessToken) // valida el token antes de setear
    // Setear cookies httpOnly (servidor)
    res.cookie('access_token', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 1000 * 60 * 15
    })
    if (refreshToken) {
      res.cookie('refresh_token', refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 1000 * 60 * 60 * 24 * 7
      })
    }

    // Opcional: inicializar session.user para que las plantillas se rendericen con usuario
    if (!req.session) req.session = {}
    req.session.user = { id: userData.id, username: userData.username, email: userData.email, role: userData.role }

    return res.send({ message: 'Cookies seteadas' })
  } catch (err) {
    return res.status(403).send('Token inválido')
  }
})

// Ruta raíz: primero ejecutar authenticate para poblar req.session.user si hay cookie JWT
app.get('/', authenticate, csrfProtection, (req, res) => {
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

// Ruta unificada /protected — funciona tanto si el usuario viene por sesión (cookie) o por JWT convertido a cookie
app.get('/protected', authenticate, csrfProtection, authorize(['admin']), (req, res) => {
  const user = req.session.user
  if (!user) return res.redirect('/') // no autenticado -> volver al inicio

  res.render('protected', { user, csrfToken: req.csrfToken() })
})

// Servidor
app.listen(PORT, () => {
  console.log(`Servidor corriendo en: http://localhost:${PORT}`)
})
