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

// Sesiones persistentes con SQLite
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

// Middleware: sincroniza JWT con sesión persistente
app.use((req, res, next) => {
  const token = req.cookies.access_token
  if (!req.session.user && token) {
    try {
      const data = jwt.verify(token, SECRET_JWT_KEY)
      req.session.user = { ...data } // sincronizamos session con token
    } catch {
      req.session.user = null
    }
  }
  next()
})

// Rutas de admin
app.use('/admin', adminRoutes)

// Ruta raíz
app.get('/', csrfProtection, (req, res) => {
  const user = req.session.user || null
  const username = user ? user.username : null
  const role = user ? user.role : null

  // Enviamos username, role y csrfToken para que la vista pueda renderizar condicionalmente
  res.render('index', { username, role, csrfToken: req.csrfToken() })
})

// Login
app.post('/login', loginRateLimiter, csrfProtection, async (req, res) => {
  const { email, password } = req.body
  try {
    const user = await UserRepository.login({ email, password })

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
      .send({ user })
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

// Logout
// Agregado csrfProtection para que logout requiera token CSRF (el frontend ya lo envía)
app.post('/logout', csrfProtection, (req, res) => {
  req.session.destroy(err => {
    if (err) {
      console.error(err)
      return res.status(500).send('Error al cerrar sesión')
    }
    res.clearCookie('access_token')
    res.clearCookie('refresh_token')
    res.send({ message: 'Sesión cerrada' })
  })
})

// Ruta protegida
app.get('/protected', authenticate, csrfProtection, authorize(['admin']), (req, res) => {
  const user = req.session.user

  if (!user) return res.redirect('/')
  res.render('protected', { user, csrfToken: req.csrfToken() })
})

// Refresh token
// Agregado csrfProtection para que el refresh requiera token CSRF (frontend lo envía)
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

// Servidor
app.listen(PORT, () => {
  console.log(`Servidor corriendo en: http://localhost:${PORT}`)
})
