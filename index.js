import express from 'express'
import jwt from 'jsonwebtoken'
import cookieParser from 'cookie-parser'
import { PORT, SECRET_JWT_KEY } from './config.js'
import { UserRepository } from './user-repository.js'
import {
  csrfProtection,
  loginRateLimiter,
  authenticate,
  generateAccessToken,
  generateRefreshToken,
  verifyRefreshToken
} from './security.js'

const app = express()

app.set('view engine', 'ejs')

// Middlewares
app.use(express.json())
app.use(cookieParser())

// Middleware para verificar access token y guardar sesión
app.use((req, res, next) => {
  const token = req.cookies.access_token
  req.session = { user: null }

  try {
    if (token) {
      const data = jwt.verify(token, SECRET_JWT_KEY)
      req.session.user = data
    }
  } catch (err) {
    req.session.user = null
  }

  next()
})

// Ruta raíz
app.get('/', (req, res) => {
  const { user } = req.session
  res.render('index', { username: user ? user.username : null })
})

// Login
app.post('/login', loginRateLimiter, csrfProtection, async (req, res) => {
  const { username, password } = req.body
  try {
    const user = await UserRepository.login({ username, password })

    const accessToken = generateAccessToken({
      id: user._id,
      username: user.username
    })
    const refreshToken = generateRefreshToken({
      id: user._id,
      username: user.username
    })

    res
      .cookie('access_token', accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 1000 * 60 * 15 // 15 min
      })
      .cookie('refresh_token', refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 1000 * 60 * 60 * 24 * 7 // 7 días
      })
      .send({ user })
  } catch (error) {
    res.status(401).send(error.message)
  }
})

// Registro
app.post('/register', csrfProtection, async (req, res) => {
  const { username, password } = req.body

  try {
    const id = await UserRepository.create({ username, password })
    res.send({ id })
  } catch (error) {
    res.status(400).send(error.message)
  }
})

// Logout
app.post('/logout', (req, res) => {
  res.clearCookie('access_token')
  res.clearCookie('refresh_token')
  res.send({ message: 'Sesión cerrada' })
})

// Ruta protegida
app.get('/protected', authenticate, (req, res) => {
  const { user } = req.session
  res.render('protected', { user })
})

// Refresh token → renovar access token
app.post('/refresh', (req, res) => {
  const refreshToken = req.cookies.refresh_token
  if (!refreshToken) {
    return res.status(401).send('No hay refresh token')
  }

  try {
    const userData = verifyRefreshToken(refreshToken)
    const newAccessToken = generateAccessToken({
      id: userData.id,
      username: userData.username
    })

    res.cookie('access_token', newAccessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 1000 * 60 * 15 // 15 minutos
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
