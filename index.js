import express from 'express'
import jwt from 'jsonwebtoken'
import cookieParser from 'cookie-parser'
import { PORT, SECRET_JWT_KEY } from './config.js'
import { UserRepository } from './user-repository.js'

const app = express()

app.set('view engine', 'ejs')

// Middlewares
app.use(express.json())
app.use(cookieParser())

// Middleware para verificar token
app.use((req, res, next) => {
  const token = req.cookies.access_token
  req.session = { user: null }

  try {
    if (token) {
      const data = jwt.verify(token, SECRET_JWT_KEY)
      req.session.user = data
    }
  } catch (err) {
    // token inválido o expirado → sesión nula
    req.session.user = null
  }

  next()
})

// Ruta raíz
app.get('/', (req, res) => {
  const { user } = req.session
  res.render('index', { user })
})

// Login
app.post('/login', async (req, res) => {
  const { username, password } = req.body
  try {
    const user = await UserRepository.login({ username, password })

    const token = jwt.sign(
      { id: user._id, username: user.username },
      SECRET_JWT_KEY,
      { expiresIn: '1h' }
    )

    res
      .cookie('access_token', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 1000 * 60 * 60 // 1 hora
      })
      .send({ user, token })
  } catch (error) {
    res.status(401).send(error.message)
  }
})

// Registro
app.post('/register', async (req, res) => {
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
  res.clearCookie('access_token').send({ message: 'Sesión cerrada' })
})

// Ruta protegida
app.get('/protected', (req, res) => {
  const { user } = req.session
  if (!user) return res.status(403).send('Acceso no autorizado')

  res.render('protected', { user })
})

// Servidor
app.listen(PORT, () => {
  console.log(`Servidor corriendo en el puerto ${PORT}`)
})
