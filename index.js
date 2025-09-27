import express from 'express'
import { PORT } from './config.js'
import { UserRepository } from './user-repository.js'

const app = express()

// Middleware para parsear JSON
app.use(express.json())

app.get('/', (req, res) => {
  res.send('Hola mundo')
})

app.post('/login', async (req, res) => {
  const { username, password } = req.body
  try {
    const user = await UserRepository.login({ username, password })
    res.send({ user })
  } catch (error) {
    res.status(401).send(error.message)
  }
})

app.post('/register', async (req, res) => {
  const { username, password } = req.body

  try {
    const id = await UserRepository.create({ username, password })
    res.send({ id })
  } catch (error) {
    res.status(400).send(error.message)
  }
})

app.post('/logout', (req, res) => {
  // Aquí iría tu lógica de logout
})

app.get('/protected', (req, res) => {
  // Aquí iría tu lógica para rutas protegidas
})

app.listen(PORT, () => {
  console.log(`Servidor corriendo en el puerto ${PORT}`)
})
