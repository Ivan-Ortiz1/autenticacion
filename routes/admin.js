import express from 'express'
import { UserRepository } from '../user-repository.js'
import { authenticate, authorize } from '../security.js'

const router = express.Router()

// Middleware: solo admins
router.use(authenticate)
router.use(authorize(['admin']))

// Listar usuarios
router.get('/users', async (req, res) => {
  const users = UserRepository.listAll()
  res.render('admin-users', { users })
})

// Cambiar rol
router.post('/users/:id/role', async (req, res) => {
  const { id } = req.params
  const { role } = req.body
  try {
    await UserRepository.updateRole(id, role)
    res.send({ message: 'Rol actualizado' })
  } catch (err) {
    res.status(400).send(err.message)
  }
})

// Eliminar usuario
router.delete('/users/:id', async (req, res) => {
  const { id } = req.params
  try {
    await UserRepository.delete(id)
    res.send({ message: 'Usuario eliminado' })
  } catch (err) {
    res.status(400).send(err.message)
  }
})

export default router
