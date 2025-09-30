import { UserRepository } from './user-repository.js'

async function makeAdmin(username) {
  try {
    // Buscar usuario por username
    const users = UserRepository.listAll()
    const user = users.find(u => u.username === username)
    if (!user) {
      console.error('Usuario no encontrado')
      return
    }

    // Actualizar rol a 'admin'
    await UserRepository.updateRole(user.id, 'admin')
    console.log(`El usuario "${username}" ahora es administrador`)
  } catch (err) {
    console.error('Error:', err.message)
  }
}

// Cambia aquí el nombre de usuario que quieras hacer admin
makeAdmin('admin')
