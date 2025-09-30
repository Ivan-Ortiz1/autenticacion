import crypto from 'node:crypto'
import bcrypt from 'bcryptjs'
import db from './db.js'
import { SALT_ROUNDS } from './config.js'

export class UserRepository {
  static async create({ username, password, role = 'user' }) {
    Validation.username(username)
    Validation.password(password)

    const validRoles = ['user', 'admin']
    if (!validRoles.includes(role)) throw new Error('Rol inválido')

    // Verificar si ya existe el usuario
    const existing = db.prepare('SELECT * FROM users WHERE username = ?').get(username)
    if (existing) throw new Error('Usuario ya existente')

    const id = crypto.randomUUID()
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS)

    db.prepare(`
      INSERT INTO users (id, username, password, role)
      VALUES (?, ?, ?, ?)
    `).run(id, username, hashedPassword, role)

    return id
  }

  static async login({ username, password }) {
    Validation.username(username)
    Validation.password(password)

    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username)
    if (!user) throw new Error('El usuario no existe')

    const isValid = await bcrypt.compare(password, user.password)
    if (!isValid) throw new Error('Contraseña inválida')

    const { password: _, ...publicUser } = user
    return publicUser
  }

  static listAll() {
    return db.prepare('SELECT id, username, role FROM users').all()
  }

  static async updateRole(id, role) {
    const validRoles = ['user', 'admin']
    if (!validRoles.includes(role)) throw new Error('Rol inválido')

    const result = db.prepare('UPDATE users SET role = ? WHERE id = ?').run(role, id)
    if (result.changes === 0) throw new Error('Usuario no encontrado')
  }

  static async delete(id) {
    const result = db.prepare('DELETE FROM users WHERE id = ?').run(id)
    if (result.changes === 0) throw new Error('Usuario no encontrado')
  }
}

class Validation {
  static username(username) {
    if (typeof username !== 'string') throw new Error('El usuario debe ser un texto')
    if (username.length < 3) throw new Error('El nombre de usuario debe contener al menos 3 caracteres')
  }

  static password(password) {
    if (typeof password !== 'string') throw new Error('La contraseña debe ser un texto')
    if (password.length < 6) throw new Error('La contraseña debe contener al menos 6 caracteres')
  }
}
