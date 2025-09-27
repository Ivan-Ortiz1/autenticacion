import DBLocal from 'db-local'
import crypto from 'node:crypto'
import bcrypt from 'bcrypt'

import { SALT_ROUNDS } from './config.js'

const { Schema } = new DBLocal({ path: './db' })

const User = Schema('User', {
  _id: { type: String, required: true },
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true }
})

export class UserRepository {
  static async create({ username, password }) {
    Validation.username(username)
    Validation.password(password)

    const user = User.findOne({ username })
    if (user) throw new Error('Usuario ya existente')

    const id = crypto.randomUUID()
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS)

    User.create({
      _id: id,
      username,
      password: hashedPassword
    }).save()

    return id
  }

  static async login({ username, password }) {
    Validation.username(username)
    Validation.password(password)

    const user = User.findOne({ username })
    if (!user) throw new Error('El usuario no existe')

    const isValid = await bcrypt.compare(password, user.password)
    if (!isValid) throw new Error('Contraseña inválida')

    return user
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
