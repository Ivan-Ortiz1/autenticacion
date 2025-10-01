// db.js
import Database from 'better-sqlite3'

// Crea la base si no existe
const db = new Database('users.sqlite')

// Crear tabla si no existe
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user'
  )
`)

export default db
