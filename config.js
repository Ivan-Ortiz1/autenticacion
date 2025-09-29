export const {
  PORT = 3000,
  SALT_ROUNDS = 10,
  SECRET_JWT_KEY = 'clave-secreta',
  REFRESH_SECRET = 'refresh-clave-secreta',
  NODE_ENV = 'development'
} = process.env
