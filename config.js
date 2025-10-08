export const PORT = Number(process.env.PORT ?? 3000)
export const SALT_ROUNDS = Number(process.env.SALT_ROUNDS ?? 10)
export const SECRET_JWT_KEY = process.env.SECRET_JWT_KEY ?? 'clave-secreta'
export const REFRESH_SECRET = process.env.REFRESH_SECRET ?? 'refresh-clave-secreta'
export const NODE_ENV = process.env.NODE_ENV ?? 'development'
