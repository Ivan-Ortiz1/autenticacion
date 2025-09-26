import express from 'express'
import { PORT } from './config.js'

const app = express()

app.get('/', (req, res) => {
    res.send('Hola mundo')
})

app.listen(PORT, () => {
    console.log(`Servidor corriendo en el puerto ${PORT}`)
})