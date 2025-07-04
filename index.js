import './database/index.js'
import express from 'express'
import helmet from 'helmet'
import cors from 'cors'
import cookieParser from 'cookie-parser'
import dotenv from 'dotenv'
import authRoutes from './routes/authRouter.js'

dotenv.config() 

const app = express()
app.use(express.json())
app.use(helmet())
app.use(cors())
app.use(cookieParser())
app.use(express.urlencoded({ extended: true }))

// Routes de base
const router = express.Router()

// Routes d'authentification
app.use('/', router)
app.use('/api/auth', authRoutes)

app.listen(process.env.PORT, (err) => {
  if (err) {
    console.error('Erreur lors du démarrage du serveur :', err);
  } else {
    console.log('Serveur en marche sur le port ' + process.env.PORT);
  }
});
