import mongoose from 'mongoose'
import dotenv from 'dotenv'
dotenv.config()

mongoose.connect(process.env.MONGO_URI)
.then(()=>{
  console.log("databasee connection done");
})
.catch(()=>{
  console.log("mongoose connection faild"); 
})


