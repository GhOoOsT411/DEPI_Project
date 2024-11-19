const mongoose = require('mongoose')


const userSchema = new mongoose.Schema({
    name : String,
    email : {
        type : String,
        unique : true,
        required : true
    },
    password : String,
    profilePic : String,
    role : String,
    resetPasswordToken: { type: String }, // Field to store the reset token
    resetPasswordTokenExpiration: { type: Date }, // Optional: Field for token expiration
},{ 
    timestamps : true
})


const userModel =  mongoose.model("user",userSchema)


module.exports = userModel
