const {Schema , model} = require('mongoose')
const { randomBytes, createHmac } = require('crypto');
const { createTokenForUser } = require('../services/authentication');

const userSchema = new Schema({
    fullName: {
        type: String, 
        required: true,
    },
    email: {
        type: String, 
        required: true,
        unique: true,
    },
    salt: {
        type: String,
    },
    password: {
        type: String, 
        required: true,
    },
    profileImageURL: {
        type: String, 
        default: "/images/default.png",
    },
    role: {
        type: String, 
        enum: ["USER" , "ADMIN"],
        default: "USER",
    }
}, {timestamps: true}
);


userSchema.pre("save", function(next){
    const user = this; 

    if(!user.isModified("password")) return res.end("Password is not modified");
 
    const salt = randomBytes(16).toString();
    const hahsedPassword = createHmac("sha256", salt)
        .update(user.password)
        .digest("hex");
    this.salt = salt;  
    this.password = hahsedPassword;
    next(); 
});

userSchema.static("matchPasswordAndGenerateToken" ,async function(email, password){
    const user =await this.findOne({email});
    if(!user) throw new Error("User not found");

    const salt = user.salt;
    const hahsedPassword = user.password;

    const userProvidedHashedPassword = createHmac("sha256", salt)
        .update(password)
        .digest("hex");
    
    if(hahsedPassword !==userProvidedHashedPassword) throw new Error("Incorrect Password"); 

    const token = createTokenForUser(user);
    return token;
});




const User = model('User', userSchema);


module.exports = User;

