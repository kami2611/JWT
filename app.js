const secretKey = "mySuperSecretKey";
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('./models/user');
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser');
const app = express();
app.use(cookieParser());
app.use(express.urlencoded({extended:true}));
app.set('view engine', 'ejs');
mongoose.connect('mongodb://127.0.0.1:27017/JWT-auth').then(() => {
    console.log("Mongoose Server Started!");
}).catch((err) => {
    console.log("Err mongoose!");
});
app.use(cookieJwtAuth);
app.use((req, res, next)=>{
    if(req.user){
        res.locals.currentUser = req.user;
        console.log('user exists in this local middleware and being set');
        console.log(res.locals.currentUser);
    }
    next();
});
app.post('/logout', (req, res)=>{
    res.clearCookie('token');
    res.redirect('/login');
});
app.get('/home', (req, res)=>{
    res.render('home');
});
app.get('/dummy', (req, res)=>{
    res.send("dummy");
})

app.get('/register', (req,res)=>{
    res.render('register');
});

app.post('/register', async(req, res)=>{
    try {
        const {username, password} = req.body;
        console.log(username);
        console.log(password);
        const hasedPassword = await bcrypt.hash(password, 12);
        const newUser = new User({username: username, password: hasedPassword});
        await newUser.save();
        const token = jwt.sign({userId: newUser._id, userName: newUser.username}, secretKey, {expiresIn: '1h'});
        res.cookie("token", token, {
            httpOnly: true
        });
    } catch (error) {
        console.log(error); 
    }
    return res.redirect('/home');
});
app.get('/login',(req, res)=>{
    res.render('login');
})

app.post('/login', async(req, res)=>{
    const {username, password} = req.body;
    const findUser = await User.findOne({username: username});
    if(findUser)
    {
        if( await bcrypt.compare(password, findUser.password))
        {
            const token = jwt.sign({userID: findUser._id, userName: findUser.username}, secretKey, {expiresIn: '1h'});
            res.cookie("token", token, {
                httpOnly:true
            });
            return res.redirect('/home'); 
        }
    }
    else{
        console.log('not authenticated');
        return res.redirect('/login');
    }
});
app.get('/add',authMiddleWare, (req, res)=>{
    // console.log(req.user);
    res.send('only logged in users can do this');
});
app.get('/topSecret',authMiddleWare, (req, res)=>{
    res.send('shh, i am an intern on nevera solutions');
});

app.listen(3000, ()=>{
    console.log('ON PORT 3000');
});


function authMiddleWare(req, res, next)
{
    if(!req.user)
    {
        return res.redirect('/login');
    }
    next();
}

function cookieJwtAuth(req, res, next)
{
    const token = req.cookies.token;
    if(!token)
    {
        req.user = null;
        return next();
    }
    try {
        
        const user = jwt.verify(token, secretKey);
        req.user = user;
        next();
    } catch (error) {
        console.log('you must be signed in to access this');
        req.user = null;
        console.log(error);
        return res.redirect('/login');
    }
};