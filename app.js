const secretKey = "mySuperSecretKey";
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('./models/user');
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser');
const app = express();
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.set('view engine', 'ejs');
mongoose.connect('mongodb://127.0.0.1:27017/JWT-auth').then(() => {
    console.log("Mongoose Server Started!");
}).catch((err) => {
    console.log("Err mongoose!");
});
app.use(cookieJwtAuth);
app.use((req, res, next) => {
    if (req.user) {
        res.locals.currentUser = req.user;
        console.log('user exists in this local middleware and being set');
        console.log(res.locals.currentUser);
    }
    next();
});
app.post('/logout', (req, res) => {
    res.clearCookie('token');
    res.clearCookie('refreshToken');  // Clear refresh token too
    res.redirect('/login');
});

app.get('/home', (req, res) => {
    res.render('home');
});


app.get('/register', (req, res) => {
    res.render('register');
});

app.post('/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        console.log(username);
        console.log(password);
        const hasedPassword = await bcrypt.hash(password, 12);
        const newUser = new User({ username: username, password: hasedPassword });
        await newUser.save();
        const token = jwt.sign({ userId: newUser._id, userName: newUser.username }, secretKey, { expiresIn: '30s' });
        const refreshToken = jwt.sign({ userId: newUser._id, userName: newUser.username }, secretKey, { expiresIn: '7d' });
        res.cookie("token", token, {
            httpOnly: true
        });
        res.cookie("refreshToken", refreshToken, { httpOnly: true });
    } catch (error) {
        console.log(error);
    }
    return res.redirect('/home');
});
app.get('/login', (req, res) => {
    res.render('login');
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const findUser = await User.findOne({ username: username });
    if (findUser) {
        if (await bcrypt.compare(password, findUser.password)) {
            const token = jwt.sign({ userId: newUser._id, userName: newUser.username }, secretKey, { expiresIn: '30s' });
            const refreshToken = jwt.sign({ userId: newUser._id, userName: newUser.username }, secretKey, { expiresIn: '7d' });
            res.cookie("token", token, {
                httpOnly: true
            });
            res.cookie("refreshToken", refreshToken, { httpOnly: true });
            return res.redirect('/home');
        }
    }
    else {
        console.log('not authenticated');
        return res.redirect('/login');
    }
});

// app.post('/refresh-token', (req, res) => {
//     const refreshToken = req.cookies.refreshToken;
//     if (!refreshToken) {
//         return res.status(401).send("No refresh token found");
//     }

//     try {
//         const user = jwt.verify(refreshToken, secretKey);
//         const newAccessToken = jwt.sign({ userID: user.userID }, secretKey, { expiresIn: '30s' });

//         res.cookie("token", newAccessToken, { httpOnly: true });
//         res.json({ accessToken: newAccessToken });
//     } catch (error) {
//         return res.status(403).send("Invalid refresh token");
//     }
// });

app.get('/add', authMiddleWare, (req, res) => {
    res.send('only logged in users can do this');
});
app.get('/topSecret', authMiddleWare, (req, res) => {
    res.send('shh, i am an intern on nevera solutions');
});

app.listen(3000, () => {
    console.log('ON PORT 3000');
});


function authMiddleWare(req, res, next) {
    if (!req.user) {
        return res.redirect('/login');
    }
    next();
}

function cookieJwtAuth(req, res, next) {
    const token = req.cookies.token;
    if (!token) {
        req.user = null;
        return next();
    }

    try {
        const user = jwt.verify(token, secretKey);
        req.user = user;
        return next();
    } catch (error) {
        if (error.name === "TokenExpiredError") {
            console.log("Access token expired, trying to refresh...");

            const refreshToken = req.cookies.refreshToken;
            if (!refreshToken) {
                return res.redirect('/login');
            }

            try {
                const user = jwt.verify(refreshToken, secretKey);
                const newAccessToken = jwt.sign({ userID: user.userID }, secretKey, { expiresIn: '30s' });

                res.cookie("token", newAccessToken, { httpOnly: true });
                req.user = jwt.verify(newAccessToken, secretKey); // Set the new user object
                return next();
            } catch (refreshError) {
                console.log("Refresh token invalid:", refreshError.message);
                return res.redirect('/login');
            }
        }
        console.log('JWT verification error:', error.message);
        req.user = null;
        return res.redirect('/login');
    }
}
