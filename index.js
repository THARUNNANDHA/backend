const express = require('express');
require('dotenv').config();
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { sequelize } = require('./config/config');
const User123 = require('./models/user');
const Googleuserdata = require('./models/Googleuserdata');
const Product = require('./models/Product');
const cookieParser = require('cookie-parser');
const { where, STRING } = require('sequelize');
const { OAuth2Client } = require('google-auth-library');
const sendmail = require('./mail')
const app = express();
const client = new OAuth2Client(process.env.GOOGLE_CLIENT)


const corsOptions = {
    // origin: process.env.CORS_ORIGIN,
    origin: "https://opentuf-jwt-node.vercel.app",
    credentials: true
}

app.use(cors(corsOptions));
app.use(bodyParser.json());
app.options('*', cors(corsOptions));
// app.use(cookieParser());

const PORT = 5000;
const ACCESS_SECRET_KEY = process.env.ACCESS_SECRET_KEY
const REFRESH_SECRET_KEY = process.env.REFRESH_SECRET_KEY

sequelize.sync()
    .then(() => {
        console.log("Database sync")
    })
    .catch(err => {
        console.error("not connected", err);
    })

app.post('/signup', async (req, res) => {
    const { username, password, email } = req.body;
    if (!username && !password && !email) {
        return res.status(400).json({ "error": "incomplete data" })
    }
    try {
        console.log(username, password, email, "\n\n\n\n\n")

        const already_exist_email = await User123.findOne({ where: { email } })
        if (already_exist_email) {
            return res.json({ "fail": "Email Already exist " })
        }

        const already_exist_username = await User123.findOne({ where: { username } })
        if (already_exist_username) {
            return res.json({ "fail": "Username Already exist " })
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = await User123.create({ username: username, password: hashedPassword, email: email })

        res.status(201).json({ "success": "Data saved successfully" })
    } catch (err) {
        console.error(err)
        res.status(500).json({ "error": err })
    }
})
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username && !password) {
        return res.status(400).json({ "error": "incomplete data" })
    }
    else {
        try {
            // const user_exists_username = await User123.findOne({ where: { username: username } })
            const user_exists_email = await User123.findOne({ where: { email: username } })
            // console.log(user_exists_email)
            if (user_exists_email) {
                password_check = await bcrypt.compare(password, user_exists_email.password)
                console.log("\n\n true " + password_check)
                if (!password_check) return res.status(400).json({ "fail": "wrong password" })

                const acess_token = jwt.sign({ userid: user_exists_email.id }, ACCESS_SECRET_KEY, { expiresIn: "10s" })
                const refresh_token = jwt.sign({ userid: user_exists_email.id }, REFRESH_SECRET_KEY, { expiresIn: "20s" })

                // res.cookie('refresh_token', refresh_token.toString(), { httpOnly: true, maxAge: 60 * 60 * 1000, secure: false });
                if (username === "admin@gmail.com") {
                    console.log(username)
                    return res.status(201).json({ "accessToken": acess_token, "refreshToken": refresh_token, "user": user_exists_email.username, 'admin': true })
                }
                res.status(201).json({ "accessToken": acess_token, "refreshToken": refresh_token, "user": user_exists_email.username })
            }
            else {
                return res.status(400).json({ "fail": "user not found" })
            }
        } catch (err) {
            console.error(err);
        }
    }
})

app.post("/refresh_access_token", async (req, res) => {
    const refreshToken = req.body.refreshToken
    // var refreshToken = null;
    // if (req.cookies.refresh_token) refreshToken = req.cookies.refresh_token;
    console.log("refresh token: " + refreshToken)
    if (refreshToken == null)
        return res.status(401).json({ "Not_found": "no referance token" });

    try {
        const decoded_data = jwt.verify(refreshToken, REFRESH_SECRET_KEY);
        console.log("hear", decoded_data.userid)
        const newAccessToken = jwt.sign({ "userid": decoded_data.userid }, ACCESS_SECRET_KEY, { expiresIn: '10s' })
        return res.status(200).json({ 'accessToken': newAccessToken })
    } catch (err) {
        console.error(err);
        // res.clearCookie('refresh_token', { httpOnly: true, secure: false });
        return res.status(401).json({ 'fail': "refresh token expired" })
    }
})


// app.post('/logout', (req, res) => {
//     res.clearCookie('refresh_token', { httpOnly: true, secure: false });
//     return res.status(200).json({ 'success': 'cookie cleared successfully' });
// })

app.get("/get_cookie", async (req, res) => {
    const refresh = req.cookies.refresh_token;
    console.log(refresh)
})

// app.post('/user_data', async (req, res) => {
//     const { accesstoken } = req.body;
//     console.log("access token", accesstoken);
//     var valid_token = await checkAccesstoken(accesstoken);
//     console.log(valid_token)
//     if (valid_token) {
//         console.log(valid_token)
//         const user = await User123.findAll()
//         return res.status(200).json(user)
//     }
//     else {
//         return res.status(401).json({ 'fail': "access token expired" })
//     }
// })

app.get('/user_data', async (req, res) => {
    const authHeader = req.headers['authorization'];
    console.log(authHeader)
    const accesstoken = authHeader.split(" ")[1]
    console.log(accesstoken)
    var valid_token = await checkAccesstoken(accesstoken);
    console.log(valid_token)
    if (valid_token) {
        console.log(valid_token)
        const user = await User123.findAll()
        return res.status(200).json(user)
    }
    else {
        return res.status(401).json({ 'fail': "access token expired" })
    }
})

const checkAccesstoken = async (accessToken) => {
    try {
        const decoded_data = jwt.verify(accessToken, ACCESS_SECRET_KEY)
        console.log(decoded_data)
        return true;
    } catch (err) {
        if (err.name === 'TokenExpiredError') {
            return false
        }
        else
            console.log(err)
    }
}

app.post("/googlelogin", async (req, res) => {
    try {
        const tokenID = req.body.respons;
        console.log("hear  \n\n", tokenID);
        const ticket = await client.verifyIdToken({
            idToken: tokenID,
            audience: '31706794484-59jdeslin0devcrcrvgjv88p1sb1uhjm.apps.googleusercontent.com',
        })
        const data = ticket.getPayload()
        console.log(data)
        user = await Googleuserdata.findOne({ where: { email: data.email } })
        if (user) {
            const acess_token = jwt.sign({ userid: user.id }, ACCESS_SECRET_KEY, { expiresIn: "10s" })
            const refresh_token = jwt.sign({ userid: user.id }, REFRESH_SECRET_KEY, { expiresIn: "20s" })
            return res.status(200).json({ "picture": data.picture, "name": data.name, "email": data.email, "accessToken": acess_token, "refreshToken": refresh_token })
        }
        else {
            newuser = await Googleuserdata.create({ email: data.email, name: data.name, picture: data.picture, sub: data.sub })
            result = await newuser.save();
            console.log("res", res);
            user_id = await Googleuserdata.findOne({ where: { email: data.email } })
            const acess_token = jwt.sign({ userid: user_id.id }, ACCESS_SECRET_KEY, { expiresIn: "10s" })
            const refresh_token = jwt.sign({ userid: user_id.id }, REFRESH_SECRET_KEY, { expiresIn: "20s" })
            return res.status(201).json({ "picture": data.picture, "name": data.name, "email": data.email, "accessToken": acess_token, "refreshToken": refresh_token })
        }
    } catch (err) {
        console.error(err)
        res.status(401).json({ "fail": "error login with google" })
    }
})

function generateRandom6DigitNumber() {
    return Math.floor(100000 + Math.random() * 900000);
}


app.post("/change_password_otp", async (req, res) => {
    const email = req.body.email;
    console.log(email)
    const user_exist = await User123.findOne({ where: { email: email } });
    if (user_exist) {
        const otp = generateRandom6DigitNumber();
        user_exist.update({ otp: otp });
        sendmail(user_exist.email, "Forgot password otp", "your otp " + otp);
        return res.status(200).json({ "Success": "data recived" })
    }
    res.status(401).json({ "fail": "error login with google" })
})
app.post("/check_otp", async (req, res) => {
    const otp = req.body.otp;
    const email = req.body.email;
    const user_exist = await User123.findOne({ where: { email: email } });
    console.log(user_exist.otp, otp)
    if (user_exist.otp === otp) {
        console.log("inside check\n\n\n\n")
        return res.status(200).json({ "Success": "verified otp" })
    }
    return res.status(401).json({ "fail": "Wrong Password" })
})

app.post("/change_password", async (req, res) => {
    const new_password = req.body.new_password
    const email = req.body.email;
    const user_exist = await User123.findOne({ where: { email: email } });
    const hashedPassword = await bcrypt.hash(new_password, 10);
    await user_exist.update({ password: hashedPassword });
    if (user_exist.password === hashedPassword) {
        return res.status(200).json({ "Success": "Password changed" })
    }
    return res.status(401).json({ "fail": "Wrong Password" })
})
app.post("/create_product_item", async (req, res) => {
    const data = req.body.formData;
    try {
        const newProduct = await Product.create({ image_src: data.image_src, description: data.description, price: data.price, title: data.title })
        newProduct.save();
    } catch (e) { return res.status(401).json({ "fail": "Wrong Password" }) }

    return res.status(200).json({ "result": "Data created successfully" })
})
// app.get("/product_data", async (req, res) => {
//     const productData = await Product.findAll({ logging: false });
// console.log(productData);
//     return res.status(200).json(productData)

// })
app.post("/update_product", async (req, res) => {
    const data = req.body.formData;
    try {
        console.log(data);
        const product = await Product.findOne({ where: { id: data.id } });
        await product.update({ description: data.description, price: data.price, title: data.title })
    } catch (e) {

        console.log(e);
        return res.status(401).json({ "un_success": "un_success" })
    }

    return res.status(200).json({ "success": "recived successfully in" })
})

app.post("/delete_product_items", async (req, res) => {
    const id = req.body.id;
    console.log("\n\n\n\n\n\n\n\ id", id);
    const product = await Product.findOne({ where: { id: id } });
    if (!product) {
        return res.status(401).json({ 'message': 'Item not found' })
    }
    await product.destroy();
    return res.status(200).json({ 'message': 'Item deleted successfully' })
})

app.get('/product_data', async (req, res) => {
    const authHeader = req.headers['authorization'];
    const accesstoken = authHeader.split(" ")[1]
    console.log(accesstoken)
    var valid_token = await checkAccesstoken(accesstoken);
    console.log(valid_token)
    if (valid_token) {
        console.log(valid_token)
        const productData = await Product.findAll({});
        return res.status(200).json(productData)
    }
    else {
        return res.status(401).json({ 'fail': "access token expired" })
    }
})

app.listen(PORT, () => {
    console.log("listening on port\n\n");
});
