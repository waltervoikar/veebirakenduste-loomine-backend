const express = require('express');
const pool = require('./database');
const cors = require('cors');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');

const port = process.env.PORT || 3000;

const app = express();


//functionthat checks if user is authenticated. If not then sends response else 
function auth(req, res, next){
    console.log('authentication request has been arrived');
    const token = req.cookies.jwt
    try {
        if (token) {
            jwt.verify(token, secret, (err) => {
                if (err) {
                    console.log(err.message);
                    console.log('token is not verified');
                    res.send({ "authenticated": false });
                } else {
                    next();
                }
            })
        } else {
            console.log('author is not authinticated');
            res.send({ "authenticated": false });
        }
    } catch (err) {
        console.error(err.message);
        res.status(400).send(err.message);
    }
}

app.use(cors({ origin: 'http://localhost:8080', credentials: true }));
app.use(express.json()); // Parses incoming requests with JSON payloads and is based on body-parser.
app.use(cookieParser()); // Parse Cookie header and populate req.cookies with an object keyed by the cookie names.

const secret = "3DBon22SMgkRTjnhh1f07pdTsrK3UkR9";
const maxAge = 60 * 60; //unlike cookies, the expiresIn in jwt token is calculated by seconds not milliseconds

const generateJWT = (id) => {
    return jwt.sign({ id }, secret, { expiresIn: maxAge })
}

app.listen(port, () => {
    console.log("Server is listening to port " + port)
});


// is used to check whether a user is authinticated
app.get('/auth/authenticate', async(req, res) => {
    console.log('authentication request has been arrived');
    const token = req.cookies.jwt;
    let authenticated = false; // a user is not authenticated until proven the opposite
    try {
        if (token) { //checks if the token exists
            await jwt.verify(token, secret, (err) => { //token exists, now we try to verify it
                if (err) { // not verified, redirect to login page
                    console.log(err.message);
                    console.log('token is not verified');
                    res.send({ "authenticated": authenticated }); // authenticated = false
                } else { // token exists and it is verified 
                    console.log('author is authinticated');
                    authenticated = true;
                    res.send({ "authenticated": authenticated }); // authenticated = true
                }
            })
        } else { //applies when the token does not exist
            console.log('author is not authinticated');
            res.send({ "authenticated": authenticated }); // authenticated = false
        }
    } catch (err) {
        console.error(err.message);
        res.status(400).send(err.message);
    }
});

// signup a user
app.post('/auth/signup', async(req, res) => {
    try {
        console.log("a signup request has arrived");
        const { email, password } = req.body;

        const salt = await bcrypt.genSalt(); //  generates the salt, i.e., a random string
        const bcryptPassword = await bcrypt.hash(password, salt) // hash the password and the salt 
        const authUser = await pool.query( // insert the user and the hashed password into the database
            "INSERT INTO users(email, password) values ($1, $2) RETURNING*", [email, bcryptPassword]
        );
        console.log(authUser.rows[0].id);
        const token = await generateJWT(authUser.rows[0].id); // generates a JWT by taking the user id as an input (payload)
        res
            .status(201)
            .cookie('jwt', token, { maxAge: 6000000, httpOnly: true })
            .json({ user_id: authUser.rows[0].id })
            .send;
    } catch (err) {
        console.error(err.message);
        res.status(400).send(err.message);
    }
});

app.post('/auth/login', async(req, res) => {
    try {
        console.log("a login request has arrived");
        const { email, password } = req.body;
        const user = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
        if (user.rows.length === 0) return res.status(401).json({ error: "User is not registered" });
        const validPassword = await bcrypt.compare(password, user.rows[0].password);
        if (!validPassword) return res.status(401).json({ error: "Incorrect password" });

        const token = await generateJWT(user.rows[0].id);
        res
            .status(201)
            .cookie('jwt', token, { maxAge: 6000000, httpOnly: true })
            .json({ user_id: user.rows[0].id })
            .send;
    } catch (error) {
        res.status(401).json({ error: error.message });
    }
});

//logout a user = deletes the jwt
app.get('/auth/logout', (req, res) => {
    console.log('delete jwt request arrived');
    res.status(202).clearCookie('jwt').json({ "Msg": "cookie cleared" }).send
});

//Middleware that checks if user is authenticated before processing requests below this
app.use((req, res, next) => {
    console.log('authentication request has been arrived');
    const token = req.cookies.jwt
    try {
        if (token) {
            jwt.verify(token, secret, (err) => {
                if (err) {
                    console.log(err.message);
                    console.log('token is not verified');
                    res.send({ "authenticated": false });
                } else {
                    next();
                }
            })
        } else {
            console.log('author is not authinticated');
            res.send({ "authenticated": false });
        }
    } catch (err) {
        console.error(err.message);
        res.status(400).send(err.message);
    }
})

//create a new post
app.post('/api/posts', async(req, res) => {
    try {
        console.log("a post request has arrived");
        const post = req.body;
        console.log(post);
        const newpost = await pool.query(
            "INSERT INTO posttable(date, body) values ($1, $2)    RETURNING*", [post.date, post.body]
        );
        res.json(newpost);
    } catch (err) {
        console.error(err.message);
    }
});


//get all posts
app.get('/api/posts', async(req, res) => {
    try {
        console.log("get posts request has arrived");
        const posts = await pool.query(
            "SELECT * FROM posttable ORDER BY id ASC"
        );
        res.json(posts.rows);
    } catch (err) {
        console.error(err.message);
    }
});

//get post by id
app.get('/api/posts/:id', async(req, res) => {
    try {
        const {id} = req.params;
        console.log("a get request has arrived");
        const posts = await pool.query(
            "SELECT * FROM posttable WHERE id = $1", [id]
        );
        res.json(posts.rows[0]);
    } catch (err) {
        console.error(err.message);
    }
});


//update post by id
app.put('/api/posts/:id', async(req, res) => {
    try {
        const {id} = req.params;
        const post = req.body;
        console.log("update request has arrived");
        const updatepost = await pool.query(
            "UPDATE posttable SET body = ($2) WHERE id = $1", [id, post.body]
        );
        res.json(updatepost);
    } catch (err) {
        console.error(err.message);
    }
});

//delete post by id
app.delete('/api/posts/:id', async(req, res) => {
    try {
        const {id} = req.params;
        console.log("delete request has arrived");
        const deletepost = await pool.query(
            "DELETE FROM posttable WHERE id = $1", [id]
        );
        res.json(deletepost);   
    } catch(err){
        console.error(err.message);
    }
});

//delete all posts
app.delete('/api/posts/', async(req, res) => {
    try {
        console.log("delete request has arrived");
        const deletepost = await pool.query(
            "DELETE FROM posttable"
        );
        res.json(deletepost);   
    } catch(err){
        console.error(err.message);
    }
});