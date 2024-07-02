const express = require("express");
var cors = require('cors');
var bodyParser = require("body-parser");
const mysql = require("mysql");
require("dotenv").config();

var bcrypt = require('bcrypt');

var app = express();
var port = process.env.PORT || 3000;

const DB_HOST = process.env.DB_HOST;
const DB_USER = process.env.DB_USER;
const DB_PASSWORD = process.env.DB_PASSWORD;
const DB_DATABASE = process.env.DB_DATABASE;
const DB_PORT = process.env.DB_PORT;

app.use(bodyParser.json());
app.use(cors());
app.use(bodyParser.urlencoded({ extended: false }));

app.listen(port, () => {
    console.log("Server started on port " + port);
});

const db = mysql.createPool({
    connectionLimit: 100,
    host: DB_HOST,
    user: DB_USER,
    password: DB_PASSWORD,
    database: DB_DATABASE,
    port: DB_PORT
});

db.getConnection((err, connection) => {
    if (err) throw err;
    console.log("DB connected successfully: " + connection.threadId);
});

function queryPromise(sql, values = []) {
    return new Promise((resolve, reject) => {
        db.query(sql, values, (err, results) => {
            if (err) {
                reject(err);
            } else {
                resolve(results);
            }
        });
    });
}

app.post('/register', async (req, res) => {
    try {
        var { username, role, email, password, cpassword } = req.body;

        if (!username || !role || !email || !password || !cpassword) {
            throw new Error("Fill in the required fields!!");
        }

        if (password !== cpassword) {
            throw new Error("Passwords do not match!!");
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const signin = [username, role, email, hashedPassword];
        const SQL = "INSERT INTO users (username, role, email, password) VALUES (?,?,?,?)";

        const result = await queryPromise(SQL, signin);
        res.status(200).json({ id: result.insertId, username, role, email });
        console.log(result);

    } catch (err) {
        console.error("Error during registration: ", err.message);
        res.status(500).json({ error: "Registration failed", message: err.message });
    }
});

app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            throw new Error("Please enter both username and password!");
        }

        const SQL = "SELECT * FROM users WHERE username = ?";
        const users = await queryPromise(SQL, [username]);

        if (users.length === 0) {
            throw new Error("User not found!");
        }

        const hashedPassword = users[0].password;
        const passwordMatch = await bcrypt.compare(password, hashedPassword);

        if (!passwordMatch) {
            throw new Error("Invalid password!");
        }

        //const token = jwt.sign({ id: users[0].id, username: users[0].username, role: users[0].role }, process.env.SECRET_KEY, { expiresIn: '1h' });

        res.status(200).json({ msg: "User logged in" });
    } catch (err) {
        console.error("Error during login: ", err.message);
        res.status(401).json({ error: "Login failed", message: err.message });
    }
});


app.post('/create', async (req, res) => {
    try {
        const { category, model, number_plate, current_city, rent_per_hr, rent_history } = req.body;

        if (!category || !model || !number_plate || !current_city || !rent_per_hr) {
            return res.status(400).json({ message: "All fields are required", status_code: 400 });
        }

        const carData = {
            category,
            model,
            number_plate,
            current_city,
            rent_per_hr,
            rent_history: JSON.stringify(rent_history)
        };

        const query = "INSERT INTO cars SET ?";
        db.query(query, carData, (err, result) => {
            if (err) {
                console.error("Error executing query: ", err);
                return res.status(500).json({ message: "Internal Server Error", status_code: 500 });
            }

            res.status(200).json({
                message: "Car added successfully",
                car_id: result.insertId,
                status_code: 200
            });
        });

    } catch (err) {
        console.error("Error in try block: ", err);
        res.status(500).json({ message: "Internal Server Error", status_code: 500 });
    }
});

module.exports = app;
