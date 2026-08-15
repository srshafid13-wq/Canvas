const express = require("express");
const { Pool } = require("pg");

const app = express();

const PORT = process.env.PORT || 3000;

app.use(express.json());


// =========================================
// DATABASE
// =========================================

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});


// =========================================
// CREATE TABLES
// =========================================

async function initializeDatabase() {

    try {

        await pool.query(`
            CREATE TABLE IF NOT EXISTS live_streams (
                id SERIAL PRIMARY KEY,
                stream_id VARCHAR(100) UNIQUE NOT NULL,
                title TEXT NOT NULL,
                category VARCHAR(100),
                description TEXT,
                creator VARCHAR(255),
                username VARCHAR(255),
                thumbnail TEXT,
                status VARCHAR(20) DEFAULT 'LIVE',
                started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ended_at TIMESTAMP
            )
        `);

        console.log("Canvas database ready.");

    } catch (error) {

        console.error(
            "Database initialization error:",
            error
        );

    }
}


// =========================================
// CANVAS BACKEND STATUS
// =========================================

app.get("/", (req, res) => {

    res.json({
        status: "online",
        message: "Canvas backend is running."
    });

});


// =========================================
// TEST DATABASE
// =========================================

app.get("/api/database-test", async (req, res) => {

    try {

        await pool.query("SELECT NOW()");

        res.json({
            success: true,
            message: "Canvas database connection is working."
        });

    } catch (error) {

        console.error(error);

        res.status(500).json({
            success: false,
            message: "Database connection failed."
        });

    }

});


// =========================================
// SIGNUP
// =========================================

app.post("/api/signup", (req, res) => {

    const {
        name,
        username,
        email,
        password
    } = req.body;


    if (
        !name ||
        !username ||
        !email ||
        !password
    ) {

        return res.status(400).json({

            success: false,
            message: "All fields are required."

        });

    }


    res.json({

        success: true,

        message:
            "Signup request received.",

        user: {
            name,
            username,
            email
        }

    });

});


// =========================================
// START SERVER
// =========================================

initializeDatabase().then(() => {

    app.listen(PORT, () => {

        console.log(
            `Canvas backend running on port ${PORT}`
        );

    });

});
