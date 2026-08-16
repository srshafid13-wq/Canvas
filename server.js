const express = require("express");
const { Pool } = require("pg");
const crypto = require("crypto");

const app = express();

const PORT = process.env.PORT || 3000;

app.use(express.json());


// =========================================
// DATABASE
// =========================================

const databaseUrl = process.env.canvas_db_r13t;

const pool = databaseUrl
    ? new Pool({
        connectionString: databaseUrl,
        ssl: {
            rejectUnauthorized: false
        }
    })
    : null;


// =========================================
// CREATE USERS TABLE
// =========================================

async function initializeDatabase() {

    if (!pool) {

        console.log(
            "Database environment variable not found."
        );

        return;

    }

    try {

        await pool.query(`

            CREATE TABLE IF NOT EXISTS users (

                id SERIAL PRIMARY KEY,

                name VARCHAR(100) NOT NULL,

                username VARCHAR(100) UNIQUE NOT NULL,

                email VARCHAR(255) UNIQUE NOT NULL,

                password_hash TEXT NOT NULL,

                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP

            );

        `);

        console.log(
            "Canvas database initialized successfully."
        );

    } catch (error) {

        console.error(
            "Database initialization failed:",
            error.message
        );

    }

}


// =========================================
// CANVAS BACKEND STATUS
// =========================================

app.get("/", (req, res) => {

    res.json({

        status: "online",

        message:
            "Canvas backend is running."

    });

});


// =========================================
// DATABASE TEST
// =========================================

app.get("/api/database-test", async (req, res) => {

    if (!pool) {

        return res.status(500).json({

            success: false,

            database: "not connected",

            message:
                "Database environment variable was not found."

        });

    }

    try {

        const result =
            await pool.query("SELECT NOW()");

        res.json({

            success: true,

            database: "connected",

            message:
                "Canvas database connection is working.",

            server_time:
                result.rows[0].now

        });

    } catch (error) {

        console.error(
            "Database test failed:",
            error.message
        );

        res.status(500).json({

            success: false,

            database: "connection failed",

            message:
                error.message

        });

    }

});


// =========================================
// SIGNUP
// =========================================

app.post("/api/signup", async (req, res) => {

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

            message:
                "All fields are required."

        });

    }


    if (!pool) {

        return res.status(500).json({

            success: false,

            message:
                "Database is not configured."

        });

    }


    try {

        // Check whether username or email already exists

        const existingUser =
            await pool.query(

                `
                SELECT id
                FROM users
                WHERE username = $1
                   OR email = $2
                LIMIT 1
                `,

                [username, email]

            );


        if (existingUser.rows.length > 0) {

            return res.status(409).json({

                success: false,

                message:
                    "Username or email already exists."

            });

        }


        // Hash password before storing it

        const passwordHash =
            crypto
                .createHash("sha256")
                .update(password)
                .digest("hex");


        // Save account

        const result =
            await pool.query(

                `
                INSERT INTO users
                (name, username, email, password_hash)

                VALUES
                ($1, $2, $3, $4)

                RETURNING
                id, name, username, email, created_at
                `,

                [
                    name,
                    username,
                    email,
                    passwordHash
                ]

            );


        const user =
            result.rows[0];


        res.status(201).json({

            success: true,

            message:
                "Canvas account created successfully.",

            user: {

                id: user.id,

                name: user.name,

                username: user.username,

                email: user.email,

                created_at:
                    user.created_at

            }

        });

    } catch (error) {

        console.error(
            "Signup failed:",
            error.message
        );

        res.status(500).json({

            success: false,

            message:
                "Unable to create account."

        });

    }

});


// =========================================
// START SERVER
// =========================================

app.listen(PORT, async () => {

    console.log(
        `Canvas backend running on port ${PORT}`
    );

    await initializeDatabase();

});
