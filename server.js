const express = require("express");
const { Pool } = require("pg");
const crypto = require("crypto");

const app = express();

const PORT = process.env.PORT || 3000;


/* =========================================
   CORS
========================================= */

app.use((req, res, next) => {

    res.header(
        "Access-Control-Allow-Origin",
        "*"
    );

    res.header(
        "Access-Control-Allow-Methods",
        "GET,POST,PUT,DELETE,OPTIONS"
    );

    res.header(
        "Access-Control-Allow-Headers",
        "Content-Type, Authorization"
    );

    if (req.method === "OPTIONS") {
        return res.sendStatus(204);
    }

    next();

});


/* =========================================
   JSON
========================================= */

app.use(
    express.json({
        limit: "10mb"
    })
);


/* =========================================
   DATABASE
========================================= */

const databaseUrl =
    process.env.canvas_db_r13t;

const pool = databaseUrl
    ? new Pool({
        connectionString: databaseUrl,

        ssl: {
            rejectUnauthorized: false
        }
    })
    : null;


/* =========================================
   PASSWORD HASH
========================================= */

function hashPassword(password) {

    return crypto
        .createHash("sha256")
        .update(String(password))
        .digest("hex");

}


/* =========================================
   USERNAME CLEANER
========================================= */

function cleanUsername(username) {

    return String(username || "")
        .trim()
        .replace(/^@/, "")
        .toLowerCase();

}


/* =========================================
   AUTH TOKEN
========================================= */

function createAuthToken() {

    return crypto
        .randomBytes(32)
        .toString("hex");

}


function hashToken(token) {

    return crypto
        .createHash("sha256")
        .update(String(token))
        .digest("hex");

}


/* =========================================
   AUTHENTICATION
========================================= */

async function authenticateUser(req, res, next) {

    if (!pool) {

        return res.status(500).json({
            success: false,
            message: "Database is not configured."
        });

    }

    const authorization =
        req.headers.authorization || "";

    if (!authorization.startsWith("Bearer ")) {

        return res.status(401).json({
            success: false,
            message: "Authentication required."
        });

    }

    const token =
        authorization
            .substring(7)
            .trim();

    if (!token) {

        return res.status(401).json({
            success: false,
            message:
                "Authentication token is missing."
        });

    }

    try {

        const tokenHash =
            hashToken(token);

        const result =
            await pool.query(
                `
                SELECT
                    users.id,
                    users.name,
                    users.username,
                    users.email,
                    users.created_at

                FROM sessions

                INNER JOIN users
                    ON users.id = sessions.user_id

                WHERE
                    sessions.token_hash = $1

                AND
                    sessions.expires_at >
                    CURRENT_TIMESTAMP

                LIMIT 1
                `,
                [tokenHash]
            );

        if (!result.rows.length) {

            return res.status(401).json({
                success: false,
                message:
                    "Invalid or expired authentication token."
            });

        }

        req.user = result.rows[0];

        next();

    } catch (error) {

        console.error(
            "Authentication failed:",
            error.message
        );

        return res.status(500).json({
            success: false,
            message:
                "Unable to authenticate user."
        });

    }

}


/* =========================================
   DATABASE INITIALIZATION
========================================= */

async function initializeDatabase() {

    if (!pool) {

        console.log(
            "Database environment variable not found."
        );

        return;

    }

    try {

        /* USERS */

        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (

                id SERIAL PRIMARY KEY,

                name VARCHAR(100)
                    NOT NULL,

                username VARCHAR(100)
                    UNIQUE NOT NULL,

                email VARCHAR(255)
                    UNIQUE NOT NULL,

                password_hash TEXT
                    NOT NULL,

                created_at TIMESTAMP
                    DEFAULT CURRENT_TIMESTAMP

            );
        `);


        /* PROFILES */

        await pool.query(`
            CREATE TABLE IF NOT EXISTS profiles (

                id SERIAL PRIMARY KEY,

                user_id INTEGER
                    UNIQUE NOT NULL
                    REFERENCES users(id)
                    ON DELETE CASCADE,

                bio TEXT
                    DEFAULT '',

                profile_picture TEXT
                    DEFAULT '',

                updated_at TIMESTAMP
                    DEFAULT CURRENT_TIMESTAMP

            );
        `);


        /* SESSIONS */

        await pool.query(`
            CREATE TABLE IF NOT EXISTS sessions (

                id SERIAL PRIMARY KEY,

                user_id INTEGER NOT NULL
                    REFERENCES users(id)
                    ON DELETE CASCADE,

                token_hash TEXT
                    UNIQUE NOT NULL,

                created_at TIMESTAMP
                    DEFAULT CURRENT_TIMESTAMP,

                expires_at TIMESTAMP
                    NOT NULL

            );
        `);


        /* STREAMS */

        await pool.query(`
            CREATE TABLE IF NOT EXISTS streams (

                id SERIAL PRIMARY KEY,

                user_id INTEGER
                    REFERENCES users(id)
                    ON DELETE CASCADE,

                title VARCHAR(255)
                    DEFAULT 'Canvas Live Stream',

                status VARCHAR(30)
                    DEFAULT 'live',

                created_at TIMESTAMP
                    DEFAULT CURRENT_TIMESTAMP,

                ended_at TIMESTAMP

            );
        `);


        /* FOLLOW SYSTEM */

        await pool.query(`
            CREATE TABLE IF NOT EXISTS follows (

                id SERIAL PRIMARY KEY,

                follower_id INTEGER NOT NULL
                    REFERENCES users(id)
                    ON DELETE CASCADE,

                following_id INTEGER NOT NULL
                    REFERENCES users(id)
                    ON DELETE CASCADE,

                created_at TIMESTAMP
                    DEFAULT CURRENT_TIMESTAMP,

                UNIQUE(
                    follower_id,
                    following_id
                )

            );
        `);


        /* CHAT */

        await pool.query(`
            CREATE TABLE IF NOT EXISTS stream_messages (

                id SERIAL PRIMARY KEY,

                stream_id INTEGER NOT NULL
                    REFERENCES streams(id)
                    ON DELETE CASCADE,

                user_id INTEGER NOT NULL
                    REFERENCES users(id)
                    ON DELETE CASCADE,

                message TEXT NOT NULL,

                created_at TIMESTAMP
                    DEFAULT CURRENT_TIMESTAMP

            );
        `);


        await pool.query(`
            CREATE INDEX IF NOT EXISTS
            stream_messages_stream_id_idx

            ON stream_messages(stream_id);
        `);


        /* GIFTS */

        await pool.query(`
            CREATE TABLE IF NOT EXISTS stream_gifts (

                id SERIAL PRIMARY KEY,

                stream_id INTEGER NOT NULL
                    REFERENCES streams(id)
                    ON DELETE CASCADE,

                sender_id INTEGER NOT NULL
                    REFERENCES users(id)
                    ON DELETE CASCADE,

                receiver_id INTEGER
                    REFERENCES users(id)
                    ON DELETE CASCADE,

                gift VARCHAR(100)
                    NOT NULL,

                amount NUMERIC(12,2)
                    DEFAULT 0,

                created_at TIMESTAMP
                    DEFAULT CURRENT_TIMESTAMP

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


/* =========================================
   SERVER STATUS
========================================= */

app.get("/", (req, res) => {

    res.json({

        status: "online",

        message:
            "Canvas backend is running."

    });

});


/* =========================================
   DATABASE TEST
========================================= */

app.get(
    "/api/database-test",
    async (req, res) => {

        if (!pool) {

            return res.status(500).json({

                success: false,

                database:
                    "not connected",

                message:
                    "Database environment variable was not found."

            });

        }

        try {

            const result =
                await pool.query(
                    "SELECT NOW()"
                );

            return res.json({

                success: true,

                database:
                    "connected",

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

            return res.status(500).json({

                success: false,

                database:
                    "connection failed",

                message:
                    error.message

            });

        }

    }
);
/* =========================================
   SIGNUP
========================================= */

app.post(
    "/api/signup",
    async (req, res) => {

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


        if (
            String(password).length < 8
        ) {

            return res.status(400).json({

                success: false,

                message:
                    "Password must be at least 8 characters."

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

            const cleanName =
                String(name).trim();


            const cleanUser =
                cleanUsername(username);


            const cleanEmail =
                String(email)
                    .trim()
                    .toLowerCase();


            if (!cleanName) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Name is required."

                });

            }


            if (!cleanUser) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Username is required."

                });

            }


            if (
                !/^[a-zA-Z0-9_.]+$/.test(
                    cleanUser
                )
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Username can only contain letters, numbers, underscores and dots."

                });

            }


            const existingUser =
                await pool.query(
                    `
                    SELECT
                        id,
                        username,
                        email

                    FROM users

                    WHERE
                        LOWER(username) = $1

                    OR
                        LOWER(email) = $2

                    LIMIT 1
                    `,
                    [
                        cleanUser,
                        cleanEmail
                    ]
                );


            if (
                existingUser.rows.length > 0
            ) {

                const existing =
                    existingUser.rows[0];


                if (
                    String(existing.username)
                        .toLowerCase() ===
                    cleanUser
                ) {

                    return res.status(409).json({

                        success: false,

                        message:
                            "Username already exists."

                    });

                }


                return res.status(409).json({

                    success: false,

                    message:
                        "Email already exists."

                });

            }


            const passwordHash =
                hashPassword(password);


            const userResult =
                await pool.query(
                    `
                    INSERT INTO users
                    (
                        name,
                        username,
                        email,
                        password_hash
                    )

                    VALUES
                    (
                        $1,
                        $2,
                        $3,
                        $4
                    )

                    RETURNING
                        id,
                        name,
                        username,
                        email,
                        created_at
                    `,
                    [
                        cleanName,
                        cleanUser,
                        cleanEmail,
                        passwordHash
                    ]
                );


            const user =
                userResult.rows[0];


            /* CREATE EMPTY PROFILE */

            await pool.query(
                `
                INSERT INTO profiles
                (
                    user_id,
                    bio,
                    profile_picture
                )

                VALUES
                (
                    $1,
                    '',
                    ''
                )

                ON CONFLICT (user_id)
                DO NOTHING
                `,
                [user.id]
            );


            /* CREATE LOGIN SESSION */

            const token =
                createAuthToken();


            const tokenHash =
                hashToken(token);


            await pool.query(
                `
                INSERT INTO sessions
                (
                    user_id,
                    token_hash,
                    expires_at
                )

                VALUES
                (
                    $1,
                    $2,
                    CURRENT_TIMESTAMP
                    + INTERVAL '30 days'
                )
                `,
                [
                    user.id,
                    tokenHash
                ]
            );


            return res.status(201).json({

                success: true,

                message:
                    "Canvas account created successfully.",

                token: token,

                user: {

                    id:
                        user.id,

                    name:
                        user.name,

                    username:
                        user.username,

                    email:
                        user.email,

                    created_at:
                        user.created_at

                }

            });


        } catch (error) {

            console.error(
                "Signup failed:",
                error.message
            );


            return res.status(500).json({

                success: false,

                message:
                    "Unable to create Canvas account."

            });

        }

    }
);


/* =========================================
   LOGIN
========================================= */

app.post(
    "/api/login",
    async (req, res) => {

        const {
            email,
            username,
            password
        } = req.body;


        if (!password) {

            return res.status(400).json({

                success: false,

                message:
                    "Password is required."

            });

        }


        if (!email && !username) {

            return res.status(400).json({

                success: false,

                message:
                    "Email or username is required."

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

            const loginValue =
                String(
                    email || username || ""
                )
                    .trim()
                    .toLowerCase()
                    .replace(/^@/, "");


            const result =
                await pool.query(
                    `
                    SELECT
                        id,
                        name,
                        username,
                        email,
                        password_hash,
                        created_at

                    FROM users

                    WHERE
                        LOWER(email) = $1

                    OR
                        LOWER(username) = $1

                    LIMIT 1
                    `,
                    [loginValue]
                );


            if (
                result.rows.length === 0
            ) {

                return res.status(401).json({

                    success: false,

                    message:
                        "Email or password is incorrect."

                });

            }


            const user =
                result.rows[0];


            const passwordHash =
                hashPassword(password);


            if (
                String(user.password_hash) !==
                String(passwordHash)
            ) {

                return res.status(401).json({

                    success: false,

                    message:
                        "Email or password is incorrect."

                });

            }


            /* CREATE NEW SESSION */

            const token =
                createAuthToken();


            const tokenHash =
                hashToken(token);


            await pool.query(
                `
                INSERT INTO sessions
                (
                    user_id,
                    token_hash,
                    expires_at
                )

                VALUES
                (
                    $1,
                    $2,
                    CURRENT_TIMESTAMP
                    + INTERVAL '30 days'
                )
                `,
                [
                    user.id,
                    tokenHash
                ]
            );


            return res.json({

                success: true,

                message:
                    "Login successful.",

                token: token,

                user: {

                    id:
                        user.id,

                    name:
                        user.name,

                    username:
                        user.username,

                    email:
                        user.email,

                    created_at:
                        user.created_at

                }

            });


        } catch (error) {

            console.error(
                "LOGIN FAILED:",
                error.message
            );


            return res.status(500).json({

                success: false,

                message:
                    "Unable to log in to Canvas."

            });

        }

    }
);


/* =========================================
   GET CURRENT USER
========================================= */

app.get(
    "/api/me",
    authenticateUser,
    async (req, res) => {

        return res.json({

            success: true,

            user: {

                id:
                    req.user.id,

                name:
                    req.user.name,

                username:
                    req.user.username,

                email:
                    req.user.email,

                created_at:
                    req.user.created_at

            }

        });

    }
);
/* =========================================
   SEND GIFT
========================================= */

app.post(
    "/api/streams/:id/gifts",
    authenticateUser,
    async (req, res) => {

        const gift =
            String(
                req.body.gift ||
                req.body.giftName ||
                req.body.name ||
                ""
            ).trim();

        const amount =
            Number(
                req.body.amount ??
                req.body.giftValue ??
                req.body.value ??
                0
            );


        if (!gift) {

            return res.status(400).json({

                success: false,

                message:
                    "Gift is required."

            });

        }


        if (
            !Number.isFinite(amount) ||
            amount < 0
        ) {

            return res.status(400).json({

                success: false,

                message:
                    "Invalid gift amount."

            });

        }


        try {

            const streamResult =
                await pool.query(
                    `
                    SELECT
                        id,
                        user_id

                    FROM streams

                    WHERE
                        id = $1

                    AND
                        status = 'live'

                    LIMIT 1
                    `,
                    [req.params.id]
                );


            if (
                streamResult.rows.length === 0
            ) {

                return res.status(404).json({

                    success: false,

                    message:
                        "Live stream not found."

                });

            }


            const streamerId =
                streamResult.rows[0].user_id;


            const result =
                await pool.query(
                    `
                    INSERT INTO stream_gifts
                    (
                        stream_id,
                        sender_id,
                        receiver_id,
                        gift,
                        amount
                    )

                    VALUES
                    (
                        $1,
                        $2,
                        $3,
                        $4,
                        $5
                    )

                    RETURNING
                        id,
                        stream_id,
                        sender_id,
                        receiver_id,
                        gift,
                        amount,
                        created_at
                    `,
                    [
                        req.params.id,
                        req.user.id,
                        streamerId,
                        gift,
                        amount
                    ]
                );


            return res.status(201).json({

                success: true,

                message:
                    "Gift sent successfully.",

                gift: {

                    ...result.rows[0],

                    sender_name:
                        req.user.name,

                    sender_username:
                        req.user.username

                }

            });


        } catch (error) {

            console.error(
                "Send gift failed:",
                error.message
            );


            return res.status(500).json({

                success: false,

                message:
                    "Unable to send gift."

            });

        }

    }
);


/* =========================================
   GET STREAM GIFTS
========================================= */

app.get(
    "/api/streams/:id/gifts",
    async (req, res) => {

        if (!pool) {

            return res.status(500).json({

                success: false,

                message:
                    "Database is not configured."

            });

        }


        try {

            const result =
                await pool.query(
                    `
                    SELECT

                        stream_gifts.id,
                        stream_gifts.stream_id,
                        stream_gifts.sender_id,
                        stream_gifts.receiver_id,
                        stream_gifts.gift,
                        stream_gifts.amount,
                        stream_gifts.created_at,

                        users.name AS sender_name,
                        users.username AS sender_username

                    FROM stream_gifts

                    INNER JOIN users

                        ON users.id =
                           stream_gifts.sender_id

                    WHERE
                        stream_gifts.stream_id = $1

                    ORDER BY
                        stream_gifts.created_at ASC

                    LIMIT 200
                    `,
                    [req.params.id]
                );


            return res.json({

                success: true,

                gifts:
                    result.rows

            });


        } catch (error) {

            console.error(
                "Get gifts failed:",
                error.message
            );


            return res.status(500).json({

                success: false,

                message:
                    "Unable to load gifts."

            });

        }

    }
);


/* =========================================
   LOGOUT
========================================= */

app.post(
    "/api/logout",
    authenticateUser,
    async (req, res) => {

        try {

            const authorization =
                req.headers.authorization || "";


            const token =
                authorization
                    .substring(7)
                    .trim();


            const tokenHash =
                hashToken(token);


            await pool.query(
                `
                DELETE FROM sessions

                WHERE
                    token_hash = $1
                `,
                [tokenHash]
            );


            return res.json({

                success: true,

                message:
                    "Logged out successfully."

            });


        } catch (error) {

            console.error(
                "Logout failed:",
                error.message
            );


            return res.status(500).json({

                success: false,

                message:
                    "Unable to log out."

            });

        }

    }
);


/* =========================================
   DELETE ACCOUNT
========================================= */

app.delete(
    "/api/account",
    authenticateUser,
    async (req, res) => {

        try {

            const result =
                await pool.query(
                    `
                    DELETE FROM users

                    WHERE
                        id = $1

                    RETURNING id
                    `,
                    [req.user.id]
                );


            if (
                result.rows.length === 0
            ) {

                return res.status(404).json({

                    success: false,

                    message:
                        "User account not found."

                });

            }


            return res.json({

                success: true,

                message:
                    "Canvas account deleted successfully."

            });


        } catch (error) {

            console.error(
                "Delete account failed:",
                error.message
            );


            return res.status(500).json({

                success: false,

                message:
                    "Unable to delete account."

            });

        }

    }
);


/* =========================================
   404
========================================= */

app.use(
    (req, res) => {

        res.status(404).json({

            success: false,

            message:
                "Canvas API endpoint not found."

        });

    }
);


/* =========================================
   GLOBAL ERROR HANDLER
========================================= */

app.use(
    (error, req, res, next) => {

        console.error(
            "Canvas server error:",
            error
        );


        return res.status(500).json({

            success: false,

            message:
                "Canvas server encountered an error."

        });

    }
);


/* =========================================
   START SERVER
========================================= */

async function startServer() {

    await initializeDatabase();


    app.listen(
        PORT,
        () => {

            console.log(
                `Canvas backend running on port ${PORT}`
            );

        }
    );

}


startServer();
