const express = require("express");
const { Pool } = require("pg");
const crypto = require("crypto");

const app = express();

const PORT = process.env.PORT || 3000;


/* =========================================
   JSON BODY LIMIT
========================================= */

app.use(express.json({
    limit: "10mb"
}));


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
        .update(password)
        .digest("hex");

}


/* =========================================
   NORMALIZE USERNAME
========================================= */

function cleanUsername(username) {

    return String(username || "")
        .trim()
        .replace(/^@/, "")
        .toLowerCase();

}


/* =========================================
   AUTHENTICATION TOKEN
========================================= */

function createAuthToken() {

    return crypto
        .randomBytes(32)
        .toString("hex");

}


function hashToken(token) {

    return crypto
        .createHash("sha256")
        .update(token)
        .digest("hex");

}


/* =========================================
   AUTHENTICATION MIDDLEWARE
========================================= */

async function authenticateUser(req, res, next) {

    if (!pool) {

        return res.status(500).json({

            success: false,

            message:
                "Database is not configured."

        });

    }


    const authorization =
        req.headers.authorization || "";


    if (
        !authorization.startsWith("Bearer ")
    ) {

        return res.status(401).json({

            success: false,

            message:
                "Authentication required."

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
                    ON users.id =
                       sessions.user_id

                WHERE sessions.token_hash = $1

                  AND sessions.expires_at >
                      CURRENT_TIMESTAMP

                LIMIT 1
                `,

                [tokenHash]

            );


        if (
            result.rows.length === 0
        ) {

            return res.status(401).json({

                success: false,

                message:
                    "Invalid or expired authentication token."

            });

        }


        req.user =
            result.rows[0];


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
   INITIALIZE DATABASE
========================================= */

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

                created_at TIMESTAMP
                    DEFAULT CURRENT_TIMESTAMP

            );

        `);


        await pool.query(`

            CREATE TABLE IF NOT EXISTS profiles (

                id SERIAL PRIMARY KEY,

                user_id INTEGER UNIQUE NOT NULL
                    REFERENCES users(id)
                    ON DELETE CASCADE,

                bio TEXT DEFAULT '',

                profile_picture TEXT DEFAULT '',

                updated_at TIMESTAMP
                    DEFAULT CURRENT_TIMESTAMP

            );

        `);


        /* =====================================
           SESSIONS TABLE
        ===================================== */

        await pool.query(`

            CREATE TABLE IF NOT EXISTS sessions (

                id SERIAL PRIMARY KEY,

                user_id INTEGER NOT NULL
                    REFERENCES users(id)
                    ON DELETE CASCADE,

                token_hash TEXT UNIQUE NOT NULL,

                created_at TIMESTAMP
                    DEFAULT CURRENT_TIMESTAMP,

                expires_at TIMESTAMP NOT NULL

            );

        `);


        /* =====================================
           STREAMS TABLE
        ===================================== */

        await pool.query(`

            CREATE TABLE IF NOT EXISTS streams (

                id SERIAL PRIMARY KEY,

                title VARCHAR(255)
                    DEFAULT 'Canvas Live Stream',

                status VARCHAR(30)
                    DEFAULT 'live',

                created_at TIMESTAMP
                    DEFAULT CURRENT_TIMESTAMP,

                ended_at TIMESTAMP

            );

        `);


        /* =====================================
           ADD USER ID TO EXISTING STREAMS
        ===================================== */

        await pool.query(`

            ALTER TABLE streams

            ADD COLUMN IF NOT EXISTS user_id
            INTEGER
            REFERENCES users(id)
            ON DELETE CASCADE;

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
   BACKEND STATUS
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


            if (!cleanUser) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Username is required."

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

                    WHERE LOWER(username) = $1
                       OR LOWER(email) = $2

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


            const result =
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
                    ($1, $2, $3, $4)

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
                result.rows[0];


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

                [
                    user.id
                ]

            );


            return res.status(201).json({

                success: true,

                message:
                    "Canvas account created successfully.",

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
                    "Unable to create account."

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
            password
        } = req.body;


        if (
            !email ||
            !password
        ) {

            return res.status(400).json({

                success: false,

                message:
                    "Email and password are required."

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

            const cleanEmail =
                String(email)
                    .trim()
                    .toLowerCase();


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

                    WHERE LOWER(email) = $1

                    LIMIT 1
                    `,

                    [
                        cleanEmail
                    ]

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
                passwordHash !==
                user.password_hash
            ) {

                return res.status(401).json({

                    success: false,

                    message:
                        "Email or password is incorrect."

                });

            }


            /* =================================
               CREATE AUTHENTICATION TOKEN
            ================================= */

            const token =
                createAuthToken();


            const tokenHash =
                hashToken(token);


            /* =================================
               CREATE 30-DAY SESSION
            ================================= */

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

                token:
                    token,

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
                "Login failed:",
                error.message
            );


            return res.status(500).json({

                success: false,

                message:
                    "Unable to log in."

            });

        }

    }
);


/* =========================================
   CURRENT AUTHENTICATED USER
========================================= */

app.get(
    "/api/me",
    authenticateUser,
    async (req, res) => {

        return res.json({

            success: true,

            user:
                req.user

        });

    }
);


/* =========================================
   LOGOUT
========================================= */

app.post(
    "/api/logout",
    authenticateUser,
    async (req, res) => {

        const authorization =
            req.headers.authorization || "";


        const token =
            authorization
                .substring(7)
                .trim();


        try {

            await pool.query(

                `
                DELETE FROM sessions

                WHERE token_hash = $1
                `,

                [
                    hashToken(token)
                ]

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
   GET PROFILE
========================================= */

app.get(
    "/api/profile/:username",
    async (req, res) => {

        const username =
            cleanUsername(
                req.params.username
            );


        if (!username) {

            return res.status(400).json({

                success: false,

                message:
                    "Username is required."

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

            const result =
                await pool.query(

                    `
                    SELECT
                        users.id,
                        users.name,
                        users.username,
                        users.email,
                        profiles.bio,
                        profiles.profile_picture,
                        profiles.updated_at

                    FROM users

                    LEFT JOIN profiles
                        ON profiles.user_id =
                           users.id

                    WHERE LOWER(users.username) = $1

                    LIMIT 1
                    `,

                    [
                        username
                    ]

                );


            if (
                result.rows.length === 0
            ) {

                return res.status(404).json({

                    success: false,

                    message:
                        "Profile not found."

                });

            }


            return res.json({

                success: true,

                profile:
                    result.rows[0]

            });

        } catch (error) {

            console.error(
                "Profile fetch failed:",
                error.message
            );

            return res.status(500).json({

                success: false,

                message:
                    "Unable to load profile."

            });

        }

    }
);


/* =========================================
   UPDATE PROFILE
========================================= */

app.put(
    "/api/profile/:username",
    authenticateUser,
    async (req, res) => {

        const username =
            cleanUsername(
                req.params.username
            );


        /* =====================================
           USER CAN ONLY EDIT OWN PROFILE
        ===================================== */

        if (
            username !==
            cleanUsername(req.user.username)
        ) {

            return res.status(403).json({

                success: false,

                message:
                    "You can only edit your own profile."

            });

        }


        const {
            name,
            bio,
            profile_picture
        } = req.body;


        if (!pool) {

            return res.status(500).json({

                success: false,

                message:
                    "Database is not configured."

            });

        }


        try {

            const userResult =
                await pool.query(

                    `
                    SELECT
                        id,
                        name,
                        username,
                        email

                    FROM users

                    WHERE LOWER(username) = $1

                    LIMIT 1
                    `,

                    [username]

                );


            if (
                userResult.rows.length === 0
            ) {

                return res.status(404).json({

                    success: false,

                    message:
                        "User not found."

                });

            }


            const user =
                userResult.rows[0];


            const userId =
                user.id;


            /* =================================
               MAKE SURE PROFILE EXISTS
            ================================= */

            await pool.query(

                `
                INSERT INTO profiles
                (
                    user_id,
                    bio,
                    profile_picture
                )

                VALUES
                ($1, '', '')

                ON CONFLICT (user_id)
                DO NOTHING
                `,

                [
                    userId
                ]

            );


            /* =================================
               UPDATE NAME
            ================================= */

            if (
                name !== undefined &&
                name !== null &&
                String(name).trim() !== ""
            ) {

                await pool.query(

                    `
                    UPDATE users

                    SET name = $1

                    WHERE id = $2
                    `,

                    [
                        String(name).trim(),
                        userId
                    ]

                );

            }


            /* =================================
               UPDATE PROFILE DATA
            ================================= */

            if (
                bio !== undefined ||
                profile_picture !== undefined
            ) {

                await pool.query(

                    `
                    UPDATE profiles

                    SET

                        bio =
                            CASE
                                WHEN $1::boolean
                                THEN $2
                                ELSE bio
                            END,

                        profile_picture =
                            CASE
                                WHEN $3::boolean
                                THEN $4
                                ELSE profile_picture
                            END,

                        updated_at =
                            CURRENT_TIMESTAMP

                    WHERE user_id = $5
                    `,

                    [

                        bio !== undefined,

                        bio !== undefined
                            ? String(bio)
                            : "",

                        profile_picture !== undefined,

                        profile_picture !== undefined
                            ? String(profile_picture)
                            : "",

                        userId

                    ]

                );

            }


            /* =================================
               RETURN UPDATED PROFILE
            ================================= */

            const updatedResult =
                await pool.query(

                    `
                    SELECT
                        users.id,
                        users.name,
                        users.username,
                        users.email,
                        profiles.bio,
                        profiles.profile_picture,
                        profiles.updated_at

                    FROM users

                    LEFT JOIN profiles
                        ON profiles.user_id =
                           users.id

                    WHERE users.id = $1

                    LIMIT 1
                    `,

                    [
                        userId
                    ]

                );


            return res.json({

                success: true,

                message:
                    "Profile updated successfully.",

                profile:
                    updatedResult.rows[0]

            });


        } catch (error) {

            console.error(
                "Profile update failed:",
                error.message
            );


            return res.status(500).json({

                success: false,

                message:
                    "Unable to update profile."

            });

        }

    }
);
/* =========================================
   START STREAM
========================================= */

app.post(
    "/api/streams/start",
    authenticateUser,
    async (req, res) => {

        if (!pool) {

            return res.status(500).json({

                success: false,

                message:
                    "Database is not configured."

            });

        }


        const title =
            String(
                req.body.title ||
                "Canvas Live Stream"
            ).trim();


        try {

            /* =================================
               PREVENT MULTIPLE LIVE STREAMS
               FOR SAME USER
            ================================= */

            const existingLiveStream =
                await pool.query(

                    `
                    SELECT
                        id,
                        title,
                        status,
                        created_at

                    FROM streams

                    WHERE user_id = $1
                      AND status = 'live'

                    LIMIT 1
                    `,

                    [
                        req.user.id
                    ]

                );


            if (
                existingLiveStream.rows.length > 0
            ) {

                return res.status(409).json({

                    success: false,

                    message:
                        "You already have a live stream.",

                    stream:
                        existingLiveStream.rows[0]

                });

            }


            /* =================================
               CREATE USER-OWNED STREAM
            ================================= */

            const result =
                await pool.query(

                    `
                    INSERT INTO streams
                    (
                        user_id,
                        title,
                        status
                    )

                    VALUES
                    (
                        $1,
                        $2,
                        'live'
                    )

                    RETURNING
                        id,
                        user_id,
                        title,
                        status,
                        created_at
                    `,

                    [
                        req.user.id,
                        title
                    ]

                );


            const stream =
                result.rows[0];


            return res.status(201).json({

                success: true,

                message:
                    "Canvas stream started.",

                streamId:
                    stream.id,

                stream:
                    stream

            });


        } catch (error) {

            console.error(
                "Stream start failed:",
                error.message
            );


            return res.status(500).json({

                success: false,

                message:
                    "Unable to start stream."

            });

        }

    }
);


/* =========================================
   STOP STREAM
========================================= */

app.post(
    "/api/streams/stop",
    authenticateUser,
    async (req, res) => {

        if (!pool) {

            return res.status(500).json({

                success: false,

                message:
                    "Database is not configured."

            });

        }


        const streamId =
            req.body.streamId;


        if (!streamId) {

            return res.status(400).json({

                success: false,

                message:
                    "Stream ID is required."

            });

        }


        try {

            /* =================================
               ONLY STREAM OWNER CAN STOP IT
            ================================= */

            const result =
                await pool.query(

                    `
                    UPDATE streams

                    SET
                        status = 'ended',
                        ended_at = CURRENT_TIMESTAMP

                    WHERE id = $1

                      AND user_id = $2

                      AND status = 'live'

                    RETURNING
                        id,
                        user_id,
                        title,
                        status,
                        created_at,
                        ended_at
                    `,

                    [
                        streamId,
                        req.user.id
                    ]

                );


            if (
                result.rows.length === 0
            ) {

                return res.status(404).json({

                    success: false,

                    message:
                        "Live stream not found or you are not the owner."

                });

            }


            return res.json({

                success: true,

                message:
                    "Canvas stream stopped.",

                stream:
                    result.rows[0]

            });


        } catch (error) {

            console.error(
                "Stream stop failed:",
                error.message
            );


            return res.status(500).json({

                success: false,

                message:
                    "Unable to stop stream."

            });

        }

    }
);


/* =========================================
   GET MY ACTIVE STREAM
========================================= */

app.get(
    "/api/streams/my-live",
    authenticateUser,
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
                        id,
                        user_id,
                        title,
                        status,
                        created_at

                    FROM streams

                    WHERE user_id = $1

                      AND status = 'live'

                    LIMIT 1
                    `,

                    [
                        req.user.id
                    ]

                );


            if (
                result.rows.length === 0
            ) {

                return res.json({

                    success: true,

                    live: false,

                    stream: null

                });

            }


            return res.json({

                success: true,

                live: true,

                stream:
                    result.rows[0]

            });


        } catch (error) {

            console.error(
                "My live stream fetch failed:",
                error.message
            );


            return res.status(500).json({

                success: false,

                message:
                    "Unable to load your live stream."

            });

        }

    }
);


/* =========================================
   GET STREAM
========================================= */

app.get(
    "/api/streams/:id",
    async (req, res) => {

        if (!pool) {

            return res.status(500).json({

                success: false,

                message:
                    "Database is not configured."

            });

        }


        const streamId =
            req.params.id;


        try {

            const result =
                await pool.query(

                    `
                    SELECT

                        streams.id,
                        streams.user_id,
                        streams.title,
                        streams.status,
                        streams.created_at,
                        streams.ended_at,

                        users.name,
                        users.username

                    FROM streams

                    LEFT JOIN users
                        ON users.id =
                           streams.user_id

                    WHERE streams.id = $1

                    LIMIT 1
                    `,

                    [
                        streamId
                    ]

                );


            if (
                result.rows.length === 0
            ) {

                return res.status(404).json({

                    success: false,

                    message:
                        "Stream not found."

                });

            }


            return res.json({

                success: true,

                stream:
                    result.rows[0]

            });


        } catch (error) {

            console.error(
                "Stream fetch failed:",
                error.message
            );


            return res.status(500).json({

                success: false,

                message:
                    "Unable to load stream."

            });

        }

    }
);


/* =========================================
   CLEAN EXPIRED SESSIONS
========================================= */

async function cleanExpiredSessions() {

    if (!pool) {

        return;
    }


    try {

        await pool.query(

            `
            DELETE FROM sessions

            WHERE expires_at <=
                  CURRENT_TIMESTAMP
            `

        );

    } catch (error) {

        console.error(
            "Session cleanup failed:",
            error.message
        );

    }

}


/* =========================================
   SERVER START
========================================= */

app.listen(
    PORT,
    async () => {

        console.log(
            `Canvas backend running on port ${PORT}`
        );


        await initializeDatabase();


        /* =====================================
           CLEAN EXPIRED SESSIONS
           EVERY 1 HOUR
        ===================================== */

        await cleanExpiredSessions();


        setInterval(
            cleanExpiredSessions,
            60 * 60 * 1000
        );

    }
);
