const express = require("express");
const { Pool } = require("pg");
const crypto = require("crypto");
const http = require("http");
const { Server } = require("socket.io");

const app = express();

const httpServer = http.createServer(app);

const io = new Server(httpServer, {
    cors: {
        origin: "*",
        methods: ["GET", "POST", "PUT", "DELETE"]
    }
});

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
        limit: "50mb"
    })
);


/* =========================================
   DATABASE
========================================= */

const databaseUrl =
    process.env.canvas_db_r13t;

const pool =
    databaseUrl
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

            message:
                "Database is not configured."

        });

    }


    const authorization =
        req.headers.authorization || "";


    if (
        !authorization.startsWith(
            "Bearer "
        )
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
                    ON users.id = sessions.user_id

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

                name VARCHAR(100) NOT NULL,

                username VARCHAR(100)
                    UNIQUE NOT NULL,

                email VARCHAR(255)
                    UNIQUE NOT NULL,

                password_hash TEXT NOT NULL,

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

                bio TEXT DEFAULT '',

                profile_picture TEXT DEFAULT '',

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

                expires_at TIMESTAMP NOT NULL
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


        /* MAKE SURE OLD DATABASE
           ALSO GETS user_id */

        await pool.query(`
            ALTER TABLE streams
            ADD COLUMN IF NOT EXISTS user_id
            INTEGER
            REFERENCES users(id)
            ON DELETE CASCADE;
        `);


        /* =====================================
           RECORDINGS TABLE
        ===================================== */

        await pool.query(`
            CREATE TABLE IF NOT EXISTS stream_recordings (

                id SERIAL PRIMARY KEY,

                stream_id INTEGER
                    UNIQUE NOT NULL
                    REFERENCES streams(id)
                    ON DELETE CASCADE,

                user_id INTEGER NOT NULL
                    REFERENCES users(id)
                    ON DELETE CASCADE,

                recording_url TEXT DEFAULT '',

                duration_seconds INTEGER
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
                    email ||
                    username ||
                    ""
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

                    WHERE LOWER(email) = $1
                       OR LOWER(username) = $1

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
                String(
                    user.password_hash
                ) !==
                String(
                    passwordHash
                )
            ) {

                return res.status(401).json({

                    success: false,

                    message:
                        "Email or password is incorrect."

                });

            }


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
                error
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
   GET PROFILE BY USERNAME
========================================= */

app.get(
    "/api/profile/:username",
    async (req, res) => {

        if (!pool) {

            return res.status(500).json({

                success: false,

                message:
                    "Database is not configured."

            });

        }


        try {

            const username =
                cleanUsername(
                    req.params.username
                );


            const result =
                await pool.query(
                    `
                    SELECT

                        users.id,
                        users.name,
                        users.username,
                        users.email,
                        users.created_at,

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
                    [username]
                );


            if (
                result.rows.length === 0
            ) {

                return res.status(404).json({

                    success: false,

                    message:
                        "Canvas profile not found."

                });

            }


            const p =
                result.rows[0];


            return res.json({

                success: true,

                profile: {

                    id:
                        p.id,

                    name:
                        p.name,

                    username:
                        p.username,

                    email:
                        p.email,

                    bio:
                        p.bio || "",

                    profile_picture:
                        p.profile_picture || "",

                    created_at:
                        p.created_at,

                    updated_at:
                        p.updated_at

                }

            });


        } catch (error) {

            console.error(
                "Get profile failed:",
                error.message
            );


            return res.status(500).json({

                success: false,

                message:
                    "Unable to load Canvas profile."

            });

        }

    }
);


/* =========================================
   GET MY PROFILE
========================================= */

app.get(
    "/api/profile",
    authenticateUser,
    async (req, res) => {

        try {

            const result =
                await pool.query(
                    `
                    SELECT

                        users.id,
                        users.name,
                        users.username,
                        users.email,
                        users.created_at,

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
                    [req.user.id]
                );


            if (
                result.rows.length === 0
            ) {

                return res.status(404).json({

                    success: false,

                    message:
                        "Canvas profile not found."

                });

            }


            const p =
                result.rows[0];


            return res.json({

                success: true,

                profile: {

                    id:
                        p.id,

                    name:
                        p.name,

                    username:
                        p.username,

                    email:
                        p.email,

                    bio:
                        p.bio || "",

                    profile_picture:
                        p.profile_picture || "",

                    created_at:
                        p.created_at,

                    updated_at:
                        p.updated_at

                }

            });


        } catch (error) {

            console.error(
                "Get my profile failed:",
                error.message
            );


            return res.status(500).json({

                success: false,

                message:
                    "Unable to load Canvas profile."

            });

        }

    }
);


/* =========================================
   UPDATE PROFILE
========================================= */

app.put(
    "/api/profile",
    authenticateUser,
    async (req, res) => {

        const {
            name,
            username,
            bio,
            profile_picture
        } = req.body;


        try {

            const cleanName =
                String(
                    name !== undefined
                        ? name
                        : req.user.name
                ).trim();


            const cleanUser =
                cleanUsername(
                    username !== undefined
                        ? username
                        : req.user.username
                );


            const cleanBio =
                String(
                    bio !== undefined
                        ? bio
                        : ""
                ).trim();


            const cleanPicture =
                String(
                    profile_picture !== undefined
                        ? profile_picture
                        : ""
                );


            if (!cleanName) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Name cannot be empty."

                });

            }


            if (!cleanUser) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Username cannot be empty."

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
                        "Invalid username."

                });

            }


            const usernameCheck =
                await pool.query(
                    `
                    SELECT id

                    FROM users

                    WHERE LOWER(username) = $1

                    AND id != $2

                    LIMIT 1
                    `,
                    [
                        cleanUser,
                        req.user.id
                    ]
                );


            if (
                usernameCheck.rows.length > 0
            ) {

                return res.status(409).json({

                    success: false,

                    message:
                        "Username already exists."

                });

            }


            const userResult =
                await pool.query(
                    `
                    UPDATE users

                    SET
                        name = $1,
                        username = $2

                    WHERE id = $3

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
                        req.user.id
                    ]
                );


            await pool.query(
                `
                INSERT INTO profiles
                (
                    user_id,
                    bio,
                    profile_picture,
                    updated_at
                )

                VALUES
                (
                    $1,
                    $2,
                    $3,
                    CURRENT_TIMESTAMP
                )

                ON CONFLICT (user_id)

                DO UPDATE SET

                    bio =
                        EXCLUDED.bio,

                    profile_picture =
                        EXCLUDED.profile_picture,

                    updated_at =
                        CURRENT_TIMESTAMP
                `,
                [
                    req.user.id,
                  cleanBio,
                    cleanPicture
                ]
            );


            const updated =
                userResult.rows[0];


            return res.json({

                success: true,

                message:
                    "Profile updated successfully.",

                user: {

                    id:
                        updated.id,

                    name:
                        updated.name,

                    username:
                        updated.username,

                    email:
                        updated.email,

                    bio:
                        cleanBio,

                    profile_picture:
                        cleanPicture

                }

            });


        } catch (error) {

            console.error(
                "Update profile failed:",
                error.message
            );


            return res.status(500).json({

                success: false,

                message:
                    "Unable to update Canvas profile."

            });

        }

    }
);
/* =========================================
   CHANGE PASSWORD
========================================= */

app.put(
    "/api/change-password",
    authenticateUser,
    async (req, res) => {

        const {
            currentPassword,
            newPassword
        } = req.body;


        if (
            !currentPassword ||
            !newPassword
        ) {

            return res.status(400).json({

                success: false,

                message:
                    "Current and new passwords are required."

            });

        }


        if (
            String(newPassword).length < 8
        ) {

            return res.status(400).json({

                success: false,

                message:
                    "New password must be at least 8 characters."

            });

        }


        try {

            const result =
                await pool.query(
                    `
                    SELECT password_hash

                    FROM users

                    WHERE id = $1

                    LIMIT 1
                    `,
                    [req.user.id]
                );


            if (
                result.rows.length === 0
            ) {

                return res.status(404).json({

                    success: false,

                    message:
                        "User not found."

                });

            }


            const currentHash =
                hashPassword(
                    currentPassword
                );


            if (
                result.rows[0].password_hash !==
                currentHash
            ) {

                return res.status(401).json({

                    success: false,

                    message:
                        "Current password is incorrect."

                });

            }


            const newHash =
                hashPassword(
                    newPassword
                );


            await pool.query(
                `
                UPDATE users

                SET password_hash = $1

                WHERE id = $2
                `,
                [
                    newHash,
                    req.user.id
                ]
            );


            return res.json({

                success: true,

                message:
                    "Password changed successfully."

            });


        } catch (error) {

            console.error(
                "Change password failed:",
                error.message
            );


            return res.status(500).json({

                success: false,

                message:
                    "Unable to change password."

            });

        }

    }
);


/* =========================================
   CREATE STREAM
========================================= */

app.post(
    "/api/streams",
    authenticateUser,
    async (req, res) => {

        const title =
            String(
                req.body.title ||
                "Canvas Live Stream"
            ).trim();


        if (!title) {

            return res.status(400).json({

                success: false,

                message:
                    "Stream title is required."

            });

        }


        try {

            /*
             * Prevent the same creator from
             * accidentally creating multiple
             * live streams at once.
             */

            const existing =
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

                    ORDER BY created_at DESC

                    LIMIT 1
                    `,
                    [req.user.id]
                );


            if (
                existing.rows.length > 0
            ) {

                return res.status(409).json({

                    success: false,

                    message:
                        "You already have a live stream.",

                    stream:
                        existing.rows[0]

                });

            }


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

                stream:
                    stream

            });


        } catch (error) {

            console.error(
                "Create stream failed:",
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
   GET MY STREAMS
========================================= */

app.get(
    "/api/streams/my",
    authenticateUser,
    async (req, res) => {

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

                        stream_recordings.id
                            AS recording_id,

                        stream_recordings.recording_url,

                        stream_recordings.duration_seconds

                    FROM streams

                    LEFT JOIN stream_recordings

                        ON stream_recordings.stream_id =
                           streams.id

                    WHERE streams.user_id = $1

                    ORDER BY
                        streams.created_at DESC
                    `,
                    [req.user.id]
                );


            return res.json({

                success: true,

                streams:
                    result.rows

            });


        } catch (error) {

            console.error(
                "Get my streams failed:",
                error.message
            );


            return res.status(500).json({

                success: false,

                message:
                    "Unable to load streams."

            });

        }

    }
);


/* =========================================
   GET LIVE STREAMS
========================================= */

app.get(
    "/api/streams/live",
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

                        streams.id,
                        streams.user_id,
                        streams.title,
                        streams.status,
                        streams.created_at,

                        users.name,
                        users.username,

                        profiles.profile_picture

                    FROM streams

                    INNER JOIN users
                        ON users.id =
                           streams.user_id

                    LEFT JOIN profiles
                        ON profiles.user_id =
                           users.id

                    WHERE streams.status =
                        'live'

                    ORDER BY
                        streams.created_at DESC
                    `
                );


            return res.json({

                success: true,

                streams:
                    result.rows

            });


        } catch (error) {

            console.error(
                "Get live streams failed:",
                error.message
            );


            return res.status(500).json({

                success: false,

                message:
                    "Unable to load live streams."

            });

        }

    }
);


/* =========================================
   END STREAM
========================================= */

app.put(
    "/api/streams/:id/end",
    authenticateUser,
    async (req, res) => {

        const streamId =
            req.params.id;


        try {

            const result =
                await pool.query(
                    `
                    UPDATE streams

                    SET
                        status = 'ended',

                        ended_at =
                            CURRENT_TIMESTAMP

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
                        "Live stream not found."

                });

            }


            return res.json({

                success: true,

                message:
                    "Canvas stream ended.",

                stream:
                    result.rows[0]

            });


        } catch (error) {

            console.error(
                "End stream failed:",
                error.message
            );


            return res.status(500).json({

                success: false,

                message:
                    "Unable to end stream."

            });

        }

    }
);


/* =========================================
   DELETE STREAM
========================================= */

app.delete(
    "/api/streams/:id",
    authenticateUser,
    async (req, res) => {

        const streamId =
            req.params.id;


        try {

            const result =
                await pool.query(
                    `
                    DELETE FROM streams

                    WHERE id = $1

                    AND user_id = $2

                    RETURNING id
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
                        "Stream not found."

                });

            }


            return res.json({

                success: true,

                message:
                    "Stream deleted successfully."

            });

        } catch (error) {

            console.error(
                "Delete stream failed:",
                error.message
            );


            return res.status(500).json({

                success: false,

                message:
                    "Unable to delete stream."

            });

        }

    }
);


/* =========================================
   RECORDING METADATA
========================================= */

app.post(
    "/api/streams/:id/recording",
    authenticateUser,
    async (req, res) => {

        const streamId =
            req.params.id;


        const {
            recordingUrl,
            durationSeconds
        } = req.body;


        if (!recordingUrl) {

            return res.status(400).json({

                success: false,

                message:
                    "Recording URL is required."

            });

        }


        try {

            const streamResult =
                await pool.query(
                    `
                    SELECT id

                    FROM streams

                    WHERE id = $1

                    AND user_id = $2

                    LIMIT 1
                    `,
                    [
                        streamId,
                        req.user.id
                    ]
                );


            if (
                streamResult.rows.length === 0
            ) {

                return res.status(404).json({

                    success: false,

                    message:
                        "Stream not found."

                });

            }


            const result =
                await pool.query(
                    `
                    INSERT INTO stream_recordings
                    (
                        stream_id,
                        user_id,
                        recording_url,
                        duration_seconds
                    )

                    VALUES
                    (
                        $1,
                        $2,
                        $3,
                        $4
                    )

                    ON CONFLICT (stream_id)

                    DO UPDATE SET

                        recording_url =
                            EXCLUDED.recording_url,

                        duration_seconds =
                            EXCLUDED.duration_seconds

                    RETURNING
                        id,
                        stream_id,
                        user_id,
                        recording_url,
                        duration_seconds,
                        created_at
                    `,
                    [
                        streamId,
                        req.user.id,
                        String(recordingUrl),
                        Number(durationSeconds) || 0
                    ]
                );


            return res.status(201).json({

                success: true,

                message:
                    "Stream recording saved.",

                recording:
                    result.rows[0]

            });


        } catch (error) {

            console.error(
                "Save recording failed:",
                error.message
            );


            return res.status(500).json({

                success: false,

                message:
                    "Unable to save stream recording."

            });

        }

    }
);
/* =========================================
   GET STREAM BY ID
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


        try {

            const streamId =
                req.params.id;


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
                        users.username,

                        profiles.profile_picture,

                        stream_recordings.id
                            AS recording_id,

                        stream_recordings.recording_url,

                        stream_recordings.duration_seconds

                    FROM streams

                    INNER JOIN users
                        ON users.id =
                           streams.user_id

                    LEFT JOIN profiles
                        ON profiles.user_id =
                           users.id

                    LEFT JOIN stream_recordings
                        ON stream_recordings.stream_id =
                           streams.id

                    WHERE streams.id = $1

                    LIMIT 1
                    `,
                    [streamId]
                );


            if (
                result.rows.length === 0
            ) {

                return res.status(404).json({

                    success: false,

                    message:
                        "Canvas stream not found."

                });

            }


            const stream =
                result.rows[0];


            return res.json({

                success: true,

                stream: {

                    id:
                        stream.id,

                    user_id:
                        stream.user_id,

                    title:
                        stream.title,

                    status:
                        stream.status,

                    created_at:
                        stream.created_at,

                    ended_at:
                        stream.ended_at,

                    name:
                        stream.name,

                    username:
                        stream.username,

                    profile_picture:
                        stream.profile_picture || "",

                    recording_id:
                        stream.recording_id || null,

                    recording_url:
                        stream.recording_url || "",

                    duration_seconds:
                        stream.duration_seconds || 0

                }

            });


        } catch (error) {

            console.error(
                "Get stream failed:",
                error.message
            );


            return res.status(500).json({

                success: false,

                message:
                    "Unable to load Canvas stream."

            });

        }

    }
);


/* =========================================
   GET MY RECORDINGS
========================================= */

app.get(
    "/api/recordings/my",
    authenticateUser,
    async (req, res) => {

        try {

            const result =
                await pool.query(
                    `
                    SELECT

                        stream_recordings.id,

                        stream_recordings.stream_id,

                        stream_recordings.recording_url,

                        stream_recordings.duration_seconds,

                        stream_recordings.created_at,

                        streams.title,

                        streams.created_at
                            AS stream_created_at,

                        streams.ended_at,

                        users.name,

                        users.username

                    FROM stream_recordings

                    INNER JOIN streams
                        ON streams.id =
                           stream_recordings.stream_id

                    INNER JOIN users
                        ON users.id =
                           stream_recordings.user_id

                    WHERE stream_recordings.user_id = $1

                    ORDER BY
                        stream_recordings.created_at DESC
                    `,
                    [req.user.id]
                );


            return res.json({

                success: true,

                recordings:
                    result.rows

            });


        } catch (error) {

            console.error(
                "Get recordings failed:",
                error.message
            );


            return res.status(500).json({

                success: false,

                message:
                    "Unable to load your recordings."

            });

        }

    }
);


/* =========================================
   DELETE RECORDING
========================================= */

app.delete(
    "/api/recordings/:id",
    authenticateUser,
    async (req, res) => {

        const recordingId =
            req.params.id;


        try {

            const result =
                await pool.query(
                    `
                    DELETE FROM stream_recordings

                    WHERE id = $1

                    AND user_id = $2

                    RETURNING id
                    `,
                    [
                        recordingId,
                        req.user.id
                    ]
                );


            if (
                result.rows.length === 0
            ) {

                return res.status(404).json({

                    success: false,

                    message:
                        "Recording not found."

                });

            }


            return res.json({

                success: true,

                message:
                    "Recording deleted successfully."

            });


        } catch (error) {

            console.error(
                "Delete recording failed:",
                error.message
            );


            return res.status(500).json({

                success: false,

                message:
                    "Unable to delete recording."

            });

        }

    }
);


/* =========================================
   WEBRTC SIGNALING
========================================= */

const streamRooms =
    new Map();


io.on(
    "connection",
    (socket) => {

        console.log(
            "Canvas WebRTC client connected:",
            socket.id
        );


        /* =====================================
           JOIN STREAM
        ===================================== */

        socket.on(
            "join-stream",
            ({ streamId, role }) => {

                if (!streamId) {
                    return;
                }


                const room =
                    String(streamId);


                socket.join(room);


                if (
                    !streamRooms.has(room)
                ) {

                    streamRooms.set(
                        room,
                        new Set()
                    );

                }


                const clients =
                    streamRooms.get(room);


                clients.add(
                    socket.id
                );


                socket.streamRoom =
                    room;


                socket.streamRole =
                    role ||
                    "viewer";


                socket.to(room).emit(
                    "peer-joined",
                    {
                        socketId:
                            socket.id,

                        role:
                            socket.streamRole
                    }
                );


                const existingPeers =
                    Array.from(clients)
                        .filter(
                            id =>
                                id !== socket.id
                        );


                socket.emit(
                    "existing-peers",
                    existingPeers
                );


                console.log(
                    `Client ${socket.id} joined stream ${room} as ${socket.streamRole}`
                );

            }
        );


        /* =====================================
           WEBRTC OFFER
        ===================================== */

        socket.on(
            "webrtc-offer",
            ({ target, offer }) => {

                if (
                    !target ||
                    !offer
                ) {

                    return;

                }


                io.to(target).emit(
                    "webrtc-offer",
                    {

                        sender:
                            socket.id,

                        offer:
                            offer

                    }
                );

            }
        );


        /* =====================================
           WEBRTC ANSWER
        ===================================== */

        socket.on(
            "webrtc-answer",
            ({ target, answer }) => {

                if (
                    !target ||
                    !answer
                ) {

                    return;

                }


                io.to(target).emit(
                    "webrtc-answer",
                    {

                        sender:
                            socket.id,

                        answer:
                            answer

                    }
                );

            }
        );


        /* =====================================
           ICE CANDIDATE
        ===================================== */

        socket.on(
            "webrtc-ice",
            ({ target, candidate }) => {

                if (
                    !target ||
                    !candidate
                ) {

                    return;

                }


                io.to(target).emit(
                    "webrtc-ice",
                    {

                        sender:
                            socket.id,

                        candidate:
                            candidate

                    }
                );

            }
        );


        /* =====================================
           LEAVE STREAM
        ===================================== */

        socket.on(
            "leave-stream",
            () => {

                removeSocketFromStream(
                    socket
                );

            }
        );


        /* =====================================
           DISCONNECT
        ===================================== */

        socket.on(
            "disconnect",
            () => {

                removeSocketFromStream(
                    socket
                );


                console.log(
                    "Canvas WebRTC client disconnected:",
                    socket.id
                );

            }
        );

    }
);


/* =========================================
   REMOVE SOCKET FROM STREAM
========================================= */

function removeSocketFromStream(
    socket
) {

    const room =
        socket.streamRoom;


    if (!room) {
        return;
    }


    const clients =
        streamRooms.get(room);


    if (clients) {

        clients.delete(
            socket.id
        );


        socket.to(room).emit(
            "peer-left",
            {
                socketId:
                    socket.id
            }
        );


        if (
            clients.size === 0
        ) {

            streamRooms.delete(
                room
            );

        }

    }


    socket.leave(
        room
    );


    socket.streamRoom =
        null;

}


/* =========================================
   SERVER HEALTH
========================================= */

app.get(
    "/api/health",
    async (req, res) => {

        if (!pool) {

            return res.status(500).json({

                success: false,

                status:
                    "unhealthy",

                database:
                    "not configured"

            });

        }


        try {

            await pool.query(
                "SELECT 1"
            );


            return res.json({

                success: true,

                status:
                    "healthy",

                database:
                    "connected",

                service:
                    "Canvas Backend"

            });


        } catch (error) {

            console.error(
                "Health check failed:",
                error.message
            );


            return res.status(500).json({

                success: false,

                status:
                    "unhealthy",

                database:
                    "connection failed"

            });

        }

    }
);
/* =========================================
   GET STREAM BY ID
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

        try {

            const streamId =
                req.params.id;


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
                        users.username,

                        profiles.profile_picture

                    FROM streams

                    INNER JOIN users
                        ON users.id =
                           streams.user_id

                    LEFT JOIN profiles
                        ON profiles.user_id =
                           users.id

                    WHERE streams.id = $1

                    LIMIT 1
                    `,
                    [streamId]
                );


            if (
                result.rows.length === 0
            ) {

                return res.status(404).json({

                    success: false,

                    message:
                        "Canvas stream not found."

                });

            }


            const stream =
                result.rows[0];


            return res.json({

                success: true,

                stream: {

                    id:
                        stream.id,

                    user_id:
                        stream.user_id,

                    title:
                        stream.title,

                    status:
                        stream.status,

                    created_at:
                        stream.created_at,

                    ended_at:
                        stream.ended_at,

                    name:
                        stream.name,

                    username:
                        stream.username,

                    profile_picture:
                        stream.profile_picture || ""

                }

            });


        } catch (error) {

            console.error(
                "Get stream failed:",
                error.message
            );


            return res.status(500).json({

                success: false,

                message:
                    "Unable to load Canvas stream."

            });

        }

    }
);


/* =========================================
   SERVER HEALTH
========================================= */

app.get(
    "/api/health",
    async (req, res) => {

        if (!pool) {

            return res.status(500).json({

                success: false,

                status:
                    "unhealthy",

                database:
                    "not configured"

            });

        }


        try {

            await pool.query(
                "SELECT 1"
            );


            return res.json({

                success: true,

                status:
                    "healthy",

                database:
                    "connected",

                service:
                    "Canvas Backend"

            });


        } catch (error) {

            console.error(
                "Health check failed:",
                error.message
            );


            return res.status(500).json({

                success: false,

                status:
                    "unhealthy",

                database:
                    "connection failed"

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


        res.status(500).json({

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


    httpServer.listen(
        PORT,
        () => {

            console.log(
                `Canvas backend running on port ${PORT}`
            );

        }
    );

}


startServer();
