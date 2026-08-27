const express = require("express");
const http = require("http");
const { Pool } = require("pg");
const crypto = require("crypto");
const { Server } = require("socket.io");

const app = express();

const server = http.createServer(app);

const io = new Server(server, {
    cors: {
        origin: "*",
        methods: [
            "GET",
            "POST",
            "PUT",
            "DELETE",
            "OPTIONS"
        ]
    }
});


const PORT =
    process.env.PORT || 3000;


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


const pool =
    databaseUrl
        ? new Pool({

            connectionString:
                databaseUrl,

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

async function authenticateUser(
    req,
    res,
    next
) {

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
                    ON users.id =
                       sessions.user_id

                WHERE
                    sessions.token_hash = $1

                AND
                    sessions.expires_at >
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

        /* =================================
           USERS
        ================================= */

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


        /* =================================
           PROFILES
        ================================= */

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


        /* =================================
           SESSIONS
        ================================= */

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


        /* =================================
           STREAMS
        ================================= */

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


        /* =================================
           STREAM USER ID
        ================================= */

        await pool.query(`
            ALTER TABLE streams

            ADD COLUMN IF NOT EXISTS
                user_id INTEGER
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
   BACKEND ROOT
========================================= */

app.get(
    "/",
    (req, res) => {

        res.json({

            status:
                "online",

            message:
                "Canvas backend is running."

        });

    }
);


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
                String(name)
                    .trim();


            const cleanUser =
                cleanUsername(
                    username
                );


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


            if (
                !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(
                    cleanEmail
                )
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Please enter a valid email address."

                });

            }


            /* =============================
               CHECK EXISTING USER
            ============================= */

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
                    String(
                        existing.username
                    ).toLowerCase() ===
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


            /* =============================
               HASH PASSWORD
            ============================= */

            const passwordHash =
                hashPassword(
                    password
                );


            /* =============================
               CREATE USER
            ============================= */

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


            /* =============================
               CREATE PROFILE
            ============================= */

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


            /* =============================
               CREATE SESSION
            ============================= */

            const token =
                createAuthToken();


            const tokenHash =
                hashToken(
                    token
                );


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


            /* =============================
               RESPONSE
            ============================= */

            return res.status(201).json({

                success: true,

                message:
                    "Canvas account created successfully.",

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
                "Signup failed:",
                error
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


        if (
            !email &&
            !username
        ) {

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


            /* =============================
               FIND USER
            ============================= */

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


            /* =============================
               CHECK PASSWORD
            ============================= */

            const passwordHash =
                hashPassword(
                    password
                );


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


            /* =============================
               CREATE SESSION
            ============================= */

            const token =
                createAuthToken();


            const tokenHash =
                hashToken(
                    token
                );


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


            /* =============================
               RESPONSE
            ============================= */

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

                    WHERE
                        LOWER(users.username) = $1

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


            const profile =
                result.rows[0];


            return res.json({

                success: true,

                profile: {

                    id:
                        profile.id,

                    name:
                        profile.name,

                    username:
                        profile.username,

                    email:
                        profile.email,

                    bio:
                        profile.bio || "",

                    profile_picture:
                        profile.profile_picture || "",

                    created_at:
                        profile.created_at,

                    updated_at:
                        profile.updated_at

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

                    WHERE
                        users.id = $1

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


            const profile =
                result.rows[0];


            return res.json({

                success: true,

                profile: {

                    id:
                        profile.id,

                    name:
                        profile.name,

                    username:
                        profile.username,

                    email:
                        profile.email,

                    bio:
                        profile.bio || "",

                    profile_picture:
                        profile.profile_picture || "",

                    created_at:
                        profile.created_at,

                    updated_at:
                        profile.updated_at

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

                    WHERE
                        LOWER(username) = $1

                    AND
                        id != $2

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

                    WHERE
                        id = $3

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
                    SELECT
                        password_hash

                    FROM users

                    WHERE
                        id = $1

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
                result.rows[0]
                    .password_hash !==
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

                SET
                    password_hash = $1

                WHERE
                    id = $2
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


        try {

            /*
             * Prevent the same user from
             * accidentally creating multiple
             * live streams.
             */

            const existing =
                await pool.query(
                    `
                    SELECT

                        id,
                        user_id,
                        title,
                        status,
                        created_at,
                        ended_at

                    FROM streams

                    WHERE
                        user_id = $1

                    AND
                        status = 'live'

                    ORDER BY
                        created_at DESC

                    LIMIT 1
                    `,
                    [req.user.id]
                );


            if (
                existing.rows.length > 0
            ) {

                return res.json({

                    success: true,

                    existing: true,

                    message:
                        "You already have a live Canvas stream.",

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
                        created_at,
                        ended_at
                    `,
                    [
                        req.user.id,

                        title ||
                        "Canvas Live Stream"
                    ]
                );


            return res.status(201).json({

                success: true,

                existing: false,

                message:
                    "Canvas stream started.",

                stream:
                    result.rows[0]

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
   GET CURRENT LIVE STREAM
========================================= */

app.get(
    "/api/streams/current",
    authenticateUser,
    async (req, res) => {

        try {

            const result =
                await pool.query(
                    `
                    SELECT

                        id,
                        user_id,
                        title,
                        status,
                        created_at,
                        ended_at

                    FROM streams

                    WHERE
                        user_id = $1

                    AND
                        status = 'live'

                    ORDER BY
                        created_at DESC

                    LIMIT 1
                    `,
                    [req.user.id]
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
                "Get current stream failed:",
                error.message
            );


            return res.status(500).json({

                success: false,

                message:
                    "Unable to check current stream."

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

                        id,
                        user_id,
                        title,
                        status,
                        created_at,
                        ended_at

                    FROM streams

                    WHERE
                        user_id = $1

                    ORDER BY
                        created_at DESC
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
                "Get streams failed:",
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
   GET ALL LIVE STREAMS
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

                    WHERE
     streams.status = 'live'

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

                    WHERE
                        id = $1

                    AND
                        user_id = $2

                    AND
                        status = 'live'

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


            /*
             * Tell all connected viewers
             * that this stream has ended.
             */

            io.to(
                `stream:${streamId}`
            ).emit(
                "stream-ended",
                {
                    streamId:
                        String(streamId)
                }
            );


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

                    WHERE
                        id = $1

                    AND
                        user_id = $2

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


            io.to(
                `stream:${streamId}`
            ).emit(
                "stream-deleted",
                {
                    streamId:
                        String(streamId)
                }
            );


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
   SOCKET.IO CONNECTION
========================================= */

io.on(
    "connection",
    (socket) => {

        console.log(
            "Canvas realtime client connected:",
            socket.id
        );


        /* =================================
           STREAMER JOIN
        ================================= */

        socket.on(
            "streamer-join",
            async (data) => {

                try {

                    const streamId =
                        String(
                            data &&
                            data.streamId ||
                            ""
                        ).trim();


                    if (!streamId) {

                        return socket.emit(
                            "signaling-error",
                            {
                                message:
                                    "Stream ID is required."
                            }
                        );

                    }


                    if (!pool) {

                        return socket.emit(
                            "signaling-error",
                            {
                                message:
                                    "Database is not configured."
                            }
                        );

                    }


                    const result =
                        await pool.query(
                            `
                            SELECT

                                id,
                                user_id,
                                title,
                                status

                            FROM streams

                            WHERE
                                id = $1

                            LIMIT 1
                            `,
                            [streamId]
                        );


                    if (
                        result.rows.length === 0
                    ) {

                        return socket.emit(
                            "signaling-error",
                            {
                                message:
                                    "Stream not found."
                            }
                        );

                    }


                    const stream =
                        result.rows[0];


                    if (
                        String(
                            stream.status
                        ) !== "live"
                    ) {

                        return socket.emit(
                            "signaling-error",
                            {
                                message:
                                    "This stream is not live."
                            }
                        );

                    }


                    /*
                     * Store information on the
                     * Socket.IO connection.
                     */

                    socket.data.role =
                        "streamer";


                    socket.data.streamId =
                        streamId;


                    socket.data.userId =
                        String(
                            stream.user_id
                        );


                    /*
                     * Put streamer inside the
                     * stream room.
                     */

                    socket.join(
                        `stream:${streamId}`
                    );


                    socket.emit(
                        "streamer-joined",
                        {
                            streamId:
                                streamId
                        }
                    );


                    /*
                     * Tell viewers already inside
                     * the room that the streamer
                     * is available.
                     */

                    socket
                        .to(
                            `stream:${streamId}`
                        )
                        .emit(
                            "streamer-ready",
                            {
                                streamId:
                                    streamId
                            }
                        );


                    console.log(
                        `Streamer ${socket.id} joined stream ${streamId}`
                    );


                } catch (error) {

                    console.error(
                        "Streamer join failed:",
                        error.message
                    );


                    socket.emit(
                        "signaling-error",
                        {
                            message:
                                "Unable to join stream as streamer."
                        }
                    );

                }

            }
        );


        /* =================================
           VIEWER JOIN
        ================================= */

        socket.on(
            "viewer-join",
            async (data) => {

                try {

                    const streamId =
                        String(
                            data &&
                            data.streamId ||
                            ""
                        ).trim();


                    if (!streamId) {

                        return socket.emit(
                            "signaling-error",
                            {
                                message:
                                    "Stream ID is required."
                            }
                        );

                    }


                    if (!pool) {

                        return socket.emit(
                            "signaling-error",
                            {
                                message:
                                    "Database is not configured."
                            }
                        );

                    }


                    /*
                     * Confirm the stream exists
                     * and is still live.
                     */

                    const result =
                        await pool.query(
                            `
                            SELECT

                                id,
                                user_id,
                                title,
                                status

                            FROM streams

                            WHERE
                                id = $1

                            LIMIT 1
                            `,
                            [streamId]
                        );


                    if (
                        result.rows.length === 0
                    ) {

                        return socket.emit(
                            "signaling-error",
                            {
                                message:
                                    "Stream not found."
                            }
                        );

                    }


                    const stream =
                        result.rows[0];


                    if (
                        String(
                            stream.status
                        ) !== "live"
                    ) {

                        return socket.emit(
                            "signaling-error",
                            {
                                message:
                                    "This stream is no longer live."
                            }
                        );

                    }


                    socket.data.role =
                        "viewer";


                    socket.data.streamId =
                        streamId;


                    socket.join(
                        `stream:${streamId}`
                    );


                    socket.emit(
                        "viewer-joined",
                        {
                            streamId:
                                streamId
                        }
                    );


                    /*
                     * Find the streamer currently
                     * connected to this stream.
                     */

                    const room =
                        io.sockets.adapter.rooms.get(
                            `stream:${streamId}`
                        );


                    if (room) {

                        for (
                            const socketId
                            of room
                        ) {

                            const otherSocket =
                                io.sockets.sockets.get(
                                    socketId
                                );


                            if (
                                otherSocket &&
                                otherSocket.data.role ===
                                "streamer"
                            ) {

                                otherSocket.emit(
                                    "viewer-ready",
                                    {
                                        streamId:
                                            streamId,

                                        viewerId:
                                            socket.id
                                    }
                                );

                            }

                        }

                    }


                    console.log(
                        `Viewer ${socket.id} joined stream ${streamId}`
                    );


                } catch (error) {

                    console.error(
                        "Viewer join failed:",
                        error.message
                    );


                    socket.emit(
                        "signaling-error",
                        {
                            message:
                                "Unable to join stream as viewer."
                        }
                    );

                }

            }
        );


        /* =================================
           WEBRTC OFFER
        ================================= */

        socket.on(
            "offer",
            (data) => {

                const viewerId =
                    data &&
                    data.viewerId;


                const streamId =
                    data &&
                    data.streamId;


                const offer =
                    data &&
                    data.offer;


                if (
                    !viewerId ||
                    !streamId ||
                    !offer
                ) {

                    return;

                }


                const viewerSocket =
                    io.sockets.sockets.get(
                        viewerId
                    );


                if (
                    !viewerSocket
                ) {

                    return;

                }


                viewerSocket.emit(
                    "offer",
                    {

                        streamId:
                            String(streamId),

                        streamerId:
                            socket.id,

                        offer:
                            offer

                    }
                );

            }
        );


        /* =================================
           WEBRTC ANSWER
        ================================= */

        socket.on(
            "answer",
            (data) => {

                const streamerId =
                    data &&
                    data.streamerId;


                const streamId =
                    data &&
                    data.streamId;


                const answer =
                    data &&
                    data.answer;


                if (
                    !streamerId ||
                    !streamId ||
                    !answer
                ) {

                    return;

                }


                const streamerSocket =
                    io.sockets.sockets.get(
                        streamerId
                    );


                if (
                    !streamerSocket
                ) {

                    return;

                }


                streamerSocket.emit(
                    "answer",
                    {

                        streamId:
                            String(streamId),

                        viewerId:
                            socket.id,

                        answer:
                            answer

                    }
                );

            }
        );


        /* =================================
           ICE CANDIDATE
        ================================= */

        socket.on(
            "ice-candidate",
            (data) => {

                const targetId =
                    data &&
                    data.targetId;


                const streamId =
                    data &&
                    data.streamId;


                const candidate =
                    data &&
                    data.candidate;


                if (
                    !targetId ||
                    !streamId ||
                    !candidate
                ) {

                    return;

                }


                const targetSocket =
                    io.sockets.sockets.get(
                        targetId
                    );


                if (
                    !targetSocket
                ) {

                    return;

                }


                targetSocket.emit(
                    "ice-candidate",
                    {

                        streamId:
                            String(streamId),

                        senderId:
                            socket.id,

                        candidate:
                            candidate

                    }
                );

            }
        );
              /* =================================
           VIEWER LEAVE
        ================================= */

        socket.on(
            "viewer-leave",
            (data) => {

                const streamId =
                    data &&
                    data.streamId;


                if (!streamId) {

                    return;

                }


                socket.leave(
                    `stream:${streamId}`
                );


                /*
                 * Tell the streamer that this
                 * viewer has disconnected.
                 */

                socket
                    .to(
                        `stream:${streamId}`
                    )
                    .emit(
                        "viewer-left",
                        {
                            streamId:
                                String(streamId),

                            viewerId:
                                socket.id
                        }
                    );

            }
        );


        /* =================================
           STREAMER LEAVE
        ================================= */

        socket.on(
            "streamer-leave",
            async (data) => {

                const streamId =
                    data &&
                    data.streamId;


                if (!streamId) {

                    return;

                }


                try {

                    /*
                     * End the database stream
                     * automatically when the
                     * streamer leaves.
                     */

                    if (pool) {

                        await pool.query(
                            `
                            UPDATE streams

                            SET

                                status = 'ended',

                                ended_at =
                                    CURRENT_TIMESTAMP

                            WHERE
                                id = $1

                            AND
                                user_id = $2

                            AND
                                status = 'live'
                            `,
                            [
                                streamId,
                                socket.data.userId
                            ]
                        );

                    }


                    /*
                     * Tell every viewer that
                     * the stream has ended.
                     */

                    io.to(
                        `stream:${streamId}`
                    ).emit(
                        "stream-ended",
                        {
                            streamId:
                                String(streamId)
                        }
                    );


                    console.log(
                        `Streamer left stream ${streamId}`
                    );


                } catch (error) {

                    console.error(
                        "Streamer leave failed:",
                        error.message
                    );

                }

            }
        );


        /* =================================
           DISCONNECT
        ================================= */

        socket.on(
            "disconnect",
            async () => {

                console.log(
                    "Canvas realtime client disconnected:",
                    socket.id
                );


                /*
                 * If the disconnected socket was
                 * a streamer, mark its stream ended.
                 */

                if (
                    socket.data &&
                    socket.data.role ===
                    "streamer" &&
                    socket.data.streamId
                ) {

                    const streamId =
                        socket.data.streamId;


                    try {

                        if (pool) {

                            await pool.query(
                                `
                                UPDATE streams

                                SET

                                    status = 'ended',

                                    ended_at =
                                        CURRENT_TIMESTAMP

                                WHERE
                                    id = $1

                                AND
                                    user_id = $2

                                AND
                                    status = 'live'
                                `,
                                [
                                    streamId,

                                    socket.data.userId
                                ]
                            );

                        }


                        io.to(
                            `stream:${streamId}`
                        ).emit(
                            "stream-ended",
                            {
                                streamId:
                                    String(streamId)
                            }
                        );


                    } catch (error) {

                        console.error(
                            "Disconnect stream cleanup failed:",
                            error.message
                        );

                    }

                }


                /*
                 * If this was a viewer,
                 * notify the streamer.
                 */

                if (
                    socket.data &&
                    socket.data.role ===
                    "viewer" &&
                    socket.data.streamId
                ) {

                    socket
                        .to(
                            `stream:${socket.data.streamId}`
                        )
                        .emit(
                            "viewer-left",
                            {
                                streamId:
                                    String(
                                        socket.data.streamId
                                    ),

                                viewerId:
                                    socket.id
                            }
                        );

                }

            }
        );

    }
);


/* =========================================
   HEALTH CHECK
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
                    "connected"

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
    (
        error,
        req,
        res,
        next
    ) => {

        console.error(
            "Canvas server error:",
            error
        );


        if (
            res.headersSent
        ) {

            return next(error);

        }


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


    server.listen(
        PORT,
        () => {

            console.log(
                `Canvas backend running on port ${PORT}`
            );

        }
    );

}


startServer();
