const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const { Pool } = require("pg");
const crypto = require("crypto");

const app = express();
const httpServer = http.createServer(app);

const io = new Server(httpServer, {
    cors: {
        origin: "*",
        methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    },
    transports: ["websocket", "polling"]
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
   JSON BODY
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
   SAFE STRING
========================================= */

function safeString(value, fallback = "") {

    if (
        value === null ||
        value === undefined
    ) {
        return fallback;
    }

    return String(value).trim();

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
            message: "Database is not configured."
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

        /* =====================================
           USERS
        ===================================== */

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

        /* =====================================
           PROFILES
        ===================================== */

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
           SESSIONS
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
           STREAMS
        ===================================== */

        await pool.query(`
            CREATE TABLE IF NOT EXISTS streams (
                id SERIAL PRIMARY KEY,
                user_id INTEGER
                    REFERENCES users(id)
                    ON DELETE CASCADE,
                stream_id TEXT UNIQUE,
                title VARCHAR(255)
                    DEFAULT 'Canvas Live Stream',
                category VARCHAR(100) DEFAULT '',
                description TEXT DEFAULT '',
                thumbnail TEXT DEFAULT '',
                status VARCHAR(30)
                    DEFAULT 'live',
                created_at TIMESTAMP
                    DEFAULT CURRENT_TIMESTAMP,
                ended_at TIMESTAMP
            );
        `);

        /* =====================================
           STREAM MIGRATIONS
        ===================================== */

        await pool.query(`
            ALTER TABLE streams
            ADD COLUMN IF NOT EXISTS user_id
            INTEGER REFERENCES users(id)
            ON DELETE CASCADE;
        `);

        await pool.query(`
            ALTER TABLE streams
            ADD COLUMN IF NOT EXISTS stream_id TEXT;
        `);

        await pool.query(`
            ALTER TABLE streams
            ADD COLUMN IF NOT EXISTS category
            VARCHAR(100) DEFAULT '';
        `);

        await pool.query(`
            ALTER TABLE streams
            ADD COLUMN IF NOT EXISTS description
            TEXT DEFAULT '';
        `);

        await pool.query(`
            ALTER TABLE streams
            ADD COLUMN IF NOT EXISTS thumbnail
            TEXT DEFAULT '';
        `);

        await pool.query(`
            CREATE UNIQUE INDEX IF NOT EXISTS
            streams_stream_id_unique
            ON streams(stream_id)
            WHERE stream_id IS NOT NULL;
        `);

        /* =====================================
           FOLLOWS
        ===================================== */

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

                UNIQUE (
                    follower_id,
                    following_id
                ),

                CHECK (
                    follower_id <> following_id
                )
            );
        `);

        await pool.query(`
            CREATE INDEX IF NOT EXISTS
            follows_follower_idx
            ON follows(follower_id);
        `);

        await pool.query(`
            CREATE INDEX IF NOT EXISTS
            follows_following_idx
            ON follows(following_id);
        `);

        /* =====================================
           CHAT MESSAGES
        ===================================== */

        await pool.query(`
            CREATE TABLE IF NOT EXISTS stream_messages (
                id BIGSERIAL PRIMARY KEY,

                stream_id TEXT NOT NULL,

                user_id INTEGER
                    REFERENCES users(id)
                    ON DELETE SET NULL,

                username VARCHAR(100) DEFAULT '',
                message TEXT NOT NULL,

                created_at TIMESTAMP
                    DEFAULT CURRENT_TIMESTAMP
            );
        `);

        await pool.query(`
            CREATE INDEX IF NOT EXISTS
            stream_messages_stream_idx
            ON stream_messages(stream_id, created_at);
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
                database: "not connected",
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
   HEALTH CHECK
========================================= */

app.get(
    "/api/health",
    async (req, res) => {

        if (!pool) {

            return res.status(500).json({
                success: false,
                status: "unhealthy",
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
                status: "healthy",
                database: "connected"
            });

        } catch (error) {

            return res.status(500).json({
                success: false,
                status: "unhealthy",
                database:
                    "connection failed"
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
                safeString(name);

            const cleanUser =
                cleanUsername(username);

            const cleanEmail =
                safeString(email)
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
                !/^[a-zA-Z0-9_.]+$/
                    .test(cleanUser)
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
                    String(
                        existing.username
                    ).toLowerCase() ===
                    cleanUser
                ) {

                    return res.status(409)
                        .json({
                            success: false,
                            message:
                                "Username already exists."
                        });

                }

                return res.status(409)
                    .json({
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
                    VALUES ($1,$2,$3,$4)
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
                VALUES ($1,'','')
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
                VALUES (
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

            return res.status(201)
                .json({
                    success: true,
                    message:
                        "Canvas account created successfully.",
                    token,
                    user: {
                        id: user.id,
                        name: user.name,
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

            return res.status(500)
                .json({
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
                safeString(email)
                    .toLowerCase();

            const passwordHash =
                hashPassword(password);

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
                    [cleanEmail]
                );

            if (
                result.rows.length === 0
            ) {

                return res.status(401)
                    .json({
                        success: false,
                        message:
                            "Email or password is incorrect."
                    });

            }

            const user =
                result.rows[0];

            if (
                user.password_hash !==
                passwordHash
            ) {

                return res.status(401)
                    .json({
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
                VALUES (
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
                token,
                user: {
                    id: user.id,
                    name: user.name,
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

            return res.status(500)
                .json({
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
                        profiles.profile_picture
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

                return res.status(404)
                    .json({
                        success: false,
                        message:
                            "User not found."
                    });

            }

            const user =
                result.rows[0];

            return res.json({
                success: true,
                user: {
                    id: user.id,
                    name: user.name,
                    username:
                        user.username,
                    email:
                        user.email,
                    profile_picture:
                        user.profile_picture
                        || "",
                    created_at:
                        user.created_at
                }
            });

        } catch (error) {

            console.error(
                "Get current user failed:",
                error.message
            );

            return res.status(500)
                .json({
                    success: false,
                    message:
                        "Unable to get current user."
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
                        profiles.id AS profile_id,
                        profiles.bio,
                        profiles.profile_picture,
                        profiles.updated_at,

                        (
                            SELECT COUNT(*)
                            FROM follows
                            WHERE following_id =
                                  users.id
                        ) AS followers_count,

                        (
                            SELECT COUNT(*)
                            FROM follows
                            WHERE follower_id =
                                  users.id
                        ) AS following_count

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

                return res.status(404)
                    .json({
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
                    id: p.id,
                    name: p.name,
                    username:
                        p.username,
                    email:
                        p.email,
                    bio:
                        p.bio || "",
                    profile_picture:
                        p.profile_picture
                        || "",
                    created_at:
                        p.created_at,
                    updated_at:
                        p.updated_at,

                    followers_count:
                        Number(
                            p.followers_count
                            || 0
                        ),

                    following_count:
                        Number(
                            p.following_count
                            || 0
                        )
                }
            });

        } catch (error) {

            console.error(
                "Get profile failed:",
                error.message
            );

            return res.status(500)
                .json({
                    success: false,
                    message:
                        "Unable to load Canvas profile."
                });

        }

    }
);

/* =========================================
   GET PUBLIC PROFILE
========================================= */

app.get(
    "/api/profile/:username",
    async (req, res) => {

        const username =
            cleanUsername(
                req.params.username
            );

        if (!username) {

            return res.status(400)
                .json({
                    success: false,
                    message:
                        "Username is required."
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
                        users.created_at,
                        profiles.bio,
                        profiles.profile_picture,

                        (
                            SELECT COUNT(*)
                            FROM follows
                            WHERE following_id =
                                  users.id
                        ) AS followers_count,

                        (
                            SELECT COUNT(*)
                            FROM follows
                            WHERE follower_id =
                                  users.id
                        ) AS following_count

                    FROM users

                    LEFT JOIN profiles
                        ON profiles.user_id =
                           users.id

                    WHERE LOWER(users.username) =
                          $1

                    LIMIT 1
                    `,
                    [username]
                );

            if (
                result.rows.length === 0
            ) {

                return res.status(404)
                    .json({
                        success: false,
                        message:
                            "Profile not found."
                    });

            }

            const p =
                result.rows[0];

            return res.json({
                success: true,

                profile: {
                    id: p.id,
                    name: p.name,
                    username:
                        p.username,
                    bio:
                        p.bio || "",
                    profile_picture:
                        p.profile_picture
                        || "",
                    created_at:
                        p.created_at,

                    followers_count:
                        Number(
                            p.followers_count
                            || 0
                        ),

                    following_count:
                        Number(
                            p.following_count
                            || 0
                        )
                }
            });

        } catch (error) {

            console.error(
                "Public profile failed:",
                error.message
            );

            return res.status(500)
                .json({
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
                safeString(
                    name !== undefined
                        ? name
                        : req.user.name
                );

            const cleanUsernameValue =
                cleanUsername(
                    username !== undefined
                        ? username
                        : req.user.username
                );

            const cleanBio =
                safeString(
                    bio !== undefined
                        ? bio
                        : ""
                );

            const cleanProfilePicture =
                profile_picture !== undefined
                    ? String(
                        profile_picture
                    )
                    : "";

            if (!cleanName) {

                return res.status(400)
                    .json({
                        success: false,
                        message:
                            "Name cannot be empty."
                    });

            }

            if (!cleanUsernameValue) {

                return res.status(400)
                    .json({
                        success: false,
                        message:
                            "Username cannot be empty."
                    });

            }

            if (
                !/^[a-zA-Z0-9_.]+$/
                    .test(
                        cleanUsernameValue
                    )
            ) {

                return res.status(400)
                    .json({
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
                        cleanUsernameValue,
                        req.user.id
                    ]
                );

            if (
                usernameCheck.rows.length > 0
            ) {

                return res.status(409)
                    .json({
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
                        cleanUsernameValue,
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
                VALUES (
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
                    cleanProfilePicture
                ]
            );

            return res.json({
                success: true,
                message:
                    "Profile updated successfully.",

                user: {
                    id:
                        userResult.rows[0].id,
                    name:
                        userResult.rows[0].name,
                    username:
                        userResult.rows[0].username,
                    email:
                        userResult.rows[0].email,
                    bio:
                        cleanBio,
                    profile_picture:
                        cleanProfilePicture
                }
            });

        } catch (error) {

            console.error(
                "Update profile failed:",
                error.message
            );

            return res.status(500)
                .json({
                    success: false,
                    message:
                        "Unable to update Canvas profile."
                });

        }

    }
);

/* =========================================
   DELETE PROFILE PICTURE
========================================= */

app.delete(
    "/api/profile/picture",
    authenticateUser,
    async (req, res) => {

        try {

            await pool.query(
                `
                UPDATE profiles
                SET
                    profile_picture = '',
                    updated_at =
                        CURRENT_TIMESTAMP
                WHERE user_id = $1
                `,
                [req.user.id]
            );

            return res.json({
                success: true,
                message:
                    "Profile picture deleted successfully."
            });

        } catch (error) {

            console.error(
                "Delete profile picture failed:",
                error.message
            );

            return res.status(500)
                .json({
                    success: false,
                    message:
                        "Unable to delete profile picture."
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
                [hashToken(token)]
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

            return res.status(500)
                .json({
                    success: false,
                    message:
                        "Unable to log out."
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

            return res.status(400)
                .json({
                    success: false,
                  message:
                        "Current and new passwords are required."
                });

        }

        if (
            String(newPassword).length < 8
        ) {

            return res.status(400)
                .json({
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

                return res.status(404)
                    .json({
                        success: false,
                        message:
                            "User not found."
                    });

            }

            if (
                result.rows[0]
                    .password_hash !==
                hashPassword(
                    currentPassword
                )
            ) {

                return res.status(401)
                    .json({
                        success: false,
                        message:
                            "Current password is incorrect."
                    });

            }

            await pool.query(
                `
                UPDATE users
                SET password_hash = $1
                WHERE id = $2
                `,
                [
                    hashPassword(
                        newPassword
                    ),
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

            return res.status(500)
                .json({
                    success: false,
                    message:
                        "Unable to change password."
                });

        }

    }
);
/* =========================================
   FOLLOW USER
========================================= */

app.post(
    "/api/users/:username/follow",
    authenticateUser,
    async (req, res) => {

        const targetUsername =
            cleanUsername(
                req.params.username
            );

        if (!targetUsername) {

            return res.status(400)
                .json({
                    success: false,
                    message:
                        "Username is required."
                });

        }

        try {

            const targetResult =
                await pool.query(
                    `
                    SELECT id, name, username
                    FROM users
                    WHERE LOWER(username) = $1
                    LIMIT 1
                    `,
                    [targetUsername]
                );

            if (
                targetResult.rows.length === 0
            ) {

                return res.status(404)
                    .json({
                        success: false,
                        message:
                            "User not found."
                    });

            }

            const target =
                targetResult.rows[0];

            if (
                Number(target.id) ===
                Number(req.user.id)
            ) {

                return res.status(400)
                    .json({
                        success: false,
                        message:
                            "You cannot follow yourself."
                    });

            }

            const insertResult =
                await pool.query(
                    `
                    INSERT INTO follows
                    (
                        follower_id,
                        following_id
                    )
                    VALUES ($1,$2)

                    ON CONFLICT
                    (
                        follower_id,
                        following_id
                    )
                    DO NOTHING

                    RETURNING id
                    `,
                    [
                        req.user.id,
                        target.id
                    ]
                );

            const counts =
                await getFollowCounts(
                    target.id
                );

            const following =
                await isFollowing(
                    req.user.id,
                    target.id
                );

            /* =================================
               REALTIME FOLLOW UPDATE
            ================================= */

            io.to(
                "user:" + target.id
            ).emit(
                "follow-updated",
                {
                    action: "follow",
                    follower: {
                        id:
                            req.user.id,
                        name:
                            req.user.name,
                        username:
                            req.user.username
                    },
                    target: {
                        id:
                            target.id,
                        name:
                            target.name,
                        username:
                            target.username
                    },
                    followersCount:
                        counts.followersCount
                }
            );

            io.to(
                "user:" + req.user.id
            ).emit(
                "follow-updated",
                {
                    action: "follow",
                    follower: {
                        id:
                            req.user.id,
                        name:
                            req.user.name,
                        username:
                            req.user.username
                    },
                    target: {
                        id:
                            target.id,
                        name:
                            target.name,
                        username:
                            target.username
                    },
                    followingCount:
                        await getFollowingCount(
                            req.user.id
                        )
                }
            );

            return res.json({
                success: true,
                following: true,
                created:
                    insertResult.rows.length > 0,

                user: {
                    id:
                        target.id,
                    name:
                        target.name,
                    username:
                        target.username
                },

                followers_count:
                    counts.followersCount,

                following_count:
                    counts.followingCount
            });

        } catch (error) {

            console.error(
                "Follow failed:",
                error.message
            );

            return res.status(500)
                .json({
                    success: false,
                    message:
                        "Unable to follow user."
                });

        }

    }
);

/* =========================================
   UNFOLLOW USER
========================================= */

app.delete(
    "/api/users/:username/follow",
    authenticateUser,
    async (req, res) => {

        const targetUsername =
            cleanUsername(
                req.params.username
            );

        if (!targetUsername) {

            return res.status(400)
                .json({
                    success: false,
                    message:
                        "Username is required."
                });

        }

        try {

            const targetResult =
                await pool.query(
                    `
                    SELECT id, name, username
                    FROM users
                    WHERE LOWER(username) = $1
                    LIMIT 1
                    `,
                    [targetUsername]
                );

            if (
                targetResult.rows.length === 0
            ) {

                return res.status(404)
                    .json({
                        success: false,
                        message:
                            "User not found."
                    });

            }

            const target =
                targetResult.rows[0];

            const deleteResult =
                await pool.query(
                    `
                    DELETE FROM follows
                    WHERE follower_id = $1
                      AND following_id = $2
                    RETURNING id
                    `,
                    [
                        req.user.id,
                        target.id
                    ]
                );

            const counts =
                await getFollowCounts(
                    target.id
                );

            io.to(
                "user:" + target.id
            ).emit(
                "follow-updated",
                {
                    action: "unfollow",
                    follower: {
                        id:
                            req.user.id,
                        name:
                            req.user.name,
                        username:
                            req.user.username
                    },
                    target: {
                        id:
                            target.id,
                        name:
                            target.name,
                        username:
                            target.username
                    },
                    followersCount:
                        counts.followersCount
                }
            );

            io.to(
                "user:" + req.user.id
            ).emit(
                "follow-updated",
                {
                    action: "unfollow",
                    follower: {
                        id:
                            req.user.id,
                        name:
                            req.user.name,
                        username:
                            req.user.username
                    },
                    target: {
                        id:
                            target.id,
                        name:
                            target.name,
                        username:
                            target.username
                    },
                    followingCount:
                        await getFollowingCount(
                            req.user.id
                        )
                }
            );

            return res.json({
                success: true,
                following: false,
                removed:
                    deleteResult.rows.length > 0,

                user: {
                    id:
                        target.id,
                    name:
                        target.name,
                    username:
                        target.username
                },

                followers_count:
                    counts.followersCount,

                following_count:
                    counts.followingCount
            });

        } catch (error) {

            console.error(
                "Unfollow failed:",
                error.message
            );

            return res.status(500)
                .json({
                    success: false,
                    message:
                        "Unable to unfollow user."
                });

        }

    }
);

/* =========================================
   CHECK FOLLOW STATUS
========================================= */

app.get(
    "/api/users/:username/follow",
    async (req, res) => {

        const targetUsername =
            cleanUsername(
                req.params.username
            );

        try {

            const targetResult =
                await pool.query(
                    `
                    SELECT id
                    FROM users
                    WHERE LOWER(username) = $1
                    LIMIT 1
                    `,
                    [targetUsername]
                );

            if (
                targetResult.rows.length === 0
            ) {

                return res.status(404)
                    .json({
                        success: false,
                        message:
                            "User not found."
                    });

            }

            const targetId =
                targetResult.rows[0].id;

            let viewerId = null;

            const authorization =
                req.headers.authorization
                || "";

            if (
                authorization.startsWith(
                    "Bearer "
                )
            ) {

                const token =
                    authorization
                        .substring(7)
                        .trim();

                if (token) {

                    const authResult =
                        await pool.query(
                            `
                            SELECT user_id
                            FROM sessions
                            WHERE token_hash = $1
                              AND expires_at >
                                  CURRENT_TIMESTAMP
                            LIMIT 1
                            `,
                            [
                                hashToken(
                                    token
                                )
                            ]
                        );

                    if (
                        authResult.rows.length
                        > 0
                    ) {

                        viewerId =
                            authResult.rows[0]
                                .user_id;

                    }

                }

            }

            let following = false;

            if (viewerId) {

                following =
                    await isFollowing(
                        viewerId,
                        targetId
                    );

            }

            const counts =
                await getFollowCounts(
                    targetId
                );

            return res.json({
                success: true,
                following,

                followers_count:
                    counts.followersCount,

                following_count:
                    counts.followingCount
            });

        } catch (error) {

            console.error(
                "Follow status failed:",
                error.message
            );

            return res.status(500)
                .json({
                    success: false,
                    message:
                        "Unable to check follow status."
                });

        }

    }
);

/* =========================================
   FOLLOWERS
========================================= */

app.get(
    "/api/users/:username/followers",
    async (req, res) => {

        const username =
            cleanUsername(
                req.params.username
            );

        try {

            const result =
                await pool.query(
                    `
                    SELECT
                        users.id,
                        users.name,
                        users.username,
                        profiles.profile_picture,
                        follows.created_at

                    FROM follows

                    INNER JOIN users
                        ON users.id =
                           follows.follower_id

                    LEFT JOIN profiles
                        ON profiles.user_id =
                           users.id

                    INNER JOIN users target
                        ON target.id =
                           follows.following_id

                    WHERE LOWER(target.username) =
                          $1

                    ORDER BY
                        follows.created_at DESC
                    `,
                    [username]
                );

            return res.json({
                success: true,
                followers:
                    result.rows.map(
                        row => ({
                            id:
                                row.id,
                            name:
                                row.name,
                            username:
                                row.username,
                            profile_picture:
                                row.profile_picture
                                || "",
                            created_at:
                                row.created_at
                        })
                    )
            });

        } catch (error) {

            console.error(
                "Followers failed:",
                error.message
            );

            return res.status(500)
                .json({
                    success: false,
                    message:
                        "Unable to load followers."
                });

        }

    }
);

/* =========================================
   FOLLOWING
========================================= */

app.get(
    "/api/users/:username/following",
    async (req, res) => {

        const username =
            cleanUsername(
                req.params.username
            );

        try {

            const result =
                await pool.query(
                    `
                    SELECT
                        users.id,
                        users.name,
                        users.username,
                        profiles.profile_picture,
                        follows.created_at

                    FROM follows

                    INNER JOIN users
                        ON users.id =
                           follows.following_id

                    LEFT JOIN profiles
                        ON profiles.user_id =
                           users.id

                    INNER JOIN users source
                        ON source.id =
                           follows.follower_id

                    WHERE LOWER(source.username) =
                          $1

                    ORDER BY
                        follows.created_at DESC
                    `,
                    [username]
                );

            return res.json({
                success: true,
                following:
                    result.rows.map(
                        row => ({
                            id:
                                row.id,
                            name:
                                row.name,
                            username:
                                row.username,
                            profile_picture:
                                row.profile_picture
                                || "",
                            created_at:
                                row.created_at
                        })
                    )
            });

        } catch (error) {

            console.error(
                "Following failed:",
                error.message
            );

            return res.status(500)
                .json({
                    success: false,
                    message:
                        "Unable to load following."
                });

        }

    }
);

/* =========================================
   MY FOLLOWERS
========================================= */

app.get(
    "/api/followers",
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
                        profiles.profile_picture,
                        follows.created_at

                    FROM follows

                    INNER JOIN users
                        ON users.id =
                           follows.follower_id

                    LEFT JOIN profiles
                        ON profiles.user_id =
                           users.id

                    WHERE follows.following_id =
                          $1

                    ORDER BY
                        follows.created_at DESC
                    `,
                    [req.user.id]
                );

            return res.json({
                success: true,
                followers:
                    result.rows
            });

        } catch (error) {

            console.error(
                "My followers failed:",
                error.message
            );

            return res.status(500)
                .json({
                    success: false,
                    message:
                        "Unable to load followers."
                });

        }

    }
);

/* =========================================
   MY FOLLOWING
========================================= */

app.get(
    "/api/following",
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
                        profiles.profile_picture,
                        follows.created_at

                    FROM follows

                    INNER JOIN users
                        ON users.id =
                           follows.following_id

                    LEFT JOIN profiles
                        ON profiles.user_id =
                           users.id

                    WHERE follows.follower_id =
                          $1

                    ORDER BY
                        follows.created_at DESC
                    `,
                    [req.user.id]
                );

            return res.json({
                success: true,
                following:
                    result.rows
            });

        } catch (error) {

            console.error(
                "My following failed:",
                error.message
            );

            return res.status(500)
                .json({
                    success: false,
                    message:
                        "Unable to load following."
                });

        }

    }
);

/* =========================================
   FOLLOW COUNT HELPERS
========================================= */

async function getFollowCounts(
    userId
) {

    const result =
        await pool.query(
            `
            SELECT

                (
                    SELECT COUNT(*)
                    FROM follows
                    WHERE following_id = $1
                ) AS followers_count,

                (
                    SELECT COUNT(*)
                    FROM follows
                    WHERE follower_id = $1
                ) AS following_count
            `,
            [userId]
        );

    return {
        followersCount:
            Number(
                result.rows[0]
                    .followers_count
                || 0
            ),

        followingCount:
            Number(
                result.rows[0]
                    .following_count
                || 0
            )
    };

}

async function getFollowingCount(
    userId
) {

    const result =
        await pool.query(
            `
            SELECT COUNT(*)
            FROM follows
            WHERE follower_id = $1
            `,
            [userId]
        );

    return Number(
        result.rows[0].count || 0
    );

}

async function isFollowing(
    followerId,
    followingId
) {

    const result =
        await pool.query(
            `
            SELECT id
            FROM follows
            WHERE follower_id = $1
              AND following_id = $2
            LIMIT 1
            `,
            [
                followerId,
                followingId
            ]
        );

    return (
        result.rows.length > 0
    );

}
/* =========================================
   CREATE STREAM
========================================= */

app.post(
    "/api/streams",
    authenticateUser,
    async (req, res) => {

        const {
            id,
            streamId,
            title,
            category,
            description,
            thumbnail
        } = req.body;

        try {

            const requestedStreamId =
                safeString(
                    streamId ||
                    id
                );

            if (!requestedStreamId) {

                return res.status(400)
                    .json({
                        success: false,
                        message:
                            "Stream ID is required."
                    });

            }

            /* =================================
               PREVENT MULTIPLE LIVE STREAMS
            ================================= */

            const existingLive =
                await pool.query(
                    `
                    SELECT
                        id,
                        stream_id
                    FROM streams
                    WHERE user_id = $1
                      AND status = 'live'
                    ORDER BY created_at DESC
                    LIMIT 1
                    `,
                    [req.user.id]
                );

            if (
                existingLive.rows.length > 0
            ) {

                return res.status(409)
                    .json({
                        success: false,
                        message:
                            "You already have a live stream.",
                        stream: {
                            id:
                                existingLive.rows[0]
                                    .id,
                            streamId:
                                existingLive.rows[0]
                                    .stream_id
                        }
                    });

            }

            const cleanTitle =
                safeString(
                    title,
                    "Canvas Live Stream"
                );

            const cleanCategory =
                safeString(category);

            const cleanDescription =
                safeString(description);

            const cleanThumbnail =
                thumbnail
                    ? String(thumbnail)
                    : "";

            const result =
                await pool.query(
                    `
                    INSERT INTO streams
                    (
                        user_id,
                        stream_id,
                        title,
                        category,
                        description,
                        thumbnail,
                        status
                    )
                    VALUES (
                        $1,
                        $2,
                        $3,
                        $4,
                        $5,
                        $6,
                        'live'
                    )

                    RETURNING
                        id,
                        user_id,
                        stream_id,
                        title,
                        category,
                        description,
                        thumbnail,
                        status,
                        created_at
                    `,
                    [
                        req.user.id,
                        requestedStreamId,
                        cleanTitle,
                        cleanCategory,
                        cleanDescription,
                        cleanThumbnail
                    ]
                );

            const stream =
                result.rows[0];

            const responseStream =
                await getStreamByInternalId(
                    stream.id
                );

            /* =================================
               REALTIME NEW STREAM
            ================================= */

            io.emit(
                "stream-created",
                {
                    stream:
                        responseStream
                }
            );

            return res.status(201)
                .json({
                    success: true,
                    message:
                        "Canvas stream started.",

                    stream:
                        responseStream
                });

        } catch (error) {

            console.error(
                "Create stream failed:",
                error.message
            );

            if (
                error.code === "23505"
            ) {

                return res.status(409)
                    .json({
                        success: false,
                        message:
                            "This stream ID is already active."
                    });

            }

            return res.status(500)
                .json({
                    success: false,
                    message:
                        "Unable to start stream."
                });

        }

    }
);

/* =========================================
   GET SINGLE STREAM
========================================= */

app.get(
    "/api/streams/:id",
    async (req, res) => {

        const streamKey =
            safeString(
                req.params.id
            );

        try {

            const stream =
                await getStreamByKey(
                    streamKey
                );

            if (!stream) {

                return res.status(404)
                    .json({
                        success: false,
                        message:
                            "Stream not found."
                    });

            }

            return res.json({
                success: true,
                stream
            });

        } catch (error) {

            console.error(
                "Get stream failed:",
                error.message
            );

            return res.status(500)
                .json({
                    success: false,
                    message:
                        "Unable to load stream."
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

            return res.status(500)
                .json({
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
                        streams.stream_id,
                        streams.user_id,
                        streams.title,
                        streams.category,
                        streams.description,
                        streams.thumbnail,
                        streams.status,
                        streams.created_at,

                        users.name AS streamer_name,
                        users.username AS streamer_username,

                        profiles.profile_picture
                            AS streamer_profile_picture

                    FROM streams

                    INNER JOIN users
                        ON users.id =
                           streams.user_id

                    LEFT JOIN profiles
                        ON profiles.user_id =
                           users.id

                    WHERE streams.status = 'live'

                    ORDER BY
                        streams.created_at DESC
                    `
                );

            return res.json({
                success: true,

                streams:
                    result.rows.map(
                        normalizeStream
                    )
            });

        } catch (error) {

            console.error(
                "Get live streams failed:",
                error.message
            );

            return res.status(500)
                .json({
                    success: false,
                    message:
                        "Unable to load live streams."
                });

        }

    }
);

/* =========================================
   SEARCH CANVAS
========================================= */

app.get(
    "/api/search",
    async (req, res) => {

        const query =
            safeString(
                req.query.q
            );

        const search =
            query.toLowerCase();

        if (!search) {

            return res.json({
                success: true,
                query: "",
                streams: [],
                profiles: []
            });

        }

        try {

            /* =================================
               SEARCH LIVE STREAMS
            ================================= */

            const streamResult =
                await pool.query(
                    `
                    SELECT

                        streams.id,
                        streams.stream_id,
                        streams.user_id,
                        streams.title,
                        streams.category,
                        streams.description,
                        streams.thumbnail,
                        streams.status,
                        streams.created_at,

                        users.name AS streamer_name,
                        users.username AS streamer_username,

                        profiles.profile_picture
                            AS streamer_profile_picture

                    FROM streams

                    INNER JOIN users
                        ON users.id =
                           streams.user_id

                    LEFT JOIN profiles
                        ON profiles.user_id =
                           users.id

                    WHERE streams.status = 'live'

                      AND (
                           LOWER(
                               streams.title
                           ) LIKE $1

                           OR LOWER(
                               COALESCE(
                                   streams.category,
                                   ''
                               )
                           ) LIKE $1

                           OR LOWER(
                               COALESCE(
                                   streams.description,
                                   ''
                               )
                           ) LIKE $1

                           OR LOWER(
                               users.name
                           ) LIKE $1

                           OR LOWER(
                               users.username
                           ) LIKE $1
                      )

                    ORDER BY
                        streams.created_at DESC

                    LIMIT 100
                    `,
                    [
                        "%" + search + "%"
                    ]
                );

            /* =================================
               SEARCH USERS
            ================================= */

            const profileResult =
                await pool.query(
                    `
                    SELECT

                        users.id,
                        users.name,
                        users.username,
                        profiles.bio,
                        profiles.profile_picture,

                        (
                            SELECT COUNT(*)
                            FROM follows
                            WHERE following_id =
                                  users.id
                        ) AS followers_count,

                        (
                            SELECT COUNT(*)
                            FROM follows
                            WHERE follower_id =
                                  users.id
                        ) AS following_count

                    FROM users

                    LEFT JOIN profiles
                        ON profiles.user_id =
                           users.id

                    WHERE
                        LOWER(users.name)
                            LIKE $1

                        OR LOWER(users.username)
                            LIKE $1

                        OR LOWER(
                            COALESCE(
                                profiles.bio,
                                ''
                            )
                        ) LIKE $1

                    ORDER BY
                        users.username ASC

                    LIMIT 100
                    `,
                    [
                        "%" + search + "%"
                    ]
                );

            return res.json({
                success: true,
                query,

                streams:
                    streamResult.rows.map(
                        normalizeStream
                    ),

                profiles:
                    profileResult.rows.map(
                        row => ({
                            id:
                                row.id,
                            name:
                                row.name,
                            username:
                                row.username,
                            bio:
                                row.bio || "",
                            profile_picture:
                                row.profile_picture
                                || "",
                            followers_count:
                                Number(
                                    row.followers_count
                                    || 0
                                ),
                            following_count:
                                Number(
                                    row.following_count
                                    || 0
                                )
                        })
                    )
            });

        } catch (error) {

            console.error(
                "Canvas search failed:",
                error.message
            );

            return res.status(500)
                .json({
                    success: false,
                    message:
                        "Unable to search Canvas."
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
                        streams.stream_id,
                        streams.user_id,
                        streams.title,
                        streams.category,
                        streams.description,
                        streams.thumbnail,
                        streams.status,
                        streams.created_at,
                        streams.ended_at,

                        users.name AS streamer_name,
                        users.username AS streamer_username,

                        profiles.profile_picture
                            AS streamer_profile_picture

                    FROM streams

                    INNER JOIN users
                        ON users.id =
                           streams.user_id

                    LEFT JOIN profiles
                        ON profiles.user_id =
                           users.id

                    WHERE streams.user_id = $1

                    ORDER BY
                        streams.created_at DESC
                    `,
                    [req.user.id]
                );

            return res.json({
                success: true,

                streams:
                    result.rows.map(
                        normalizeStream
                    )
            });

        } catch (error) {

            console.error(
                "Get my streams failed:",
                error.message
            );

            return res.status(500)
                .json({
                    success: false,
                    message:
                        "Unable to load streams."
                });

        }

    }
);

/* =========================================
   STREAM HEARTBEAT
========================================= */

app.post(
    "/api/streams/:id/heartbeat",
    authenticateUser,
    async (req, res) => {

        const streamKey =
            safeString(
                req.params.id
            );

        try {

            const result =
                await pool.query(
                    `
                    UPDATE streams
                    SET created_at = created_at
                    WHERE (
                        stream_id = $1
                        OR CAST(id AS TEXT) = $1
                    )
                    AND user_id = $2
                    AND status = 'live'

                    RETURNING
                        id,
                        stream_id,
                        status
                    `,
                    [
                        streamKey,
                        req.user.id
                    ]
                );

            if (
                result.rows.length === 0
            ) {

                return res.status(404)
                    .json({
                        success: false,
                        message:
                            "Live stream not found."
                    });

            }

            return res.json({
                success: true,
                live: true,
                streamId:
                    result.rows[0]
                        .stream_id
            });

        } catch (error) {

            console.error(
                "Stream heartbeat failed:",
                error.message
            );

            return res.status(500)
                .json({
                    success: false,
                    message:
                        "Unable to update stream heartbeat."
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

        const streamKey =
            safeString(
                req.params.id
            );

        try {

            const result =
                await pool.query(
                    `
                    UPDATE streams
                    SET
                        status = 'ended',
                        ended_at =
                            CURRENT_TIMESTAMP

                    WHERE (
                        stream_id = $1
                        OR CAST(id AS TEXT) = $1
                    )

                    AND user_id = $2
                    AND status = 'live'

                    RETURNING
                        id,
                        stream_id,
                        user_id,
                        title,
                        category,
                        description,
                        thumbnail,
                        status,
                        created_at,
                        ended_at
                    `,
                    [
                        streamKey,
                        req.user.id
                    ]
                );

            if (
                result.rows.length === 0
            ) {

                return res.status(404)
                    .json({
                        success: false,
                        message:
                            "Live stream not found."
                    });

            }

            const ended =
                result.rows[0];

            const endedId =
                ended.stream_id ||
                String(ended.id);

            /* =================================
               REALTIME END EVENT
            ================================= */

            io.to(
                "stream:" + endedId
            ).emit(
                "stream-ended",
                {
                    streamId:
                        endedId
                }
            );

            io.emit(
                "stream-removed",
                {
                    streamId:
                        endedId
                }
            );

            return res.json({
                success: true,
                message:
                    "Canvas stream ended.",
                stream: {
                    id:
                        ended.id,
                    streamId:
                        endedId,
                    status:
                        ended.status,
                    ended_at:
                        ended.ended_at
                }
            });

        } catch (error) {

            console.error(
                "End stream failed:",
                error.message
            );

            return res.status(500)
                .json({
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

        const streamKey =
            safeString(
                req.params.id
            );

        try {

            const result =
                await pool.query(
                    `
                    DELETE FROM streams

                    WHERE (
                        stream_id = $1
                        OR CAST(id AS TEXT) = $1
                    )

                    AND user_id = $2

                    RETURNING
                        id,
                        stream_id
                    `,
                    [
                        streamKey,
                        req.user.id
                    ]
                );

            if (
                result.rows.length === 0
            ) {

                return res.status(404)
                    .json({
                        success: false,
                        message:
                            "Stream not found."
                    });

            }

            const deleted =
                result.rows[0];

            const deletedId =
                deleted.stream_id ||
                String(deleted.id);

            io.to(
                "stream:" + deletedId
            ).emit(
                "stream-ended",
                {
                    streamId:
                        deletedId
                }
            );

            io.emit(
                "stream-removed",
                {
                    streamId:
                        deletedId
                }
            );

            return res.json({
                success: true,
                message:
                    "Stream deleted successfully.",
                streamId:
                    deletedId
            });

        } catch (error) {

            console.error(
                "Delete stream failed:",
                error.message
            );

            return res.status(500)
                .json({
                    success: false,
                    message:
                        "Unable to delete stream."
                });

        }

    }
);

/* =========================================
   GET STREAM CHAT HISTORY
========================================= */

app.get(
    "/api/streams/:id/messages",
    async (req, res) => {

        const streamId =
            safeString(
                req.params.id
            );

        try {

            const result =
                await pool.query(
                    `
                    SELECT
                        stream_messages.id,
                        stream_messages.stream_id,
                        stream_messages.user_id,
                        stream_messages.username,
                        stream_messages.message,
                        stream_messages.created_at,
                        profiles.profile_picture

                    FROM stream_messages

                    LEFT JOIN profiles
                        ON profiles.user_id =
                           stream_messages.user_id

                    WHERE stream_messages.stream_id =
                          $1

                    ORDER BY
                        stream_messages.created_at ASC

                    LIMIT 200
                    `,
                    [streamId]
                );

            return res.json({
                success: true,
                messages:
                    result.rows
            });

        } catch (error) {

            console.error(
                "Get chat history failed:",
                error.message
            );

            return res.status(500)
                .json({
                    success: false,
                    message:
                        "Unable to load chat."
                });

        }

    }
);

/* =========================================
   SOCKET.IO
========================================= */

io.on(
    "connection",
    socket => {

        console.log(
            "Canvas socket connected:",
            socket.id
        );

        /* =====================================
           JOIN STREAM
        ===================================== */

        socket.on(
            "join-stream",
            async data => {

                const streamId =
                    safeString(
                        data &&
                        data.streamId
                    );

                if (!streamId) {
                    return;
                }

                socket.join(
                    "stream:" + streamId
                );

                socket.data.streamId =
                    streamId;

                socket.emit(
                    "stream-joined",
                    {
                        streamId
                    }
                );

                try {

                    const stream =
                        await getStreamByKey(
                            streamId
                        );

                    if (stream) {

                        socket.emit(
                            "stream-info",
                            {
                                stream
                            }
                        );

                    }

                } catch (error) {

                    console.warn(
                        "Socket stream lookup failed:",
                        error.message
                    );

                }

            }
        );

        /* =====================================
           LEAVE STREAM
        ===================================== */

        socket.on(
            "leave-stream",
            data => {

                const streamId =
                    safeString(
                        data &&
                        data.streamId
                    );

                if (!streamId) {
                    return;
                }

                socket.leave(
                    "stream:" + streamId
                );

            }
        );

        /* =====================================
           JOIN USER ROOM
        ===================================== */

        socket.on(
            "join-user",
            data => {

                const userId =
                    safeString(
                        data &&
                        data.userId
                    );

                if (!userId) {
                    return;
                }

                socket.join(
                    "user:" + userId
                );

                socket.data.userId =
                    userId;

            }
        );

        /* =====================================
           STREAM STARTED
        ===================================== */

        socket.on(
            "stream-started",
            data => {

                const streamId =
                    safeString(
                        data &&
                        data.streamId
                    );

                if (!streamId) {
                    return;
                }

                socket.join(
                    "stream:" + streamId
                );

                socket.data.streamId =
                    streamId;

                socket.broadcast.emit(
                    "stream-started",
                    {
                        ...data,
                        streamId
                    }
                );

            }
        );

        /* =====================================
           STREAM HEARTBEAT
        ===================================== */

        socket.on(
            "stream-heartbeat",
            data => {

                const streamId =
                    safeString(
                        data &&
                        data.streamId
                    );

                if (!streamId) {
                    return;
                }

                socket.to(
                    "stream:" + streamId
                ).emit(
                    "stream-heartbeat",
                    {
                        streamId,
                        time: Date.now()
                    }
                );

            }
        );

        /* =====================================
           CHAT MESSAGE
        ===================================== */

        socket.on(
            "chat-message",
            async data => {

                const streamId =
                    safeString(
                        data &&
                        data.streamId
                    );

                const message =
                    safeString(
                        data &&
                        data.message
                    );

                if (
                    !streamId ||
                    !message
                ) {
                    return;
                }

                if (
                    message.length > 500
                ) {
                    return;
                }

                let userId = null;
                let username =
                    safeString(
                        data &&
                        data.username,
                        "Canvas User"
                    );

                if (
                    socket.data &&
                    socket.data.userId
                ) {

                    userId =
                        Number(
                            socket.data.userId
                        );

                }

                try {

                    if (userId) {

                        const userResult =
                            await pool.query(
                                `
                                SELECT
                                    users.id,
                                    users.username,
                                    profiles.profile_picture
                                FROM users

                                LEFT JOIN profiles
                                    ON profiles.user_id =
                                       users.id

                                WHERE users.id = $1

                                LIMIT 1
                                `,
                                [userId]
                            );

                        if (
                            userResult.rows.length
                            > 0
                        ) {

                            username =
                                userResult.rows[0]
                                    .username;

                            const saved =
                                await pool.query(
                                    `
                                    INSERT INTO
                                    stream_messages
                                    (
                                        stream_id,
                                        user_id,
                                        username,
                                        message
                                    )
                                    VALUES (
                                        $1,
                                        $2,
                                        $3,
                                        $4
                                    )

                                    RETURNING
                                        id,
                                        stream_id,
                                        user_id,
                                        username,
                                        message,
                                        created_at
                                    `,
                                    [
                                        streamId,
                                        userId,
                                        username,
                                        message
                                    ]
                                );

                            const chatMessage =
                                {
                                    ...saved
                                        .rows[0],

                                    profile_picture:
                                        userResult
                                            .rows[0]
                                            .profile_picture
                                            || ""
                                };

                            io.to(
                                "stream:" +
                                streamId
                            ).emit(
                                "chat-message",
                                chatMessage
                            );

                            return;

                        }

                    }

                    /* =================================
                       GUEST / FALLBACK MESSAGE
                    ================================= */

                    const saved =
                        await pool.query(
                            `
                            INSERT INTO
                            stream_messages
                            (
                                stream_id,
                                username,
                                message
                            )
                            VALUES ($1,$2,$3)

                            RETURNING
                                id,
                                stream_id,
                                user_id,
                                username,
                                message,
                                created_at
                            `,
                            [
                                streamId,
                                username,
                                message
                            ]
                        );

                    io.to(
                        "stream:" +
                        streamId
                    ).emit(
                        "chat-message",
                        saved.rows[0]
                    );

                } catch (error) {

                    console.error(
                        "Socket chat failed:",
                        error.message
                    );

                }

            }
        );

        /* =====================================
           GENERIC STREAM ENDED
        ===================================== */

        socket.on(
            "stream-ended",
            data => {

                const streamId =
                    safeString(
                        data &&
                        data.streamId
                    );

                if (!streamId) {
                    return;
                }

                io.to(
                    "stream:" + streamId
                ).emit(
                    "stream-ended",
                    {
                        streamId
                    }
                );

                socket.leave(
                    "stream:" + streamId
                );

            }
        );

        /* =====================================
           DISCONNECT
        ===================================== */

        socket.on(
            "disconnect",
            reason => {

                console.log(
                    "Canvas socket disconnected:",
                    socket.id,
                    reason
                );

            }
        );

    }
);

/* =========================================
   STREAM HELPERS
========================================= */

function normalizeStream(
    row
) {

    return {

        id:
            row.id,

        streamId:
            row.stream_id ||
            String(row.id),

        userId:
            row.user_id,

        title:
            row.title ||
            "Canvas Live Stream",

        category:
            row.category ||
            "",

        description:
            row.description ||
            "",

        thumbnail:
            row.thumbnail ||
            "",

        status:
            row.status,

        isLive:
            row.status === "live",

        createdAt:
            row.created_at,

        endedAt:
            row.ended_at ||
            null,

        streamer:
            row.streamer_username ||
            "",

        username:
            row.streamer_username ||
            "",

        streamerName:
            row.streamer_name ||
            "",

        profilePicture:
            row.streamer_profile_picture ||
            ""

    };

}

async function getStreamByInternalId(
    id
) {

    const result =
        await pool.query(
            `
            SELECT

                streams.id,
                streams.stream_id,
                streams.user_id,
                streams.title,
                streams.category,
                streams.description,
                streams.thumbnail,
                streams.status,
                streams.created_at,
                streams.ended_at,

                users.name AS streamer_name,
                users.username AS streamer_username,

                profiles.profile_picture
                    AS streamer_profile_picture

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
            [id]
        );

    if (
        result.rows.length === 0
    ) {

        return null;

    }

    return normalizeStream(
        result.rows[0]
    );

}

async function getStreamByKey(
    streamKey
) {

    const result =
        await pool.query(
            `
            SELECT

                streams.id,
                streams.stream_id,
                streams.user_id,
                streams.title,
                streams.category,
                streams.description,
                streams.thumbnail,
                streams.status,
                streams.created_at,
                streams.ended_at,

                users.name AS streamer_name,
                users.username AS streamer_username,

                profiles.profile_picture
                    AS streamer_profile_picture

            FROM streams

            INNER JOIN users
                ON users.id =
                   streams.user_id

            LEFT JOIN profiles
                ON profiles.user_id =
                   users.id

            WHERE (
                streams.stream_id = $1
                OR CAST(streams.id AS TEXT) = $1
            )

            LIMIT 1
            `,
            [streamKey]
        );

    if (
        result.rows.length === 0
    ) {

        return null;

    }

    return normalizeStream(
        result.rows[0]
    );

}

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
   GLOBAL ERROR
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

            console.log(
                "Canvas Socket.IO realtime server ready."
            );

        }
    );

}

startServer();
      
