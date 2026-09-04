// ============================================================
// CANVAS SERVER.JS
// Full Canvas backend
// ============================================================

const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const { Pool } = require("pg");
const crypto = require("crypto");

const app = express();
const httpServer = http.createServer(app);

const PORT = process.env.PORT || 3000;
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || "*";

// ============================================================
// SOCKET.IO
// ============================================================

const io = new Server(httpServer, {
    cors: {
        origin: FRONTEND_ORIGIN,
        methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    },
    transports: ["websocket", "polling"]
});

// ============================================================
// CORS
// ============================================================

app.use((req, res, next) => {

    res.header(
        "Access-Control-Allow-Origin",
        FRONTEND_ORIGIN
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

// ============================================================
// JSON
// ============================================================

app.use(
    express.json({
        limit: "50mb"
    })
);

// ============================================================
// DATABASE
// ============================================================

const databaseUrl =
    process.env.canvas_db_r13t ||
    process.env.DATABASE_URL ||
    "";

const pool = databaseUrl
    ? new Pool({
        connectionString: databaseUrl,
        ssl: {
            rejectUnauthorized: false
        }
    })
    : null;

// ============================================================
// PASSWORD HASH
// Keep SHA-256 for compatibility with existing accounts.
// ============================================================

function hashPassword(password) {

    return crypto
        .createHash("sha256")
        .update(String(password))
        .digest("hex");

}

// ============================================================
// USERNAME CLEANER
// ============================================================

function cleanUsername(username) {

    return String(username || "")
        .trim()
        .replace(/^@/, "")
        .toLowerCase();

}

// ============================================================
// AUTH TOKEN
// ============================================================

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

// ============================================================
// AUTHENTICATION
// ============================================================

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
        authorization.substring(7).trim();

    if (!token) {

        return res.status(401).json({
            success: false,
            message: "Authentication token is missing."
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
                  AND sessions.expires_at > CURRENT_TIMESTAMP
                LIMIT 1
                `,
                [tokenHash]
            );

        if (result.rows.length === 0) {

            return res.status(401).json({
                success: false,
                message:
                    "Invalid or expired authentication token."
            });

        }

        req.user =
            result.rows[0];

        req.authToken =
            token;

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

// ============================================================
// DATABASE INITIALIZATION
// ============================================================

async function initializeDatabase() {

    if (!pool) {

        console.log(
            "Database environment variable not found."
        );

        return;

    }

    try {

        // ----------------------------------------------------
        // USERS
        // ----------------------------------------------------

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

        // ----------------------------------------------------
        // PROFILES
        // ----------------------------------------------------

        await pool.query(`
            CREATE TABLE IF NOT EXISTS profiles (
                id SERIAL PRIMARY KEY,
                user_id INTEGER UNIQUE NOT NULL
                    REFERENCES users(id)
                    ON DELETE CASCADE,
                bio TEXT DEFAULT '',
                profile_picture TEXT DEFAULT '',
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // ----------------------------------------------------
        // SESSIONS
        // ----------------------------------------------------

        await pool.query(`
            CREATE TABLE IF NOT EXISTS sessions (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL
                    REFERENCES users(id)
                    ON DELETE CASCADE,
                token_hash TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL
            );
        `);

        // ----------------------------------------------------
        // STREAMS
        // ----------------------------------------------------

        await pool.query(`
            CREATE TABLE IF NOT EXISTS streams (
                id SERIAL PRIMARY KEY,
                user_id INTEGER
                    REFERENCES users(id)
                    ON DELETE CASCADE,
                title VARCHAR(255)
                    DEFAULT 'Canvas Live Stream',
                category VARCHAR(100)
                    DEFAULT 'Other',
                description TEXT
                    DEFAULT '',
                thumbnail TEXT
                    DEFAULT '',
                streamer VARCHAR(255)
                    DEFAULT '',
                username VARCHAR(100)
                    DEFAULT '',
                profile_picture TEXT
                    DEFAULT '',
                status VARCHAR(30)
                    DEFAULT 'live',
                created_at TIMESTAMP
                    DEFAULT CURRENT_TIMESTAMP,
                ended_at TIMESTAMP
            );
        `);

        // ----------------------------------------------------
        // ADD MISSING COLUMNS TO OLD DATABASES
        // ----------------------------------------------------

        await pool.query(`
            ALTER TABLE streams
            ADD COLUMN IF NOT EXISTS user_id
            INTEGER REFERENCES users(id)
            ON DELETE CASCADE;
        `);

        await pool.query(`
            ALTER TABLE streams
            ADD COLUMN IF NOT EXISTS category
            VARCHAR(100) DEFAULT 'Other';
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
            ALTER TABLE streams
            ADD COLUMN IF NOT EXISTS streamer
            VARCHAR(255) DEFAULT '';
        `);

        await pool.query(`
            ALTER TABLE streams
            ADD COLUMN IF NOT EXISTS username
            VARCHAR(100) DEFAULT '';
        `);

        await pool.query(`
            ALTER TABLE streams
            ADD COLUMN IF NOT EXISTS profile_picture
            TEXT DEFAULT '';
        `);

        await pool.query(`
            ALTER TABLE streams
            ADD COLUMN IF NOT EXISTS ended_at
            TIMESTAMP;
        `);

        // ----------------------------------------------------
        // CHAT
        // ----------------------------------------------------

        await pool.query(`
            CREATE TABLE IF NOT EXISTS stream_messages (
                id BIGSERIAL PRIMARY KEY,
                stream_id INTEGER NOT NULL
                    REFERENCES streams(id)
                    ON DELETE CASCADE,
                user_id INTEGER
                    REFERENCES users(id)
                    ON DELETE SET NULL,
                username VARCHAR(100) DEFAULT '',
                message TEXT NOT NULL,
                created_at TIMESTAMP
                    DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // ----------------------------------------------------
        // FOLLOWS
        // ----------------------------------------------------

        await pool.query(`
            CREATE TABLE IF NOT EXISTS follows (
                id BIGSERIAL PRIMARY KEY,
                follower_id INTEGER NOT NULL
                    REFERENCES users(id)
                    ON DELETE CASCADE,
                following_id INTEGER NOT NULL
                    REFERENCES users(id)
                    ON DELETE CASCADE,
                created_at TIMESTAMP
                    DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(follower_id, following_id)
            );
        `);

        // ----------------------------------------------------
        // SUPPORT / GIFTS
        // ----------------------------------------------------

        await pool.query(`
            CREATE TABLE IF NOT EXISTS stream_support (
                id BIGSERIAL PRIMARY KEY,
                stream_id INTEGER NOT NULL
                    REFERENCES streams(id)
                    ON DELETE CASCADE,
                user_id INTEGER
                    REFERENCES users(id)
                    ON DELETE SET NULL,
                type VARCHAR(50) DEFAULT 'support',
                amount NUMERIC(10,2) DEFAULT 0,
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
// ============================================================
// BACKEND STATUS
// ============================================================

app.get("/", (req, res) => {

    res.json({
        success: true,
        status: "online",
        message:
            "Canvas backend is running."
    });

});

// ============================================================
// HEALTH CHECK
// ============================================================

app.get("/api/health", async (req, res) => {

    if (!pool) {

        return res.status(500).json({
            success: false,
            status: "unhealthy",
            database: "not configured"
        });

    }

    try {

        await pool.query("SELECT 1");

        return res.json({
            success: true,
            status: "healthy",
            database: "connected"
        });

    } catch (error) {

        return res.status(500).json({
            success: false,
            status: "unhealthy",
            database: "connection failed"
        });

    }

});

// ============================================================
// DATABASE TEST
// ============================================================

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

        return res.json({
            success: true,
            database: "connected",
            message:
                "Canvas database connection is working.",
            server_time:
                result.rows[0].now
        });

    } catch (error) {

        return res.status(500).json({
            success: false,
            database: "connection failed",
            message: error.message
        });

    }

});

// ============================================================
// SIGNUP
// ============================================================

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

    if (String(password).length < 8) {

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

        if (
            !/^[a-zA-Z0-9_.]+$/.test(cleanUser)
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
                SELECT id, username, email
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

        if (existingUser.rows.length > 0) {

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
                hashToken(token)
            ]
        );

        return res.status(201).json({
            success: true,
            message:
                "Canvas account created successfully.",
            token,
            user
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

});

// ============================================================
// LOGIN
// ============================================================

app.post("/api/login", async (req, res) => {

    const {
        email,
        password
    } = req.body;

    if (!email || !password) {

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

        if (result.rows.length === 0) {

            return res.status(401).json({
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

            return res.status(401).json({
                success: false,
                message:
                    "Email or password is incorrect."
            });

        }

        const token =
            createAuthToken();

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
                hashToken(token)
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
                username: user.username,
                email: user.email,
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
                "Unable to log in to Canvas."
        });

    }

});

// ============================================================
// CURRENT USER
// ============================================================

app.get(
    "/api/me",
    authenticateUser,
    async (req, res) => {

        try {

            const profile =
                await pool.query(
                    `
                    SELECT
                        profile_picture
                    FROM profiles
                    WHERE user_id = $1
                    LIMIT 1
                    `,
                    [req.user.id]
                );

            return res.json({
                success: true,
                user: {
                    id: req.user.id,
                    name: req.user.name,
                    username:
                        req.user.username,
                    email: req.user.email,
                    created_at:
                        req.user.created_at,
                    profile_picture:
                        profile.rows[0]
                            ?.profile_picture || ""
                }
            });

        } catch (error) {

            return res.status(500).json({
                success: false,
                message:
                    "Unable to get current user."
            });

        }

    }
);

// ============================================================
// GET PROFILE
// ============================================================

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

            if (result.rows.length === 0) {

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
                    id: p.id,
                    name: p.name,
                    username: p.username,
                    email: p.email,
                    bio: p.bio || "",
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
// ============================================================
// UPDATE PROFILE
// ============================================================

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

            const cleanUsernameValue =
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

            const cleanProfilePicture =
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

            if (
                !/^[a-zA-Z0-9_.]+$/.test(
                    cleanUsernameValue
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
                        cleanUsernameValue,
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

            return res.status(500).json({
                success: false,
                message:
                    "Unable to update Canvas profile."
            });

        }

    }
);

// ============================================================
// DELETE PROFILE PICTURE
// ============================================================

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

            return res.status(500).json({
                success: false,
                message:
                    "Unable to delete profile picture."
            });

        }

    }
);

// ============================================================
// LOGOUT
// ============================================================

app.post(
    "/api/logout",
    authenticateUser,
    async (req, res) => {

        try {

            await pool.query(
                `
                DELETE FROM sessions
                WHERE token_hash = $1
                `,
                [
                    hashToken(
                        req.authToken
                    )
                ]
            );

            return res.json({
                success: true,
                message:
                    "Logged out successfully."
            });

        } catch (error) {

            return res.status(500).json({
                success: false,
                message:
                    "Unable to log out."
            });

        }

    }
);

// ============================================================
// CHANGE PASSWORD
// ============================================================

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

            if (result.rows.length === 0) {

                return res.status(404).json({
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

                return res.status(401).json({
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

            return res.status(500).json({
                success: false,
                message:
                    "Unable to change password."
            });

        }

    }
);

// ============================================================
// CREATE STREAM
// Main endpoint used by the current Go Live page.
// ============================================================

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
            thumbnail,
            streamer,
            username,
            profilePicture
        } = req.body;

        try {

            // ------------------------------------------------
            // Prevent one user from accidentally creating
            // multiple simultaneous live streams.
            // ------------------------------------------------

            const existing =
                await pool.query(
                    `
                    SELECT id
                    FROM streams
                    WHERE user_id = $1
                      AND status = 'live'
                    LIMIT 1
                    `,
                    [req.user.id]
                );

            if (existing.rows.length > 0) {

                return res.status(409).json({
                    success: false,
                    message:
                        "You already have a live Canvas stream.",
                    streamId:
                        String(
                            existing.rows[0].id
                        ),
                    id:
                        existing.rows[0].id
                });

            }

            const cleanTitle =
                String(
                    title ||
                    "Canvas Live Stream"
                ).trim();

            const cleanCategory =
                String(
                    category ||
                    "Other"
                ).trim();

            const cleanDescription =
                String(
                    description || ""
                ).trim();

            const cleanThumbnail =
                String(
                    thumbnail || ""
                );

            const cleanUsername =
                cleanUsername(
                    username ||
                    req.user.username
                );

            const cleanStreamer =
                String(
                    streamer ||
                    req.user.name ||
                    ""
                ).trim();

            const cleanProfilePicture =
                String(
                    profilePicture || ""
                );

            const result =
                await pool.query(
                    `
                    INSERT INTO streams
                    (
                        user_id,
                        title,
                        category,
                        description,
                        thumbnail,
                        streamer,
                        username,
                        profile_picture,
                        status
                    )
                    VALUES (
                        $1,$2,$3,$4,$5,$6,$7,$8,'live'
                    )
                    RETURNING *
                    `,
                    [
                        req.user.id,
                        cleanTitle,
                        cleanCategory,
                        cleanDescription,
                        cleanThumbnail,
                        cleanStreamer,
                        cleanUsername,
                        cleanProfilePicture
                    ]
                );

            const stream =
                result.rows[0];

            const responseStream = {
                ...stream,
                streamId:
                    String(stream.id),
                id:
                    stream.id,
                isLive:
                    true
            };

            io.emit(
                "stream-started",
                responseStream
            );

            return res.status(201).json({
                success: true,
                message:
                    "Canvas stream started.",
                streamId:
                    String(stream.id),
                id:
                    stream.id,
                stream:
                    responseStream
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

// ============================================================
// COMPATIBILITY ENDPOINT
// Supports the older script.js which calls:
// POST /api/streams/start
// ============================================================

app.post(
    "/api/streams/start",
    authenticateUser,
    async (req, res) => {

        const {
            title,
            category,
            description,
            thumbnail,
            streamer,
            username,
            profilePicture
        } = req.body;

        req.body = {
            title,
            category,
            description,
            thumbnail,
            streamer,
            username,
            profilePicture
        };

        try {

            const existing =
                await pool.query(
                    `
                    SELECT *
                    FROM streams
                    WHERE user_id = $1
                      AND status = 'live'
                    LIMIT 1
                    `,
                    [req.user.id]
                );

            if (existing.rows.length > 0) {

                return res.status(409).json({
                    success: false,
                    message:
                        "You already have a live Canvas stream.",
                    streamId:
                        String(
                            existing.rows[0].id
                        ),
                    id:
                        existing.rows[0].id,
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
                        category,
                        description,
                        thumbnail,
                        streamer,
                        username,
                        profile_picture,
                        status
                    )
                    VALUES (
                        $1,
                        $2,
                        $3,
                        $4,
                        $5,
                        $6,
                        $7,
                        $8,
                        'live'
                    )
                    RETURNING *
                    `,
                    [
                        req.user.id,
                        String(
                            title ||
                            "Canvas Live Stream"
                        ).trim(),
                        String(
                            category ||
                            "Other"
                        ).trim(),
                        String(
                            description ||
                            ""
                        ).trim(),
                        String(
                            thumbnail ||
                            ""
                        ),
                        String(
                            streamer ||
                            req.user.name ||
                            ""
                        ).trim(),
                        cleanUsername(
                            username ||
                            req.user.username
                        ),
                        String(
                            profilePicture ||
                            ""
                        )
                    ]
                );

            const stream =
                result.rows[0];

            const payload = {
                ...stream,
                streamId:
                    String(stream.id),
                id:
                    stream.id,
                isLive:
                    true
            };

            io.emit(
                "stream-started",
                payload
            );

            return res.status(201).json({
                success: true,
                message:
                    "Canvas stream started.",
                streamId:
                    String(stream.id),
                id:
                    stream.id,
                stream:
                    payload
            });

        } catch (error) {

            console.error(
                "Start stream failed:",
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
// ============================================================
// STREAM FORMATTER
// ============================================================

function formatStream(row) {

    if (!row) {
        return null;
    }

    return {
        id:
            row.id,

        streamId:
            String(row.id),

        userId:
            row.user_id,

        title:
            row.title ||
            "Canvas Live Stream",

        category:
            row.category ||
            "Other",

        description:
            row.description ||
            "",

        thumbnail:
            row.thumbnail ||
            "",

        streamer:
            row.streamer ||
            row.name ||
            "",

        creator:
            row.streamer ||
            row.name ||
            "",

        username:
            row.username ||
            "",

        profilePicture:
            row.profile_picture ||
            row.profilePicture ||
            "",

        profile_picture:
            row.profile_picture ||
            "",

        status:
            row.status,

        isLive:
            row.status === "live",

        createdAt:
            row.created_at,

        created_at:
            row.created_at,

        endedAt:
            row.ended_at,

        ended_at:
            row.ended_at
    };

}

// ============================================================
// GET ALL STREAMS
// Used by Explore and compatibility with Home.
// ============================================================

app.get(
    "/api/streams",
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
                        streams.*,
                        users.name,
                        users.username
                    FROM streams
                    LEFT JOIN users
                        ON users.id =
                           streams.user_id
                    ORDER BY
                        streams.created_at DESC
                    LIMIT 100
                    `
                );

            return res.json({
                success: true,
                streams:
                    result.rows.map(
                        formatStream
                    )
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

// ============================================================
// GET LIVE STREAMS
// ============================================================

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
                        streams.*,
                        users.name,
                        users.username
                    FROM streams
                    INNER JOIN users
                        ON users.id =
                           streams.user_id
                    WHERE streams.status = 'live'
                    ORDER BY
                        streams.created_at DESC
                    `
                );

            return res.json({
                success: true,
                streams:
                    result.rows.map(
                        formatStream
                    )
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

// ============================================================
// GET MY STREAMS
// ============================================================

app.get(
    "/api/streams/my",
    authenticateUser,
    async (req, res) => {

        try {

            const result =
                await pool.query(
                    `
                    SELECT *
                    FROM streams
                    WHERE user_id = $1
                    ORDER BY
                        created_at DESC
                    `,
                    [req.user.id]
                );

            return res.json({
                success: true,
                streams:
                    result.rows.map(
                        formatStream
                    )
            });

        } catch (error) {

            return res.status(500).json({
                success: false,
                message:
                    "Unable to load streams."
            });

        }

    }
);

// ============================================================
// GET SINGLE STREAM
// IMPORTANT FOR WATCH PAGE
// ============================================================

app.get(
    "/api/streams/:id",
    async (req, res) => {

        try {

            const streamId =
                String(
                    req.params.id
                );

            if (!/^\d+$/.test(streamId)) {

                return res.status(404).json({
                    success: false,
                    message:
                        "Stream not found."
                });

            }

            const result =
                await pool.query(
                    `
                    SELECT
                        streams.*,
                        users.name,
                        users.username
                    FROM streams
                    LEFT JOIN users
                        ON users.id =
                           streams.user_id
                    WHERE streams.id = $1
                    LIMIT 1
                    `,
                    [streamId]
                );

            if (result.rows.length === 0) {

                return res.status(404).json({
                    success: false,
                    message:
                        "Stream not found."
                });

            }

            return res.json({
                success: true,
                stream:
                    formatStream(
                        result.rows[0]
                    )
            });

        } catch (error) {

            console.error(
                "Get stream failed:",
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

// ============================================================
// END STREAM
// ============================================================

app.put(
    "/api/streams/:id/end",
    authenticateUser,
    async (req, res) => {

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
                    RETURNING *
                    `,
                    [
                        req.params.id,
                        req.user.id
                    ]
                );

            if (result.rows.length === 0) {

                return res.status(404).json({
                    success: false,
                    message:
                        "Live stream not found."
                });

            }

            const endedStream =
                formatStream(
                    result.rows[0]
                );

            io.to(
                `stream:${req.params.id}`
            ).emit(
                "stream-ended",
                endedStream
            );

            io.emit(
                "stream-ended",
                endedStream
            );

            return res.json({
                success: true,
                message:
                    "Canvas stream ended.",
                stream:
                    endedStream
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

// ============================================================
// COMPATIBILITY STOP ENDPOINT
// Supports old script.js:
// POST /api/streams/stop
// ============================================================

app.post(
    "/api/streams/stop",
    authenticateUser,
    async (req, res) => {

        const streamId =
            req.body.streamId ||
            req.body.id;

        if (!streamId) {

            return res.status(400).json({
                success: false,
                message:
                    "Stream ID is required."
            });

        }

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
                    RETURNING *
                    `,
                    [
                        streamId,
                        req.user.id
                    ]
                );

            if (result.rows.length === 0) {

                return res.status(404).json({
                    success: false,
                    message:
                        "Live stream not found."
                });

            }

            const endedStream =
                formatStream(
                    result.rows[0]
                );

            io.to(
                `stream:${streamId}`
            ).emit(
                "stream-ended",
                endedStream
            );

            io.emit(
                "stream-ended",
                endedStream
            );

            return res.json({
                success: true,
                message:
                    "Canvas stream stopped.",
                stream:
                    endedStream
            });

        } catch (error) {

            return res.status(500).json({
                success: false,
                message:
                    "Unable to stop stream."
            });

        }

    }
);

// ============================================================
// DELETE STREAM
//
// IMPORTANT:
// We do NOT physically delete it.
// We mark it ended so completed streams remain
// available to Explore.
// ============================================================

app.delete(
    "/api/streams/:id",
    authenticateUser,
    async (req, res) => {

        try {

            const result =
                await pool.query(
                    `
                    UPDATE streams
                    SET
                        status =
                            CASE
                                WHEN status = 'live'
                                THEN 'ended'
                                ELSE status
                            END,
                        ended_at =
                            CASE
                                WHEN status = 'live'
                                THEN CURRENT_TIMESTAMP
                                ELSE ended_at
                            END
                    WHERE id = $1
                      AND user_id = $2
                    RETURNING *
                    `,
                    [
                        req.params.id,
                        req.user.id
                    ]
                );

            if (result.rows.length === 0) {

                return res.status(404).json({
                    success: false,
                    message:
                        "Stream not found."
                });

            }

            const stream =
                formatStream(
                    result.rows[0]
                );

            io.to(
                `stream:${req.params.id}`
            ).emit(
                "stream-ended",
                stream
            );

            return res.json({
                success: true,
                message:
                    "Stream ended successfully.",
                stream
            });

        } catch (error) {

            console.error(
                "Stream delete/end failed:",
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

// ============================================================
// CHAT — GET HISTORY
// ============================================================

app.get(
    "/api/streams/:id/chat",
    async (req, res) => {

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
                    WHERE stream_messages.stream_id = $1
                    ORDER BY
                        stream_messages.created_at ASC
                    LIMIT 200
                    `,
                    [req.params.id]
                );

            return res.json({
                success: true,
                messages:
                    result.rows.map(
                        message => ({
                            id:
                                String(message.id),
                            streamId:
                                message.stream_id,
                            userId:
                                message.user_id,
                            username:
                                message.username,
                            message:
                                message.message,
                            text:
                                message.message,
                            profilePicture:
                                message.profile_picture ||
                                "",
                            createdAt:
                                message.created_at
                        })
                    )
            });

        } catch (error) {

            return res.status(500).json({
                success: false,
                message:
                    "Unable to load chat."
            });

        }

    }
);

// ============================================================
// CHAT — SEND MESSAGE
// ============================================================

app.post(
    "/api/streams/:id/chat",
    authenticateUser,
    async (req, res) => {

        const text =
            String(
                req.body.message ||
                req.body.text ||
                ""
            ).trim();

        if (!text) {

            return res.status(400).json({
                success: false,
                message:
                    "Message cannot be empty."
            });

        }

        if (text.length > 500) {

            return res.status(400).json({
                success: false,
                message:
                    "Message is too long."
            });

        }

        try {

            const streamResult =
                await pool.query(
                    `
                    SELECT id, status
                    FROM streams
                    WHERE id = $1
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
                        "Stream not found."
                });

            }

            if (
                streamResult.rows[0].status !==
                "live"
            ) {

                return res.status(409).json({
                    success: false,
                    message:
                        "This stream has ended."
                });

            }

            const result =
                await pool.query(
                    `
                    INSERT INTO stream_messages
                    (
                        stream_id,
                        user_id,
                        username,
                        message
                    )
                    VALUES ($1,$2,$3,$4)
                    RETURNING
                        id,
                        stream_id,
                        user_id,
                        username,
                        message,
                        created_at
                    `,
                    [
                        req.params.id,
                        req.user.id,
                        req.user.username,
                        text
                    ]
                );

            const row =
                result.rows[0];

            const message = {
                id:
                    String(row.id),
                streamId:
                    row.stream_id,
                userId:
                    row.user_id,
                username:
                    row.username,
                message:
                    row.message,
                text:
                    row.message,
                createdAt:
                    row.created_at
            };

            // ONE broadcast only.
            // This prevents "hi hi".
            io.to(
                `stream:${req.params.id}`
            ).emit(
                "chat-message",
                message
            );

            return res.status(201).json({
                success: true,
                message
            });

        } catch (error) {

            console.error(
                "Send chat failed:",
                error.message
            );

            return res.status(500).json({
                success: false,
                message:
                    "Unable to send chat message."
            });

        }

    }
);
// ============================================================
// FOLLOW CREATOR
// ============================================================

app.post(
    "/api/follow",
    authenticateUser,
    async (req, res) => {

        const followingId =
            req.body.userId ||
            req.body.followingId;

        if (!followingId) {

            return res.status(400).json({
                success: false,
                message:
                    "Creator ID is required."
            });

        }

        if (
            String(followingId) ===
            String(req.user.id)
        ) {

            return res.status(400).json({
                success: false,
                message:
                    "You cannot follow yourself."
            });

        }

        try {

            await pool.query(
                `
                INSERT INTO follows
                (
                    follower_id,
                    following_id
                )
                VALUES ($1,$2)
                ON CONFLICT
                    (follower_id, following_id)
                DO NOTHING
                `,
                [
                    req.user.id,
                    followingId
                ]
            );

            return res.json({
                success: true,
                following: true
            });

        } catch (error) {

            return res.status(500).json({
                success: false,
                message:
                    "Unable to follow creator."
            });

        }

    }
);

// ============================================================
// SUPPORT / GIFTS
// ============================================================

app.post(
    "/api/support",
    authenticateUser,
    async (req, res) => {

        const streamId =
            req.body.streamId ||
            req.body.id;

        const type =
            String(
                req.body.type ||
                "support"
            ).trim();

        const amount =
            Number(
                req.body.amount || 0
            );

        if (!streamId) {

            return res.status(400).json({
                success: false,
                message:
                    "Stream ID is required."
            });

        }

        try {

            const stream =
                await pool.query(
                    `
                    SELECT id
                    FROM streams
                    WHERE id = $1
                    LIMIT 1
                    `,
                    [streamId]
                );

            if (stream.rows.length === 0) {

                return res.status(404).json({
                    success: false,
                    message:
                        "Stream not found."
                });

            }

            const result =
                await pool.query(
                    `
                    INSERT INTO stream_support
                    (
                        stream_id,
                        user_id,
                        type,
                        amount
                    )
                    VALUES ($1,$2,$3,$4)
                    RETURNING *
                    `,
                    [
                        streamId,
                        req.user.id,
                        type,
                        Number.isFinite(amount)
                            ? amount
                            : 0
                    ]
                );

            const support =
                result.rows[0];

            io.to(
                `stream:${streamId}`
            ).emit(
                "support",
                {
                    id:
                        String(support.id),
                    streamId:
                        streamId,
                    type:
                        support.type,
                    amount:
                        support.amount
                }
            );

            return res.status(201).json({
                success: true,
                support
            });

        } catch (error) {

            return res.status(500).json({
                success: false,
                message:
                    "Unable to send support."
            });

        }

    }
);

// ============================================================
// ACTIVE VIEWER COUNTS
// ============================================================

const streamViewers =
    new Map();

function getViewerCount(streamId) {

    const set =
        streamViewers.get(
            String(streamId)
        );

    return set
        ? set.size
        : 0;

}

function sendViewerCount(streamId) {

    const count =
        getViewerCount(streamId);

    io.to(
        `stream:${streamId}`
    ).emit(
        "viewer-count",
        {
            streamId:
                String(streamId),
            viewers:
                count,
            viewerCount:
                count,
            watching:
                count
        }
    );

}

// ============================================================
// SOCKET.IO
// ============================================================

io.on("connection", socket => {

    console.log(
        "Canvas Socket connected:",
        socket.id
    );

    // --------------------------------------------------------
    // JOIN STREAM
    // --------------------------------------------------------

    socket.on(
        "join-stream",
        async data => {

            const streamId =
                String(
                    data?.streamId ||
                    data?.id ||
                    ""
                );

            if (!streamId) {
                return;
            }

            const room =
                `stream:${streamId}`;

            socket.join(room);

            socket.canvasStreamId =
                streamId;

            if (
                !streamViewers.has(
                    streamId
                )
            ) {

                streamViewers.set(
                    streamId,
                    new Set()
                );

            }

            streamViewers
                .get(streamId)
                .add(socket.id);

            sendViewerCount(
                streamId
            );

            console.log(
                "Viewer joined:",
                streamId,
                socket.id
            );

        }
    );

    // --------------------------------------------------------
    // LEAVE STREAM
    // --------------------------------------------------------

    socket.on(
        "leave-stream",
        data => {

            const streamId =
                String(
                    data?.streamId ||
                    data?.id ||
                    socket.canvasStreamId ||
                    ""
                );

            removeViewer(
                socket,
                streamId
            );

        }
    );

    // --------------------------------------------------------
    // BROADCASTER JOIN
    // --------------------------------------------------------

    socket.on(
        "join-broadcaster",
        data => {

            const streamId =
                String(
                    data?.streamId ||
                    data?.id ||
                    ""
                );

            if (!streamId) {
                return;
            }

            socket.join(
                `stream:${streamId}`
            );

            socket.canvasBroadcasterStreamId =
                streamId;

        }
    );

    // --------------------------------------------------------
    // STREAM STARTED
    // --------------------------------------------------------

    socket.on(
        "stream-started",
        data => {

            const streamId =
                String(
                    data?.streamId ||
                    data?.id ||
                    ""
                );

            if (!streamId) {
                return;
            }

            io.emit(
                "stream-started",
                {
                    ...data,
                    streamId
                }
            );

        }
    );

    // --------------------------------------------------------
    // STREAM UPDATED
    // --------------------------------------------------------

    socket.on(
        "stream-updated",
        data => {

            const streamId =
                String(
                    data?.streamId ||
                    data?.id ||
                    ""
                );

            if (!streamId) {
                return;
            }

            io.to(
                `stream:${streamId}`
            ).emit(
                "stream-updated",
                data
            );

        }
    );

    // --------------------------------------------------------
    // HEARTBEAT
    // --------------------------------------------------------

    socket.on(
        "stream-heartbeat",
        data => {

            const streamId =
                String(
                    data?.streamId ||
                    data?.id ||
                    socket.canvasBroadcasterStreamId ||
                    ""
                );

            if (!streamId) {
                return;
            }

            socket.emit(
                "stream-heartbeat",
                {
                    streamId,
                    ok: true,
                    timestamp:
                        Date.now()
                }
            );

        }
    );

    // --------------------------------------------------------
    // STREAM ENDED
    // --------------------------------------------------------

    socket.on(
        "stream-ended",
        async data => {

            const streamId =
                String(
                    data?.streamId ||
                    data?.id ||
                    socket.canvasBroadcasterStreamId ||
                    ""
                );

            if (!streamId) {
                return;
            }

            try {

                if (pool) {

                    await pool.query(
                        `
                        UPDATE streams
                        SET
                            status = 'ended',
                            ended_at =
                                CURRENT_TIMESTAMP
                        WHERE id = $1
                          AND status = 'live'
                        `,
                        [streamId]
                    );

                }

            } catch (error) {

                console.error(
                    "Socket stream end failed:",
                    error.message
                );

            }

            io.to(
                `stream:${streamId}`
            ).emit(
                "stream-ended",
                {
                    streamId,
                    id:
                        streamId
                }
            );

            io.emit(
                "stream-ended",
                {
                    streamId,
                    id:
                        streamId
                }
            );

        }
    );

    // --------------------------------------------------------
    // DISCONNECT
    // IMPORTANT:
    // Disconnecting a broadcaster does NOT automatically
    // end the database stream.
    // Only explicit End Streaming ends it.
    // --------------------------------------------------------

    socket.on(
        "disconnect",
        () => {

            const streamId =
                socket.canvasStreamId;

            if (streamId) {

                removeViewer(
                    socket,
                    streamId
                );

            }

            console.log(
                "Canvas Socket disconnected:",
                socket.id
            );

        }
    );

});

// ============================================================
// REMOVE VIEWER
// ============================================================

function removeViewer(
    socket,
    streamId
) {

    if (!streamId) {
        return;
    }

    const set =
        streamViewers.get(
            String(streamId)
        );

    if (!set) {
        return;
    }

    set.delete(
        socket.id
    );

    socket.leave(
        `stream:${streamId}`
    );

    if (set.size === 0) {

        streamViewers.delete(
            String(streamId)
        );

    }

    sendViewerCount(
        streamId
    );

}

// ============================================================
// CLEAN EXPIRED SESSIONS
// ============================================================

async function cleanExpiredSessions() {

    if (!pool) {
        return;
    }

    try {

        await pool.query(
            `
            DELETE FROM sessions
            WHERE expires_at <= CURRENT_TIMESTAMP
            `
        );

    } catch (error) {

        console.error(
            "Session cleanup failed:",
            error.message
        );

    }

}

setInterval(
    cleanExpiredSessions,
    60 * 60 * 1000
);

// ============================================================
// 404
// ============================================================

app.use(
    (req, res) => {

        res.status(404).json({
            success: false,
            message:
                "Canvas API endpoint not found."
        });

    }
);

// ============================================================
// GLOBAL ERROR HANDLER
// ============================================================

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

// ============================================================
// START SERVER
// ============================================================

async function startServer() {

    await initializeDatabase();

    httpServer.listen(
        PORT,
        () => {

            console.log(
                `Canvas backend running on port ${PORT}`
            );

            console.log(
                "Canvas Socket.IO is ready."
            );

        }
    );

}

startServer();
