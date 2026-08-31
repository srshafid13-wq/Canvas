const express = require("express");
const { Pool } = require("pg");
const crypto = require("crypto");
const http = require("http");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);

const PORT = process.env.PORT || 10000;


/* =========================================
   SOCKET.IO
========================================= */

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
   USERNAME
========================================= */

function cleanUsername(username) {

    return String(username || "")
        .trim()
        .replace(/^@/, "")
        .toLowerCase();

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
            message: "Authentication token is missing."
        });

    }

    try {

        const result =
            await pool.query(
                `
                SELECT
                    u.id,
                    u.name,
                    u.username,
                    u.email,
                    u.created_at
                FROM sessions s
                INNER JOIN users u
                    ON u.id = s.user_id
                WHERE s.token_hash = $1
                AND s.expires_at > CURRENT_TIMESTAMP
                LIMIT 1
                `,
                [hashToken(token)]
            );

        if (result.rows.length === 0) {

            return res.status(401).json({
                success: false,
                message: "Invalid or expired authentication token."
            });

        }

        req.user = result.rows[0];

        next();

    } catch (error) {

        console.error(
            "Authentication error:",
            error.message
        );

        return res.status(500).json({
            success: false,
            message: "Unable to authenticate user."
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
            )
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
            )
        `);


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
            )
        `);


        /* =====================================
           STREAM TABLE
        ===================================== */

        await pool.query(`
            CREATE TABLE IF NOT EXISTS streams (
                id SERIAL PRIMARY KEY,
                user_id INTEGER
                    REFERENCES users(id)
                    ON DELETE CASCADE,
                title VARCHAR(255)
                    DEFAULT 'Canvas Live Stream',
                description TEXT DEFAULT '',
                category VARCHAR(100)
                    DEFAULT 'Entertainment',
                thumbnail TEXT DEFAULT '',
                status VARCHAR(30)
                    DEFAULT 'live',
                is_live BOOLEAN DEFAULT true,
                viewer_count INTEGER DEFAULT 0,
                created_at TIMESTAMP
                    DEFAULT CURRENT_TIMESTAMP,
                ended_at TIMESTAMP
            )
        `);


        /* =====================================
           IMPORTANT MIGRATIONS
        ===================================== */

        await pool.query(`
            ALTER TABLE streams
            ADD COLUMN IF NOT EXISTS
            description TEXT DEFAULT ''
        `);

        await pool.query(`
            ALTER TABLE streams
            ADD COLUMN IF NOT EXISTS
            category VARCHAR(100)
            DEFAULT 'Entertainment'
        `);

        await pool.query(`
            ALTER TABLE streams
            ADD COLUMN IF NOT EXISTS
            thumbnail TEXT DEFAULT ''
        `);

        await pool.query(`
            ALTER TABLE streams
            ADD COLUMN IF NOT EXISTS
            is_live BOOLEAN DEFAULT true
        `);

        await pool.query(`
            ALTER TABLE streams
            ADD COLUMN IF NOT EXISTS
            viewer_count INTEGER DEFAULT 0
        `);

        await pool.query(`
            ALTER TABLE streams
            ADD COLUMN IF NOT EXISTS
            ended_at TIMESTAMP
        `);


        console.log(
            "Canvas database initialized."
        );

    } catch (error) {

        console.error(
            "Database initialization failed:",
            error.message
        );

    }

}


/* =========================================
   START DATABASE INITIALIZATION
========================================= */

initializeDatabase();
/* =========================================
   SIGNUP
========================================= */

app.post("/api/signup", async (req, res) => {

    const {
        name,
        username,
        email,
        password
    } = req.body;

    if (!name || !username || !email || !password) {

        return res.status(400).json({
            success: false,
            message: "All fields are required."
        });

    }

    if (String(password).length < 8) {

        return res.status(400).json({
            success: false,
            message: "Password must be at least 8 characters."
        });

    }

    if (!pool) {

        return res.status(500).json({
            success: false,
            message: "Database is not configured."
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

        const existing =
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

        if (existing.rows.length) {

            const old = existing.rows[0];

            if (
                String(old.username).toLowerCase()
                === cleanUser
            ) {

                return res.status(409).json({
                    success: false,
                    message: "Username already exists."
                });

            }

            return res.status(409).json({
                success: false,
                message: "Email already exists."
            });

        }

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
                    hashPassword(password)
                ]
            );

        const user = result.rows[0];

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
                hashToken(token)
            ]
        );

        res.status(201).json({
            success: true,
            message: "Canvas account created successfully.",
            token,
            user
        });

    } catch (error) {

        console.error(
            "Signup error:",
            error.message
        );

        res.status(500).json({
            success: false,
            message: "Unable to create Canvas account."
        });

    }

});


/* =========================================
   LOGIN
========================================= */

app.post("/api/login", async (req, res) => {

    const {
        email,
        password
    } = req.body;

    if (!email || !password) {

        return res.status(400).json({
            success: false,
            message: "Email and password are required."
        });

    }

    if (!pool) {

        return res.status(500).json({
            success: false,
            message: "Database is not configured."
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
                [cleanEmail]
            );

        if (!result.rows.length) {

            return res.status(401).json({
                success: false,
                message: "Email or password is incorrect."
            });

        }

        const user = result.rows[0];

        if (
            user.password_hash !==
            hashPassword(password)
        ) {

            return res.status(401).json({
                success: false,
                message: "Email or password is incorrect."
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
                hashToken(token)
            ]
        );

        res.json({
            success: true,
            message: "Login successful.",
            token,
            user: {
                id: user.id,
                name: user.name,
                username: user.username,
                email: user.email,
                created_at: user.created_at
            }
        });

    } catch (error) {

        console.error(
            "Login error:",
            error.message
        );

        res.status(500).json({
            success: false,
            message: "Unable to log in to Canvas."
        });

    }

});


/* =========================================
   CURRENT USER
========================================= */

app.get(
    "/api/me",
    authenticateUser,
    async (req, res) => {

        res.json({
            success: true,
            user: req.user
        });

    }
);


/* =========================================
   PROFILE
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
                        u.id,
                        u.name,
                        u.username,
                        u.email,
                        p.bio,
                        p.profile_picture
                    FROM users u
                    LEFT JOIN profiles p
                        ON p.user_id = u.id
                    WHERE u.id = $1
                    LIMIT 1
                    `,
                    [req.user.id]
                );

            if (!result.rows.length) {

                return res.status(404).json({
                    success: false,
                    message: "Profile not found."
                });

            }

            res.json({
                success: true,
                profile: result.rows[0]
            });

        } catch (error) {

            console.error(
                "Profile load error:",
                error.message
            );

            res.status(500).json({
                success: false,
                message: "Unable to load profile."
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

        try {

            const {
                name,
                username,
                bio,
                profile_picture
            } = req.body;

            const cleanName =
                String(
                    name || req.user.name
                ).trim();

            const cleanUser =
                cleanUsername(
                    username || req.user.username
                );

            await pool.query(
                `
                UPDATE users
                SET
                    name = $1,
                    username = $2
                WHERE id = $3
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
                    bio = EXCLUDED.bio,
                    profile_picture =
                        EXCLUDED.profile_picture,
                    updated_at =
                        CURRENT_TIMESTAMP
                `,
                [
                    req.user.id,
                    String(bio || ""),
                    String(profile_picture || "")
                ]
            );

            res.json({
                success: true,
                message: "Profile updated successfully."
            });

        } catch (error) {

            console.error(
                "Profile update error:",
                error.message
            );

            res.status(500).json({
                success: false,
                message: "Unable to update profile."
            });

        }

    }
);


/* =========================================
   START STREAM
========================================= */

app.post(
    "/api/streams",
    authenticateUser,
    async (req, res) => {

        try {

            const {
                title,
                category,
                description,
                thumbnail
            } = req.body;

            const streamTitle =
                String(
                    title || "Canvas Live Stream"
                ).trim();

            if (!streamTitle) {

                return res.status(400).json({
                    success: false,
                    message: "Stream title is required."
                });

            }

            const existing =
                await pool.query(
                    `
                    SELECT id
                    FROM streams
                    WHERE user_id = $1
                    AND is_live = true
                    LIMIT 1
                    `,
                    [req.user.id]
                );

            if (existing.rows.length) {

                return res.status(409).json({
                    success: false,
                    message: "You already have a live stream."
                });

            }

            const result =
                await pool.query(
                    `
                    INSERT INTO streams
                    (
                        user_id,
                        title,
                        description,
                        category,
                        thumbnail,
                        status,
                        is_live,
                        viewer_count,
                        created_at
                    )
                    VALUES
                    (
                        $1,
                        $2,
                        $3,
                        $4,
                        $5,
                        'live',
                        true,
                        0,
                        CURRENT_TIMESTAMP
                    )
                    RETURNING *
                    `,
                    [
                        req.user.id,
                        streamTitle,
                        String(description || ""),
                        String(
                            category ||
                            "Entertainment"
                        ),
                        String(thumbnail || "")
                    ]
                );

            const stream =
                result.rows[0];

            io.emit(
                "stream-updated",
                stream
            );

            res.status(201).json({
                success: true,
                stream
            });

        } catch (error) {

            console.error(
                "Create stream error:",
                error
            );

            res.status(500).json({
                success: false,
                message: "Unable to start stream.",
                error: error.message
            });

        }

    }
);
/* =========================================
   GET LIVE STREAM
========================================= */

app.get(
    "/api/streams/:streamId",
    async (req, res) => {

        try {

            const result =
                await pool.query(
                    `
                    SELECT
                        s.*,
                        u.username,
                        u.name,
                        p.profile_picture
                    FROM streams s
                    LEFT JOIN users u
                        ON u.id = s.user_id
                    LEFT JOIN profiles p
                        ON p.user_id = s.user_id
                    WHERE s.id = $1
                    AND s.is_live = true
                    LIMIT 1
                    `,
                    [req.params.streamId]
                );

            if (!result.rows.length) {

                return res.status(404).json({
                    success: false,
                    message: "Live stream not found."
                });

            }

            res.json({
                success: true,
                stream: result.rows[0]
            });

        } catch (error) {

            console.error(
                "Get stream error:",
                error.message
            );

            res.status(500).json({
                success: false,
                message: "Unable to load stream."
            });

        }

    }
);


/* =========================================
   END STREAM
========================================= */

app.post(
    "/api/streams/:streamId/end",
    authenticateUser,
    async (req, res) => {

        try {

            const result =
                await pool.query(
                    `
                    UPDATE streams
                    SET
                        is_live = false,
                        status = 'ended',
                        ended_at = CURRENT_TIMESTAMP
                    WHERE id = $1
                    AND user_id = $2
                    AND is_live = true
                    RETURNING *
                    `,
                    [
                        req.params.streamId,
                        req.user.id
                    ]
                );

            if (!result.rows.length) {

                return res.status(404).json({
                    success: false,
                    message: "Live stream not found."
                });

            }

            const stream =
                result.rows[0];

            io.to(
                "stream:" + req.params.streamId
            ).emit(
                "stream-ended",
                stream
            );

            io.emit(
                "stream-updated",
                stream
            );

            res.json({
                success: true,
                stream
            });

        } catch (error) {

            console.error(
                "End stream error:",
                error.message
            );

            res.status(500).json({
                success: false,
                message: "Unable to end stream."
            });

        }

    }
);


/* =========================================
   STREAM DISCOVERY
========================================= */

app.get(
    "/api/streams",
    async (req, res) => {

        try {

            const result =
                await pool.query(
                    `
                    SELECT
                        s.*,
                        u.username,
                        u.name,
                        p.profile_picture
                    FROM streams s
                    LEFT JOIN users u
                        ON u.id = s.user_id
                    LEFT JOIN profiles p
                        ON p.user_id = s.user_id
                    WHERE s.is_live = true
                    ORDER BY s.created_at DESC
                    LIMIT 100
                    `
                );

            res.json({
                success: true,
                streams: result.rows
            });

        } catch (error) {

            console.error(
                "Stream discovery error:",
                error.message
            );

            res.status(500).json({
                success: false,
                message: "Unable to load live streams."
            });

        }

    }
);


/* =========================================
   STREAM SEARCH
========================================= */

app.get(
    "/api/search/streams",
    async (req, res) => {

        try {

            const query =
                String(
                    req.query.q || ""
                ).trim();

            if (!query) {

                return res.json({
                    success: true,
                    streams: []
                });

            }

            const search =
                "%" + query + "%";

            const result =
                await pool.query(
                    `
                    SELECT
                        s.*,
                        u.username,
                        u.name,
                        p.profile_picture
                    FROM streams s
                    LEFT JOIN users u
                        ON u.id = s.user_id
                    LEFT JOIN profiles p
                        ON p.user_id = s.user_id
                    WHERE s.is_live = true
                    AND (
                        s.title ILIKE $1
                        OR s.category ILIKE $1
                        OR u.username ILIKE $1
                        OR u.name ILIKE $1
                    )
                    ORDER BY s.created_at DESC
                    LIMIT 50
                    `,
                    [search]
                );

            res.json({
                success: true,
                streams: result.rows
            });

        } catch (error) {

            console.error(
                "Stream search error:",
                error.message
            );

            res.status(500).json({
                success: false,
                message: "Unable to search streams."
            });

        }

    }
);


/* =========================================
   CHAT TABLE
========================================= */

async function ensureChatTable() {

    if (!pool) return;

    try {

        await pool.query(`
            CREATE TABLE IF NOT EXISTS stream_chat (
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
            )
        `);

        console.log("Chat table ready.");

    } catch (error) {

        console.error(
            "Chat table error:",
            error.message
        );

    }

}

ensureChatTable();


/* =========================================
   SEND CHAT
========================================= */

app.post(
    "/api/streams/:streamId/chat",
    authenticateUser,
    async (req, res) => {

        try {

            const streamId =
                req.params.streamId;

            const message =
                String(
                    req.body.message || ""
                ).trim();

            if (!message) {

                return res.status(400).json({
                    success: false,
                    message: "Message cannot be empty."
                });

            }

            if (message.length > 500) {

                return res.status(400).json({
                    success: false,
                    message: "Message is too long."
                });

            }

            const stream =
                await pool.query(
                    `
                    SELECT id
                    FROM streams
                    WHERE id = $1
                    AND is_live = true
                    LIMIT 1
                    `,
                    [streamId]
                );

            if (!stream.rows.length) {

                return res.status(404).json({
                    success: false,
                    message: "This stream is no longer live."
                });

            }

            const result =
                await pool.query(
                    `
                    INSERT INTO stream_chat
                    (
                        stream_id,
                        user_id,
                        message
                    )
                    VALUES ($1,$2,$3)
                    RETURNING *
                    `,
                    [
                        streamId,
                        req.user.id,
                        message
                    ]
                );

            const chat =
                result.rows[0];

            const user =
                await pool.query(
                    `
                    SELECT
                        username,
                        name
                    FROM users
                    WHERE id = $1
                    LIMIT 1
                    `,
                    [req.user.id]
                );

            const info =
                user.rows[0] || {};

            const chatMessage = {
                id: chat.id,
                streamId: Number(streamId),
                userId: req.user.id,
                username:
                    info.username || "User",
                name:
                    info.name ||
                    info.username ||
                    "User",
                message: chat.message,
                created_at:
                    chat.created_at
            };

            io.to(
                "stream:" + streamId
            ).emit(
                "chat-message",
                chatMessage
            );

            res.status(201).json({
                success: true,
                message: chatMessage
            });

        } catch (error) {

            console.error(
                "Send chat error:",
                error.message
            );

            res.status(500).json({
                success: false,
                message: "Unable to send chat message."
            });

        }

    }
);
/* =========================================
   CHAT HISTORY
========================================= */

app.get(
    "/api/streams/:streamId/chat",
    async (req, res) => {

        try {

            const result =
                await pool.query(
                    `
                    SELECT
                        c.id,
                        c.stream_id,
                        c.user_id,
                        c.message,
                        c.created_at,
                        u.username,
                        u.name
                    FROM stream_chat c
                    LEFT JOIN users u
                        ON u.id = c.user_id
                    WHERE c.stream_id = $1
                    ORDER BY c.created_at ASC
                    LIMIT 100
                    `,
                    [req.params.streamId]
                );

            const messages =
                result.rows.map(row => ({
                    id: row.id,
                    streamId:
                        Number(row.stream_id),
                    userId: row.user_id,
                    username:
                        row.username || "User",
                    name:
                        row.name ||
                        row.username ||
                        "User",
                    message: row.message,
                    created_at:
                        row.created_at
                }));

            res.json({
                success: true,
                messages
            });

        } catch (error) {

            console.error(
                "Chat history error:",
                error.message
            );

            res.status(500).json({
                success: false,
                message: "Unable to load chat."
            });

        }

    }
);


/* =========================================
   FOLLOW TABLE
========================================= */

async function ensureFollowTable() {

    if (!pool) return;

    try {

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
                UNIQUE(follower_id, following_id)
            )
        `);

        console.log("Follow table ready.");

    } catch (error) {

        console.error(
            "Follow table error:",
            error.message
        );

    }

}

ensureFollowTable();


/* =========================================
   FOLLOW CREATOR
========================================= */

app.post(
    "/api/follow",
    authenticateUser,
    async (req, res) => {

        try {

            const creatorId =
                Number(req.body.userId);

            if (!creatorId) {

                return res.status(400).json({
                    success: false,
                    message: "Creator ID is required."
                });

            }

            if (
                creatorId ===
                Number(req.user.id)
            ) {

                return res.status(400).json({
                    success: false,
                    message: "You cannot follow yourself."
                });

            }

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
                `,
                [
                    req.user.id,
                    creatorId
                ]
            );

            res.json({
                success: true,
                following: true
            });

        } catch (error) {

            console.error(
                "Follow error:",
                error.message
            );

            res.status(500).json({
                success: false,
                message: "Unable to follow creator."
            });

        }

    }
);


/* =========================================
   FOLLOW STATUS
========================================= */

app.get(
    "/api/follow/:creatorId",
    authenticateUser,
    async (req, res) => {

        try {

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
                        req.user.id,
                        req.params.creatorId
                    ]
                );

            res.json({
                success: true,
                following:
                    result.rows.length > 0
            });

        } catch (error) {

            console.error(
                "Follow status error:",
                error.message
            );

            res.status(500).json({
                success: false,
                message: "Unable to check follow status."
            });

        }

    }
);


/* =========================================
   UNFOLLOW
========================================= */

app.delete(
    "/api/follow/:creatorId",
    authenticateUser,
    async (req, res) => {

        try {

            await pool.query(
                `
                DELETE FROM follows
                WHERE follower_id = $1
                AND following_id = $2
                `,
                [
                    req.user.id,
                    req.params.creatorId
                ]
            );

            res.json({
                success: true,
                following: false
            });

        } catch (error) {

            console.error(
                "Unfollow error:",
                error.message
            );

            res.status(500).json({
                success: false,
                message: "Unable to unfollow creator."
            });

        }

    }
);


/* =========================================
   SUPPORT TABLE
========================================= */

async function ensureSupportTable() {

    if (!pool) return;

    try {

        await pool.query(`
            CREATE TABLE IF NOT EXISTS stream_support (
                id SERIAL PRIMARY KEY,
                sender_id INTEGER NOT NULL
                    REFERENCES users(id)
                    ON DELETE CASCADE,
                creator_id INTEGER NOT NULL
                    REFERENCES users(id)
                    ON DELETE CASCADE,
                stream_id INTEGER
                    REFERENCES streams(id)
                    ON DELETE SET NULL,
                amount NUMERIC(12,2)
                    NOT NULL DEFAULT 0,
                type VARCHAR(30)
                    DEFAULT 'money',
                gift VARCHAR(100),
                emoji VARCHAR(20),
                created_at TIMESTAMP
                    DEFAULT CURRENT_TIMESTAMP
            )
        `);

        console.log("Support table ready.");

    } catch (error) {

        console.error(
            "Support table error:",
            error.message
        );

    }

}

ensureSupportTable();


/* =========================================
   SEND SUPPORT
========================================= */

app.post(
    "/api/support",
    authenticateUser,
    async (req, res) => {

        try {

            const creatorId =
                Number(req.body.creatorId);

            const streamId =
                req.body.streamId
                    ? Number(req.body.streamId)
                    : null;

            const amount =
                Number(req.body.amount);

            const type =
                req.body.type === "gift"
                    ? "gift"
                    : "money";

            const gift =
                req.body.gift || null;

            const emoji =
                req.body.emoji || null;

            if (!creatorId) {

                return res.status(400).json({
                    success: false,
                    message: "Creator information is required."
                });

            }

            if (
                !Number.isFinite(amount) ||
                amount <= 0
            ) {

                return res.status(400).json({
                    success: false,
                    message: "Invalid support amount."
                });

            }

            const creator =
                await pool.query(
                    `
                    SELECT id
                    FROM users
                    WHERE id = $1
                    LIMIT 1
                    `,
                    [creatorId]
                );

            if (!creator.rows.length) {

                return res.status(404).json({
                    success: false,
                    message: "Creator not found."
                });

            }

            if (streamId) {

                const stream =
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
                            creatorId
                        ]
                    );

                if (!stream.rows.length) {

                    return res.status(404).json({
                        success: false,
                        message: "Stream not found."
                    });

                }

            }

            const result =
                await pool.query(
                    `
                    INSERT INTO stream_support
                    (
                        sender_id,
                        creator_id,
                        stream_id,
                        amount,
                        type,
                        gift,
                        emoji
                    )
                    VALUES ($1,$2,$3,$4,$5,$6,$7)
                    RETURNING *
                    `,
                    [
                        req.user.id,
                        creatorId,
                        streamId,
                        amount,
                        type,
                        gift,
                        emoji
                    ]
                );

            const support =
                result.rows[0];

            if (streamId) {

                io.to(
                    "stream:" + streamId
                ).emit(
                    "support-received",
                    {
                        id: support.id,
                        streamId,
                        creatorId,
                        amount:
                            Number(support.amount),
                        type:
                            support.type,
                        gift:
                            support.gift,
                        emoji:
                            support.emoji
                    }
                );

            }

            res.status(201).json({
                success: true,
                support: {
                    id: support.id,
                    amount:
                        Number(support.amount),
                    type:
                        support.type,
                    gift:
                        support.gift,
                    emoji:
                        support.emoji
                }
            });

        } catch (error) {

            console.error(
                "Support error:",
                error.message
            );

            res.status(500).json({
                success: false,
                message: "Unable to send support."
            });

        }

    }
);
/* =========================================
   PART 5/8 — CHAT + FOLLOW
========================================= */


/* =========================================
   CHAT TABLE
========================================= */

async function ensureChatTable() {

    if (!pool) return;

    try {

        await pool.query(`
            CREATE TABLE IF NOT EXISTS stream_chat (
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
            )
        `);

        console.log("Chat table ready.");

    } catch (error) {

        console.error(
            "Chat table error:",
            error.message
        );

    }

}

ensureChatTable();


/* =========================================
   SEND CHAT
========================================= */

app.post(
    "/api/streams/:streamId/chat",
    authenticateUser,
    async (req, res) => {

        try {

            const streamId =
                Number(req.params.streamId);

            const message =
                String(
                    req.body.message || ""
                ).trim();

            if (!Number.isInteger(streamId)) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Invalid stream ID."
                });

            }

            if (!message) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Message cannot be empty."
                });

            }

            if (message.length > 500) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Message is too long."
                });

            }


            const live =
                await pool.query(`
                    SELECT id
                    FROM streams
                    WHERE id = $1
                    AND is_live = true
                    LIMIT 1
                `, [streamId]);


            if (!live.rows.length) {

                return res.status(404).json({
                    success: false,
                    message:
                        "This stream is no longer live."
                });

            }


            const result =
                await pool.query(`
                    INSERT INTO stream_chat
                    (
                        stream_id,
                        user_id,
                        message
                    )
                    VALUES ($1,$2,$3)
                    RETURNING *
                `, [
                    streamId,
                    req.user.id,
                    message
                ]);


            const row =
                result.rows[0];


            const chatMessage = {

                id: row.id,

                streamId: streamId,

                userId: req.user.id,

                username:
                    req.user.username,

                name:
                    req.user.name,

                message:
                    row.message,

                created_at:
                    row.created_at

            };


            io.to(
                "stream:" + streamId
            ).emit(
                "chat-message",
                chatMessage
            );


            return res.status(201).json({

                success: true,

                message:
                    chatMessage

            });

        } catch (error) {

            console.error(
                "Send chat error:",
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


/* =========================================
   CHAT HISTORY
========================================= */

app.get(
    "/api/streams/:streamId/chat",
    async (req, res) => {

        try {

            const streamId =
                Number(req.params.streamId);


            const result =
                await pool.query(`
                    SELECT
                        c.id,
                        c.stream_id,
                        c.user_id,
                        c.message,
                        c.created_at,
                        u.username,
                        u.name
                    FROM stream_chat c
                    LEFT JOIN users u
                        ON u.id = c.user_id
                    WHERE c.stream_id = $1
                    ORDER BY c.created_at ASC
                    LIMIT 100
                `, [streamId]);


            const messages =
                result.rows.map(row => ({

                    id:
                        row.id,

                    streamId:
                        Number(row.stream_id),

                    userId:
                        row.user_id,

                    username:
                        row.username || "User",

                    name:
                        row.name ||
                        row.username ||
                        "User",

                    message:
                        row.message,

                    created_at:
                        row.created_at

                }));


            return res.json({
                success: true,
                messages: messages
            });

        } catch (error) {

            console.error(
                "Chat history error:",
                error.message
            );

            return res.status(500).json({
                success: false,
                message:
                    "Unable to load chat."
            });

        }

    }
);


/* =========================================
   FOLLOW TABLE
========================================= */

async function ensureFollowTable() {

    if (!pool) return;

    try {

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
            )
        `);

        console.log("Follow table ready.");

    } catch (error) {

        console.error(
            "Follow table error:",
            error.message
        );

    }

}

ensureFollowTable();


/* =========================================
   FOLLOW CREATOR
========================================= */

app.post(
    "/api/follow",
    authenticateUser,
    async (req, res) => {

        try {

            const creatorId =
                Number(req.body.userId);


            if (!Number.isInteger(creatorId)) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Creator ID is required."
                });

            }


            if (
                creatorId ===
                Number(req.user.id)
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        "You cannot follow yourself."
                });

            }


            await pool.query(`
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
            `, [
                req.user.id,
                creatorId
            ]);


            return res.json({
                success: true,
                following: true
            });

        } catch (error) {

            console.error(
                "Follow error:",
                error.message
            );

            return res.status(500).json({
                success: false,
                message:
                    "Unable to follow creator."
            });

        }

    }
);


/* =========================================
   FOLLOW STATUS
========================================= */

app.get(
    "/api/follow/:creatorId",
    authenticateUser,
    async (req, res) => {

        try {

            const creatorId =
                Number(req.params.creatorId);


            const result =
                await pool.query(`
                    SELECT id
                    FROM follows
                    WHERE follower_id = $1
                    AND following_id = $2
                    LIMIT 1
                `, [
                    req.user.id,
                    creatorId
                ]);


            return res.json({
                success: true,
                following:
                    result.rows.length > 0
            });

        } catch (error) {

            console.error(
                "Follow status error:",
                error.message
            );

            return res.status(500).json({
                success: false,
                message:
                    "Unable to check follow status."
            });

        }

    }
);
