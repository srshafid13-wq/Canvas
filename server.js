const express = require("express");
const { Pool } = require("pg");
const crypto = require("crypto");
const http = require("http");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);

const PORT = process.env.PORT || 10000;

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
   PASSWORD
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
                AND s.expires_at >
                    CURRENT_TIMESTAMP
                LIMIT 1
                `,
                [hashToken(token)]
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
            "Authentication error:",
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
            "WARNING: canvas_db_r13t is not configured."
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
                is_live BOOLEAN
                    DEFAULT TRUE,
                viewer_count INTEGER
                    DEFAULT 0,
                created_at TIMESTAMP
                    DEFAULT CURRENT_TIMESTAMP,
                ended_at TIMESTAMP
            );
        `);


        console.log(
            "Canvas core database initialized."
        );

    } catch (error) {

        console.error(
            "Database initialization error:",
            error.message
        );

    }

}


/* =========================================
   CURRENT USER
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
                        u.id,
                        u.name,
                        u.username,
                        u.email,
                        u.created_at,
                        COALESCE(
                            p.profile_picture,
                            ''
                        ) AS profile_picture
                    FROM users u
                    LEFT JOIN profiles p
                        ON p.user_id = u.id
                    WHERE u.id = $1
                    LIMIT 1
                    `,
                    [req.user.id]
                );

            res.json({
                success: true,
                user:
                    result.rows[0]
            });

        } catch (error) {

            console.error(
                "Me error:",
                error.message
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to load user."
            });

        }

    }
);
/* =========================================
   PART 2/8 — STREAM DATABASE + CREATION
========================================= */


/* =========================================
   FIX / MIGRATE STREAM TABLE
========================================= */

async function ensureStreamTable() {

    if (!pool) return;

    try {

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
                is_live BOOLEAN
                    DEFAULT TRUE,
                viewer_count INTEGER
                    DEFAULT 0,
                created_at TIMESTAMP
                    DEFAULT CURRENT_TIMESTAMP,
                ended_at TIMESTAMP
            );
        `);


        /* Add missing columns to old
           Canvas databases */

        await pool.query(`
            ALTER TABLE streams
            ADD COLUMN IF NOT EXISTS
            description TEXT DEFAULT '';
        `);


        await pool.query(`
            ALTER TABLE streams
            ADD COLUMN IF NOT EXISTS
            category VARCHAR(100)
            DEFAULT 'Entertainment';
        `);


        await pool.query(`
            ALTER TABLE streams
            ADD COLUMN IF NOT EXISTS
            thumbnail TEXT DEFAULT '';
        `);


        await pool.query(`
            ALTER TABLE streams
            ADD COLUMN IF NOT EXISTS
            status VARCHAR(30)
            DEFAULT 'live';
        `);


        await pool.query(`
            ALTER TABLE streams
            ADD COLUMN IF NOT EXISTS
            is_live BOOLEAN
            DEFAULT TRUE;
        `);


        await pool.query(`
            ALTER TABLE streams
            ADD COLUMN IF NOT EXISTS
            viewer_count INTEGER
            DEFAULT 0;
        `);


        await pool.query(`
            ALTER TABLE streams
            ADD COLUMN IF NOT EXISTS
            ended_at TIMESTAMP;
        `);


        /* Keep old status and new is_live
           synchronized */

        await pool.query(`
            UPDATE streams
            SET is_live =
                CASE
                    WHEN LOWER(
                        COALESCE(status, '')
                    ) = 'live'
                    THEN TRUE
                    ELSE FALSE
                END
            WHERE is_live IS NULL;
        `);


        await pool.query(`
            UPDATE streams
            SET viewer_count = 0
            WHERE viewer_count IS NULL;
        `);


        console.log(
            "Canvas stream database is ready."
        );

    } catch (error) {

        console.error(
            "Stream database setup failed:",
            error.message
        );

    }

}


/* =========================================
   CREATE STREAM
========================================= */

app.post(
    "/api/streams",
    authenticateUser,
    async (req, res) => {

        try {

            if (!pool) {

                return res.status(500).json({
                    success: false,
                    message:
                        "Database is not configured."
                });

            }


            const title =
                String(
                    req.body.title || ""
                ).trim();

            const category =
                String(
                    req.body.category ||
                    "Entertainment"
                ).trim();

            const description =
                String(
                    req.body.description || ""
                ).trim();

            const thumbnail =
                String(
                    req.body.thumbnail || ""
                ).trim();


            if (!title) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Stream title is required."
                });

            }


            /* -----------------------------
               CHECK EXISTING LIVE STREAM
            ----------------------------- */

            const existing =
                await pool.query(
                    `
                    SELECT id
                    FROM streams
                    WHERE user_id = $1
                    AND is_live = TRUE
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
                    streamId:
                        existing.rows[0].id
                });

            }


            /* -----------------------------
               CREATE STREAM
            ----------------------------- */

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
                        TRUE,
                        0,
                        CURRENT_TIMESTAMP
                    )
                    RETURNING *
                    `,
                    [
                        req.user.id,
                        title,
                        description,
                        category,
                        thumbnail
                    ]
                );


            const stream =
                result.rows[0];


            /* -----------------------------
               GET CREATOR PROFILE
            ----------------------------- */

            const creatorResult =
                await pool.query(
                    `
                    SELECT
                        u.id,
                        u.name,
                        u.username,
                        COALESCE(
                            p.profile_picture,
                            ''
                        ) AS profile_picture
                    FROM users u
                    LEFT JOIN profiles p
                        ON p.user_id = u.id
                    WHERE u.id = $1
                    LIMIT 1
                    `,
                    [req.user.id]
                );


            const creator =
                creatorResult.rows[0] || {};


            const streamData = {

                ...stream,

                name:
                    creator.name ||
                    req.user.name,

                username:
                    creator.username ||
                    req.user.username,

                profile_picture:
                    creator.profile_picture ||
                    ""

            };


            /* -----------------------------
               REAL-TIME UPDATE
            ----------------------------- */

            io.emit(
                "stream-updated",
                streamData
            );


            return res.status(201).json({

                success: true,

                message:
                    "Canvas stream created successfully.",

                stream:
                    streamData

            });

        } catch (error) {

            console.error(
                "CREATE STREAM ERROR:",
                error
            );

            return res.status(500).json({

                success: false,

                message:
                    "Unable to create Canvas stream.",

                error:
                    error.message

            });

        }

    }
);


/* =========================================
   STREAM LIST
========================================= */

app.get(
    "/api/streams",
    async (req, res) => {

        try {

            if (!pool) {

                return res.status(500).json({
                    success: false,
                    message:
                        "Database is not configured."
                });

            }


            const result =
                await pool.query(
                    `
                    SELECT
                        s.id,
                        s.user_id,
                        s.title,
                        s.description,
                        s.category,
                        s.thumbnail,
                        s.status,
                        s.is_live,
                        s.viewer_count,
                        s.created_at,
                        s.ended_at,

                        u.name,
                        u.username,

                        COALESCE(
                            p.profile_picture,
                            ''
                        ) AS profile_picture

                    FROM streams s

                    LEFT JOIN users u
                        ON u.id = s.user_id

                    LEFT JOIN profiles p
                        ON p.user_id = s.user_id

                    WHERE s.is_live = TRUE

                    ORDER BY
                        s.created_at DESC

                    LIMIT 100
                    `
                );


            res.json({
                success: true,
                streams:
                    result.rows
            });

        } catch (error) {

            console.error(
                "Stream list error:",
                error.message
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to load live streams."
            });

        }

    }
);
/* =========================================
   PART 3/8 — STREAM CONTROL + SEARCH
========================================= */


/* =========================================
   GET SINGLE LIVE STREAM
========================================= */

app.get(
    "/api/streams/:streamId",
    async (req, res) => {

        try {

            if (!pool) {

                return res.status(500).json({
                    success: false,
                    message:
                        "Database is not configured."
                });

            }


            const streamId =
                Number(req.params.streamId);


            if (!Number.isInteger(streamId)) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Invalid stream ID."
                });

            }


            const result =
                await pool.query(
                    `
                    SELECT
                        s.id,
                        s.user_id,
                        s.title,
                        s.description,
                        s.category,
                        s.thumbnail,
                        s.status,
                        s.is_live,
                        s.viewer_count,
                        s.created_at,

                        u.name,
                        u.username,

                        COALESCE(
                            p.profile_picture,
                            ''
                        ) AS profile_picture

                    FROM streams s

                    LEFT JOIN users u
                        ON u.id = s.user_id

                    LEFT JOIN profiles p
                        ON p.user_id = s.user_id

                    WHERE s.id = $1
                    AND s.is_live = TRUE

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
                        "Live stream not found."
                });

            }


            res.json({
                success: true,
                stream:
                    result.rows[0]
            });

        } catch (error) {

            console.error(
                "Get stream error:",
                error.message
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to load stream."
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

            if (!pool) {

                return res.status(500).json({
                    success: false,
                    message:
                        "Database is not configured."
                });

            }


            const streamId =
                Number(req.params.streamId);


            if (!Number.isInteger(streamId)) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Invalid stream ID."
                });

            }


            const result =
                await pool.query(
                    `
                    UPDATE streams

                    SET
                        is_live = FALSE,
                        status = 'ended',
                        ended_at =
                            CURRENT_TIMESTAMP

                    WHERE id = $1
                    AND user_id = $2
                    AND is_live = TRUE

                    RETURNING *
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


            const stream =
                result.rows[0];


            /* Tell everyone watching */

            io.to(
                "stream:" + streamId
            ).emit(
                "stream-ended",
                stream
            );


            /* Update home/explore */

            io.emit(
                "stream-updated",
                stream
            );


            res.json({
                success: true,
                message:
                    "Stream ended successfully.",
                stream:
                    stream
            });

        } catch (error) {

            console.error(
                "End stream error:",
                error.message
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to end stream."
            });

        }

    }
);


/* =========================================
   SEARCH LIVE STREAMS
========================================= */

app.get(
    "/api/search/streams",
    async (req, res) => {

        try {

            if (!pool) {

                return res.status(500).json({
                    success: false,
                    message:
                        "Database is not configured."
                });

            }


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
                        s.id,
                        s.user_id,
                        s.title,
                        s.description,
                        s.category,
                        s.thumbnail,
                        s.status,
                        s.is_live,
                        s.viewer_count,
                        s.created_at,

                        u.name,
                        u.username,

                        COALESCE(
                            p.profile_picture,
                            ''
                        ) AS profile_picture

                    FROM streams s

                    LEFT JOIN users u
                        ON u.id = s.user_id

                    LEFT JOIN profiles p
                        ON p.user_id = s.user_id

                    WHERE s.is_live = TRUE

                    AND (
                        s.title ILIKE $1

                        OR s.category ILIKE $1

                        OR s.description ILIKE $1

                        OR u.username ILIKE $1

                        OR u.name ILIKE $1
                    )

                    ORDER BY
                        s.created_at DESC

                    LIMIT 50
                    `,
                    [search]
                );


            res.json({
                success: true,
                streams:
                    result.rows
            });

        } catch (error) {

            console.error(
                "Stream search error:",
                error.message
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to search streams."
            });

        }

    }
);
/* =========================================
   PART 4/8 — CHAT SYSTEM
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
            );
        `);


        console.log(
            "Canvas chat table ready."
        );

    } catch (error) {

        console.error(
            "Chat table setup error:",
            error.message
        );

    }

}


/* =========================================
   SEND CHAT
========================================= */

app.post(
    "/api/streams/:streamId/chat",
    authenticateUser,
    async (req, res) => {

        try {

            if (!pool) {

                return res.status(500).json({
                    success: false,
                    message:
                        "Database is not configured."
                });

            }


            const streamId =
                Number(req.params.streamId);


            const message =
                String(
                    req.body.message || ""
                ).trim();


            if (
                !Number.isInteger(streamId)
            ) {

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


            /* -----------------------------
               CHECK LIVE STREAM
            ----------------------------- */

            const streamResult =
                await pool.query(
                    `
                    SELECT
                        id,
                        user_id
                    FROM streams
                    WHERE id = $1
                    AND is_live = TRUE
                    LIMIT 1
                    `,
                    [streamId]
                );


            if (
                streamResult.rows.length === 0
            ) {

                return res.status(404).json({
                    success: false,
                    message:
                        "This stream is no longer live."
                });

            }


            /* -----------------------------
               SAVE MESSAGE
            ----------------------------- */

            const result =
                await pool.query(
                    `
                    INSERT INTO stream_chat
                    (
                        stream_id,
                        user_id,
                        message
                    )
                    VALUES
                    (
                        $1,
                        $2,
                        $3
                    )
                    RETURNING
                        id,
                        stream_id,
                        user_id,
                        message,
                        created_at
                    `,
                    [
                        streamId,
                        req.user.id,
                        message
                    ]
                );


            const row =
                result.rows[0];


            /* -----------------------------
               USER DATA
            ----------------------------- */

            const userResult =
                await pool.query(
                    `
                    SELECT
                        u.id,
                        u.name,
                        u.username,

                        COALESCE(
                            p.profile_picture,
                            ''
                        ) AS profile_picture

                    FROM users u

                    LEFT JOIN profiles p
                        ON p.user_id = u.id

                    WHERE u.id = $1

                    LIMIT 1
                    `,
                    [req.user.id]
                );


            const user =
                userResult.rows[0] || {};


            const chatMessage = {

                id:
                    row.id,

                streamId:
                    Number(row.stream_id),

                userId:
                    row.user_id,

                name:
                    user.name ||
                    "User",

                username:
                    user.username ||
                    "User",

                profile_picture:
                    user.profile_picture ||
                    "",

                message:
                    row.message,

                created_at:
                    row.created_at

            };


            /* -----------------------------
               REAL-TIME BROADCAST
            ----------------------------- */

            io.to(
                "stream:" + streamId
            ).emit(
                "chat-message",
                chatMessage
            );


            res.status(201).json({

                success: true,

                message:
                    chatMessage

            });

        } catch (error) {

            console.error(
                "Send chat error:",
                error.message
            );

            res.status(500).json({
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

            if (!pool) {

                return res.status(500).json({
                    success: false,
                    message:
                        "Database is not configured."
                });

            }


            const streamId =
                Number(req.params.streamId);


            if (
                !Number.isInteger(streamId)
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Invalid stream ID."
                });

            }


            const result =
                await pool.query(
                    `
                    SELECT
                        c.id,
                        c.stream_id,
                        c.user_id,
                        c.message,
                        c.created_at,

                        u.name,
                        u.username,

                        COALESCE(
                            p.profile_picture,
                            ''
                        ) AS profile_picture

                    FROM stream_chat c

                    LEFT JOIN users u
                        ON u.id = c.user_id

                    LEFT JOIN profiles p
                        ON p.user_id = c.user_id

                    WHERE c.stream_id = $1

                    ORDER BY
                        c.created_at ASC

                    LIMIT 100
                    `,
                    [streamId]
                );


            const messages =
                result.rows.map(row => ({

                    id:
                        row.id,

                    streamId:
                        Number(
                            row.stream_id
                        ),

                    userId:
                        row.user_id,

                    name:
                        row.name ||
                        "User",

                    username:
                        row.username ||
                        "User",

                    profile_picture:
                        row.profile_picture ||
                        "",

                    message:
                        row.message,

                    created_at:
                        row.created_at

                }));


            res.json({
                success: true,
                messages:
                    messages
            });

        } catch (error) {

            console.error(
                "Chat history error:",
                error.message
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to load chat."
            });

        }

    }
);


/* =========================================
   INITIALIZE CHAT
========================================= */

ensureChatTable();
/* =========================================
   404 API HANDLER
========================================= */

app.use("/api", (req, res) => {

    res.status(404).json({
        success: false,
        message: "Canvas API endpoint not found.",
        path: req.originalUrl
    });

});


/* =========================================
   GLOBAL ERROR HANDLER
========================================= */

app.use((error, req, res, next) => {

    console.error(
        "Canvas server error:",
        error
    );

    if (res.headersSent) {
        return next(error);
    }

    res.status(500).json({
        success: false,
        message: "Canvas server error."
    });

});


/* =========================================
   SOCKET ERROR HANDLING
========================================= */

io.engine.on("connection_error", (error) => {

    console.error(
        "Socket connection error:",
        error.message
    );

});


/* =========================================
   START SERVER
========================================= */

server.listen(
    PORT,
    () => {

        console.log(
            "================================="
        );

        console.log(
            "Canvas server running on port " +
            PORT
        );

        console.log(
            "Socket.IO is enabled."
        );

        console.log(
            "Database:",
            pool
                ? "configured"
                : "NOT configured"
        );

        console.log(
            "================================="
        );

    }
);


/* =========================================
   GRACEFUL SHUTDOWN
========================================= */

process.on(
    "SIGTERM",
    async () => {

        console.log(
            "Canvas server shutting down..."
        );

        await new Promise(
            (resolve) => {

                server.close(resolve);

            }
        );

        if (pool) {
            await pool.end();
        }

        process.exit(0);

    }
);
