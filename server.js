const express = require("express");
const { Pool } = require("pg");
const crypto = require("crypto");
const http = require("http");
const { Server } = require("socket.io");

const app = express();

/*
 * Canvas uses Socket.IO for live stream
 * communication and chat.
 *
 * Keep the Express app itself unchanged.
 */
const httpServer = http.createServer(app);

const io = new Server(httpServer, {
    cors: {
        origin: "*",
        methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
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
   JSON BODY
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
   AUTHENTICATION MIDDLEWARE
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

                user_id INTEGER
                    UNIQUE NOT NULL
                    REFERENCES users(id)
                    ON DELETE CASCADE,

                bio TEXT DEFAULT '',

                profile_picture TEXT
                    DEFAULT '',

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

                token_hash TEXT
                    UNIQUE NOT NULL,

                created_at TIMESTAMP
                    DEFAULT CURRENT_TIMESTAMP,

                expires_at TIMESTAMP NOT NULL
            );
        `);


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


        /*
         * Preserve the existing streams table
         * and only add user_id if necessary.
         */

        await pool.query(`
            ALTER TABLE streams
            ADD COLUMN IF NOT EXISTS user_id
            INTEGER REFERENCES users(id)
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
   DATABASE TABLE HELPERS
========================================= */

async function ensureFollowTable() {

    if (!pool) return;

    await pool.query(`
        CREATE TABLE IF NOT EXISTS follows (
            follower_id INTEGER NOT NULL
                REFERENCES users(id)
                ON DELETE CASCADE,

            following_id INTEGER NOT NULL
                REFERENCES users(id)
                ON DELETE CASCADE,

            created_at TIMESTAMP
                DEFAULT CURRENT_TIMESTAMP,

            PRIMARY KEY (
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
        idx_follows_follower
        ON follows(follower_id);
    `);

    await pool.query(`
        CREATE INDEX IF NOT EXISTS
        idx_follows_following
        ON follows(following_id);
    `);
}


async function ensureChatTable() {

    if (!pool) return;

    await pool.query(`
        CREATE TABLE IF NOT EXISTS chat_messages (
            id SERIAL PRIMARY KEY,

            stream_id INTEGER NOT NULL,

            user_id INTEGER
                REFERENCES users(id)
                ON DELETE SET NULL,

            username VARCHAR(100),

            message TEXT NOT NULL,

            created_at TIMESTAMP
                DEFAULT CURRENT_TIMESTAMP
        );
    `);

    await pool.query(`
        CREATE INDEX IF NOT EXISTS
        idx_chat_messages_stream
        ON chat_messages(stream_id);
    `);

    await pool.query(`
        CREATE INDEX IF NOT EXISTS
        idx_chat_messages_created
        ON chat_messages(created_at);
    `);
}


/* =========================================
   STREAM COLUMNS
========================================= */

async function ensureStreamColumns() {

    if (!pool) return;

    /*
     * These ALTER statements are intentionally
     * non-destructive.
     *
     * They make the current Render database
     * compatible without deleting existing data.
     */

    await pool.query(`
        ALTER TABLE streams
        ADD COLUMN IF NOT EXISTS
        thumbnail TEXT DEFAULT '';
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
        is_live BOOLEAN
        DEFAULT FALSE;
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
        updated_at TIMESTAMP
        DEFAULT CURRENT_TIMESTAMP;
    `);

    await pool.query(`
        ALTER TABLE streams
        ADD COLUMN IF NOT EXISTS
        ended_at TIMESTAMP;
    `);
}


/* =========================================
   FOLLOW COUNTS
========================================= */

async function getFollowCounts(userId) {

    if (!pool) {

        return {
            followers: 0,
            following: 0
        };
    }

    const result =
        await pool.query(
            `
            SELECT

                (
                    SELECT COUNT(*)
                    FROM follows
                    WHERE following_id = $1
                ) AS followers,

                (
                    SELECT COUNT(*)
                    FROM follows
                    WHERE follower_id = $1
                ) AS following
            `,
            [userId]
        );

    return {
        followers:
            Number(
                result.rows[0].followers || 0
            ),

        following:
            Number(
                result.rows[0].following || 0
            )
    };
}


/* =========================================
   STREAM HELPERS
========================================= */

function cleanStreamTitle(title) {

    const value =
        String(
            title ||
            "Canvas Live Stream"
        ).trim();

    return value.substring(0, 255);
}


function cleanStreamCategory(category) {

    const value =
        String(
            category ||
            "Entertainment"
        ).trim();

    return value.substring(0, 100);
}


function normalizeStreamId(value) {

    const id =
        Number(value);

    if (!Number.isInteger(id) || id <= 0) {
        return null;
    }

    return id;
}


/* =========================================
   STREAM VIEWER COUNTS
========================================= */

const streamViewerCounts =
    new Map();

const streamRooms =
    new Map();


function getStreamRoom(streamId) {

    return `stream:${streamId}`;
}


function getViewerCount(streamId) {

    return Number(
        streamViewerCounts.get(
            String(streamId)
        ) || 0
    );
}


function addViewer(
    streamId,
    socketId
) {

    streamId =
        String(streamId);

    let viewers =
        streamRooms.get(streamId);

    if (!viewers) {

        viewers =
            new Set();

        streamRooms.set(
            streamId,
            viewers
        );
    }

    /*
     * A socket can only count once
     * inside one stream room.
     */

    if (viewers.has(socketId)) {

        return viewers.size;
    }

    viewers.add(socketId);

    streamViewerCounts.set(
        streamId,
        viewers.size
    );

    return viewers.size;
}


function removeViewer(
    streamId,
    socketId
) {

    streamId =
        String(streamId);

    const viewers =
        streamRooms.get(streamId);

    if (!viewers) {
        return 0;
    }

    viewers.delete(socketId);

    if (viewers.size === 0) {

        streamRooms.delete(
            streamId
        );

        streamViewerCounts.delete(
            streamId
        );

        return 0;
    }

    streamViewerCounts.set(
        streamId,
        viewers.size
    );

    return viewers.size;
}


/* =========================================
   OPTIONAL AUTHENTICATION
========================================= */

async function optionalAuthenticateUser(
    req,
    res,
    next
) {

    req.user = null;

    if (!pool) {
        return next();
    }

    const authorization =
        req.headers.authorization || "";

    if (
        !authorization.startsWith(
            "Bearer "
        )
    ) {
        return next();
    }

    const token =
        authorization
            .substring(7)
            .trim();

    if (!token) {
        return next();
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
            result.rows.length > 0
        ) {
            req.user =
                result.rows[0];
        }

    } catch (error) {

        console.error(
            "Optional authentication failed:",
            error.message
        );
    }

    next();
}


/* =========================================
   STREAM FORMATTER
========================================= */

function formatStreamRow(row) {

    if (!row) {
        return null;
    }

    const streamId =
        normalizeStreamId(row.id);

    const userId =
        row.user_id
            ? Number(row.user_id)
            : null;

    const viewerCount =
        getViewerCount(streamId);


    const creatorName =
        row.name ||
        row.username ||
        "Canvas User";


    const creatorUsername =
        row.username ||
        "";


    const profilePicture =
        row.profile_picture ||
        "";


    return {

        id:
            streamId,

        stream_id:
            streamId,

        user_id:
            userId,

        title:
            row.title ||
            "Canvas Live Stream",

        stream_title:
            row.title ||
            "Canvas Live Stream",

        category:
            row.category ||
            "Entertainment",

        stream_category:
            row.category ||
            "Entertainment",

        thumbnail:
            row.thumbnail ||
            "",

        status:
            row.status ||
            "live",

        is_live:
            Boolean(row.is_live),

        viewer_count:
            viewerCount,

        created_at:
            row.created_at,

        updated_at:
            row.updated_at,

        creator: {

            id:
                userId,

            userId:
                userId,

            name:
                creatorName,

            displayName:
                creatorName,

            username:
                creatorUsername,

            profile_picture:
                profilePicture,

            profileImage:
                profilePicture,

            profilePhoto:
                profilePicture,

            avatar:
                profilePicture
        },

        creator_id:
            userId,

        creator_name:
            creatorName,

        creator_username:
            creatorUsername,

        profile_picture:
            profilePicture,

        profileImage:
            profilePicture
    };
}


/* =========================================
   GET ACTIVE STREAM FOR USER
========================================= */

async function getUserActiveStream(userId) {

    if (!pool) {
        return null;
    }

    const result =
        await pool.query(
            `
            SELECT
                s.*,

                u.username,

                u.name,

                p.profile_picture

            FROM streams s

            INNER JOIN users u
                ON u.id = s.user_id

            LEFT JOIN profiles p
                ON p.user_id = u.id

            WHERE s.user_id = $1
              AND s.is_live = TRUE

            ORDER BY s.created_at DESC

            LIMIT 1
            `,
            [userId]
        );

    return result.rows[0] || null;
}


/* =========================================
   GET STREAM BY ID
========================================= */

async function getStreamById(streamId) {

    if (!pool) {
        return null;
    }

    streamId =
        normalizeStreamId(streamId);

    if (!streamId) {
        return null;
    }

    const result =
        await pool.query(
            `
            SELECT
                s.*,

                u.username,

                u.name,

                p.profile_picture

            FROM streams s

            INNER JOIN users u
                ON u.id = s.user_id

            LEFT JOIN profiles p
                ON p.user_id = u.id

            WHERE s.id = $1

            LIMIT 1
            `,
            [streamId]
        );

    return result.rows[0] || null;
}


/* =========================================
   GET ALL LIVE STREAMS
========================================= */

async function getLiveStreams() {

    if (!pool) {
        return [];
    }

    const result =
        await pool.query(
            `
            SELECT
                s.*,

                u.username,

                u.name,

                p.profile_picture

            FROM streams s

            INNER JOIN users u
                ON u.id = s.user_id

            LEFT JOIN profiles p
                ON p.user_id = u.id

            WHERE s.is_live = TRUE

            ORDER BY
                s.created_at DESC
            `
        );

    return result.rows.map(
        formatStreamRow
    );
}


/* =========================================
   UPDATE STREAM VIEWER COUNT
========================================= */

async function syncStreamViewerCount(
    streamId
) {

    if (!pool) {
        return;
    }

    const count =
        getViewerCount(streamId);

    try {

        await pool.query(
            `
            UPDATE streams
            SET viewer_count = $1,
                updated_at =
                    CURRENT_TIMESTAMP

            WHERE id = $2
            `,
            [
                count,
                streamId
            ]
        );

    } catch (error) {

        console.error(
            "Failed to sync viewer count:",
            error.message
        );
    }
                  }
/* =========================================
   GET ALL LIVE STREAMS
========================================= */

app.get(
    "/api/streams",
    async (req, res) => {

        try {

            if (!pool) {

                return res.json({
                    streams: []
                });
            }

            const streams =
                await getLiveStreams();

            return res.json({
                streams
            });

        } catch (error) {

            console.error(
                "GET /api/streams error:",
                error
            );

            return res.status(500).json({
                error:
                    "Failed to load streams"
            });
        }
    }
);


/* =========================================
   GET SINGLE STREAM
========================================= */

app.get(
    "/api/streams/:streamId",
    async (req, res) => {

        try {

            const streamId =
                normalizeStreamId(
                    req.params.streamId
                );

            if (!streamId) {

                return res.status(400).json({
                    error:
                        "Invalid stream ID"
                });
            }

            const stream =
                await getStreamById(
                    streamId
                );

            if (!stream) {

                return res.status(404).json({
                    error:
                        "Stream not found"
                });
            }

            const formatted =
                formatStreamRow(stream);

            return res.json({
                stream:
                    formatted
            });

        } catch (error) {

            console.error(
                "GET /api/streams/:streamId error:",
                error
            );

            return res.status(500).json({
                error:
                    "Failed to load stream"
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

        try {

            if (!pool) {

                return res.status(503).json({
                    error:
                        "Database unavailable"
                });
            }


            /*
             * Only one active stream
             * is allowed per user.
             */

            const existingStream =
                await getUserActiveStream(
                    req.user.id
                );

            if (existingStream) {

                return res.status(409).json({

                    error:
                        "You already have an active stream",

                    stream:
                        formatStreamRow(
                            existingStream
                        )
                });
            }


            const title =
                cleanStreamTitle(
                    req.body.title
                );


            const category =
                cleanStreamCategory(
                    req.body.category
                );


            const thumbnail =
                String(
                    req.body.thumbnail ||
                    ""
                ).trim();


            const result =
                await pool.query(
                    `
                    INSERT INTO streams
                    (
                        user_id,
                        title,
                        category,
                        thumbnail,
                        status,
                        is_live,
                        viewer_count,
                        created_at,
                        updated_at
                    )

                    VALUES
                    (
                        $1,
                        $2,
                        $3,
                        $4,
                        'live',
                        TRUE,
                        0,
                        CURRENT_TIMESTAMP,
                        CURRENT_TIMESTAMP
                    )

                    RETURNING *
                    `,
                    [
                        req.user.id,
                        title,
                        category,
                        thumbnail
                    ]
                );


            const created =
                await getStreamById(
                    result.rows[0].id
                );


            const formatted =
                formatStreamRow(
                    created
                );


            /*
             * Notify connected clients
             * that a new live stream exists.
             *
             * This is harmless when Socket.IO
             * is not connected yet.
             */

            if (
                typeof io !== "undefined"
            ) {

                io.emit(
                    "stream-updated",
                    formatted
                );
            }


            return res.status(201).json({

                success: true,

                stream:
                    formatted
            });

        } catch (error) {

            console.error(
                "POST /api/streams error:",
                error
            );

            return res.status(500).json({
                error:
                    "Failed to create stream"
            });
        }
    }
);


/* =========================================
   END STREAM
========================================= */

app.put(
    "/api/streams/:streamId/end",
    authenticateUser,
    async (req, res) => {

        try {

            if (!pool) {

                return res.status(503).json({
                    error:
                        "Database unavailable"
                });
            }


            const streamId =
                normalizeStreamId(
                    req.params.streamId
                );


            if (!streamId) {

                return res.status(400).json({
                    error:
                        "Invalid stream ID"
                });
            }


            const result =
                await pool.query(
                    `
                    UPDATE streams

                    SET
                        is_live = FALSE,
                        status = 'ended',
                        viewer_count = 0,
                        ended_at =
                            CURRENT_TIMESTAMP,
                        updated_at =
                            CURRENT_TIMESTAMP

                    WHERE id = $1
                      AND user_id = $2

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
                    error:
                        "Stream not found"
                });
            }


            /*
             * Remove all in-memory viewers
             * belonging to this stream.
             */

            streamRooms.delete(
                String(streamId)
            );

            streamViewerCounts.delete(
                String(streamId)
            );


            const stream =
                await getStreamById(
                    streamId
                );


            const formatted =
                formatStreamRow(
                    stream
                );


            if (
                typeof io !== "undefined"
            ) {

                io.to(
                    getStreamRoom(streamId)
                ).emit(
                    "stream-ended",
                    {
                        streamId
                    }
                );

                io.emit(
                    "stream-updated",
                    formatted
                );
            }


            return res.json({

                success: true,

                stream:
                    formatted
            });

        } catch (error) {

            console.error(
                "End stream error:",
                error
            );

            return res.status(500).json({
                error:
                    "Failed to end stream"
            });
        }
    }
);


/* =========================================
   DELETE STREAM
========================================= */

app.delete(
    "/api/streams/:streamId",
    authenticateUser,
    async (req, res) => {

        try {

            if (!pool) {

                return res.status(503).json({
                    error:
                        "Database unavailable"
                });
            }


            const streamId =
                normalizeStreamId(
                    req.params.streamId
                );


            if (!streamId) {

                return res.status(400).json({
                    error:
                        "Invalid stream ID"
                });
            }


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
                    error:
                        "Stream not found"
                });
            }


            streamRooms.delete(
                String(streamId)
            );

            streamViewerCounts.delete(
                String(streamId)
            );


            if (
                typeof io !== "undefined"
            ) {

                io.to(
                    getStreamRoom(streamId)
                ).emit(
                    "stream-ended",
                    {
                        streamId
                    }
                );

                io.emit(
                    "stream-updated",
                    {
                        id:
                            streamId,

                        stream_id:
                            streamId,

                        is_live:
                            false,

                        status:
                            "ended"
                    }
                );
            }


            return res.json({
                success: true
            });

        } catch (error) {

            console.error(
                "Delete stream error:",
                error
            );

            return res.status(500).json({
                error:
                    "Failed to delete stream"
            });
        }
    }
);


/* =========================================
   UPDATE STREAM
========================================= */

app.put(
    "/api/streams/:streamId",
    authenticateUser,
    async (req, res) => {

        try {

            if (!pool) {

                return res.status(503).json({
                    error:
                        "Database unavailable"
                });
            }


            const streamId =
                normalizeStreamId(
                    req.params.streamId
                );


            if (!streamId) {

                return res.status(400).json({
                    error:
                        "Invalid stream ID"
                });
            }


            const title =
                cleanStreamTitle(
                    req.body.title
                );


            const category =
                cleanStreamCategory(
                    req.body.category
                );


            const thumbnail =
                String(
                    req.body.thumbnail ||
                    ""
                ).trim();


            const result =
                await pool.query(
                    `
                    UPDATE streams

                    SET
                        title = $1,
                        category = $2,
                        thumbnail = $3,
                        updated_at =
                            CURRENT_TIMESTAMP

                    WHERE id = $4
                      AND user_id = $5

                    RETURNING *
                    `,
                    [
                        title,
                        category,
                        thumbnail,
                        streamId,
                        req.user.id
                    ]
                );


            if (
                result.rows.length === 0
            ) {

                return res.status(404).json({
                    error:
                        "Stream not found"
                });
            }


            const stream =
                await getStreamById(
                    streamId
                );


            const formatted =
                formatStreamRow(
                    stream
                );


            if (
                typeof io !== "undefined"
            ) {

                io.to(
                    getStreamRoom(streamId)
                ).emit(
                    "stream-updated",
                    formatted
                );

                io.emit(
                    "stream-updated",
                    formatted
                );
            }


            return res.json({

                success: true,

                stream:
                    formatted
            });

        } catch (error) {

            console.error(
                "Update stream error:",
                error
            );

            return res.status(500).json({
                error:
                    "Failed to update stream"
            });
        }
    }
);


/* =========================================
   FOLLOW USER
========================================= */

app.post(
    "/api/follows/:userId",
    authenticateUser,
    async (req, res) => {

        try {

            if (!pool) {

                return res.status(503).json({
                    error:
                        "Database unavailable"
                });
            }


            const targetUserId =
                Number(
                    req.params.userId
                );


            if (
                !Number.isInteger(
                    targetUserId
                ) ||
                targetUserId <= 0
            ) {

                return res.status(400).json({
                    error:
                        "Invalid user ID"
                });
            }


            if (
                targetUserId ===
                Number(req.user.id)
            ) {

                return res.status(400).json({
                    error:
                        "You cannot follow yourself"
                });
            }


            const userResult =
                await pool.query(
                    `
                    SELECT id
                    FROM users
                    WHERE id = $1
                    LIMIT 1
                    `,
                    [targetUserId]
                );


            if (
                userResult.rows.length === 0
            ) {

                return res.status(404).json({
                    error:
                        "User not found"
                });
            }


            await pool.query(
                `
                INSERT INTO follows
                (
                    follower_id,
                    following_id
                )

                VALUES
                (
                    $1,
                    $2
                )

                ON CONFLICT
                (
                    follower_id,
                    following_id
                )

                DO NOTHING
                `,
                [
                    req.user.id,
                    targetUserId
                ]
            );


            const counts =
                await getFollowCounts(
                    targetUserId
                );


            return res.json({

                success: true,

                following: true,

                followers_count:
                    counts.followers,

                following_count:
                    counts.following
            });

        } catch (error) {

            console.error(
                "Follow error:",
                error
            );

            return res.status(500).json({
                error:
                    "Failed to follow user"
            });
        }
    }
);
/* =========================================
   UNFOLLOW USER
========================================= */

app.delete(
    "/api/follows/:userId",
    authenticateUser,
    async (req, res) => {

        try {

            if (!pool) {

                return res.status(503).json({
                    error:
                        "Database unavailable"
                });
            }


            const targetUserId =
                Number(
                    req.params.userId
                );


            if (
                !Number.isInteger(
                    targetUserId
                ) ||
                targetUserId <= 0
            ) {

                return res.status(400).json({
                    error:
                        "Invalid user ID"
                });
            }


            await pool.query(
                `
                DELETE FROM follows

                WHERE follower_id = $1
                  AND following_id = $2
                `,
                [
                    req.user.id,
                    targetUserId
                ]
            );


            const counts =
                await getFollowCounts(
                    targetUserId
                );


            return res.json({

                success: true,

                following: false,

                followers_count:
                    counts.followers,

                following_count:
                    counts.following
            });

        } catch (error) {

            console.error(
                "Unfollow error:",
                error
            );

            return res.status(500).json({
                error:
                    "Failed to unfollow user"
            });
        }
    }
);


/* =========================================
   CHECK FOLLOW STATUS
========================================= */

app.get(
    "/api/follows/:userId",
    optionalAuthenticateUser,
    async (req, res) => {

        try {

            if (!pool) {

                return res.json({
                    following: false
                });
            }


            const targetUserId =
                Number(
                    req.params.userId
                );


            if (
                !Number.isInteger(
                    targetUserId
                ) ||
                targetUserId <= 0
            ) {

                return res.status(400).json({
                    error:
                        "Invalid user ID"
                });
            }


            let following = false;


            if (req.user) {

                const result =
                    await pool.query(
                        `
                        SELECT 1

                        FROM follows

                        WHERE follower_id = $1
                          AND following_id = $2

                        LIMIT 1
                        `,
                        [
                            req.user.id,
                            targetUserId
                        ]
                    );


                following =
                    result.rows.length > 0;
            }


            const counts =
                await getFollowCounts(
                    targetUserId
                );


            return res.json({

                following,

                followers_count:
                    counts.followers,

                following_count:
                    counts.following
            });

        } catch (error) {

            console.error(
                "Follow status error:",
                error
            );

            return res.status(500).json({
                error:
                    "Failed to check follow status"
            });
        }
    }
);


/* =========================================
   USER FOLLOWERS
========================================= */

app.get(
    "/api/users/:userId/followers",
    async (req, res) => {

        try {

            if (!pool) {

                return res.json({
                    followers: []
                });
            }


            const userId =
                Number(
                    req.params.userId
                );


            if (
                !Number.isInteger(userId) ||
                userId <= 0
            ) {

                return res.status(400).json({
                    error:
                        "Invalid user ID"
                });
            }


            const result =
                await pool.query(
                    `
                    SELECT

                        u.id,

                        u.name,

                        u.username,

                        p.profile_picture,

                        f.created_at

                    FROM follows f

                    INNER JOIN users u
                        ON u.id =
                           f.follower_id

                    LEFT JOIN profiles p
                        ON p.user_id =
                           u.id

                    WHERE
                        f.following_id = $1

                    ORDER BY
                        f.created_at DESC
                    `,
                    [userId]
                );


            return res.json({
                followers:
                    result.rows
            });

        } catch (error) {

            console.error(
                "Followers error:",
                error
            );

            return res.status(500).json({
                error:
                    "Failed to load followers"
            });
        }
    }
);


/* =========================================
   USER FOLLOWING
========================================= */

app.get(
    "/api/users/:userId/following",
    async (req, res) => {

        try {

            if (!pool) {

                return res.json({
                    following: []
                });
            }


            const userId =
                Number(
                    req.params.userId
                );


            if (
                !Number.isInteger(userId) ||
                userId <= 0
            ) {

                return res.status(400).json({
                    error:
                        "Invalid user ID"
                });
            }


            const result =
                await pool.query(
                    `
                    SELECT

                        u.id,

                        u.name,

                        u.username,

                        p.profile_picture,

                        f.created_at

                    FROM follows f

                    INNER JOIN users u
                        ON u.id =
                           f.following_id

                    LEFT JOIN profiles p
                        ON p.user_id =
                           u.id

                    WHERE
                        f.follower_id = $1

                    ORDER BY
                        f.created_at DESC
                    `,
                    [userId]
                );


            return res.json({
                following:
                    result.rows
            });

        } catch (error) {

            console.error(
                "Following error:",
                error
            );

            return res.status(500).json({
                error:
                    "Failed to load following"
            });
        }
    }
);


/* =========================================
   STREAM VIEWER JOIN
========================================= */

app.post(
    "/api/streams/:streamId/view",
    async (req, res) => {

        try {

            if (!pool) {

                return res.status(503).json({
                    error:
                        "Database unavailable"
                });
            }


            const streamId =
                normalizeStreamId(
                    req.params.streamId
                );


            if (!streamId) {

                return res.status(400).json({
                    error:
                        "Invalid stream ID"
                });
            }


            const stream =
                await getStreamById(
                    streamId
                );


            if (!stream) {

                return res.status(404).json({
                    error:
                        "Stream not found"
                });
            }


            if (!stream.is_live) {

                return res.status(400).json({
                    error:
                        "Stream is not live"
                });
            }


            /*
             * HTTP fallback for clients that
             * don't establish Socket.IO viewer
             * tracking.
             *
             * Socket.IO tracking remains the
             * preferred method for Watch.
             */

            const current =
                getViewerCount(streamId);


            const next =
                current + 1;


            streamViewerCounts.set(
                String(streamId),
                next
            );


            await syncStreamViewerCount(
                streamId
            );


            return res.json({

                success: true,

                viewer_count:
                    next
            });

        } catch (error) {

            console.error(
                "Join stream error:",
                error
            );

            return res.status(500).json({
                error:
                    "Failed to join stream"
            });
        }
    }
);


/* =========================================
   STREAM VIEWER LEAVE
========================================= */

app.post(
    "/api/streams/:streamId/leave",
    async (req, res) => {

        try {

            if (!pool) {

                return res.status(503).json({
                    error:
                        "Database unavailable"
                });
            }


            const streamId =
                normalizeStreamId(
                    req.params.streamId
                );


            if (!streamId) {

                return res.status(400).json({
                    error:
                        "Invalid stream ID"
                });
            }


            const current =
                getViewerCount(streamId);


            const next =
                Math.max(
                    0,
                    current - 1
                );


            streamViewerCounts.set(
                String(streamId),
                next
            );


            if (next === 0) {

                streamViewerCounts.delete(
                    String(streamId)
                );
            }


            await syncStreamViewerCount(
                streamId
            );


            return res.json({

                success: true,

                viewer_count:
                    next
            });

        } catch (error) {

            console.error(
                "Leave stream error:",
                error
            );

            return res.status(500).json({
                error:
                    "Failed to leave stream"
            });
        }
    }
);


/* =========================================
   STREAM HEARTBEAT
========================================= */

app.post(
    "/api/streams/:streamId/heartbeat",
    async (req, res) => {

        try {

            if (!pool) {

                return res.status(503).json({
                    error:
                        "Database unavailable"
                });
            }


            const streamId =
                normalizeStreamId(
                    req.params.streamId
                );


            if (!streamId) {

                return res.status(400).json({
                    error:
                        "Invalid stream ID"
                });
            }


            const result =
                await pool.query(
                    `
                    SELECT
                        id,
                        is_live
                    FROM streams
                    WHERE id = $1
                    LIMIT 1
                    `,
                    [streamId]
                );


            if (
                result.rows.length === 0
            ) {

                return res.status(404).json({
                    error:
                        "Stream not found"
                });
            }


            if (
                !result.rows[0].is_live
            ) {

                return res.status(410).json({
                    error:
                        "Stream has ended"
                });
            }


            await pool.query(
                `
                UPDATE streams

                SET updated_at =
                    CURRENT_TIMESTAMP

                WHERE id = $1
                `,
                [streamId]
            );


            return res.json({

                success: true,

                stream_id:
                    streamId,

                viewer_count:
                    getViewerCount(
                        streamId
                    )
            });

        } catch (error) {

            console.error(
                "Stream heartbeat error:",
                error
            );

            return res.status(500).json({
                error:
                    "Heartbeat failed"
            });
        }
    }
);


/* =========================================
   STREAM CHAT HISTORY
========================================= */

app.get(
    "/api/streams/:streamId/chat",
    async (req, res) => {

        try {

            if (!pool) {

                return res.json({
                    messages: []
                });
            }


            const streamId =
                normalizeStreamId(
                    req.params.streamId
                );


            if (!streamId) {

                return res.status(400).json({
                    error:
                        "Invalid stream ID"
                });
            }


            const result =
                await pool.query(
                    `
                    SELECT

                        id,

                        stream_id,

                        user_id,

                        username,

                        message,

                        created_at

                    FROM chat_messages

                    WHERE stream_id = $1

                    ORDER BY
                        created_at ASC

                    LIMIT 100
                    `,
                    [streamId]
                );


            return res.json({

                messages:
                    result.rows
            });

        } catch (error) {

            console.error(
                "Chat history error:",
                error
            );

            return res.status(500).json({
                error:
                    "Failed to load chat"
            });
        }
    }
);
/* =========================================
   CHAT MESSAGE API
========================================= */

app.post(
    "/api/streams/:streamId/chat",
    authenticateUser,
    async (req, res) => {

        try {

            if (!pool) {

                return res.status(503).json({
                    error:
                        "Database unavailable"
                });
            }


            const streamId =
                normalizeStreamId(
                    req.params.streamId
                );


            if (!streamId) {

                return res.status(400).json({
                    error:
                        "Invalid stream ID"
                });
            }


            const stream =
                await getStreamById(
                    streamId
                );


            if (!stream) {

                return res.status(404).json({
                    error:
                        "Stream not found"
                });
            }


            if (!stream.is_live) {

                return res.status(400).json({
                    error:
                        "Stream has ended"
                });
            }


            const message =
                String(
                    req.body.message || ""
                ).trim();


            if (!message) {

                return res.status(400).json({
                    error:
                        "Message cannot be empty"
                });
            }


            /*
             * Prevent extremely large chat
             * messages from being stored.
             */

            const cleanMessage =
                message.substring(
                    0,
                    500
                );


            const result =
                await pool.query(
                    `
                    INSERT INTO chat_messages
                    (
                        stream_id,
                        user_id,
                        username,
                        message
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
                        stream_id,
                        user_id,
                        username,
                        message,
                        created_at
                    `,
                    [
                        streamId,
                        req.user.id,
                        req.user.username ||
                            req.user.name ||
                            "Canvas User",
                        cleanMessage
                    ]
                );


            const chatMessage =
                result.rows[0];


            /*
             * Broadcast to every viewer
             * currently inside this stream room.
             */

            if (
                typeof io !== "undefined"
            ) {

                io.to(
                    getStreamRoom(streamId)
                ).emit(
                    "chat-message",
                    chatMessage
                );
            }


            return res.status(201).json({

                success: true,

                message:
                    chatMessage
            });

        } catch (error) {

            console.error(
                "Send chat message error:",
                error
            );

            return res.status(500).json({
                error:
                    "Failed to send message"
            });
        }
    }
);


/* =========================================
   DELETE CHAT MESSAGE
========================================= */

app.delete(
    "/api/streams/:streamId/chat/:messageId",
    authenticateUser,
    async (req, res) => {

        try {

            if (!pool) {

                return res.status(503).json({
                    error:
                        "Database unavailable"
                });
            }


            const streamId =
                normalizeStreamId(
                    req.params.streamId
                );


            const messageId =
                Number(
                    req.params.messageId
                );


            if (
                !streamId ||
                !Number.isInteger(
                    messageId
                ) ||
                messageId <= 0
            ) {

                return res.status(400).json({
                    error:
                        "Invalid message"
                });
            }


            /*
             * Only the message owner or
             * stream owner can delete it.
             */

            const result =
                await pool.query(
                    `
                    DELETE FROM chat_messages c

                    USING streams s

                    WHERE c.id = $1

                      AND c.stream_id = $2

                      AND s.id = c.stream_id

                      AND (
                            c.user_id = $3
                            OR
                            s.user_id = $3
                          )

                    RETURNING c.id
                    `,
                    [
                        messageId,
                        streamId,
                        req.user.id
                    ]
                );


            if (
                result.rows.length === 0
            ) {

                return res.status(404).json({
                    error:
                        "Message not found"
                });
            }


            if (
                typeof io !== "undefined"
            ) {

                io.to(
                    getStreamRoom(streamId)
                ).emit(
                    "chat-message-deleted",
                    {
                        messageId
                    }
                );
            }


            return res.json({
                success: true
            });

        } catch (error) {

            console.error(
                "Delete chat message error:",
                error
            );

            return res.status(500).json({
                error:
                    "Failed to delete message"
            });
        }
    }
);


/* =========================================
   PROFILE BY USERNAME
========================================= */

app.get(
    "/api/profile/:username",
    optionalAuthenticateUser,
    async (req, res) => {

        try {

            if (!pool) {

                return res.status(503).json({
                    error:
                        "Database unavailable"
                });
            }


            const username =
                cleanUsername(
                    req.params.username
                );


            if (!username) {

                return res.status(400).json({
                    error:
                        "Invalid username"
                });
            }


            const result =
                await pool.query(
                    `
                    SELECT

                        u.id,

                        u.name,

                        u.username,

                        p.bio,

                        p.profile_picture,

                        u.created_at

                    FROM users u

                    LEFT JOIN profiles p
                        ON p.user_id = u.id

                    WHERE
                        LOWER(u.username) = $1

                    LIMIT 1
                    `,
                    [username]
                );


            if (
                result.rows.length === 0
            ) {

                return res.status(404).json({
                    error:
                        "Profile not found"
                });
            }


            const user =
                result.rows[0];


            const counts =
                await getFollowCounts(
                    user.id
                );


            let isFollowing =
                false;


            if (req.user) {

                const followResult =
                    await pool.query(
                        `
                        SELECT 1

                        FROM follows

                        WHERE follower_id = $1
                          AND following_id = $2

                        LIMIT 1
                        `,
                        [
                            req.user.id,
                            user.id
                        ]
                    );


                isFollowing =
                    followResult.rows.length > 0;
            }


            return res.json({

                profile: {

                    id:
                        Number(user.id),

                    userId:
                        Number(user.id),

                    name:
                        user.name || "",

                    username:
                        user.username || "",

                    bio:
                        user.bio || "",

                    profile_picture:
                        user.profile_picture || "",

                    followers_count:
                        counts.followers,

                    following_count:
                        counts.following,

                    is_following:
                        isFollowing,

                    isFollowing:
                        isFollowing,

                    created_at:
                        user.created_at
                }

            });

        } catch (error) {

            console.error(
                "Profile lookup error:",
                error
            );

            return res.status(500).json({
                error:
                    "Failed to load profile"
            });
        }
    }
);


/* =========================================
   USER BY USERNAME
========================================= */

app.get(
    "/api/users/:username",
    optionalAuthenticateUser,
    async (req, res) => {

        try {

            if (!pool) {

                return res.status(503).json({
                    error:
                        "Database unavailable"
                });
            }


            const username =
                cleanUsername(
                    req.params.username
                );


            if (!username) {

                return res.status(400).json({
                    error:
                        "Invalid username"
                });
            }


            const result =
                await pool.query(
                    `
                    SELECT

                        u.id,

                        u.name,

                        u.username,

                        p.bio,

                        p.profile_picture,

                        u.created_at

                    FROM users u

                    LEFT JOIN profiles p
                        ON p.user_id = u.id

                    WHERE
                        LOWER(u.username) = $1

                    LIMIT 1
                    `,
                    [username]
                );


            if (
                result.rows.length === 0
            ) {

                return res.status(404).json({
                    error:
                        "User not found"
                });
            }


            const user =
                result.rows[0];


            const counts =
                await getFollowCounts(
                    user.id
                );


            let isFollowing =
                false;


            if (req.user) {

                const followResult =
                    await pool.query(
                        `
                        SELECT 1

                        FROM follows

                        WHERE follower_id = $1
                          AND following_id = $2

                        LIMIT 1
                        `,
                        [
                            req.user.id,
                            user.id
                        ]
                    );


                isFollowing =
                    followResult.rows.length > 0;
            }


            return res.json({

                user: {

                    id:
                        Number(user.id),

                    userId:
                        Number(user.id),

                    name:
                        user.name || "",

                    username:
                        user.username || "",

                    bio:
                        user.bio || "",

                    profile_picture:
                        user.profile_picture || "",

                    followers_count:
                        counts.followers,

                    following_count:
                        counts.following,

                    is_following:
                        isFollowing,

                    isFollowing:
                        isFollowing,

                    created_at:
                        user.created_at
                }

            });

        } catch (error) {

            console.error(
                "User lookup error:",
                error
            );

            return res.status(500).json({
                error:
                    "Failed to load user"
            });
        }
    }
);


/* =========================================
   HEALTH CHECK
========================================= */

app.get(
    "/",
    (req, res) => {

        res.json({

            success: true,

            message:
                "Canvas server is running",

            database:
                Boolean(pool),

            timestamp:
                new Date().toISOString()
        });
    }
);


/* =========================================
   API HEALTH CHECK
========================================= */

app.get(
    "/api/health",
    async (req, res) => {

        let database =
            false;


        if (pool) {

            try {

                await pool.query(
                    "SELECT 1"
                );

                database = true;

            } catch (error) {

                database = false;
            }
        }


        res.json({

            success: true,

            server:
                true,

            database,

            timestamp:
                new Date().toISOString()
        });
    }
);
/* =========================================
   SOCKET.IO
========================================= */

if (typeof io !== "undefined") {

    io.on(
        "connection",
        (socket) => {

            console.log(
                "Canvas socket connected:",
                socket.id
            );


            /* ================================
               JOIN STREAM ROOM
            ================================= */

            socket.on(
                "join-stream",
                async (data) => {

                    try {

                        const streamId =
                            normalizeStreamId(
                                data &&
                                (
                                    data.streamId ||
                                    data.stream_id ||
                                    data.id
                                )
                            );


                        if (!streamId) {

                            socket.emit(
                                "stream-error",
                                {
                                    error:
                                        "Invalid stream ID"
                                }
                            );

                            return;
                        }


                        const stream =
                            await getStreamById(
                                streamId
                            );


                        if (!stream) {

                            socket.emit(
                                "stream-error",
                                {
                                    error:
                                        "Stream not found"
                                }
                            );

                            return;
                        }


                        if (!stream.is_live) {

                            socket.emit(
                                "stream-error",
                                {
                                    error:
                                        "Stream has ended"
                                }
                            );

                            return;
                        }


                        /*
                         * If this socket was already
                         * watching another stream,
                         * remove it first.
                         */

                        if (
                            socket.currentStreamId &&
                            String(
                                socket.currentStreamId
                            ) !== String(streamId)
                        ) {

                            const oldStreamId =
                                socket.currentStreamId;


                            socket.leave(
                                getStreamRoom(
                                    oldStreamId
                                )
                            );


                            const oldCount =
                                removeViewer(
                                    oldStreamId,
                                    socket.id
                                );


                            await syncStreamViewerCount(
                                oldStreamId
                            );


                            io.to(
                                getStreamRoom(
                                    oldStreamId
                                )
                            ).emit(
                                "viewer-count",
                                {
                                    streamId:
                                        oldStreamId,

                                    viewer_count:
                                        oldCount
                                }
                            );
                        }


                        const room =
                            getStreamRoom(
                                streamId
                            );


                        socket.join(room);


                        socket.currentStreamId =
                            streamId;


                        const viewerCount =
                            addViewer(
                                streamId,
                                socket.id
                            );


                        await syncStreamViewerCount(
                            streamId
                        );


                        /*
                         * Tell the joining viewer
                         * the current stream data.
                         */

                        socket.emit(
                            "stream-joined",
                            {
                                stream:
                                    formatStreamRow(
                                        stream
                                    ),

                                viewer_count:
                                    viewerCount
                            }
                        );


                        /*
                         * Tell every viewer in the
                         * room about the new count.
                         */

                        io.to(room).emit(
                            "viewer-count",
                            {
                                streamId,

                                viewer_count:
                                    viewerCount
                            }
                        );

                    } catch (error) {

                        console.error(
                            "join-stream error:",
                            error
                        );

                        socket.emit(
                            "stream-error",
                            {
                                error:
                                    "Unable to join stream"
                            }
                        );
                    }
                }
            );


            /* ================================
               LEAVE STREAM ROOM
            ================================= */

            socket.on(
                "leave-stream",
                async (data) => {

                    try {

                        const streamId =
                            normalizeStreamId(
                                data &&
                                (
                                    data.streamId ||
                                    data.stream_id ||
                                    data.id
                                )
                            ) ||
                            socket.currentStreamId;


                        if (!streamId) {
                            return;
                        }


                        socket.leave(
                            getStreamRoom(
                                streamId
                            )
                        );


                        const viewerCount =
                            removeViewer(
                                streamId,
                                socket.id
                            );


                        if (
                            String(
                                socket.currentStreamId
                            ) === String(streamId)
                        ) {

                            socket.currentStreamId =
                                null;
                        }


                        await syncStreamViewerCount(
                            streamId
                        );


                        io.to(
                            getStreamRoom(
                                streamId
                            )
                        ).emit(
                            "viewer-count",
                            {
                                streamId,

                                viewer_count:
                                    viewerCount
                            }
                        );

                    } catch (error) {

                        console.error(
                            "leave-stream error:",
                            error
                        );
                    }
                }
            );


            /* ================================
               CHAT MESSAGE
            ================================= */

            socket.on(
                "chat-message",
                async (data) => {

                    try {

                        if (!pool) {

                            socket.emit(
                                "chat-error",
                                {
                                    error:
                                        "Database unavailable"
                                }
                            );

                            return;
                        }


                        const streamId =
                            normalizeStreamId(
                                data &&
                                (
                                    data.streamId ||
                                    data.stream_id
                                )
                            );


                        if (!streamId) {

                            socket.emit(
                                "chat-error",
                                {
                                    error:
                                        "Invalid stream ID"
                                }
                            );

                            return;
                        }


                        /*
                         * A socket may only send chat
                         * to the stream it actually joined.
                         */

                        if (
                            String(
                                socket.currentStreamId
                            ) !== String(streamId)
                        ) {

                            socket.emit(
                                "chat-error",
                                {
                                    error:
                                        "You are not watching this stream"
                                }
                            );

                            return;
                        }


                        const message =
                            String(
                                data.message || ""
                            ).trim();


                        if (!message) {
                            return;
                        }


                        const cleanMessage =
                            message.substring(
                                0,
                                500
                            );


                        /*
                         * Authenticate the socket
                         * using the token supplied by
                         * Watch / Go Live.
                         */

                        const token =
                            data.token ||
                            data.authToken ||
                            data.auth_token ||
                            "";


                        if (!token) {

                            socket.emit(
                                "chat-error",
                                {
                                    error:
                                        "Authentication required"
                                }
                            );

                            return;
                        }


                        const tokenHash =
                            hashToken(token);


                        const userResult =
                            await pool.query(
                                `
                                SELECT

                                    users.id,

                                    users.name,

                                    users.username

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
                            userResult.rows.length === 0
                        ) {

                            socket.emit(
                                "chat-error",
                                {
                                    error:
                                        "Authentication failed"
                                }
                            );

                            return;
                        }


                        const user =
                            userResult.rows[0];


                        const stream =
                            await getStreamById(
                                streamId
                            );


                        if (
                            !stream ||
                            !stream.is_live
                        ) {

                            socket.emit(
                                "chat-error",
                                {
                                    error:
                                        "Stream has ended"
                                }
                            );

                            return;
                        }


                        const result =
                            await pool.query(
                                `
                                INSERT INTO chat_messages
                                (
                                    stream_id,
                                    user_id,
                                    username,
                                    message
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
                                    stream_id,
                                    user_id,
                                    username,
                                    message,
                                    created_at
                                `,
                                [
                                    streamId,
                                    user.id,
                                    user.username ||
                                        user.name ||
                                        "Canvas User",
                                    cleanMessage
                                ]
                            );


                        const chatMessage =
                            result.rows[0];


                        /*
                         * THIS is the important part:
                         *
                         * The message is broadcast to
                         * the entire stream room,
                         * not only returned to the
                         * sender.
                         */

                        io.to(
                            getStreamRoom(
                                streamId
                            )
                        ).emit(
                            "chat-message",
                            chatMessage
                        );

                    } catch (error) {

                        console.error(
                            "Socket chat error:",
                            error
                        );

                        socket.emit(
                            "chat-error",
                            {
                                error:
                                    "Failed to send message"
                            }
                        );
                    }
                }
            );


            /* ================================
               STREAM UPDATE
            ================================= */

            socket.on(
                "stream-update",
                async (data) => {

                    try {

                        const streamId =
                            normalizeStreamId(
                                data &&
                                (
                                    data.streamId ||
                                    data.stream_id ||
                                    data.id
                                )
                            );


                        if (!streamId) {
                            return;
                        }


                        const stream =
                            await getStreamById(
                                streamId
                            );


                        if (!stream) {
                            return;
                        }


                        io.to(
                            getStreamRoom(
                                streamId
                            )
                        ).emit(
                            "stream-updated",
                            formatStreamRow(
                                stream
                            )
                        );

                    } catch (error) {

                        console.error(
                            "Socket stream update error:",
                            error
                        );
                    }
                }
            );


            /* ================================
               DISCONNECT
            ================================= */

            socket.on(
                "disconnect",
                async () => {

                    try {

                        const streamId =
                            socket.currentStreamId;


                        if (!streamId) {

                            console.log(
                                "Canvas socket disconnected:",
                                socket.id
                            );

                            return;
                        }


                        const viewerCount =
                            removeViewer(
                                streamId,
                                socket.id
                            );


                        await syncStreamViewerCount(
                            streamId
                        );


                        io.to(
                            getStreamRoom(
                                streamId
                            )
                        ).emit(
                            "viewer-count",
                            {
                                streamId,

                                viewer_count:
                                    viewerCount
                            }
                        );


                        console.log(
                            "Canvas socket disconnected:",
                            socket.id
                        );

                    } catch (error) {

                      console.error(
                            "Socket disconnect error:",
                            error
                        );
                    }
                }
            );
        }
    );
}


/* =========================================
   SERVER STARTUP
========================================= */

async function startServer() {

    try {

        await initializeDatabase();


        if (pool) {

            await ensureFollowTable();

            await ensureChatTable();

            await ensureStreamColumns();

            console.log(
                "Canvas database ready"
            );

        } else {

            console.log(
                "Canvas database is not configured"
            );
        }


        app.listen(
            PORT,
            "0.0.0.0",
            () => {

                console.log(
                    `Canvas server running on port ${PORT}`
                );

            }
        );

    } catch (error) {

        console.error(
            "Canvas server startup error:",
            error
        );

        process.exit(1);
    }
}


startServer();
