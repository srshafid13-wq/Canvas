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

function getStreamRoom(streamId) {

    return `stream:${streamId}`;

}


/* =========================================
   STREAM VIEWER MEMORY
========================================= */

const streamViewerCounts = new Map();

const streamRooms = new Map();


function getViewerSet(streamId) {

    const id = String(streamId);

    if (!streamRooms.has(id)) {

        streamRooms.set(
            id,
            new Set()
        );

    }

    return streamRooms.get(id);

}


function addViewer(
    streamId,
    socketId
) {

    const viewers =
        getViewerSet(streamId);

    if (
        !viewers.has(socketId)
    ) {

        viewers.add(socketId);

    }

    const count =
        viewers.size;

    streamViewerCounts.set(
        String(streamId),
        count
    );

    return count;

}


function removeViewer(
    streamId,
    socketId
) {

    const id =
        String(streamId);

    const viewers =
        streamRooms.get(id);

    if (!viewers) {

        return 0;

    }

    viewers.delete(socketId);

    const count =
        viewers.size;

    if (count <= 0) {

        streamRooms.delete(id);

        streamViewerCounts.delete(id);

        return 0;

    }

    streamViewerCounts.set(
        id,
        count
    );

    return count;

}


/* =========================================
   STREAM DATABASE HELPERS
========================================= */

async function getStreamById(
    streamId
) {

    if (!pool) {

        return null;

    }

    const result =
        await pool.query(
            `
            SELECT
                s.*,

                u.username,
                u.email,

                p.name,
                p.bio,
                p.profile_picture

            FROM streams s

            LEFT JOIN users u
                ON u.id = s.user_id

            LEFT JOIN profiles p
                ON p.user_id = s.user_id

            WHERE s.id = $1

            LIMIT 1
            `,
            [streamId]
        );

    return result.rows[0] || null;

}


async function getUserActiveStream(
    userId
) {

    if (!pool) {

        return null;

    }

    const result =
        await pool.query(
            `
            SELECT
                s.*,

                u.username,

                p.name,
                p.bio,
                p.profile_picture

            FROM streams s

            LEFT JOIN users u
                ON u.id = s.user_id

            LEFT JOIN profiles p
                ON p.user_id = s.user_id

            WHERE
                s.user_id = $1
                AND s.is_live = TRUE

            ORDER BY s.created_at DESC

            LIMIT 1
            `,
            [userId]
        );

    return result.rows[0] || null;

}


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

                p.name,
                p.bio,
                p.profile_picture

            FROM streams s

            LEFT JOIN users u
                ON u.id = s.user_id

            LEFT JOIN profiles p
                ON p.user_id = s.user_id

            WHERE
                s.is_live = TRUE

            ORDER BY s.created_at DESC
            `
        );

    return result.rows;

}


/* =========================================
   STREAM ROW FORMATTER
========================================= */

function formatStreamRow(
    row
) {

    if (!row) {

        return null;

    }

    return {

        id: row.id,

        title:
            row.title ||
            "Canvas Live Stream",

        category:
            row.category ||
            "Entertainment",

        thumbnail:
            row.thumbnail ||
            null,

        status:
            row.status ||
            "live",

        is_live:
            Boolean(row.is_live),

        viewer_count:
            Number(
                row.viewer_count || 0
            ),

        user_id:
            row.user_id,

        creator: {

            id:
                row.user_id,

            username:
                row.username ||
                null,

            name:
                row.name ||
                row.username ||
                "Canvas User",

            bio:
                row.bio ||
                "",

            profile_picture:
                row.profile_picture ||
                null

        }

    };

}


/* =========================================
   VIEWER COUNT DATABASE SYNC
========================================= */

async function syncStreamViewerCount(
    streamId
) {

    if (!pool) {

        return;

    }

    const id =
        String(streamId);

    const count =
        streamViewerCounts.get(id) || 0;

    try {

        await pool.query(
            `
            UPDATE streams

            SET viewer_count = $1

            WHERE id = $2
            `,
            [
                count,
                streamId
            ]
        );

    } catch (error) {

        console.error(
            "Viewer count sync error:",
            error.message
        );

    }

}


/* =========================================
   OPTIONAL AUTH
========================================= */

function optionalAuthenticateUser(
    req,
    res,
    next
) {

    const auth =
        req.headers.authorization || "";

    if (
        !auth.startsWith(
            "Bearer "
        )
    ) {

        req.user = null;

        return next();

    }

    const token =
        auth
            .replace(
                "Bearer ",
                ""
            )
            .trim();

    if (!token) {

        req.user = null;

        return next();

    }

    try {

        const tokenHash =
            hashToken(token);

        if (!pool) {

            req.user = null;

            return next();

        }

        pool.query(
            `
            SELECT
                u.id,
                u.username,
                u.email

            FROM sessions s

            JOIN users u
                ON u.id = s.user_id

            WHERE
                s.token_hash = $1
                AND s.expires_at > NOW()

            LIMIT 1
            `,
            [tokenHash]
        )
        .then(
            result => {

                req.user =
                    result.rows[0] ||
                    null;

                next();

            }
        )
        .catch(
            error => {

                console.error(
                    "Optional auth error:",
                    error.message
                );

                req.user = null;

                next();

            }
        );

    } catch (error) {

        req.user = null;

        next();

    }

}


/* =========================================
   STREAM LIST
========================================= */

app.get(
    "/api/streams",
    optionalAuthenticateUser,
    async (req, res) => {

        try {

            const streams =
                await getLiveStreams();

            res.json({

                success: true,

                streams:
                    streams.map(
                        formatStreamRow
                    )

            });

        } catch (error) {

            console.error(
                "Get streams error:",
                error
            );

            res.status(500).json({

                success: false,

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
    optionalAuthenticateUser,
    async (req, res) => {

        try {

            const stream =
                await getStreamById(
                    req.params.streamId
                );

            if (!stream) {

                return res.status(404).json({

                    success: false,

                    error:
                        "Stream not found"

                });

            }

            res.json({

                success: true,

                stream:
                    formatStreamRow(
                        stream
                    )

            });

        } catch (error) {

            console.error(
                "Get stream error:",
                error
            );

            res.status(500).json({

                success: false,

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

                    success: false,

                    error:
                        "Database unavailable"

                });

            }

            /*
             * Only one active stream is
             * allowed for each user.
             */

            const existing =
                await getUserActiveStream(
                    req.user.id
                );

            if (existing) {

                return res.status(409).json({

                    success: false,

                    error:
                        "You already have an active stream",

                    stream:
                        formatStreamRow(
                            existing
                        )

                });

            }


            const title =
                String(
                    req.body.title ||
                    "Canvas Live Stream"
                ).trim();

            const category =
                String(
                    req.body.category ||
                    "Entertainment"
                ).trim();

            const thumbnail =
                req.body.thumbnail ||
                null;


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
                        viewer_count
                    )

                    VALUES
                    (
                        $1,
                        $2,
                        $3,
                        $4,
                        'live',
                        TRUE,
                        0
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


            const stream =
                await getStreamById(
                    result.rows[0].id
                );


            /*
             * Tell every connected Canvas
             * client that a new stream exists.
             */

            io.emit(
                "stream-updated",
                {
                    action: "created",

                    stream:
                        formatStreamRow(
                            stream
                        )
                }
            );


            res.status(201).json({

                success: true,

                stream:
                    formatStreamRow(
                        stream
                    )

            });

        } catch (error) {

            console.error(
                "Create stream error:",
                error
            );

            res.status(500).json({

                success: false,

                error:
                    "Failed to create stream"

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

                return res.status(503).json({

                    success: false,

                    error:
                        "Database unavailable"

                });

            }


            const stream =
                await getStreamById(
                    req.params.streamId
                );


            if (!stream) {

                return res.status(404).json({

                    success: false,

                    error:
                        "Stream not found"

                });

            }


            if (
                Number(stream.user_id) !==
                Number(req.user.id)
            ) {

                return res.status(403).json({

                    success: false,

                    error:
                        "You can only end your own stream"

                });

            }


            await pool.query(
                `
                UPDATE streams

                SET
                    is_live = FALSE,
                    status = 'ended'

                WHERE id = $1
                `,
                [
                    req.params.streamId
                ]
            );


            /*
             * Remove all remembered viewers
             * for this stream.
             */

            const streamId =
                String(
                    req.params.streamId
                );

            streamRooms.delete(
                streamId
            );

            streamViewerCounts.delete(
                streamId
            );


            io.to(
                getStreamRoom(
                    streamId
                )
            ).emit(
                "stream-ended",
                {
                    streamId
                }
            );


            io.emit(
                "stream-updated",
                {
                    action: "ended",

                    streamId
                }
            );


            res.json({

                success: true,

                message:
                    "Stream ended"

            });

        } catch (error) {

            console.error(
                "End stream error:",
                error
            );

            res.status(500).json({

                success: false,

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

                    success: false,

                    error:
                        "Database unavailable"

                });

            }


            const stream =
                await getStreamById(
                    req.params.streamId
                );


            if (!stream) {

                return res.status(404).json({

                    success: false,

                    error:
                        "Stream not found"

                });

            }


            if (
                Number(stream.user_id) !==
                Number(req.user.id)
            ) {

                return res.status(403).json({

                    success: false,

                    error:
                        "You can only delete your own stream"

                });

            }


            await pool.query(
                `
                DELETE FROM streams

                WHERE id = $1
                `,
                [
                    req.params.streamId
                ]
            );


            const streamId =
                String(
                    req.params.streamId
                );

            streamRooms.delete(
                streamId
            );

            streamViewerCounts.delete(
                streamId
            );


            io.emit(
                "stream-updated",
                {
                    action: "deleted",

                    streamId
                }
            );


            res.json({

                success: true,

                message:
                    "Stream deleted"

            });

        } catch (error) {

            console.error(
                "Delete stream error:",
                error
            );

            res.status(500).json({

                success: false,

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

                    success: false,

                    error:
                        "Database unavailable"

                });

            }


            const existing =
                await getStreamById(
                    req.params.streamId
                );


            if (!existing) {

                return res.status(404).json({

                    success: false,

                    error:
                        "Stream not found"

                });

            }


            if (
                Number(existing.user_id) !==
                Number(req.user.id)
            ) {

                return res.status(403).json({

                    success: false,

                    error:
                        "You can only update your own stream"

                });

            }


            const title =
                req.body.title !== undefined
                    ? String(
                        req.body.title
                    ).trim()
                    : existing.title;


            const category =
                req.body.category !== undefined
                    ? String(
                        req.body.category
                    ).trim()
                    : existing.category;


            const thumbnail =
                req.body.thumbnail !== undefined
                    ? req.body.thumbnail
                    : existing.thumbnail;


            const result =
                await pool.query(
                    `
                    UPDATE streams

                    SET
                        title = $1,
                        category = $2,
                        thumbnail = $3

                    WHERE id = $4

                    RETURNING *
                    `,
                    [
                        title,
                        category,
                        thumbnail,
                        req.params.streamId
                    ]
                );


            const updated =
                await getStreamById(
                    result.rows[0].id
                );


            io.emit(
                "stream-updated",
                {
                    action: "updated",

                    stream:
                        formatStreamRow(
                            updated
                        )
                }
            );


            res.json({

                success: true,

                stream:
                    formatStreamRow(
                        updated
                    )

            });

        } catch (error) {

            console.error(
                "Update stream error:",
                error
            );

            res.status(500).json({

                success: false,

                error:
                    "Failed to update stream"

            });

        }

    }
);
/* =========================================
   FOLLOW USER RESOLVER
========================================= */

async function resolveFollowUser(
    identifier
) {

    if (!pool) {

        return null;

    }

    const value =
        String(
            identifier || ""
        ).trim();


    if (!value) {

        return null;

    }


    const numericId =
        Number(value);


    let result;


    if (
        Number.isInteger(numericId) &&
        numericId > 0
    ) {

        result =
            await pool.query(
                `
                SELECT id

                FROM users

                WHERE id = $1

                LIMIT 1
                `,
                [
                    numericId
                ]
            );

    } else {

        const username =
            cleanUsername(value);

        result =
            await pool.query(
                `
                SELECT id

                FROM users

                WHERE LOWER(username) = $1

                LIMIT 1
                `,
                [
                    username
                ]
            );

    }


    return (
        result.rows[0] ||
        null
    );

}


/* =========================================
   FOLLOW USER
   Supports:
   /api/follows/:identifier
   /api/follow/:identifier
========================================= */

app.post(
    [
        "/api/follows/:identifier",
        "/api/follow/:identifier"
    ],
    authenticateUser,
    async (req, res) => {

        try {

            if (!pool) {

                return res.status(503).json({

                    success: false,

                    error:
                        "Database unavailable"

                });

            }


            const target =
                await resolveFollowUser(
                    req.params.identifier
                );


            if (!target) {

                return res.status(404).json({

                    success: false,

                    error:
                        "User not found"

                });

            }


            const targetId =
                Number(target.id);

            const currentUserId =
                Number(req.user.id);


            /* ==============================
               PREVENT FOLLOWING YOURSELF
            ============================== */

            if (
                targetId ===
                currentUserId
            ) {

                return res.status(400).json({

                    success: false,

                    error:
                        "You cannot follow yourself",

                    following: false

                });

            }


            /* ==============================
               CREATE FOLLOW
            ============================== */

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
                    currentUserId,
                    targetId
                ]
            );


            const counts =
                await getFollowCounts(
                    targetId
                );


            res.json({

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

            res.status(500).json({

                success: false,

                error:
                    "Failed to follow user"

            });

        }

    }
);


/* =========================================
   UNFOLLOW USER
   Supports:
   /api/follows/:identifier
   /api/follow/:identifier
========================================= */

app.delete(
    [
        "/api/follows/:identifier",
        "/api/follow/:identifier"
    ],
    authenticateUser,
    async (req, res) => {

        try {

            if (!pool) {

                return res.status(503).json({

                    success: false,

                    error:
                        "Database unavailable"

                });

            }


            const target =
                await resolveFollowUser(
                    req.params.identifier
                );


            if (!target) {

                return res.status(404).json({

                    success: false,

                    error:
                        "User not found"

                });

            }


            const targetId =
                Number(target.id);


            if (
                targetId ===
                Number(req.user.id)
            ) {

                return res.json({

                    success: true,

                    following: false

                });

            }


            await pool.query(
                `
                DELETE FROM follows

                WHERE
                    follower_id = $1

                    AND

                    following_id = $2
                `,
                [
                    req.user.id,
                    targetId
                ]
            );


            const counts =
                await getFollowCounts(
                    targetId
                );


            res.json({

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

            res.status(500).json({

                success: false,

                error:
                    "Failed to unfollow user"

            });

        }

    }
);


/* =========================================
   CHECK FOLLOW STATUS
   Supports:
   /api/follows/:identifier
   /api/follow/:identifier
========================================= */

app.get(
    [
        "/api/follows/:identifier",
        "/api/follow/:identifier"
    ],
    optionalAuthenticateUser,
    async (req, res) => {

        try {

            if (!pool) {

                return res.status(503).json({

                    success: false,

                    error:
                        "Database unavailable"

                });

            }


            const target =
                await resolveFollowUser(
                    req.params.identifier
                );


            if (!target) {

                return res.status(404).json({

                    success: false,

                    error:
                        "User not found"

                });

            }


            const targetId =
                Number(target.id);


            let following = false;


            if (
                req.user &&
                Number(req.user.id) !==
                targetId
            ) {

                const result =
                    await pool.query(
                        `
                        SELECT 1

                        FROM follows

                        WHERE
                            follower_id = $1

                            AND

                            following_id = $2

                        LIMIT 1
                        `,
                        [
                            req.user.id,
                            targetId
                        ]
                    );


                following =
                    result.rows.length > 0;

            }


            const counts =
                await getFollowCounts(
                    targetId
                );


            res.json({

                success: true,

                following,

                followers_count:
                    counts.followers,

                following_count:
                    counts.following

            });

        } catch (error) {

            console.error(
                "Check follow error:",
                error
            );

            res.status(500).json({

                success: false,

                error:
                    "Failed to check follow status"

            });

        }

    }
);


/* =========================================
   FOLLOWERS LIST
========================================= */

app.get(
    "/api/users/:userId/followers",
    async (req, res) => {

        try {

            if (!pool) {

                return res.status(503).json({

                    success: false,

                    error:
                        "Database unavailable"

                });

            }


            const result =
                await pool.query(
                    `
                    SELECT
                        u.id,
                        u.username,

                        p.name,
                        p.profile_picture

                    FROM follows f

                    JOIN users u
                        ON u.id = f.follower_id

                    LEFT JOIN profiles p
                        ON p.user_id = u.id

                    WHERE
                        f.following_id = $1

                    ORDER BY
                        u.username ASC
                    `,
                    [
                        req.params.userId
                    ]
                );


            res.json({

                success: true,

                users:
                    result.rows

            });

        } catch (error) {

            console.error(
                "Followers error:",
                error
            );

            res.status(500).json({

                success: false,

                error:
                    "Failed to load followers"

            });

        }

    }
);


/* =========================================
   FOLLOWING LIST
========================================= */

app.get(
    "/api/users/:userId/following",
    async (req, res) => {

        try {

            if (!pool) {

                return res.status(503).json({

                    success: false,

                    error:
                        "Database unavailable"

                });

            }


            const result =
                await pool.query(
                    `
                    SELECT
                        u.id,
                        u.username,

                        p.name,
                        p.profile_picture

                    FROM follows f

                    JOIN users u
                        ON u.id = f.following_id

                    LEFT JOIN profiles p
                        ON p.user_id = u.id

                    WHERE
                        f.follower_id = $1

                    ORDER BY
                        u.username ASC
                    `,
                    [
                        req.params.userId
                    ]
                );


            res.json({

                success: true,

                users:
                    result.rows

            });

        } catch (error) {

            console.error(
                "Following error:",
                error
            );

            res.status(500).json({

                success: false,

                error:
                    "Failed to load following"

            });

        }

    }
);
/* =========================================
   VIEW STREAM
========================================= */

app.post(
    "/api/streams/:streamId/view",
    optionalAuthenticateUser,
    async (req, res) => {

        try {

            if (!pool) {

                return res.status(503).json({

                    success: false,

                    error:
                        "Database unavailable"

                });

            }


            const stream =
                await getStreamById(
                    req.params.streamId
                );


            if (!stream) {

                return res.status(404).json({

                    success: false,

                    error:
                        "Stream not found"

                });

            }


            if (!stream.is_live) {

                return res.status(400).json({

                    success: false,

                    error:
                        "Stream is no longer live"

                });

            }


            const streamId =
                String(
                    req.params.streamId
                );


            let count =
                streamViewerCounts.get(
                    streamId
                );


            /*
             * HTTP fallback viewer count.
             * Socket.IO performs the normal
             * real-time viewer tracking.
             */

            if (
                count === undefined
            ) {

                count =
                    Number(
                        stream.viewer_count ||
                        0
                    );

            }


            count += 1;


            streamViewerCounts.set(
                streamId,
                count
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
                    count
                }
            );


            res.json({

                success: true,

                viewer_count:
                    count

            });

        } catch (error) {

            console.error(
                "View stream error:",
                error
            );

            res.status(500).json({

                success: false,

                error:
                    "Failed to register viewer"

            });

        }

    }
);


/* =========================================
   LEAVE STREAM
========================================= */

app.post(
    "/api/streams/:streamId/leave",
    async (req, res) => {

        try {

            const streamId =
                String(
                    req.params.streamId
                );

            const socketId =
                req.body &&
                req.body.socketId;


            if (socketId) {

                const count =
                    removeViewer(
                        streamId,
                        socketId
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
                        count
                    }
                );


                return res.json({

                    success: true,

                    viewer_count:
                        count

                });

            }


            res.json({

                success: true

            });

        } catch (error) {

            console.error(
                "Leave stream error:",
                error
            );

            res.status(500).json({

                success: false,

                error:
                    "Failed to leave stream"

            });

        }

    }
);


/* =========================================
   VIEWER HEARTBEAT
========================================= */

app.post(
    "/api/streams/:streamId/heartbeat",
    async (req, res) => {

        try {

            const streamId =
                String(
                    req.params.streamId
                );

            const socketId =
                req.body &&
                req.body.socketId;


            if (
                socketId &&
                streamRooms.has(streamId)
            ) {

                const viewers =
                    streamRooms.get(
                        streamId
                    );


                if (
                    viewers.has(
                        socketId
                    )
                ) {

                    const count =
                        viewers.size;


                    streamViewerCounts.set(
                        streamId,
                        count
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
                            count
                        }
                    );

                }

            }


            res.json({

                success: true

            });

        } catch (error) {

            console.error(
                "Viewer heartbeat error:",
                error
            );

            res.status(500).json({

                success: false,

                error:
                    "Heartbeat failed"

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

                return res.status(503).json({

                    success: false,

                    error:
                        "Database unavailable"

                });

            }


            const limit =
                Math.min(
                    Number(
                        req.query.limit || 100
                    ),
                    200
                );


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

                        p.name,
                        p.profile_picture

                    FROM stream_chat c

                    LEFT JOIN users u
                        ON u.id = c.user_id

                    LEFT JOIN profiles p
                        ON p.user_id = c.user_id

                    WHERE
                        c.stream_id = $1

                    ORDER BY
                        c.created_at ASC

                    LIMIT $2
                    `,
                    [
                        req.params.streamId,
                        limit
                    ]
                );


            res.json({

                success: true,

                messages:
                    result.rows

            });

        } catch (error) {

            console.error(
                "Chat history error:",
                error
            );

            res.status(500).json({

                success: false,

                error:
                    "Failed to load chat"

            });

        }

    }
);


/* =========================================
   SEND CHAT MESSAGE
========================================= */

app.post(
    "/api/streams/:streamId/chat",
    authenticateUser,
    async (req, res) => {

        try {

            if (!pool) {

                return res.status(503).json({

                    success: false,

                    error:
                        "Database unavailable"

                });

            }


            const stream =
                await getStreamById(
                    req.params.streamId
                );


            if (!stream) {

                return res.status(404).json({

                    success: false,

                    error:
                        "Stream not found"

                });

            }


            if (!stream.is_live) {

                return res.status(400).json({

                    success: false,

                    error:
                        "Stream is not live"

                });

            }


            const message =
                String(
                    req.body.message ||
                    ""
                ).trim();


            if (!message) {

                return res.status(400).json({

                    success: false,

                    error:
                        "Message is required"

                });

            }


            if (
                message.length > 500
            ) {

                return res.status(400).json({

                    success: false,

                    error:
                        "Message is too long"

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
                        req.params.streamId,
                        req.user.id,
                        message
                    ]
                );


            const chatMessage = {

                ...result.rows[0],

                username:
                    req.user.username

            };


            /*
             * IMPORTANT:
             * Broadcast to EVERY viewer
             * inside this stream room.
             */

            io.to(
                getStreamRoom(
                    req.params.streamId
                )
            ).emit(
                "chat-message",
                chatMessage
            );


            res.json({

                success: true,

                message:
                    chatMessage

            });

        } catch (error) {

            console.error(
                "Send chat error:",
                error
            );

            res.status(500).json({

                success: false,

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

                    success: false,

                    error:
                        "Database unavailable"

                });

            }


            const result =
                await pool.query(
                    `
                    DELETE FROM stream_chat

                    WHERE
                        id = $1

                        AND

                        stream_id = $2

                        AND

                        user_id = $3

                    RETURNING id
                    `,
                    [
                        req.params.messageId,
                        req.params.streamId,
                        req.user.id
                    ]
                );


            if (
                result.rows.length === 0
            ) {

                return res.status(404).json({

                    success: false,

                    error:
                        "Message not found"

                });

            }


            io.to(
                getStreamRoom(
                    req.params.streamId
                )
            ).emit(
                "chat-message-deleted",
                {
                    streamId:
                        req.params.streamId,

                    messageId:
                        req.params.messageId
                }
            );


            res.json({

                success: true

            });

        } catch (error) {

            console.error(
                "Delete chat error:",
                error
            );

            res.status(500).json({

                success: false,

                error:
                    "Failed to delete message"

            });

        }

    }
);
/* =========================================
   SOCKET.IO
========================================= */

io.on(
    "connection",
    (socket) => {

        console.log(
            "Canvas socket connected:",
            socket.id
        );


        /* =====================================
           JOIN STREAM
        ===================================== */

        socket.on(
            "join-stream",
            async (data = {}) => {

                try {

                    const streamId =
                        String(
                            data.streamId ||
                            data.id ||
                            ""
                        ).trim();


                    if (!streamId) {

                        socket.emit(
                            "stream-error",
                            {
                                error:
                                    "Stream ID is required"
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
                                    "Stream is no longer live"
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
                        ) !== streamId
                    ) {

                        const oldStreamId =
                            String(
                                socket.currentStreamId
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

                                count:
                                    oldCount
                            }
                        );


                        socket.leave(
                            getStreamRoom(
                                oldStreamId
                            )
                        );

                    }


                    const room =
                        getStreamRoom(
                            streamId
                        );


                    socket.join(room);


                    socket.currentStreamId =
                        streamId;


                    const count =
                        addViewer(
                            streamId,
                            socket.id
                        );


                    await syncStreamViewerCount(
                        streamId
                    );


                    /*
                     * Tell the current viewer
                     * that joining succeeded.
                     */

                    socket.emit(
                        "stream-joined",
                        {
                            streamId,

                            viewer_count:
                                count,

                            stream:
                                formatStreamRow(
                                    stream
                                )
                        }
                    );


                    /*
                     * Update EVERY viewer in
                     * this stream room.
                     */

                    io.to(room).emit(
                        "viewer-count",
                        {
                            streamId,

                            count
                        }
                    );


                    console.log(
                        `Socket ${socket.id} joined stream ${streamId}`
                    );

                } catch (error) {

                    console.error(
                        "Join stream error:",
                        error
                    );


                    socket.emit(
                        "stream-error",
                        {
                            error:
                                "Failed to join stream"
                        }
                    );

                }

            }
        );


        /* =====================================
           LEAVE STREAM
        ===================================== */

        socket.on(
            "leave-stream",
            async (data = {}) => {

                try {

                    const streamId =
                        String(
                            data.streamId ||
                            socket.currentStreamId ||
                            ""
                        ).trim();


                    if (!streamId) {

                        return;

                    }


                    const count =
                        removeViewer(
                            streamId,
                            socket.id
                        );


                    socket.leave(
                        getStreamRoom(
                            streamId
                        )
                    );


                    socket.currentStreamId =
                        null;


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

                            count
                        }
                    );

                } catch (error) {

                    console.error(
                        "Leave stream error:",
                        error
                    );

                }

            }
        );


        /* =====================================
           SOCKET CHAT
        ===================================== */

        socket.on(
            "chat-message",
            async (data = {}) => {

                try {

                    const streamId =
                        String(
                            data.streamId ||
                            socket.currentStreamId ||
                            ""
                        ).trim();


                    const message =
                        String(
                            data.message ||
                            ""
                        ).trim();


                    if (!streamId) {

                        return;

                    }


                    if (!message) {

                        return;

                    }


                    if (
                        message.length > 500
                    ) {

                        return;

                    }


                    /*
                     * Make sure the socket is
                     * actually inside this stream.
                     */

                    if (
                        String(
                            socket.currentStreamId
                        ) !== streamId
                    ) {

                        return;

                    }


                    const token =
                        data.token ||
                        data.authToken ||
                        data.auth_token ||
                        "";


                    let userId = null;
                    let username = null;


                    /*
                     * Authenticate the socket
                     * message using the Canvas
                     * session token.
                     */

                    if (
                        token &&
                        pool
                    ) {

                        const tokenHash =
                            hashToken(
                                String(token)
                            );


                        const userResult =
                            await pool.query(
                                `
                                SELECT
                                    u.id,
                                    u.username

                                FROM sessions s

                                JOIN users u
                                    ON u.id = s.user_id

                                WHERE
                                    s.token_hash = $1

                                    AND

                                    s.expires_at > NOW()

                                LIMIT 1
                                `,
                                [
                                    tokenHash
                                ]
                            );


                        if (
                            userResult.rows.length
                        ) {

                            userId =
                                userResult
                                    .rows[0]
                                    .id;

                            username =
                                userResult
                                    .rows[0]
                                    .username;

                        }

                    }


                    /*
                     * Do not allow unauthenticated
                     * chat messages.
                     */

                    if (!userId) {

                        socket.emit(
                            "chat-error",
                            {
                                error:
                                    "Login required"
                            }
                        );

                        return;

                    }


                    if (!pool) {

                        return;

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
                                userId,
                                message
                            ]
                        );


                    const chatMessage = {

                        ...result.rows[0],

                        username

                    };


                    /*
                     * THIS is the important part:
                     *
                     * The message is sent to the
                     * whole stream room, not only
                     * back to the sender.
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


        /* =====================================
           STREAM UPDATE BROADCAST
        ===================================== */

        socket.on(
            "stream-updated",
            (data = {}) => {

                io.emit(
                    "stream-updated",
                    data
                );

            }
        );


        /* =====================================
           DISCONNECT
        ===================================== */

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


                    const id =
                        String(
                            streamId
                        );


                    const count =
                        removeViewer(
                            id,
                            socket.id
                        );


                    await syncStreamViewerCount(
                        id
                    );


                    io.to(
                        getStreamRoom(id)
                    ).emit(
                        "viewer-count",
                        {
                            streamId: id,

                            count
                        }
                    );


                    console.log(
                        `Socket ${socket.id} left stream ${id}`
                    );

                } catch (error) {

                    console.error(
                        "Disconnect viewer error:",
                        error
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
    "/health",
    async (req, res) => {

        res.json({

            success: true,

            status: "ok",

            socketio: true,

            database:
                Boolean(pool)

        });

    }
);


/* =========================================
   API HEALTH CHECK
========================================= */

app.get(
    "/api/health",
    async (req, res) => {

        res.json({

            success: true,

            status: "ok",

            socketio: true,

            database:
                Boolean(pool)

        });

    }
);


/* =========================================
   START CANVAS SERVER
========================================= */

async function startServer() {

    try {

        await initializeDatabase();

        await ensureFollowTable();

        await ensureChatTable();

        await ensureStreamColumns();


        /*
         * IMPORTANT:
         *
         * DO NOT use app.listen().
         *
         * Socket.IO is attached to
         * httpServer, so httpServer must
         * be the server that listens.
         */

        httpServer.listen(
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


        /*
         * Start the HTTP + Socket.IO server
         * even if a non-critical DB setup
         * step fails.
         */

        httpServer.listen(
            PORT,
            "0.0.0.0",
            () => {

                console.log(
                    `Canvas server running on port ${PORT}`
                );

            }
        );

    }

}


startServer();
