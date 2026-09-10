const express = require("express");
const { Pool } = require("pg");
const crypto = require("crypto");
const http = require("http");
const { Server } = require("socket.io");

const app = express();
const httpServer = http.createServer(app);

const PORT =
    process.env.PORT ||
    3000;


/* =========================================
   CANVAS SOCKET.IO
========================================= */

const io =
    new Server(
        httpServer,
        {
            cors: {
                origin: "*",
                methods: [
                    "GET",
                    "POST",
                    "PUT",
                    "PATCH",
                    "DELETE"
                ]
            },

            transports: [
                "websocket",
                "polling"
            ],

            pingTimeout:
                20000,

            pingInterval:
                25000,

            connectionStateRecovery: {
                maxDisconnectionDuration:
                    2 * 60 * 1000,

                skipMiddlewares:
                    true
            }
        }
    );


/* =========================================
   EXPRESS BODY PARSING
========================================= */

app.use(
    express.json({
        limit: "50mb"
    })
);

app.use(
    express.urlencoded({
        extended: true,
        limit: "50mb"
    })
);


/* =========================================
   CORS
========================================= */

app.use(
    (req, res, next) => {

        res.header(
            "Access-Control-Allow-Origin",
            "*"
        );

        res.header(
            "Access-Control-Allow-Methods",
            "GET,POST,PUT,PATCH,DELETE,OPTIONS"
        );

        res.header(
            "Access-Control-Allow-Headers",
            "Origin, X-Requested-With, Content-Type, Accept, Authorization"
        );

        if (
            req.method === "OPTIONS"
        ) {

            return res.sendStatus(
                204
            );

        }

        next();

    }
);


/* =========================================
   DATABASE
========================================= */

let pool = null;

const DATABASE_URL =
    process.env.canvas_db_r13t ||
    process.env.DATABASE_URL ||
    process.env.POSTGRES_URL ||
    "";


if (
    DATABASE_URL
) {

    pool =
        new Pool({
            connectionString:
                DATABASE_URL,

            ssl:
                process.env.NODE_ENV === "production"
                    ? {
                        rejectUnauthorized:
                            false
                    }
                    : false,

            max:
                10,

            idleTimeoutMillis:
                30000,

            connectionTimeoutMillis:
                10000
        });


    pool.on(
        "error",
        (error) => {

            console.error(
                "PostgreSQL pool error:",
                error
            );

        }
    );

}


/* =========================================
   AUTH HELPERS
========================================= */

function normalizeEmail(
    value
) {

    return String(
        value || ""
    )
        .trim()
        .toLowerCase();

}


function cleanUsername(
    value
) {

    return String(
        value || ""
    )
        .trim()
        .toLowerCase()
        .replace(
            /[^a-z0-9_.]/g,
            ""
        )
        .slice(
            0,
            30
        );

}


function hashPassword(
    password
) {

    return crypto
        .createHash("sha256")
        .update(
            String(password || "")
        )
        .digest("hex");

}


function createAuthToken() {

    return crypto
        .randomBytes(48)
        .toString("hex");

}


function hashToken(
    token
) {

    return crypto
        .createHash("sha256")
        .update(
            String(token || "")
        )
        .digest("hex");

}


/* =========================================
   SIGNUP VERIFICATION
========================================= */

const signupVerificationCodes =
    new Map();


/* =========================================
   STREAM VIEWER STATE
========================================= */

const streamViewerCounts =
    new Map();


const streamRooms =
    new Map();


function getStreamRoom(
    streamId
) {

    return `stream:${String(
        streamId
    )}`;

}


function normalizeStreamId(
    value
) {

    return String(
        value || ""
    )
        .trim()
        .slice(
            0,
            200
        );

}


function getViewerCount(
    streamId
) {

    const id =
        normalizeStreamId(
            streamId
        );

    if (!id) {
        return 0;
    }

    return Number(
        streamViewerCounts.get(
            id
        ) || 0
    );

}


/* =========================================
   ADD VIEWER
========================================= */

function addViewer(
    streamId,
    socketId
) {

    const id =
        normalizeStreamId(
            streamId
        );

    if (
        !id ||
        !socketId
    ) {
        return 0;
    }


    let viewers =
        streamRooms.get(
            id
        );


    if (!viewers) {

        viewers =
            new Set();

        streamRooms.set(
            id,
            viewers
        );

    }


    /*
     * A socket can only count once
     * inside the same stream room.
     */

    if (
        viewers.has(
            socketId
        )
    ) {

        return getViewerCount(
            id
        );

    }


    viewers.add(
        socketId
    );


    const count =
        Number(
            streamViewerCounts.get(
                id
            ) || 0
        ) + 1;


    streamViewerCounts.set(
        id,
        count
    );


    return count;

}


/* =========================================
   REMOVE VIEWER
========================================= */

function removeViewer(
    streamId,
    socketId
) {

    const id =
        normalizeStreamId(
            streamId
        );

    if (
        !id ||
        !socketId
    ) {
        return 0;
    }


    const viewers =
        streamRooms.get(
            id
        );


    if (
        !viewers ||
        !viewers.has(
            socketId
        )
    ) {

        return getViewerCount(
            id
        );

    }


    viewers.delete(
        socketId
    );


    let count =
        Number(
            streamViewerCounts.get(
                id
            ) || 0
        );


    count =
        Math.max(
            0,
            count - 1
        );


    if (
        count === 0
    ) {

        streamViewerCounts.delete(
            id
        );

    } else {

        streamViewerCounts.set(
            id,
            count
        );

    }


    if (
        viewers.size === 0
    ) {

        streamRooms.delete(
            id
        );

    }


    return count;

}


/* =========================================
   CHAT MESSAGE HELPERS
========================================= */

function normalizeChatMessage(
    value
) {

    return String(
        value || ""
    )
        .trim()
        .slice(
            0,
            500
        );

}


function formatChatMessage(
    row
) {

    return {

        id:
            row.id,

        streamId:
            String(
                row.stream_id
            ),

        userId:
            row.user_id,

        username:
            row.username ||
            "User",

        message:
            row.message,

        createdAt:
            row.created_at

    };

}


/* =========================================
   DATABASE AUTHENTICATION
========================================= */

async function authenticateUser(
    req,
    res,
    next
) {

    try {

        if (!pool) {

            return res.status(
                503
            ).json({
                success: false,
                message:
                    "Database is not configured"
            });

        }


        const header =
            String(
                req.headers.authorization ||
                ""
            );


        if (
            !header.toLowerCase()
                .startsWith("bearer ")
        ) {

            return res.status(
                401
            ).json({
                success: false,
                message:
                    "Authentication required"
            });

        }


        const token =
            header
                .slice(7)
                .trim();


        if (!token) {

            return res.status(
                401
            ).json({
                success: false,
                message:
                    "Authentication required"
            });

        }


        const tokenHash =
            hashToken(
                token
            );


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
                WHERE
                    s.token_hash = $1
                    AND
                    s.expires_at > CURRENT_TIMESTAMP
                LIMIT 1
                `,
                [
                    tokenHash
                ]
            );


        if (
            !result.rows.length
        ) {

            return res.status(
                401
            ).json({
                success: false,
                message:
                    "Invalid or expired session"
            });

        }


        req.user =
            result.rows[0];

        req.userId =
            result.rows[0].id;


        next();

    } catch (error) {

        console.error(
            "Authentication error:",
            error
        );


        return res.status(
            500
        ).json({
            success: false,
            message:
                "Authentication failed"
        });

    }

}


/* =========================================
   OPTIONAL AUTHENTICATION
========================================= */

async function optionalAuthenticateUser(
    req,
    res,
    next
) {

    try {

        req.user = null;
        req.userId = null;


        if (!pool) {

            return next();

        }


        const header =
            String(
                req.headers.authorization ||
                ""
            );


        if (
            !header.toLowerCase()
                .startsWith("bearer ")
        ) {

            return next();

        }


        const token =
            header
                .slice(7)
                .trim();


        if (!token) {

            return next();

        }


        const tokenHash =
            hashToken(
                token
            );


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
                WHERE
                    s.token_hash = $1
                    AND
                    s.expires_at > CURRENT_TIMESTAMP
                LIMIT 1
                `,
                [
                    tokenHash
                ]
            );


        if (
            result.rows.length
        ) {

            req.user =
                result.rows[0];

            req.userId =
                result.rows[0].id;

        }


        next();

    } catch (error) {

        console.error(
            "Optional authentication error:",
            error
        );

        /*
         * Optional authentication must
         * never block public requests.
         */

        req.user = null;
        req.userId = null;

        next();

    }

}


/* =========================================
   DATABASE INITIALIZATION
========================================= */

async function initializeDatabase() {

    if (!pool) {

        console.log(
            "Database is not configured. Skipping database initialization."
        );

        return;

    }


    await pool.query(
        `
        CREATE TABLE IF NOT EXISTS users (

            id SERIAL PRIMARY KEY,

            name TEXT NOT NULL,

            username TEXT NOT NULL UNIQUE,

            email TEXT NOT NULL UNIQUE,

            password_hash TEXT NOT NULL,

            created_at TIMESTAMP
                DEFAULT CURRENT_TIMESTAMP

        )
        `
    );


    await pool.query(
        `
        CREATE TABLE IF NOT EXISTS profiles (

            id SERIAL PRIMARY KEY,

            user_id INTEGER NOT NULL UNIQUE
                REFERENCES users(id)
                ON DELETE CASCADE,

            bio TEXT DEFAULT '',

            profile_picture TEXT DEFAULT '',

            updated_at TIMESTAMP
                DEFAULT CURRENT_TIMESTAMP

        )
        `
    );


    await pool.query(
        `
        CREATE TABLE IF NOT EXISTS sessions (

            id SERIAL PRIMARY KEY,

            user_id INTEGER NOT NULL
                REFERENCES users(id)
                ON DELETE CASCADE,

            token_hash TEXT NOT NULL UNIQUE,

            created_at TIMESTAMP
                DEFAULT CURRENT_TIMESTAMP,

            expires_at TIMESTAMP NOT NULL

        )
        `
    );


    await pool.query(
        `
        CREATE INDEX IF NOT EXISTS
        idx_sessions_token_hash
        ON sessions(token_hash)
        `
    );


    await pool.query(
        `
        CREATE INDEX IF NOT EXISTS
        idx_sessions_user_id
        ON sessions(user_id)
        `
    );


    /*
     * Main Canvas live-stream table.
     *
     * is_live is kept separately from status
     * for compatibility with the existing
     * Canvas frontend.
     */

    await pool.query(
        `
        CREATE TABLE IF NOT EXISTS streams (

            id BIGSERIAL PRIMARY KEY,

            user_id INTEGER NOT NULL
                REFERENCES users(id)
                ON DELETE CASCADE,

            title TEXT
                DEFAULT 'Canvas Live Stream',

            category TEXT
                DEFAULT 'Entertainment',

            thumbnail TEXT
                DEFAULT '',

            status TEXT
                DEFAULT 'live',

            is_live BOOLEAN
                DEFAULT TRUE,

            viewer_count INTEGER
                DEFAULT 0,

            created_at TIMESTAMP
                DEFAULT CURRENT_TIMESTAMP,

            updated_at TIMESTAMP
                DEFAULT CURRENT_TIMESTAMP

        )
        `
    );


    await pool.query(
        `
        CREATE INDEX IF NOT EXISTS
        idx_streams_user_id
        ON streams(user_id)
        `
    );


    await pool.query(
        `
        CREATE INDEX IF NOT EXISTS
        idx_streams_is_live
        ON streams(is_live)
        `
    );


    await pool.query(
        `
        CREATE INDEX IF NOT EXISTS
        idx_streams_created_at
        ON streams(created_at DESC)
        `
    );

      }
/* =========================================
   FOLLOW TABLE
========================================= */

async function ensureFollowTable() {

    if (!pool) {
        return;
    }


    await pool.query(
        `
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

        )
        `
    );


    await pool.query(
        `
        CREATE INDEX IF NOT EXISTS
        idx_follows_follower_id
        ON follows(follower_id)
        `
    );


    await pool.query(
        `
        CREATE INDEX IF NOT EXISTS
        idx_follows_following_id
        ON follows(following_id)
        `
    );

}


/* =========================================
   CHAT TABLE
========================================= */

async function ensureChatTable() {

    if (!pool) {
        return;
    }


    await pool.query(
        `
        CREATE TABLE IF NOT EXISTS chat_messages (

            id BIGSERIAL PRIMARY KEY,

            stream_id TEXT NOT NULL,

            user_id INTEGER
                REFERENCES users(id)
                ON DELETE SET NULL,

            username TEXT
                DEFAULT 'User',

            message TEXT NOT NULL,

            created_at TIMESTAMP
                DEFAULT CURRENT_TIMESTAMP

        )
        `
    );


    await pool.query(
        `
        CREATE INDEX IF NOT EXISTS
        idx_chat_messages_stream_id
        ON chat_messages(stream_id)
        `
    );


    await pool.query(
        `
        CREATE INDEX IF NOT EXISTS
        idx_chat_messages_created_at
        ON chat_messages(
            stream_id,
            created_at DESC,
            id DESC
        )
        `
    );

}


/* =========================================
   RECORDINGS TABLE
========================================= */

async function ensureRecordingsTable() {

    if (!pool) {
        return;
    }


    await pool.query(
        `
        CREATE TABLE IF NOT EXISTS stream_recordings (

            id BIGSERIAL PRIMARY KEY,

            stream_id TEXT NOT NULL,

            user_id INTEGER
                REFERENCES users(id)
                ON DELETE SET NULL,

            title TEXT
                DEFAULT '',

            thumbnail TEXT
                DEFAULT '',

            recording_url TEXT
                DEFAULT '',

            created_at TIMESTAMP
                DEFAULT CURRENT_TIMESTAMP

        )
        `
    );


    await pool.query(
        `
        CREATE INDEX IF NOT EXISTS
        idx_stream_recordings_stream_id
        ON stream_recordings(stream_id)
        `
    );


    await pool.query(
        `
        CREATE INDEX IF NOT EXISTS
        idx_stream_recordings_created_at
        ON stream_recordings(
            created_at DESC,
            id DESC
        )
        `
    );

}


/* =========================================
   FOLLOW COUNTS
========================================= */

async function getFollowCounts(
    userId
) {

    if (
        !pool ||
        !userId
    ) {

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
            [
                userId
            ]
        );


    const row =
        result.rows[0] ||
        {};


    return {

        followers:
            Number(
                row.followers || 0
            ),

        following:
            Number(
                row.following || 0
            )

    };

}


/* =========================================
   STREAM DATA HELPERS
========================================= */

function normalizeStreamTitle(
    value
) {

    return String(
        value ||
        "Canvas Live Stream"
    )
        .trim()
        .slice(
            0,
            200
        ) ||
        "Canvas Live Stream";

}


function normalizeCategory(
    value
) {

    return String(
        value ||
        "Entertainment"
    )
        .trim()
        .slice(
            0,
            100
        ) ||
        "Entertainment";

}


/* =========================================
   STREAM CREATOR DATA
========================================= */

function formatStreamRow(
    row
) {

    return {

        id:
            row.id,

        stream_id:
            String(
                row.id
            ),

        user_id:
            row.user_id,

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
            Boolean(
                row.is_live
            ),

        viewer_count:
            getViewerCount(
                String(row.id)
            ),

        created_at:
            row.created_at,

        updated_at:
            row.updated_at,

        creator: {

            id:
                row.user_id,

            userId:
                row.user_id,

            name:
                row.creator_name ||
                "",

            displayName:
                row.creator_name ||
                "",

            username:
                row.creator_username ||
                "",

            profile_picture:
                row.profile_picture ||
                "",

            profileImage:
                row.profile_picture ||
                "",

            profilePhoto:
                row.profile_picture ||
                "",

            avatar:
                row.profile_picture ||
                ""

        },

        creator_id:
            row.user_id,

        creator_name:
            row.creator_name ||
            "",

        creator_username:
            row.creator_username ||
            "",

        profile_picture:
            row.profile_picture ||
            "",

        profileImage:
            row.profile_picture ||
            ""

    };

}


/* =========================================
   FIND ACTIVE STREAM FOR USER
========================================= */

async function getUserActiveStream(
    userId
) {

    if (
        !pool ||
        !userId
    ) {

        return null;

    }


    const result =
        await pool.query(
            `
            SELECT
                id,
                user_id,
                title,
                category,
                thumbnail,
                status,
                is_live,
                viewer_count,
                created_at,
                updated_at
            FROM streams
            WHERE
                user_id = $1
                AND
                is_live = TRUE
            ORDER BY
                created_at DESC,
                id DESC
            LIMIT 1
            `,
            [
                userId
            ]
        );


    return (
        result.rows[0] ||
        null
    );

}


/* =========================================
   GET STREAM BY ID
========================================= */

async function getStreamById(
    streamId
) {

    if (
        !pool
    ) {

        return null;

    }


    const id =
        normalizeStreamId(
            streamId
        );


    if (!id) {
        return null;
    }


    const result =
        await pool.query(
            `
            SELECT

                s.id,
                s.user_id,
                s.title,
                s.category,
                s.thumbnail,
                s.status,
                s.is_live,
                s.viewer_count,
                s.created_at,
                s.updated_at,

                u.name AS creator_name,
                u.username AS creator_username,

                p.profile_picture

            FROM streams s

            INNER JOIN users u
                ON u.id = s.user_id

            LEFT JOIN profiles p
                ON p.user_id = u.id

            WHERE
                s.id::text = $1

            LIMIT 1
            `,
            [
                id
            ]
        );


    if (
        !result.rows.length
    ) {

        return null;

    }


    return formatStreamRow(
        result.rows[0]
    );

}


/* =========================================
   GET LIVE STREAMS
========================================= */

async function getLiveStreams() {

    if (!pool) {

        return [];

    }


    const result =
        await pool.query(
            `
            SELECT

                s.id,
                s.user_id,
                s.title,
                s.category,
                s.thumbnail,
                s.status,
                s.is_live,
                s.viewer_count,
                s.created_at,
                s.updated_at,

                u.name AS creator_name,
                u.username AS creator_username,

                p.profile_picture

            FROM streams s

            INNER JOIN users u
                ON u.id = s.user_id

            LEFT JOIN profiles p
                ON p.user_id = u.id

            WHERE
                s.is_live = TRUE

            ORDER BY
                s.created_at DESC,
                s.id DESC
            `
        );


    return result.rows.map(
        formatStreamRow
    );

}


/* =========================================
   SYNC DATABASE VIEWER COUNT
========================================= */

async function syncStreamViewerCount(
    streamId
) {

    if (!pool) {
        return;
    }


    const id =
        normalizeStreamId(
            streamId
        );


    if (!id) {
        return;
    }


    const count =
        getViewerCount(
            id
        );


    try {

        await pool.query(
            `
            UPDATE streams
            SET
                viewer_count = $1,
                updated_at = CURRENT_TIMESTAMP
            WHERE
                id::text = $2
                AND
                is_live = TRUE
            `,
            [
                count,
                id
            ]
        );

    } catch (error) {

        console.error(
            "Unable to sync stream viewer count:",
            error
        );

    }

}


/* =========================================
   LOAD CHAT HISTORY
========================================= */

async function getChatHistory(
    streamId
) {

    if (!pool) {
        return [];
    }


    const id =
        normalizeStreamId(
            streamId
        );


    if (!id) {
        return [];
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

            WHERE
                stream_id = $1

            ORDER BY
                created_at DESC,
                id DESC

            LIMIT 100
            `,
            [
                id
            ]
        );


    return result.rows
        .reverse()
        .map(
            formatChatMessage
        );

}


/* =========================================
   SAVE CHAT MESSAGE
========================================= */

async function saveChatMessage(
    streamId,
    userId,
    username,
    message
) {

    if (!pool) {

        throw new Error(
            "Database is not configured"
        );

    }


    const id =
        normalizeStreamId(
            streamId
        );


    const text =
        normalizeChatMessage(
            message
        );


    if (
        !id ||
        !text
    ) {

        throw new Error(
            "Invalid stream or message"
        );

    }


    const safeUsername =
        String(
            username ||
            "User"
        )
            .trim()
            .slice(
                0,
                80
            ) ||
            "User";


    const result =
        await pool.query(
            `
            INSERT INTO chat_messages
                (
                    stream_id,
                    user_id,
                    username,
                    message,
                    created_at
                )
            VALUES
                (
                    $1,
                    $2,
                    $3,
                    $4,
                    CURRENT_TIMESTAMP
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
                id,
                userId || null,
                safeUsername,
                text
            ]
        );


    return formatChatMessage(
        result.rows[0]
    );

}
/* =========================================
   LIVE STREAM ROUTES
========================================= */


/* =========================================
   GET ALL LIVE STREAMS
========================================= */

app.get(
    "/api/streams",
    optionalAuthenticateUser,
    async (req, res) => {

        try {

            if (!pool) {

                return res.status(503).json({
                    success: false,
                    message:
                        "Database is not configured",
                    streams: []
                });

            }


            /*
             * Only streams that are currently
             * marked live are returned.
             *
             * This is the endpoint used by
             * stream.html / Canvas Home.
             */

            const streams =
                await getLiveStreams();


            /*
             * Make sure the response always
             * contains an array called streams.
             */

            return res.json({
                success: true,
                streams
            });

        } catch (error) {

            console.error(
                "GET /api/streams error:",
                error
            );


            return res.status(500).json({
                success: false,
                message:
                    "Unable to load live streams",
                streams: []
            });

        }

    }
);


/* =========================================
   GET SINGLE STREAM
========================================= */

app.get(
    "/api/streams/:id",
    optionalAuthenticateUser,
    async (req, res) => {

        try {

            if (!pool) {

                return res.status(503).json({
                    success: false,
                    message:
                        "Database is not configured"
                });

            }


            const streamId =
                normalizeStreamId(
                    req.params.id
                );


            if (!streamId) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Stream ID is required"
                });

            }


            const stream =
                await getStreamById(
                    streamId
                );


            if (!stream) {

                return res.status(404).json({
                    success: false,
                    message:
                        "Stream not found"
                });

            }


            return res.json({
                success: true,
                stream
            });

        } catch (error) {

            console.error(
                "GET /api/streams/:id error:",
                error
            );


            return res.status(500).json({
                success: false,
                message:
                    "Unable to load stream"
            });

        }

    }
);


/* =========================================
   CREATE LIVE STREAM
========================================= */

app.post(
    "/api/streams",
    authenticateUser,
    async (req, res) => {

        try {

            if (!pool) {

                return res.status(503).json({
                    success: false,
                    message:
                        "Database is not configured"
                });

            }


            /*
             * Prevent one user from creating
             * multiple simultaneous streams.
             */

            const existing =
                await getUserActiveStream(
                    req.userId
                );


            if (existing) {

                const existingStream =
                    await getStreamById(
                        String(
                            existing.id
                        )
                    );


                return res.status(409).json({
                    success: false,
                    message:
                        "You already have an active live stream",
                    stream:
                        existingStream ||
                        existing
                });

            }


            const title =
                normalizeStreamTitle(
                    req.body?.title ||
                    req.body?.stream_title ||
                    req.body?.streamTitle
                );


            const category =
                normalizeCategory(
                    req.body?.category ||
                    req.body?.stream_category ||
                    req.body?.streamCategory
                );


            const thumbnail =
                String(
                    req.body?.thumbnail ||
                    req.body?.thumbnailUrl ||
                    req.body?.image ||
                    ""
                )
                    .trim();


            /*
             * Create the stream in a transaction.
             */

            const client =
                await pool.connect();


            let stream;


            try {

                await client.query(
                    "BEGIN"
                );


                /*
                 * Check again inside the
                 * transaction to reduce the
                 * chance of duplicate streams
                 * from rapid requests.
                 */

                const activeCheck =
                    await client.query(
                        `
                        SELECT
                            id,
                            user_id,
                            title,
                            category,
                            thumbnail,
                            status,
                            is_live,
                            viewer_count,
                            created_at,
                            updated_at
                        FROM streams
                        WHERE
                            user_id = $1
                            AND
                            is_live = TRUE
                        ORDER BY
                            created_at DESC,
                            id DESC
                        LIMIT 1
                        FOR UPDATE
                        `,
                        [
                            req.userId
                        ]
                    );


                if (
                    activeCheck.rows.length
                ) {

                    await client.query(
                        "ROLLBACK"
                    );


                    const active =
                        await getStreamById(
                            String(
                                activeCheck.rows[0].id
                            )
                        );


                    return res.status(
                        409
                    ).json({
                        success: false,
                        message:
                            "You already have an active live stream",
                        stream:
                            active ||
                            activeCheck.rows[0]
                    });

                }


                const result =
                    await client.query(
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
                        RETURNING
                            id,
                            user_id,
                            title,
                            category,
                            thumbnail,
                            status,
                            is_live,
                            viewer_count,
                            created_at,
                            updated_at
                        `,
                        [
                            req.userId,
                            title,
                            category,
                            thumbnail
                        ]
                    );


                stream =
                    result.rows[0];


                await client.query(
                    "COMMIT"
                );

            } catch (error) {

                try {

                    await client.query(
                        "ROLLBACK"
                    );

                } catch (_) {}


                throw error;

            } finally {

                client.release();

            }


            /*
             * Reload the complete stream so
             * creator/profile information is
             * included in the response.
             */

            const completeStream =
                await getStreamById(
                    String(
                        stream.id
                    )
                );


            /*
             * Notify Home / Explore / Watch
             * clients that a new stream exists.
             */

            io.emit(
                "stream-updated",
                {
                    streamId:
                        String(
                            stream.id
                        ),

                    stream:
                        completeStream ||
                        stream,

                    action:
                        "started"
                }
            );


            return res.status(
                201
            ).json({
                success: true,

                stream:
                    completeStream ||
                    stream,

                message:
                    "Live stream created successfully"
            });

        } catch (error) {

            console.error(
                "POST /api/streams error:",
                error
            );


            /*
             * PostgreSQL unique/check errors
             * can still occur under very fast
             * simultaneous requests.
             */

            if (
                error &&
                error.code === "23505"
            ) {

                return res.status(
                    409
                ).json({
                    success: false,
                    message:
                        "You already have an active live stream"
                });

            }


            return res.status(500).json({
                success: false,
                message:
                    "Unable to create live stream"
            });

        }

    }
);


/* =========================================
   UPDATE LIVE STREAM
========================================= */

app.put(
    "/api/streams/:id",
    authenticateUser,
    async (req, res) => {

        try {

            if (!pool) {

                return res.status(503).json({
                    success: false,
                    message:
                        "Database is not configured"
                });

            }


            const streamId =
                normalizeStreamId(
                    req.params.id
                );


            if (!streamId) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Stream ID is required"
                });

            }


            /*
             * Only the owner of the stream
             * may update it.
             */

            const ownerCheck =
                await pool.query(
                    `
                    SELECT
                        id
                    FROM streams
                    WHERE
                        id::text = $1
                        AND
                        user_id = $2
                    LIMIT 1
                    `,
                    [
                        streamId,
                        req.userId
                    ]
                );


            if (
                !ownerCheck.rows.length
            ) {

                return res.status(404).json({
                    success: false,
                    message:
                        "Stream not found"
                });

            }


            const titleProvided =
                req.body &&
                (
                    Object.prototype
                        .hasOwnProperty
                        .call(
                            req.body,
                            "title"
                        ) ||
                    Object.prototype
                        .hasOwnProperty
                        .call(
                            req.body,
                            "stream_title"
                        ) ||
                    Object.prototype
                        .hasOwnProperty
                        .call(
                            req.body,
                            "streamTitle"
                        )
                );


            const categoryProvided =
                req.body &&
                (
                    Object.prototype
                        .hasOwnProperty
                        .call(
                            req.body,
                            "category"
                        ) ||
                    Object.prototype
                        .hasOwnProperty
                        .call(
                            req.body,
                            "stream_category"
                        ) ||
                    Object.prototype
                        .hasOwnProperty
                        .call(
                            req.body,
                            "streamCategory"
                        )
                );


            const thumbnailProvided =
                req.body &&
                (
                    Object.prototype
                        .hasOwnProperty
                        .call(
                            req.body,
                            "thumbnail"
                        ) ||
                    Object.prototype
                        .hasOwnProperty
                        .call(
                            req.body,
                            "thumbnailUrl"
                        )
                );


            const current =
                await pool.query(
                    `
                    SELECT
                        title,
                        category,
                        thumbnail
                    FROM streams
                    WHERE
                        id::text = $1
                    LIMIT 1
                    `,
                    [
                        streamId
                    ]
                );


            const currentStream =
                current.rows[0];


            const title =
                titleProvided
                    ? normalizeStreamTitle(
                        req.body?.title ||
                        req.body?.stream_title ||
                        req.body?.streamTitle
                    )
                    : currentStream.title;


            const category =
                categoryProvided
                    ? normalizeCategory(
                        req.body?.category ||
                        req.body?.stream_category ||
                        req.body?.streamCategory
                    )
                    : currentStream.category;


            const thumbnail =
                thumbnailProvided
                    ? String(
                        req.body?.thumbnail ||
                        req.body?.thumbnailUrl ||
                        ""
                    )
                        .trim()
                    : currentStream.thumbnail;


            const result =
                await pool.query(
                    `
                    UPDATE streams
                    SET
                        title = $1,
                        category = $2,
                        thumbnail = $3,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE
                        id::text = $4
                        AND
                        user_id = $5
                    RETURNING
                        id
                    `,
                    [
                        title,
                        category,
                        thumbnail,
                        streamId,
                        req.userId
                    ]
                );


            if (
                !result.rows.length
            ) {

                return res.status(404).json({
                    success: false,
                    message:
                        "Stream not found"
                });

            }


            const updatedStream =
                await getStreamById(
                    streamId
                );


            io.emit(
                "stream-updated",
                {
                    streamId,

                    stream:
                        updatedStream,

                    action:
                        "updated"
                }
            );


            io.to(
                getStreamRoom(
                    streamId
                )
            ).emit(
                "stream-updated",
                {
                    streamId,

                    stream:
                        updatedStream,

                    action:
                        "updated"
                }
            );


            return res.json({
                success: true,
                stream:
                    updatedStream
            });

        } catch (error) {

            console.error(
                "PUT /api/streams/:id error:",
                error
            );


            return res.status(500).json({
                success: false,
                message:
                    "Unable to update stream"
            });

        }

    }
);


/* =========================================
   END LIVE STREAM
========================================= */

app.post(
    "/api/streams/:id/end",
    authenticateUser,
    async (req, res) => {

        try {

            if (!pool) {

                return res.status(503).json({
                    success: false,
                    message:
                        "Database is not configured"
                });

            }


            const streamId =
                normalizeStreamId(
                    req.params.id
                );


            if (!streamId) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Stream ID is required"
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
                        updated_at = CURRENT_TIMESTAMP
                    WHERE
                        id::text = $1
                        AND
                        user_id = $2
                        RETURNING
                        id,
                        user_id,
                        title,
                        category,
                        thumbnail,
                        status,
                        is_live,
                        viewer_count,
                        created_at,
                        updated_at
                    `,
                    [
                        streamId,
                        req.userId
                    ]
                );


            if (
                !result.rows.length
            ) {

                return res.status(404).json({
                    success: false,
                    message:
                        "Stream not found"
                });

            }


            io.to(
                getStreamRoom(
                    streamId
                )
            ).emit(
                "stream-ended",
                {
                    streamId,
                    ended: true
                }
            );


            const viewers =
                streamRooms.get(
                    streamId
                );


            if (viewers) {

                for (
                    const socketId
                    of viewers
                ) {

                    const viewerSocket =
                        io.sockets.sockets.get(
                            socketId
                        );


                    if (
                        viewerSocket
                    ) {

                        try {

                            viewerSocket.leave(
                                getStreamRoom(
                                    streamId
                                )
                            );

                        } catch (_) {}


                        if (
                            viewerSocket.data &&
                            viewerSocket.data.streamId === streamId
                        ) {

                            delete viewerSocket
                                .data.streamId;

                            delete viewerSocket
                                .data.streamRoom;

                        }

                    }

                }

            }


            streamRooms.delete(
                streamId
            );

            streamViewerCounts.delete(
                streamId
            );


            io.emit(
                "stream-updated",
                {
                    streamId,
                    action:
                        "ended"
                }
            );


            return res.json({
                success: true,
                streamId,
                ended: true
            });

        } catch (error) {

            console.error(
                "DELETE /api/streams/:id error:",
                error
            );


            return res.status(500).json({
                success: false,
                message:
                    "Unable to end stream"
            });

        }

    }
);
/* =========================================
   SIGNUP / VERIFICATION ROUTES
========================================= */

app.post("/api/signup/send-code", async (req, res) => {

    try {

        if (!pool) {
            return res.status(503).json({
                success: false,
                message: "Database unavailable"
            });
        }

        const email = normalizeEmail(req.body.email);

        if (!email) {
            return res.status(400).json({
                success: false,
                message: "Email is required"
            });
        }

        const existing = await pool.query(
            `
            SELECT id
            FROM users
            WHERE LOWER(email) = $1
            LIMIT 1
            `,
            [email]
        );

        if (existing.rows.length) {
            return res.status(409).json({
                success: false,
                message: "An account with this email already exists"
            });
        }

        const code = String(
            Math.floor(100000 + Math.random() * 900000)
        );

        signupVerificationCodes.set(email, {
            code,
            expiresAt: Date.now() + (10 * 60 * 1000)
        });

        console.log(
            `[Canvas] Signup verification code for ${email}: ${code}`
        );

        return res.json({
            success: true,
            message: "Verification code generated",
            email
        });

    } catch (error) {

        console.error(
            "POST /api/signup/send-code:",
            error
        );

        return res.status(500).json({
            success: false,
            message: "Failed to send verification code"
        });
    }
});


app.post("/api/signup/verify-code", async (req, res) => {

    try {

        const email = normalizeEmail(req.body.email);
        const code = String(req.body.code || "").trim();

        if (!email || !code) {
            return res.status(400).json({
                success: false,
                message: "Email and verification code are required"
            });
        }

        const record = signupVerificationCodes.get(email);

        if (!record) {
            return res.status(400).json({
                success: false,
                message: "Verification code not found or expired"
            });
        }

        if (Date.now() > record.expiresAt) {

            signupVerificationCodes.delete(email);

            return res.status(400).json({
                success: false,
                message: "Verification code expired"
            });
        }

        if (record.code !== code) {
            return res.status(400).json({
                success: false,
                message: "Invalid verification code"
            });
        }

        signupVerificationCodes.set(email, {
            ...record,
            verified: true,
            verifiedAt: Date.now()
        });

        return res.json({
            success: true,
            verified: true,
            email
        });

    } catch (error) {

        console.error(
            "POST /api/signup/verify-code:",
            error
        );

        return res.status(500).json({
            success: false,
            message: "Verification failed"
        });
    }
});


app.post("/api/signup/verified", async (req, res) => {

    if (!pool) {
        return res.status(503).json({
            success: false,
            message: "Database unavailable"
        });
    }

    const client = await pool.connect();

    try {

        const email = normalizeEmail(req.body.email);
        const username = cleanUsername(req.body.username);
        const name = String(
            req.body.name ||
            req.body.displayName ||
            username
        ).trim();

        const password = String(
            req.body.password || ""
        );

        if (!email || !username || !password) {
            return res.status(400).json({
                success: false,
                message: "Name, username, email and password are required"
            });
        }

        const verification =
            signupVerificationCodes.get(email);

        if (
            !verification ||
            !verification.verified ||
            Date.now() > verification.expiresAt
        ) {
            return res.status(400).json({
                success: false,
                message: "Email verification is required"
            });
        }

        const existing = await pool.query(
            `
            SELECT id, email, username
            FROM users
            WHERE LOWER(email) = $1
               OR LOWER(username) = $2
            LIMIT 1
            `,
            [
                email,
                username.toLowerCase()
            ]
        );

        if (existing.rows.length) {

            const found = existing.rows[0];

            if (
                String(found.email).toLowerCase() === email
            ) {
                return res.status(409).json({
                    success: false,
                    message: "Email is already registered"
                });
            }

            return res.status(409).json({
                success: false,
                message: "Username is already taken"
            });
        }

        await client.query("BEGIN");

        const passwordHash =
            hashPassword(password);

        const userResult = await client.query(
            `
            INSERT INTO users (
                email,
                username,
                password_hash
            )
            VALUES ($1, $2, $3)
            RETURNING id, email, username, created_at
            `,
            [
                email,
                username,
                passwordHash
            ]
        );

        const user = userResult.rows[0];

        await client.query(
            `
            INSERT INTO profiles (
                user_id,
                name,
                username
            )
            VALUES ($1, $2, $3)
            ON CONFLICT (user_id)
            DO UPDATE SET
                name = EXCLUDED.name,
                username = EXCLUDED.username
            `,
            [
                user.id,
                name,
                username
            ]
        );

        const rawToken = createAuthToken();
        const tokenHash = hashToken(rawToken);

        await client.query(
            `
            INSERT INTO sessions (
                user_id,
                token_hash,
                expires_at
            )
            VALUES (
                $1,
                $2,
                NOW() + INTERVAL '30 days'
            )
            `,
            [
                user.id,
                tokenHash
            ]
        );

        await client.query("COMMIT");

        signupVerificationCodes.delete(email);

        return res.status(201).json({
            success: true,
            message: "Account created successfully",

            token: rawToken,
            accessToken: rawToken,
            authToken: rawToken,

            user: {
                id: user.id,
                email: user.email,
                username: user.username,
                name
            }
        });

    } catch (error) {

        try {
            await client.query("ROLLBACK");
        } catch (_) {}

        console.error(
            "POST /api/signup/verified:",
            error
        );

        return res.status(500).json({
            success: false,
            message: "Failed to create account"
        });

    } finally {

        client.release();
    }
});


/* =========================================
   LOGIN
========================================= */

app.post("/api/login", async (req, res) => {

    try {

        if (!pool) {
            return res.status(503).json({
                success: false,
                message: "Database unavailable"
            });
        }

        const identifier = String(
            req.body.email ||
            req.body.username ||
            req.body.identifier ||
            ""
        ).trim();

        const password = String(
            req.body.password || ""
        );

        if (!identifier || !password) {
            return res.status(400).json({
                success: false,
                message: "Username/email and password are required"
            });
        }

        const identifierLower =
            identifier.toLowerCase();

        const result = await pool.query(
            `
            SELECT
                u.id,
                u.email,
                u.username,
                u.password_hash,

                p.name,
                p.bio,
                p.profile_picture

            FROM users u

            LEFT JOIN profiles p
                ON p.user_id = u.id

            WHERE LOWER(u.email) = $1
               OR LOWER(u.username) = $1

            LIMIT 1
            `,
            [identifierLower]
        );

        if (!result.rows.length) {
            return res.status(401).json({
                success: false,
                message: "Invalid login credentials"
            });
        }

        const user = result.rows[0];

        const suppliedHash =
            hashPassword(password);

        if (
            suppliedHash !==
            user.password_hash
        ) {
            return res.status(401).json({
                success: false,
                message: "Invalid login credentials"
            });
        }

        const rawToken =
            createAuthToken();

        const tokenHash =
            hashToken(rawToken);

        await pool.query(
            `
            INSERT INTO sessions (
                user_id,
                token_hash,
                expires_at
            )
            VALUES (
                $1,
                $2,
                NOW() + INTERVAL '30 days'
            )
            `,
            [
                user.id,
                tokenHash
            ]
        );

        return res.json({
            success: true,
            message: "Login successful",

            token: rawToken,
            accessToken: rawToken,
            authToken: rawToken,

            user: {
                id: user.id,
                email: user.email,
                username: user.username,
                name: user.name || user.username,
                bio: user.bio || "",
                profile_picture:
                    user.profile_picture || null
            }
        });

    } catch (error) {

        console.error(
            "POST /api/login:",
            error
        );

        return res.status(500).json({
            success: false,
            message: "Login failed"
        });
    }
});


/* =========================================
   LOGIN COMPATIBILITY ALIAS
========================================= */

app.post("/api/auth/login", async (req, res) => {

    req.url = "/api/login";

    return app._router
        ? res.redirect(307, "/api/login")
        : res.status(500).json({
            success: false,
            message: "Login route unavailable"
        });
});


/* =========================================
   CURRENT USER
========================================= */

app.get("/api/me", authenticateUser, async (req, res) => {

    try {

        if (!pool) {
            return res.status(503).json({
                success: false,
                message: "Database unavailable"
            });
        }

        const result = await pool.query(
            `
            SELECT
                u.id,
                u.email,
                u.username,

                p.name,
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
                message: "User not found"
            });
        }

        const user = result.rows[0];

        const counts =
            await getFollowCounts(user.id);

        return res.json({
            success: true,

            user: {
                id: user.id,
                email: user.email,
                username: user.username,
                name: user.name || user.username,
                bio: user.bio || "",
                profile_picture:
                    user.profile_picture || null,

                followers_count:
                    counts.followers,

                following_count:
                    counts.following
            }
        });

    } catch (error) {

        console.error(
            "GET /api/me:",
            error
        );

        return res.status(500).json({
            success: false,
            message: "Failed to load current user"
        });
    }
});
/* =========================================
   PROFILE ROUTES
========================================= */

app.get("/api/profile", authenticateUser, async (req, res) => {

    try {

        if (!pool) {
            return res.status(503).json({
                success: false,
                message: "Database unavailable"
            });
        }

        const result = await pool.query(
            `
            SELECT
                u.id,
                u.email,
                u.username,

                p.name,
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
                message: "Profile not found"
            });
        }

        const profile = result.rows[0];

        const counts =
            await getFollowCounts(profile.id);

        const activeStream =
            await getUserActiveStream(profile.id);

        return res.json({
            success: true,

            profile: {
                id: profile.id,

                user_id: profile.id,

                name:
                    profile.name ||
                    profile.username,

                username:
                    profile.username,

                email:
                    profile.email,

                bio:
                    profile.bio || "",

                profile_picture:
                    profile.profile_picture || null,

                followers_count:
                    counts.followers,

                following_count:
                    counts.following,

                followers:
                    counts.followers,

                following:
                    counts.following,

                is_live:
                    !!activeStream,

                active_stream:
                    activeStream
                        ? formatStreamRow(activeStream)
                        : null
            }
        });

    } catch (error) {

        console.error(
            "GET /api/profile:",
            error
        );

        return res.status(500).json({
            success: false,
            message: "Failed to load profile"
        });
    }
});


/* =========================================
   PUBLIC PROFILE BY USERNAME / ID
========================================= */

app.get("/api/profile/:identifier", optionalAuthenticateUser, async (req, res) => {

    try {

        if (!pool) {
            return res.status(503).json({
                success: false,
                message: "Database unavailable"
            });
        }

        const identifier =
            String(req.params.identifier || "").trim();

        if (!identifier) {
            return res.status(400).json({
                success: false,
                message: "Profile identifier is required"
            });
        }

        const result = await pool.query(
            `
            SELECT
                u.id,
                u.email,
                u.username,

                p.name,
                p.bio,
                p.profile_picture

            FROM users u

            LEFT JOIN profiles p
                ON p.user_id = u.id

            WHERE
                CAST(u.id AS TEXT) = $1
                OR LOWER(u.username) = LOWER($1)

            LIMIT 1
            `,
            [identifier]
        );

        if (!result.rows.length) {
            return res.status(404).json({
                success: false,
                message: "Profile not found"
            });
        }

        const profile =
            result.rows[0];

        const counts =
            await getFollowCounts(profile.id);

        let isFollowing = false;

        if (
            req.user &&
            Number(req.user.id) !==
            Number(profile.id)
        ) {

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
                        profile.id
                    ]
                );

            isFollowing =
                followResult.rows.length > 0;
        }

        const activeStream =
            await getUserActiveStream(profile.id);

        return res.json({
            success: true,

            profile: {
                id: profile.id,

                user_id: profile.id,

                name:
                    profile.name ||
                    profile.username,

                username:
                    profile.username,

                bio:
                    profile.bio || "",

                profile_picture:
                    profile.profile_picture || null,

                followers_count:
                    counts.followers,

                following_count:
                    counts.following,

                followers:
                    counts.followers,

                following:
                    counts.following,

                isFollowing,

                followingUser:
                    isFollowing,

                is_live:
                    !!activeStream,

                active_stream:
                    activeStream
                        ? formatStreamRow(activeStream)
                        : null
            }
        });

    } catch (error) {

        console.error(
            "GET /api/profile/:identifier:",
            error
        );

        return res.status(500).json({
            success: false,
            message: "Failed to load profile"
        });
    }
});


/* =========================================
   PUBLIC USER PROFILE COMPATIBILITY ROUTE
========================================= */

app.get("/api/users/:username", optionalAuthenticateUser, async (req, res) => {

    try {

        if (!pool) {
            return res.status(503).json({
                success: false,
                message: "Database unavailable"
            });
        }

        const username =
            String(req.params.username || "").trim();

        if (!username) {
            return res.status(400).json({
                success: false,
                message: "Username is required"
            });
        }

        const result = await pool.query(
            `
            SELECT
                u.id,
                u.email,
                u.username,

                p.name,
                p.bio,
                p.profile_picture

            FROM users u

            LEFT JOIN profiles p
                ON p.user_id = u.id

            WHERE LOWER(u.username) = LOWER($1)

            LIMIT 1
            `,
            [username]
        );

        if (!result.rows.length) {
            return res.status(404).json({
                success: false,
                message: "User not found"
            });
        }

        const user =
            result.rows[0];

        const counts =
            await getFollowCounts(user.id);

        let isFollowing = false;

        if (
            req.user &&
            Number(req.user.id) !==
            Number(user.id)
        ) {

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
            success: true,

            user: {
                id: user.id,

                name:
                    user.name ||
                    user.username,

                username:
                    user.username,

                bio:
                    user.bio || "",

                profile_picture:
                    user.profile_picture || null,

                followers_count:
                    counts.followers,

                following_count:
                    counts.following,

                followers:
                    counts.followers,

                following:
                    counts.following,

                isFollowing,

                followingUser:
                    isFollowing
            },

            profile: {
                id: user.id,

                name:
                    user.name ||
                    user.username,

                username:
                    user.username,

                bio:
                    user.bio || "",

                profile_picture:
                    user.profile_picture || null,

                followers_count:
                    counts.followers,

                following_count:
                    counts.following,

                isFollowing
            }
        });

    } catch (error) {

        console.error(
            "GET /api/users/:username:",
            error
        );

        return res.status(500).json({
            success: false,
            message: "Failed to load user"
        });
    }
});


/* =========================================
   UPDATE PROFILE
========================================= */

app.put("/api/profile", authenticateUser, async (req, res) => {

    if (!pool) {
        return res.status(503).json({
            success: false,
            message: "Database unavailable"
        });
    }

    const client = await pool.connect();

    try {

        const name =
            String(
                req.body.name ??
                req.body.displayName ??
                ""
            ).trim();

        const username =
            cleanUsername(
                req.body.username
            );

        const bio =
            String(
                req.body.bio ?? ""
            ).trim();

        let profilePicture;

        if (
            Object.prototype.hasOwnProperty.call(
                req.body,
                "profile_picture"
            )
        ) {
            profilePicture =
                req.body.profile_picture;
        } else if (
            Object.prototype.hasOwnProperty.call(
                req.body,
                "profilePicture"
            )
        ) {
            profilePicture =
                req.body.profilePicture;
        } else if (
            Object.prototype.hasOwnProperty.call(
                req.body,
                "photo"
            )
        ) {
            profilePicture =
                req.body.photo;
        }

        if (!username) {
            return res.status(400).json({
                success: false,
                message: "Username is required"
            });
        }

        const usernameCheck =
            await pool.query(
                `
                SELECT id
                FROM users
                WHERE LOWER(username) = LOWER($1)
                  AND id <> $2
                LIMIT 1
                `,
                [
                    username,
                    req.user.id
                ]
            );

        if (usernameCheck.rows.length) {
            return res.status(409).json({
                success: false,
                message: "Username is already taken"
            });
        }

        await client.query("BEGIN");

        await client.query(
            `
            UPDATE users
            SET username = $1
            WHERE id = $2
            `,
            [
                username,
                req.user.id
            ]
        );

        if (profilePicture !== undefined) {

            await client.query(
                `
                INSERT INTO profiles (
                    user_id,
                    name,
                    username,
                    bio,
                    profile_picture
                )
                VALUES (
                    $1,
                    $2,
                    $3,
                    $4,
                    $5
                )

                ON CONFLICT (user_id)
                DO UPDATE SET
                    name = EXCLUDED.name,
                    username = EXCLUDED.username,
                    bio = EXCLUDED.bio,
                    profile_picture =
                        EXCLUDED.profile_picture
                `,
                [
                    req.user.id,
                    name,
                    username,
                    bio,
                    profilePicture || null
                ]
            );

        } else {

            await client.query(
                `
                INSERT INTO profiles (
                    user_id,
                    name,
                    username,
                    bio
                )
                VALUES (
                    $1,
                    $2,
                    $3,
                    $4
                )

                ON CONFLICT (user_id)
                DO UPDATE SET
                    name = EXCLUDED.name,
                    username = EXCLUDED.username,
                    bio = EXCLUDED.bio
                `,
                [
                    req.user.id,
                    name,
                    username,
                    bio
                ]
            );
        }

        await client.query("COMMIT");

        const result =
            await pool.query(
                `
                SELECT
                    u.id,
                    u.email,
                    u.username,

                    p.name,
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

        const profile =
            result.rows[0];

        const counts =
            await getFollowCounts(req.user.id);

        return res.json({
            success: true,

            message: "Profile updated successfully",

            profile: {
                id: profile.id,
                email: profile.email,
                username: profile.username,

                name:
                    profile.name ||
                    profile.username,

                bio:
                    profile.bio || "",

                profile_picture:
                    profile.profile_picture || null,

                followers_count:
                    counts.followers,

                following_count:
                    counts.following
            }
        });

    } catch (error) {

        try {
            await client.query("ROLLBACK");
        } catch (_) {}

        console.error(
            "PUT /api/profile:",
            error
        );

        return res.status(500).json({
            success: false,
            message: "Failed to update profile"
        });

    } finally {

        client.release();
    }
});


/* =========================================
   PROFILE UPDATE COMPATIBILITY
========================================= */

app.patch("/api/profile", authenticateUser, async (req, res) => {

    req.method = "PUT";

    return app._router
        ? res.redirect(307, "/api/profile")
        : res.status(500).json({
            success: false,
            message: "Profile route unavailable"
        });
});
/* =========================================
   FOLLOW STATUS
========================================= */

app.get("/api/follow/status", authenticateUser, async (req, res) => {

    try {

        if (!pool) {
            return res.status(503).json({
                success: false,
                message: "Database unavailable"
            });
        }

        const targetId = Number(
            req.query.userId ||
            req.query.user_id ||
            req.query.id ||
            req.query.followingId
        );

        if (!Number.isInteger(targetId)) {
            return res.status(400).json({
                success: false,
                message: "Valid user ID is required"
            });
        }

        if (Number(req.user.id) === targetId) {
            return res.json({
                success: true,
                following: false,
                isFollowing: false
            });
        }

        const result = await pool.query(
            `
            SELECT 1
            FROM follows
            WHERE follower_id = $1
              AND following_id = $2
            LIMIT 1
            `,
            [
                req.user.id,
                targetId
            ]
        );

        return res.json({
            success: true,
            following: result.rows.length > 0,
            isFollowing: result.rows.length > 0
        });

    } catch (error) {

        console.error(
            "GET /api/follow/status:",
            error
        );

        return res.status(500).json({
            success: false,
            message: "Failed to check follow status"
        });
    }
});


/* =========================================
   FOLLOW / UNFOLLOW
========================================= */

app.post("/api/follow", authenticateUser, async (req, res) => {

    try {

        if (!pool) {
            return res.status(503).json({
                success: false,
                message: "Database unavailable"
            });
        }

        const targetId = Number(
            req.body.userId ||
            req.body.user_id ||
            req.body.followingId ||
            req.body.targetUserId
        );

        if (!Number.isInteger(targetId)) {
            return res.status(400).json({
                success: false,
                message: "Valid user ID is required"
            });
        }

        if (Number(req.user.id) === targetId) {
            return res.status(400).json({
                success: false,
                message: "You cannot follow yourself"
            });
        }

        const targetUser =
            await pool.query(
                `
                SELECT id
                FROM users
                WHERE id = $1
                LIMIT 1
                `,
                [targetId]
            );

        if (!targetUser.rows.length) {
            return res.status(404).json({
                success: false,
                message: "User not found"
            });
        }

        const existing =
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
                    targetId
                ]
            );

        let following;

        if (existing.rows.length) {

            await pool.query(
                `
                DELETE FROM follows
                WHERE follower_id = $1
                  AND following_id = $2
                `,
                [
                    req.user.id,
                    targetId
                ]
            );

            following = false;

        } else {

            await pool.query(
                `
                INSERT INTO follows (
                    follower_id,
                    following_id
                )
                VALUES ($1, $2)
                ON CONFLICT DO NOTHING
                `,
                [
                    req.user.id,
                    targetId
                ]
            );

            following = true;
        }

        const counts =
            await getFollowCounts(targetId);

        io.emit("follow-updated", {
            followerId: Number(req.user.id),
            followingId: targetId,
            following,

            followers:
                counts.followers,

            followingCount:
                counts.following
        });

        return res.json({
            success: true,

            following,
            isFollowing: following,

            followers_count:
                counts.followers,

            following_count:
                counts.following
        });

    } catch (error) {

        console.error(
            "POST /api/follow:",
            error
        );

        return res.status(500).json({
            success: false,
            message: "Failed to update follow"
        });
    }
});


/* =========================================
   FOLLOWERS LIST
========================================= */

app.get("/api/users/:id/followers", async (req, res) => {

    try {

        if (!pool) {
            return res.status(503).json({
                success: false,
                message: "Database unavailable"
            });
        }

        const userId =
            Number(req.params.id);

        if (!Number.isInteger(userId)) {
            return res.status(400).json({
                success: false,
                message: "Invalid user ID"
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

                WHERE f.following_id = $1

                ORDER BY f.created_at DESC
                `,
                [userId]
            );

        return res.json({
            success: true,
            followers: result.rows.map(user => ({
                id: user.id,

                username:
                    user.username,

                name:
                    user.name ||
                    user.username,

                profile_picture:
                    user.profile_picture || null
            }))
        });

    } catch (error) {

        console.error(
            "GET /api/users/:id/followers:",
            error
        );

        return res.status(500).json({
            success: false,
            message: "Failed to load followers"
        });
    }
});


/* =========================================
   CHAT HISTORY
========================================= */

app.get("/api/streams/:id/chat", optionalAuthenticateUser, async (req, res) => {

    try {

        if (!pool) {
            return res.status(503).json({
                success: false,
                message: "Database unavailable"
            });
        }

        const streamId =
            normalizeStreamId(req.params.id);

        if (!streamId) {
            return res.status(400).json({
                success: false,
                message: "Invalid stream ID"
            });
        }

        const stream =
            await getStreamById(streamId);

        if (!stream) {
            return res.status(404).json({
                success: false,
                message: "Stream not found"
            });
        }

        const messages =
            await getChatHistory(streamId);

        return res.json({
            success: true,
            messages
        });

    } catch (error) {

        console.error(
            "GET /api/streams/:id/chat:",
            error
        );

        return res.status(500).json({
            success: false,
            message: "Failed to load chat"
        });
    }
});


/* =========================================
   SEND CHAT MESSAGE
========================================= */

app.post("/api/streams/:id/chat", authenticateUser, async (req, res) => {

    try {

        if (!pool) {
            return res.status(503).json({
                success: false,
                message: "Database unavailable"
            });
        }

        const streamId =
            normalizeStreamId(req.params.id);

        const message =
            String(
                req.body.message ||
                req.body.text ||
                ""
            ).trim();

        if (!streamId) {
            return res.status(400).json({
                success: false,
                message: "Invalid stream ID"
            });
        }

        if (!message) {
            return res.status(400).json({
                success: false,
                message: "Message cannot be empty"
            });
        }

        const stream =
            await getStreamById(streamId);

        if (!stream) {
            return res.status(404).json({
                success: false,
                message: "Stream not found"
            });
        }

        const username =
            req.user.username ||
            "User";

        const saved =
            await saveChatMessage(
                streamId,
                req.user.id,
                username,
                message
            );

        const room =
            getStreamRoom(streamId);

        io.to(room).emit(
            "chat-message",
            saved
        );

        return res.status(201).json({
            success: true,
            message: saved
        });

    } catch (error) {

        console.error(
            "POST /api/streams/:id/chat:",
            error
        );

        return res.status(500).json({
            success: false,
            message: "Failed to send chat message"
        });
    }
});


/* =========================================
   DELETE CHAT MESSAGE
========================================= */

app.delete(
    "/api/streams/:id/chat/:messageId",
    authenticateUser,
    async (req, res) => {

        try {

            if (!pool) {
                return res.status(503).json({
                    success: false,
                    message: "Database unavailable"
                });
            }

            const streamId =
                normalizeStreamId(req.params.id);

            const messageId =
                Number(req.params.messageId);

            if (
                !streamId ||
                !Number.isInteger(messageId)
            ) {
                return res.status(400).json({
                    success: false,
                    message: "Invalid stream or message ID"
                });
            }

            const result =
                await pool.query(
                    `
                    DELETE FROM chat_messages
                    WHERE id = $1
                      AND stream_id = $2
                      AND user_id = $3
                    RETURNING id
                    `,
                    [
                        messageId,
                        streamId,
                        req.user.id
                    ]
                );

            if (!result.rows.length) {
                return res.status(404).json({
                    success: false,
                    message: "Message not found"
                });
            }

            const room =
                getStreamRoom(streamId);

            io.to(room).emit(
                "chat-message-deleted",
                {
                    streamId,
                    messageId
                }
            );

            return res.json({
                success: true,
                messageId
            });

        } catch (error) {

            console.error(
                "DELETE /api/streams/:id/chat/:messageId:",
                error
            );

            return res.status(500).json({
                success: false,
                message: "Failed to delete chat message"
            });
        }
    }
);
/* =========================================
   STREAM VIEWER ENDPOINTS
========================================= */

app.get("/api/streams/:id/viewers", async (req, res) => {

    try {

        const streamId =
            normalizeStreamId(req.params.id);

        if (!streamId) {
            return res.status(400).json({
                success: false,
                message: "Invalid stream ID"
            });
        }

        const count =
            getViewerCount(streamId);

        return res.json({
            success: true,
            streamId,
            viewer_count: count,
            viewers: count
        });

    } catch (error) {

        console.error(
            "GET /api/streams/:id/viewers:",
            error
        );

        return res.status(500).json({
            success: false,
            message: "Failed to get viewer count"
        });
    }
});


app.get("/api/streams/:id/status", async (req, res) => {

    try {

        const streamId =
            normalizeStreamId(req.params.id);

        if (!streamId) {
            return res.status(400).json({
                success: false,
                message: "Invalid stream ID"
            });
        }

        const stream =
            await getStreamById(streamId);

        if (!stream) {
            return res.status(404).json({
                success: false,
                message: "Stream not found"
            });
        }

        return res.json({
            success: true,

            stream_id:
                streamId,

            is_live:
                !!stream.is_live,

            status:
                stream.status,

            viewer_count:
                getViewerCount(streamId)
        });

    } catch (error) {

        console.error(
            "GET /api/streams/:id/status:",
            error
        );

        return res.status(500).json({
            success: false,
            message: "Failed to get stream status"
        });
    }
});


app.get("/api/streams/:id/socket-status", async (req, res) => {

    try {

        const streamId =
            normalizeStreamId(req.params.id);

        if (!streamId) {
            return res.status(400).json({
                success: false,
                message: "Invalid stream ID"
            });
        }

        const room =
            getStreamRoom(streamId);

        const sockets =
            streamRooms.get(streamId);

        return res.json({
            success: true,

            stream_id:
                streamId,

            room,

            connected:
                sockets
                    ? sockets.size
                    : 0,

            viewer_count:
                getViewerCount(streamId)
        });

    } catch (error) {

        console.error(
            "GET /api/streams/:id/socket-status:",
            error
        );

        return res.status(500).json({
            success: false,
            message: "Failed to get socket status"
        });
    }
});


/* =========================================
   STREAM EVENTS
========================================= */

app.post(
    "/api/streams/:id/event",
    authenticateUser,
    async (req, res) => {

        try {

            const streamId =
                normalizeStreamId(req.params.id);

            const event =
                String(
                    req.body.event ||
                    req.body.type ||
                    ""
                ).trim();

            const allowedEvents = new Set([
                "stream-started",
                "stream-updated",
                "stream-title-updated",
                "stream-thumbnail-updated"
            ]);

            if (!streamId) {
                return res.status(400).json({
                    success: false,
                    message: "Invalid stream ID"
                });
            }

            if (!allowedEvents.has(event)) {
                return res.status(400).json({
                    success: false,
                    message: "Invalid stream event"
                });
            }

            const stream =
                await getStreamById(streamId);

            if (!stream) {
                return res.status(404).json({
                    success: false,
                    message: "Stream not found"
                });
            }

            if (
                Number(stream.user_id) !==
                Number(req.user.id)
            ) {
                return res.status(403).json({
                    success: false,
                    message: "You do not own this stream"
                });
            }

            io.emit("stream-updated", {
                action: event,
                stream: formatStreamRow(stream)
            });

            return res.json({
                success: true,
                event,
                stream: formatStreamRow(stream)
            });

        } catch (error) {

            console.error(
                "POST /api/streams/:id/event:",
                error
            );

            return res.status(500).json({
                success: false,
                message: "Failed to process stream event"
            });
        }
    }
);


/* =========================================
   RECORDINGS
========================================= */

app.get("/api/recordings", async (req, res) => {

    try {

        if (!pool) {
            return res.status(503).json({
                success: false,
                message: "Database unavailable"
            });
        }

        const result =
            await pool.query(
                `
                SELECT
                    r.id,
                    r.stream_id,
                    r.user_id,
                    r.title,
                    r.thumbnail,
                    r.recording_url,
                    r.created_at,

                    u.username,

                    p.name,
                    p.profile_picture

                FROM stream_recordings r

                LEFT JOIN users u
                    ON u.id = r.user_id

                LEFT JOIN profiles p
                    ON p.user_id = r.user_id

                ORDER BY r.created_at DESC

                LIMIT 100
                `
            );

        return res.json({
            success: true,

            recordings:
                result.rows.map(row => ({
                    id: row.id,

                    stream_id:
                        row.stream_id,

                    user_id:
                        row.user_id,

                    title:
                        row.title,

                    thumbnail:
                        row.thumbnail || null,

                    recording_url:
                        row.recording_url || null,

                    created_at:
                        row.created_at,

                    creator: {
                        id:
                            row.user_id,

                        username:
                            row.username,

                        name:
                            row.name ||
                            row.username,

                        profile_picture:
                            row.profile_picture || null
                    }
                }))
        });

    } catch (error) {

        console.error(
            "GET /api/recordings:",
            error
        );

        return res.status(500).json({
            success: false,
            message: "Failed to load recordings"
        });
    }
});


app.get("/api/recordings/:streamId", async (req, res) => {

    try {

        if (!pool) {
            return res.status(503).json({
                success: false,
                message: "Database unavailable"
            });
        }

        const streamId =
            normalizeStreamId(req.params.streamId);

        if (!streamId) {
            return res.status(400).json({
                success: false,
                message: "Invalid stream ID"
            });
        }

        const result =
            await pool.query(
                `
                SELECT
                    r.id,
                    r.stream_id,
                    r.user_id,
                    r.title,
                    r.thumbnail,
                    r.recording_url,
                    r.created_at,

                    u.username,

                    p.name,
                    p.profile_picture

                FROM stream_recordings r

                LEFT JOIN users u
                    ON u.id = r.user_id

                LEFT JOIN profiles p
                    ON p.user_id = r.user_id

                WHERE r.stream_id = $1

                ORDER BY r.created_at DESC

                LIMIT 1
                `,
                [streamId]
            );

        if (!result.rows.length) {
            return res.status(404).json({
                success: false,
                message: "Recording not found"
            });
        }

        const row =
            result.rows[0];

        return res.json({
            success: true,

            recording: {
                id: row.id,

                stream_id:
                    row.stream_id,

                user_id:
                    row.user_id,

                title:
                    row.title,

                thumbnail:
                    row.thumbnail || null,

                recording_url:
                    row.recording_url || null,

                created_at:
                    row.created_at,

                creator: {
                    id:
                        row.user_id,

                    username:
                        row.username,

                    name:
                        row.name ||
                        row.username,

                    profile_picture:
                        row.profile_picture || null
                }
            }
        });

    } catch (error) {

        console.error(
            "GET /api/recordings/:streamId:",
            error
        );

        return res.status(500).json({
            success: false,
            message: "Failed to load recording"
        });
    }
});


app.post(
    "/api/recordings",
    authenticateUser,
    async (req, res) => {

        try {

            if (!pool) {
                return res.status(503).json({
                    success: false,
                    message: "Database unavailable"
                });
            }

            const streamId =
                normalizeStreamId(
                    req.body.streamId ||
                    req.body.stream_id
                );

            const title =
                normalizeStreamTitle(
                    req.body.title
                );

            const thumbnail =
                req.body.thumbnail ||
                null;

            const recordingUrl =
                req.body.recording_url ||
                req.body.recordingUrl ||
                req.body.url ||
                null;

            if (!streamId) {
                return res.status(400).json({
                    success: false,
                    message: "Stream ID is required"
                });
            }

            const stream =
                await getStreamById(streamId);

            if (!stream) {
                return res.status(404).json({
                    success: false,
                    message: "Stream not found"
                });
            }

            if (
                Number(stream.user_id) !==
                Number(req.user.id)
            ) {
                return res.status(403).json({
                    success: false,
                    message: "You do not own this stream"
                });
            }

            const result =
                await pool.query(
                    `
                    INSERT INTO stream_recordings (
                        stream_id,
                        user_id,
                        title,
                        thumbnail,
                        recording_url
                    )
                    VALUES ($1, $2, $3, $4, $5)
                    RETURNING *
                    `,
                    [
                        streamId,
                        req.user.id,
                        title,
                        thumbnail,
                        recordingUrl
                    ]
                );

            return res.status(201).json({
                success: true,
                recording:
                    result.rows[0]
            });

        } catch (error) {

            console.error(
                "POST /api/recordings:",
                error
            );

            return res.status(500).json({
                success: false,
                message: "Failed to save recording"
            });
        }
    }
);


/* =========================================
   SUPPORT / GIFT COMPATIBILITY
========================================= */

app.post(
    "/api/streams/:id/support",
    authenticateUser,
    async (req, res) => {

        const streamId =
            normalizeStreamId(req.params.id);

        if (!streamId) {
            return res.status(400).json({
                success: false,
                message: "Invalid stream ID"
            });
        }

        return res.json({
            success: true,
            message: "Support received"
        });
    }
);
/* =========================================
   SOCKET.IO STREAM ROOMS
========================================= */

function joinStreamRoom(socket, streamId) {

    streamId =
        normalizeStreamId(streamId);

    if (!streamId) {
        return false;
    }

    /* Leave previous stream first */

    if (
        socket.data &&
        socket.data.streamId &&
        socket.data.streamId !== streamId
    ) {
        leaveStreamRoom(socket);
    }

    const room =
        getStreamRoom(streamId);

    socket.join(room);

    socket.data.streamId =
        streamId;

    socket.data.streamRoom =
        room;

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

    /* Prevent the same socket
       from being counted twice */

    const alreadyJoined =
        viewers.has(socket.id);

    if (!alreadyJoined) {

        viewers.add(socket.id);

        streamViewerCounts.set(
            streamId,
            viewers.size
        );
    }

    const viewerCount =
        getViewerCount(streamId);

    syncStreamViewerCount(
        streamId
    );

    io.to(room).emit(
        "viewer-count",
        {
            streamId,
            count: viewerCount,
            viewer_count: viewerCount
        }
    );

    socket.emit(
        "viewer-count",
        {
            streamId,
            count: viewerCount,
            viewer_count: viewerCount
        }
    );

    return true;
}


function leaveStreamRoom(socket) {

    if (
        !socket.data ||
        !socket.data.streamId
    ) {
        return;
    }

    const streamId =
        socket.data.streamId;

    const room =
        socket.data.streamRoom ||
        getStreamRoom(streamId);

    const viewers =
        streamRooms.get(streamId);

    if (viewers) {

        viewers.delete(
            socket.id
        );

        if (viewers.size === 0) {

            streamRooms.delete(
                streamId
            );

            streamViewerCounts.delete(
                streamId
            );

        } else {

            streamViewerCounts.set(
                streamId,
                viewers.size
            );
        }
    }

    socket.leave(room);

    socket.data.streamId =
        null;

    socket.data.streamRoom =
        null;

    const viewerCount =
        getViewerCount(streamId);

    syncStreamViewerCount(
        streamId
    );

    io.to(room).emit(
        "viewer-count",
        {
            streamId,
            count: viewerCount,
            viewer_count: viewerCount
        }
    );
}


async function sendChatHistory(
    socket,
    streamId
) {

    try {

        streamId =
            normalizeStreamId(streamId);

        if (!streamId) {
            return;
        }

        const messages =
            await getChatHistory(
                streamId
            );

        socket.emit(
            "chat-history",
            {
                streamId,
                messages
            }
        );

    } catch (error) {

        console.error(
            "Socket chat history error:",
            error
        );

        socket.emit(
            "chat-error",
            {
                message:
                    "Failed to load chat history"
            }
        );
    }
}


async function saveSocketChatMessage(
    socket,
    streamId,
    message
) {

    try {

        streamId =
            normalizeStreamId(streamId);

        const cleanMessage =
            String(
                message || ""
            ).trim();

        if (!streamId) {
            return;
        }

        if (!cleanMessage) {
            return;
        }

        if (cleanMessage.length > 500) {
            socket.emit(
                "chat-error",
                {
                    message:
                        "Message is too long"
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
                "chat-error",
                {
                    message:
                        "Stream not found"
                }
            );

            return;
        }

        let userId = null;
        let username = "User";

        if (socket.data.user) {

            userId =
                socket.data.user.id;

            username =
                socket.data.user.username ||
                "User";

        } else {

            /* If the socket was authenticated
               but user data is stored directly */

            userId =
                socket.data.userId ||
                null;

            username =
                socket.data.username ||
                "User";
        }

        const saved =
            await saveChatMessage(
                streamId,
                userId,
                username,
                cleanMessage
            );

        const room =
            getStreamRoom(streamId);

        /*
         * IMPORTANT:
         * Broadcast to EVERY socket inside
         * this stream's room.
         *
         * This is what makes chat work
         * across different phones/devices.
         */

        io.to(room).emit(
            "chat-message",
            saved
        );

        return saved;

    } catch (error) {

        console.error(
            "Socket send chat error:",
            error
        );

        socket.emit(
            "chat-error",
            {
                message:
                    "Failed to send message"
            }
        );

        return null;
    }
}


/* =========================================
   SOCKET CONNECTION
========================================= */

io.on("connection", (socket) => {

    console.log(
        "[Canvas Socket] Connected:",
        socket.id
    );


    /* -----------------------------------------
       SOCKET AUTHENTICATION
    ----------------------------------------- */

    socket.on(
        "authenticate",
        async (data = {}) => {

            try {

                const token =
                    data.token ||
                    data.authToken ||
                    data.accessToken;

                if (!token) {

                    socket.emit(
                        "authenticated",
                        {
                            success: false
                        }
                    );

                    return;
                }

                const user =
                    await authenticateUserToken(
                        token
                    );

                if (!user) {

                    socket.emit(
                        "authenticated",
                        {
                            success: false
                        }
                    );

                    return;
                }

                socket.data.user =
                    user;

                socket.data.userId =
                    user.id;

                socket.data.username =
                    user.username;

                socket.emit(
                    "authenticated",
                    {
                        success: true,

                        user: {
                            id: user.id,
                            username:
                                user.username,
                            email:
                                user.email
                        }
                    }
                );

            } catch (error) {

                console.error(
                    "Socket authentication error:",
                    error
                );

                socket.emit(
                    "authenticated",
                    {
                        success: false
                    }
                );
            }
        }
    );


    /* -----------------------------------------
       JOIN STREAM
    ----------------------------------------- */

    socket.on(
        "join-stream",
        async (data = {}) => {

            try {

                const streamId =
                    normalizeStreamId(
                        data.streamId ||
                        data.stream_id ||
                        data.id
                    );

                if (!streamId) {

                    socket.emit(
                        "stream-error",
                        {
                            message:
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
                            message:
                                "Stream not found"
                        }
                    );

                    return;
                }

                joinStreamRoom(
                    socket,
                    streamId
                );

                await sendChatHistory(
                    socket,
                    streamId
                );

                socket.emit(
                    "stream-joined",
                    {
                        streamId,

                        room:
                            getStreamRoom(
                                streamId
                            ),

                        viewer_count:
                            getViewerCount(
                                streamId
                            )
                    }
                );

            } catch (error) {

                console.error(
                    "Socket join-stream error:",
                    error
                );

                socket.emit(
                    "stream-error",
                    {
                        message:
                            "Failed to join stream"
                    }
                );
            }
        }
    );


    /* -----------------------------------------
       LEAVE STREAM
    ----------------------------------------- */

    socket.on(
        "leave-stream",
        () => {

            leaveStreamRoom(
                socket
            );
        }
    );


    /* -----------------------------------------
       SEND CHAT
    ----------------------------------------- */

    socket.on(
        "send-chat",
        async (data = {}) => {

            const streamId =
                data.streamId ||
                data.stream_id ||
                socket.data.streamId;

            const message =
                data.message ||
                data.text ||
                "";

            /*
             * Only allow chat through the room
             * the socket actually joined.
             */

            if (
                socket.data.streamId &&
                normalizeStreamId(streamId) !==
                normalizeStreamId(
                    socket.data.streamId
                )
            ) {

                socket.emit(
                    "chat-error",
                    {
                        message:
                            "You are not in this stream"
                    }
                );

                return;
            }

            await saveSocketChatMessage(
                socket,
                streamId,
                message
            );
        }
    );


    /* -----------------------------------------
       GET CHAT HISTORY
    ----------------------------------------- */

    socket.on(
        "get-chat-history",
        async (data = {}) => {

            const streamId =
                data.streamId ||
                data.stream_id ||
                socket.data.streamId;

            await sendChatHistory(
                socket,
                streamId
            );
        }
    );


    /* -----------------------------------------
       GET VIEWER COUNT
    ----------------------------------------- */

    socket.on(
        "get-viewer-count",
        (data = {}) => {

            const streamId =
                normalizeStreamId(
                    data.streamId ||
                    data.stream_id ||
                    socket.data.streamId
                );

            if (!streamId) {
                return;
            }

            const count =
                getViewerCount(
                    streamId
                );

            socket.emit(
                "viewer-count",
                {
                    streamId,
                    count,
                    viewer_count:
                        count
                }
            );
        }
    );


    /* -----------------------------------------
       FOLLOW SYNC
    ----------------------------------------- */

    socket.on(
        "sync-follow",
        async (data = {}) => {

            try {

                if (!pool) {
                    return;
                }

                if (!socket.data.user) {
                    return;
                }

                const targetId =
                    Number(
                        data.userId ||
                        data.user_id ||
                        data.targetUserId
                    );

                if (!Number.isInteger(targetId)) {
                    return;
                }

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
                            socket.data.user.id,
                            targetId
                        ]
                    );

                socket.emit(
                    "follow-status",
                    {
                        userId:
                            targetId,

                        following:
                            result.rows.length > 0,

                        isFollowing:
                            result.rows.length > 0
                    }
                );

            } catch (error) {

                console.error(
                    "Socket follow sync error:",
                    error
                );
            }
        }
    );


    /* -----------------------------------------
       DISCONNECT
    ----------------------------------------- */

    socket.on(
        "disconnect",
        () => {

            console.log(
                "[Canvas Socket] Disconnected:",
                socket.id
            );

            leaveStreamRoom(
                socket
            );
        }
    );
});


/* =========================================
   HEALTH
========================================= */

app.get("/health", async (req, res) => {

    try {

        if (!pool) {

            return res.status(503).json({
                success: false,
                status: "database_unavailable"
            });
        }

        await pool.query(
            "SELECT 1"
        );

        return res.json({
            success: true,
            status: "ok",
            database: "connected"
        });

    } catch (error) {

        console.error(
            "GET /health:",
            error
        );

        return res.status(503).json({
            success: false,
            status: "database_error"
        });
    }
});


app.get("/api/health", async (req, res) => {

    try {

        if (!pool) {

            return res.status(503).json({
                success: false,
                status: "database_unavailable"
            });
        }

        await pool.query(
            "SELECT 1"
        );

        return res.json({
            success: true,
            status: "ok",
            database: "connected"
        });

    } catch (error) {

        console.error(
            "GET /api/health:",
            error
        );

        return res.status(503).json({
            success: false,
            status: "database_error"
        });
    }
});


/* =========================================
   404 HANDLER
========================================= */

app.use((req, res) => {

    return res.status(404).json({
        success: false,
        message: "Route not found",
        path: req.originalUrl
    });
});


/* =========================================
   GLOBAL ERROR HANDLER
========================================= */

app.use((error, req, res, next) => {

    console.error(
        "[Canvas Server Error]",
        error
    );

    if (res.headersSent) {
        return next(error);
    }

    return res.status(500).json({
        success: false,
        message: "Internal server error"
    });
});


/* =========================================
   DATABASE INITIALIZATION
========================================= */

(async () => {

    try {

        if (pool) {

            await initializeDatabase();

            await ensureFollowTable();

            await ensureChatTable();

            await ensureRecordingsTable();

            console.log(
                "[Canvas] Database initialized successfully"
            );

        } else {

            console.warn(
                "[Canvas] No database connection configured"
            );
        }

    } catch (error) {

        console.error(
            "[Canvas] Database initialization failed:",
            error
        );

        /*
         * Do not immediately terminate the server.
         * Render can still start the HTTP/socket server,
         * and the database can be inspected/fixed separately.
         */
    }

})();


/* =========================================
   SERVER START
========================================= */

httpServer.listen(
    PORT,
    "0.0.0.0",
    () => {

        console.log(
            `[Canvas] Server running on port ${PORT}`
        );

        console.log(
            `[Canvas] Socket.IO ready`
        );
    }
);


/* =========================================
   GRACEFUL SHUTDOWN
========================================= */

async function shutdown(signal) {

    console.log(
        `[Canvas] ${signal} received. Shutting down...`
    );

    try {

        await new Promise(resolve => {

            httpServer.close(() => {
                resolve();
            });

        });

    } catch (error) {

        console.error(
            "[Canvas] HTTP shutdown error:",
            error
        );
    }

    try {

        if (pool) {
            await pool.end();
        }

    } catch (error) {

        console.error(
            "[Canvas] Database shutdown error:",
            error
        );
    }

    process.exit(0);
}


process.on(
    "SIGTERM",
    () => shutdown("SIGTERM")
);

process.on(
    "SIGINT",
    () => shutdown("SIGINT")
);
  
