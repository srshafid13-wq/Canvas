const express = require("express");
const { Pool } = require("pg");
const crypto = require("crypto");
const http = require("http");
const { Server } = require("socket.io");

const app = express();
const httpServer = http.createServer(app);

const PORT =
    process.env.PORT || 3000;


/* =========================================================
   SOCKET.IO
========================================================= */

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

            pingTimeout: 20000,
            pingInterval: 25000,

            connectionStateRecovery: {
                maxDisconnectionDuration: 2 * 60 * 1000,
                skipMiddlewares: true
            }
        }
    );


/* =========================================================
   EXPRESS
========================================================= */

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


/* =========================================================
   BASIC CORS
========================================================= */

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

            return res.sendStatus(204);

        }

        next();

    }
);


/* =========================================================
   DATABASE
========================================================= */

let pool = null;


const DATABASE_URL =
    process.env.canvas_db_r13t ||
    process.env.DATABASE_URL ||
    process.env.POSTGRES_URL ||
    "";


if (DATABASE_URL) {

    pool =
        new Pool({
            connectionString:
                DATABASE_URL,

            ssl:
                process.env.NODE_ENV === "production"
                    ? {
                        rejectUnauthorized: false
                    }
                    : false,

            max: 10,

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


/* =========================================================
   AUTH / SESSION HELPERS
========================================================= */

function normalizeEmail(
    email
) {

    return String(
        email || ""
    )
    .trim()
    .toLowerCase();

}


function cleanUsername(
    username
) {

    return String(
        username || ""
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


/* =========================================================
   SIGNUP VERIFICATION CODES
========================================================= */

const signupVerificationCodes =
    new Map();


/* =========================================================
   STREAM VIEWER STATE
   Lightweight in-memory state only.
   Chat itself is stored permanently in PostgreSQL.
========================================================= */

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


function getViewerCount(
    streamId
) {

    return (
        streamViewerCounts.get(
            String(streamId)
        ) || 0
    );

}


function addViewer(
    streamId
) {

    const id =
        String(streamId);

    const current =
        getViewerCount(id);

    const next =
        current + 1;

    streamViewerCounts.set(
        id,
        next
    );

    return next;

}


function removeViewer(
    streamId
) {

    const id =
        String(streamId);

    const current =
        getViewerCount(id);

    const next =
        Math.max(
            0,
            current - 1
        );

    if (next === 0) {

        streamViewerCounts.delete(
            id
        );

    } else {

        streamViewerCounts.set(
            id,
            next
        );

    }

    return next;

}


/* =========================================================
   AUTHENTICATION MIDDLEWARE
========================================================= */

async function authenticateUser(
    req,
    res,
    next
) {

    try {

        if (!pool) {

            return res.status(503).json({
                success: false,
                message:
                    "Database is not configured"
            });

        }


        const authorization =
            String(
                req.headers.authorization ||
                ""
            );


        if (
            !authorization.startsWith(
                "Bearer "
            )
        ) {

            return res.status(401).json({
                success: false,
                message:
                    "Authentication required"
            });

        }


        const token =
            authorization
                .slice(7)
                .trim();


        if (!token) {

            return res.status(401).json({
                success: false,
                message:
                    "Authentication required"
            });

        }


        const tokenHash =
            hashToken(token);


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
                JOIN users u
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

            return res.status(401).json({
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

        res.status(500).json({
            success: false,
            message:
                "Authentication failed"
        });

    }

}


/* =========================================================
   OPTIONAL AUTHENTICATION
========================================================= */

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


        const authorization =
            String(
                req.headers.authorization ||
                ""
            );


        if (
            !authorization.startsWith(
                "Bearer "
            )
        ) {

            return next();

        }


        const token =
            authorization
                .slice(7)
                .trim();


        if (!token) {

            return next();

        }


        const tokenHash =
            hashToken(token);


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
                JOIN users u
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

        next();

    }

}


/* =========================================================
   DATABASE INITIALIZATION
========================================================= */

async function initializeDatabase() {

    if (!pool) {

        console.log(
            "Database is not configured."
        );

        return;

    }


    const client =
        await pool.connect();


    try {

        await client.query(
            "BEGIN"
        );


        /* USERS */

        await client.query(
            `
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            `
        );


        /* PROFILES */

        await client.query(
            `
            CREATE TABLE IF NOT EXISTS profiles (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL UNIQUE
                    REFERENCES users(id)
                    ON DELETE CASCADE,
                bio TEXT DEFAULT '',
                profile_picture TEXT DEFAULT '',
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            `
        );


        /* SESSIONS */

        await client.query(
            `
            CREATE TABLE IF NOT EXISTS sessions (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL
                    REFERENCES users(id)
                    ON DELETE CASCADE,
                token_hash TEXT NOT NULL UNIQUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL
            )
            `
        );


        await client.query(
            `
            CREATE INDEX IF NOT EXISTS
            idx_sessions_token_hash
            ON sessions(token_hash)
            `
        );


        await client.query(
            `
            CREATE INDEX IF NOT EXISTS
            idx_sessions_user_id
            ON sessions(user_id)
            `
        );


        await client.query(
            "COMMIT"
        );


        console.log(
            "Database initialized successfully."
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

}


/* =========================================================
   FOLLOW TABLE
========================================================= */

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
        idx_follows_following_id
        ON follows(following_id)
        `
    );


    await pool.query(
        `
        CREATE INDEX IF NOT EXISTS
        idx_follows_follower_id
        ON follows(follower_id)
        `
    );

}


/* =========================================================
   CHAT TABLE
========================================================= */

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

            username TEXT NOT NULL,

            message TEXT NOT NULL,

            created_at TIMESTAMP
                DEFAULT CURRENT_TIMESTAMP
        )
        `
    );


    await pool.query(
        `
        CREATE INDEX IF NOT EXISTS
        idx_chat_messages_stream_created
        ON chat_messages(
            stream_id,
            created_at,
            id
        )
        `
    );

}


/* =========================================================
   RECORDINGS TABLE
========================================================= */

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

            title TEXT DEFAULT '',

            thumbnail TEXT DEFAULT '',

            recording_url TEXT DEFAULT '',

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

  }
/* =========================================================
   STREAM / CHAT HELPERS
========================================================= */

function normalizeStreamId(
    streamId
) {

    return String(
        streamId || ""
    )
    .trim()
    .slice(
        0,
        200
    );

}


function normalizeChatMessage(
    message
) {

    return String(
        message || ""
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
        id: row.id,
        streamId:
            String(
                row.stream_id
            ),
        userId:
            row.user_id,
        username:
            row.username,
        message:
            row.message,
        createdAt:
            row.created_at
    };

}


/* =========================================================
   FOLLOW HELPERS
========================================================= */

async function getFollowCounts(
    userId
) {

    if (!pool) {

        return {
            followers: 0,
            following: 0
        };

    }


    const followersResult =
        await pool.query(
            `
            SELECT COUNT(*)::INTEGER AS count
            FROM follows
            WHERE following_id = $1
            `,
            [
                userId
            ]
        );


    const followingResult =
        await pool.query(
            `
            SELECT COUNT(*)::INTEGER AS count
            FROM follows
            WHERE follower_id = $1
            `,
            [
                userId
            ]
        );


    return {
        followers:
            Number(
                followersResult.rows[0]?.count ||
                0
            ),

        following:
            Number(
                followingResult.rows[0]?.count ||
                0
            )
    };

}


/* =========================================================
   CHAT HISTORY
========================================================= */

app.get(
    "/api/streams/:id/chat",
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


            /*
             * Load the most recent messages first
             * so an extremely large chat history
             * does not slow down Watch.
             */

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
                    FROM (
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
                            created_at DESC,
                            id DESC
                        LIMIT 100
                    ) recent
                    ORDER BY
                        created_at ASC,
                        id ASC
                    `,
                    [
                        streamId
                    ]
                );


            const messages =
                result.rows.map(
                    formatChatMessage
                );


            res.json({
                success: true,
                streamId,
                messages
            });


        } catch (error) {

            console.error(
                "GET stream chat error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to load chat"
            });

        }

    }
);


/* =========================================================
   SEND CHAT MESSAGE
========================================================= */

app.post(
    "/api/streams/:id/chat",
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


            const message =
                normalizeChatMessage(
                    req.body?.message ||
                    req.body?.text
                );


            if (!streamId) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Stream ID is required"
                });

            }


            if (!message) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Message cannot be empty"
                });

            }


            if (!req.user) {

                return res.status(401).json({
                    success: false,
                    message:
                        "Authentication required"
                });

            }


            const username =
                String(
                    req.user.username ||
                    req.user.name ||
                    "User"
                )
                .trim()
                .slice(
                    0,
                    80
                );


            /*
             * IMPORTANT:
             * Save first, broadcast second.
             *
             * This guarantees that if a viewer leaves
             * Canvas and comes back later, the message
             * is still available from PostgreSQL.
             */

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
                        streamId,
                        req.userId,
                        username,
                        message
                    ]
                );


            const chatMessage =
                formatChatMessage(
                    result.rows[0]
                );


            /*
             * Broadcast to EVERYONE currently
             * watching this stream.
             */

            io
                .to(
                    getStreamRoom(
                        streamId
                    )
                )
                .emit(
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
                "POST stream chat error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to send chat message"
            });

        }

    }
);


/* =========================================================
   FOLLOW STATUS
========================================================= */

app.get(
    "/api/follow/status",
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


            const targetId =
                Number(
                    req.query.userId ||
                    req.query.followingId ||
                    req.query.creatorId
                );


            if (
                !Number.isInteger(
                    targetId
                ) ||
                targetId <= 0
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Valid user ID is required"
                });

            }


            let following = false;


            if (req.userId) {

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
                            req.userId,
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
                isFollowing:
                    following,
                followers:
                    counts.followers,
                followingCount:
                    counts.following
            });


        } catch (error) {

            console.error(
                "Follow status error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to load follow status"
            });

        }

    }
);


/* =========================================================
   FOLLOW / UNFOLLOW
========================================================= */

app.post(
    "/api/follow",
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


            const targetId =
                Number(
                    req.body?.followingId ||
                    req.body?.userId ||
                    req.body?.creatorId
                );


            if (
                !Number.isInteger(
                    targetId
                ) ||
                targetId <= 0
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Valid user ID is required"
                });

            }


            if (
                Number(req.userId) ===
                targetId
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        "You cannot follow yourself"
                });

            }


            /*
             * Optional action support.
             *
             * If Watch sends:
             *   action: "follow"
             *   action: "unfollow"
             *
             * we respect it.
             *
             * If no action is supplied,
             * the endpoint toggles automatically.
             */

            const action =
                String(
                    req.body?.action ||
                    ""
                )
                .trim()
                .toLowerCase();


            const existing =
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
                        req.userId,
                        targetId
                    ]
                );


            const alreadyFollowing =
                existing.rows.length > 0;


            let following;


            if (
                action === "unfollow"
            ) {

                if (
                    alreadyFollowing
                ) {

                    await pool.query(
                        `
                        DELETE FROM follows
                        WHERE
                            follower_id = $1
                            AND
                            following_id = $2
                        `,
                        [
                            req.userId,
                            targetId
                        ]
                    );

                }

                following = false;


            } else if (
                action === "follow"
            ) {

                if (
                    !alreadyFollowing
                ) {

                    await pool.query(
                        `
                        INSERT INTO follows
                            (
                                follower_id,
                                following_id,
                                created_at
                            )
                        VALUES
                            (
                                $1,
                                $2,
                                CURRENT_TIMESTAMP
                            )
                        ON CONFLICT
                            (
                                follower_id,
                                following_id
                            )
                        DO NOTHING
                        `,
                        [
                            req.userId,
                            targetId
                        ]
                    );

                }

                following = true;


            } else {

                /*
                 * Default behavior:
                 * toggle follow state.
                 */

                if (
                    alreadyFollowing
                ) {

                    await pool.query(
                        `
                        DELETE FROM follows
                        WHERE
                            follower_id = $1
                            AND
                            following_id = $2
                        `,
                        [
                            req.userId,
                            targetId
                        ]
                    );

                    following = false;

                } else {

                    await pool.query(
                        `
                        INSERT INTO follows
                            (
                                follower_id,
                                following_id,
                                created_at
                            )
                        VALUES
                            (
                                $1,
                                $2,
                                CURRENT_TIMESTAMP
                            )
                        ON CONFLICT
                            (
                                follower_id,
                                following_id
                            )
                        DO NOTHING
                        `,
                        [
                            req.userId,
                            targetId
                        ]
                    );

                    following = true;

                }

            }


            const counts =
                await getFollowCounts(
                    targetId
                );


            /*
             * Let other Canvas pages know that
             * this creator's follower count changed.
             *
             * This is lightweight and does not affect
             * the actual Watch video stream.
             */

            io.emit(
                "follow-updated",
                {
                    userId:
                        targetId,

                    followerId:
                        req.userId,

                    following,

                    followers:
                        counts.followers,

                    followingCount:
                        counts.following
                }
            );


            res.json({
                success: true,

                following,

                isFollowing:
                    following,

                followers:
                    counts.followers,

                followingCount:
                    counts.following,

                message:
                    following
                        ? "Following"
                        : "Unfollowed"
            });


        } catch (error) {

            console.error(
                "Follow error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to update follow"
            });

        }

    }
);


/* =========================================================
   FOLLOWER COUNT
========================================================= */

app.get(
    "/api/users/:id/followers",
    async (req, res) => {

        try {

            if (!pool) {

                return res.status(503).json({
                    success: false,
                    message:
                        "Database is not configured"
                });

            }


            const userId =
                Number(
                    req.params.id
                );


            if (
                !Number.isInteger(
                    userId
                ) ||
                userId <= 0
            ) {

                return res.status(400).json({
                    success: false,
                    message:
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
                        p.profile_picture
                    FROM follows f
                    JOIN users u
                        ON u.id = f.follower_id
                    LEFT JOIN profiles p
                        ON p.user_id = u.id
                    WHERE
                        f.following_id = $1
                    ORDER BY
                        f.created_at DESC
                    LIMIT 100
                    `,
                    [
                        userId
                        ]
                );


            res.json({
                success: true,
                users:
                    result.rows
            });


        } catch (error) {

            console.error(
                "Following list error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to load following"
            });

        }

    }
);
/* =========================================================
   SOCKET.IO STREAM ROOM MANAGEMENT
========================================================= */

/*
 * Keep Socket.IO room names consistent everywhere.
 * Every viewer of the same stream enters the same room.
 */

function joinStreamRoom(
    socket,
    streamId
) {

    const id =
        normalizeStreamId(
            streamId
        );


    if (!id) {
        return null;
    }


    const room =
        getStreamRoom(id);


    socket.join(room);


    /*
     * Track which stream this socket is watching.
     * This prevents incorrect viewer-count changes
     * when a socket disconnects or switches streams.
     */

    socket.data =
        socket.data || {};

    socket.data.streamId =
        id;

    socket.data.streamRoom =
        room;


    if (
        !streamRooms.has(id)
    ) {

        streamRooms.set(
            id,
            new Set()
        );

    }


    streamRooms
        .get(id)
        .add(socket.id);


    const viewerCount =
        addViewer(id);


    io.to(room).emit(
        "viewer-count",
        {
            streamId: id,
            count:
                viewerCount,
            viewers:
                viewerCount
        }
    );


    /*
     * Also send the count directly to the
     * newly connected viewer immediately.
     */

    socket.emit(
        "viewer-count",
        {
            streamId: id,
            count:
                viewerCount,
            viewers:
                viewerCount
        }
    );


    return {
        streamId: id,
        room,
        viewerCount
    };

}


/* =========================================================
   LEAVE STREAM ROOM
========================================================= */

function leaveStreamRoom(
    socket
) {

    if (
        !socket ||
        !socket.data
    ) {

        return;

    }


    const streamId =
        normalizeStreamId(
            socket.data.streamId
        );


    if (!streamId) {

        return;

    }


    const room =
        socket.data.streamRoom ||
        getStreamRoom(
            streamId
        );


    try {

        socket.leave(
            room
        );

    } catch (_) {}


    const viewers =
        streamRooms.get(
            streamId
        );


    if (viewers) {

        viewers.delete(
            socket.id
        );


        if (
            viewers.size === 0
        ) {

            streamRooms.delete(
                streamId
            );

        }

    }


    const viewerCount =
        removeViewer(
            streamId
        );


    io.to(room).emit(
        "viewer-count",
        {
            streamId,
            count:
                viewerCount,
            viewers:
                viewerCount
        }
    );


    delete socket.data.streamId;
    delete socket.data.streamRoom;

}


/* =========================================================
   LOAD CHAT HISTORY FOR SOCKET
========================================================= */

async function sendChatHistory(
    socket,
    streamId
) {

    if (!pool) {

        socket.emit(
            "chat-history",
            {
                streamId,
                messages: []
            }
        );

        return;

    }


    try {

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
                FROM (
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
                ) recent
                ORDER BY
                    created_at ASC,
                    id ASC
                `,
                [
                    streamId
                ]
            );


        const messages =
            result.rows.map(
                formatChatMessage
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
            "chat-history",
            {
                streamId,
                messages: []
            }
        );

    }

}


/* =========================================================
   SAVE SOCKET CHAT MESSAGE
========================================================= */

async function saveSocketChatMessage(
    socket,
    streamId,
    message
) {

    if (!pool) {

        socket.emit(
            "chat-error",
            {
                success: false,
                message:
                    "Database is not configured"
            }
        );

        return;

    }


    const cleanMessage =
        normalizeChatMessage(
            message
        );


    if (!cleanMessage) {

        socket.emit(
            "chat-error",
            {
                success: false,
                message:
                    "Message cannot be empty"
            }
        );

        return;

    }


    /*
     * Socket chat is optional compatibility support.
     *
     * Watch can continue using:
     *
     * POST /api/streams/:id/chat
     *
     * while other clients can use Socket.IO.
     *
     * Both paths save to the same PostgreSQL table.
     */

    let userId =
        socket.data.userId ||
        null;

    let username =
        socket.data.username ||
        "User";


    if (
        userId &&
        pool
    ) {

        try {

            const userResult =
                await pool.query(
                    `
                    SELECT
                        id,
                        username,
                        name
                    FROM users
                    WHERE id = $1
                    LIMIT 1
                    `,
                    [
                        userId
                    ]
                );


            if (
                userResult.rows.length
            ) {

                const user =
                    userResult.rows[0];

                userId =
                    user.id;

                username =
                    String(
                        user.username ||
                        user.name ||
                        "User"
                    )
                    .trim()
                    .slice(
                        0,
                        80
                    );

            }

        } catch (error) {

            console.error(
                "Socket user lookup error:",
                error
            );

        }

    }


    try {

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
                    streamId,
                    userId,
                    username,
                    cleanMessage
                ]
            );


        const chatMessage =
            formatChatMessage(
                result.rows[0]
            );


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
            "Socket chat save error:",
            error
        );


        socket.emit(
            "chat-error",
            {
                success: false,
                message:
                    "Unable to send chat message"
            }
        );

    }

}


/* =========================================================
   SOCKET.IO CONNECTION
========================================================= */

io.on(
    "connection",
    (socket) => {

        console.log(
            "Canvas Socket.IO connected:",
            socket.id
        );


        socket.data = {
            streamId: null,
            streamRoom: null,
            userId: null,
            username: null
        };


        /* ================================================
           AUTHENTICATE SOCKET
        ================================================ */

        socket.on(
            "authenticate",
            async (data = {}) => {

                try {

                    if (!pool) {

                        return;

                    }


                    const token =
                        String(
                            data.token ||
                            data.authToken ||
                            data.accessToken ||
                            ""
                        )
                        .trim();


                    if (!token) {

                        return;

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
                                u.email
                            FROM sessions s
                            JOIN users u
                                ON u.id = s.user_id
                            WHERE
                                s.token_hash = $1
                                AND
                                s.expires_at >
                                    CURRENT_TIMESTAMP
                            LIMIT 1
                            `,
                            [
                                tokenHash
                            ]
                        );


                    if (
                        !result.rows.length
                    ) {

                        socket.emit(
                            "authentication-error",
                            {
                                success: false,
                                message:
                                    "Invalid or expired session"
                            }
                        );

                        return;

                    }


                    const user =
                        result.rows[0];


                    socket.data.userId =
                        user.id;

                    socket.data.username =
                        String(
                            user.username ||
                            user.name ||
                            "User"
                        )
                        .trim()
                        .slice(
                            0,
                            80
                        );


                    socket.emit(
                        "authenticated",
                        {
                            success: true,

                            user: {
                                id:
                                    user.id,
                                name:
                                    user.name,
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

                }

            }
        );


        /* ================================================
           JOIN STREAM
        ================================================ */

        socket.on(
            "join-stream",
            async (data = {}) => {

                try {

                    /*
                     * If this socket was already watching
                     * another stream, remove it first.
                     */

                    if (
                        socket.data.streamId
                    ) {

                        const oldStream =
                            socket.data.streamId;


                        if (
                            oldStream !==
                            normalizeStreamId(
                                data.streamId ||
                                data.id
                            )
                        ) {

                            leaveStreamRoom(
                                socket
                            );

                        }

                    }


                    const streamId =
                        normalizeStreamId(
                            data.streamId ||
                            data.id ||
                            data.stream_id
                        );


                    if (!streamId) {

                        socket.emit(
                            "stream-error",
                            {
                                success: false,
                                message:
                                    "Stream ID is required"
                            }
                        );

                        return;

                    }


                    const joined =
                        joinStreamRoom(
                            socket,
                            streamId
                        );


                    if (!joined) {

                        return;

                    }


                    /*
                     * Send persistent chat history
                     * only to this viewer.
                     */

                    await sendChatHistory(
                        socket,
                        streamId
                    );


                    socket.emit(
                        "stream-joined",
                        {
                            success: true,

                            streamId,

                            room:
                                joined.room,

                            viewerCount:
                                joined.viewerCount,

                            viewers:
                                joined.viewerCount
                        }
                    );


                } catch (error) {

                    console.error(
                        "Join stream error:",
                        error
                    );


                    socket.emit(
                        "stream-error",
                        {
                            success: false,
                            message:
                                "Unable to join stream"
                        }
                    );

                }

            }
        );


        /* ================================================
           LEAVE STREAM
        ================================================ */

        socket.on(
            "leave-stream",
            () => {

                leaveStreamRoom(
                    socket
                );

            }
        );


        /* ================================================
           SOCKET CHAT
        ================================================ */

        socket.on(
            "send-chat",
            async (data = {}) => {

                try {

                    const streamId =
                        normalizeStreamId(
                            data.streamId ||
                            data.id ||
                            socket.data.streamId
                        );


                    if (!streamId) {

                        socket.emit(
                            "chat-error",
                            {
                                success: false,
                                message:
                                    "Stream ID is required"
                            }
                        );

                        return;

                    }


                    /*
                     * Do not allow a socket to send
                     * into a stream it hasn't joined.
                     */

                    if (
                        socket.data.streamId !==
                        streamId
                    ) {

                        socket.emit(
                            "chat-error",
                            {
                                success: false,
                                message:
                                    "Join the stream before chatting"
                            }
                        );

                        return;

                    }


                    await saveSocketChatMessage(
                        socket,
                        streamId,
                        data.message ||
                        data.text
                    );


                } catch (error) {

                    console.error(
                        "Socket send-chat error:",
                        error
                    );

                }

            }
        );


        /* ================================================
           REQUEST CHAT HISTORY
        ================================================ */

        socket.on(
            "get-chat-history",
            async (data = {}) => {

                const streamId =
                    normalizeStreamId(
                        data.streamId ||
                        data.id ||
                        socket.data.streamId
                    );


                if (!streamId) {

                    return;

                }


                await sendChatHistory(
                    socket,
                    streamId
                );

            }
        );


        /* ================================================
           REQUEST VIEWER COUNT
        ================================================ */

        socket.on(
            "get-viewer-count",
            (data = {}) => {

                const streamId =
                    normalizeStreamId(
                        data.streamId ||
                        data.id ||
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
                        viewers:
                            count
                    }
                );

            }
        );


        /* ================================================
           DISCONNECT
        ===============/*
      socket.on(
            "disconnect",
            (reason) => {

                /*
                 * Clean up only this socket.
                 * No database chat history is deleted.
                 */

                leaveStreamRoom(
                    socket
                );


                console.log(
                    "Canvas Socket.IO disconnected:",
                    socket.id,
                    reason
                );

            }
        );

    }
);
/* =========================================================
   SIGNUP - SEND VERIFICATION CODE
========================================================= */

app.post(
    "/api/signup/send-code",
    async (req, res) => {

        try {

            if (!pool) {

                return res.status(503).json({
                    success: false,
                    message:
                        "Database is not configured"
                });

            }


            const email =
                normalizeEmail(
                    req.body?.email
                );


            if (!email) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Email is required"
                });

            }


            const existing =
                await pool.query(
                    `
                    SELECT
                        id
                    FROM users
                    WHERE
                        LOWER(email) = LOWER($1)
                    LIMIT 1
                    `,
                    [
                        email
                    ]
                );


            if (
                existing.rows.length
            ) {

                return res.status(409).json({
                    success: false,
                    message:
                        "Email already exists"
                });

            }


            /*
             * Generate a six-digit verification code.
             */

            const code =
                String(
                    crypto.randomInt(
                        100000,
                        1000000
                    )
                );


            const expiresAt =
                Date.now() +
                (
                    10 * 60 * 1000
                );


            signupVerificationCodes.set(
                email,
                {
                    code,
                    expiresAt
                }
            );


            /*
             * Resend configuration.
             *
             * Keep the existing environment-variable
             * compatibility so the current Canvas setup
             * continues working.
             */

            const resendApiKey =
                process.env.RESEND_API_KEY ||
                process.env.resendApiKey ||
                process.env.RESEND_KEY ||
                "";


            const resendFromEmail =
                process.env.RESEND_FROM_EMAIL ||
                process.env.resendFromEmail ||
                "";


            if (
                !resendApiKey ||
                !resendFromEmail
            ) {

                console.error(
                    "Resend configuration is missing."
                );


                signupVerificationCodes.delete(
                    email
                );


                return res.status(500).json({
                    success: false,
                    message:
                        "Email service is not configured"
                });

            }


            /*
             * Send verification email through Resend.
             *
             * Using fetch keeps the server lightweight
             * and avoids adding another dependency.
             */

            const response =
                await fetch(
                    "https://api.resend.com/emails",
                    {
                        method: "POST",

                        headers: {
                            "Authorization":
                                `Bearer ${resendApiKey}`,

                            "Content-Type":
                                "application/json"
                        },

                        body:
                            JSON.stringify({
                                from:
                                    resendFromEmail,

                                to: [
                                    email
                                ],

                                subject:
                                    "Canvas verification code",

                                html:
                                    `
                                    <div style="
                                        font-family:Arial,sans-serif;
                                        max-width:600px;
                                        margin:auto;
                                        padding:24px;
                                    ">

                                        <h2>
                                            Canvas
                                        </h2>

                                        <p>
                                            Your Canvas
                                            verification code is:
                                        </p>

                                        <div style="
                                            font-size:32px;
                                            font-weight:bold;
                                            letter-spacing:8px;
                                            padding:18px 0;
                                        ">
                                            ${code}
                                        </div>

                                        <p>
                                            This code expires
                                            in 10 minutes.
                                        </p>

                                        <p>
                                            If you did not request
                                            this code, you can
                                            safely ignore this email.
                                        </p>

                                    </div>
                                    `
                            })
                    }
                );


            let responseData = null;


            try {

                responseData =
                    await response.json();

            } catch (_) {

                responseData = null;

            }


            if (
                !response.ok
            ) {

                console.error(
                    "Resend API error:",
                    responseData
                );


                signupVerificationCodes.delete(
                    email
                );


                return res.status(500).json({
                    success: false,
                    message:
                        "Unable to send verification email"
                });

            }


            res.json({
                success: true,

                message:
                    "Verification code sent",

                email
            });


        } catch (error) {

            console.error(
                "Signup send-code error:",
                error
            );


            res.status(500).json({
                success: false,
                message:
                    "Unable to send verification code"
            });

        }

    }
);


/* =========================================================
   SIGNUP - VERIFY CODE
========================================================= */

app.post(
    "/api/signup/verify-code",
    async (req, res) => {

        try {

            const email =
                normalizeEmail(
                    req.body?.email
                );


            const code =
                String(
                    req.body?.code ||
                    req.body?.verificationCode ||
                    req.body?.verification_code ||
                    ""
                )
                .trim();


            if (
                !email ||
                !code
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Email and verification code are required"
                });

            }


            const saved =
                signupVerificationCodes.get(
                    email
                );


            if (!saved) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Verification code not found or expired"
                });

            }


            if (
                Date.now() >
                saved.expiresAt
            ) {

                signupVerificationCodes.delete(
                    email
                );


                return res.status(400).json({
                    success: false,
                    message:
                        "Verification code expired"
                });

            }


            if (
                saved.code !== code
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Invalid verification code"
                });

            }


            signupVerificationCodes.delete(
                email
            );


            res.json({
                success: true,
                verified: true,
                email
            });


        } catch (error) {

            console.error(
                "Signup verify-code error:",
                error
            );


            res.status(500).json({
                success: false,
                message:
                    "Verification failed"
            });

        }

    }
);


/* =========================================================
   SIGNUP - VERIFIED ACCOUNT CREATION
========================================================= */

app.post(
    "/api/signup/verified",
    async (req, res) => {

        try {

            if (!pool) {

                return res.status(503).json({
                    success: false,
                    message:
                        "Database is not configured"
                });

            }


            const name =
                String(
                    req.body?.name ||
                    req.body?.displayName ||
                    ""
                )
                .trim()
                .slice(
                    0,
                    100
                );


            const username =
                cleanUsername(
                    req.body?.username
                );


            const email =
                normalizeEmail(
                    req.body?.email
                );


            const password =
                String(
                    req.body?.password ||
                    ""
                );


            if (
                !name ||
                !username ||
                !email ||
                !password
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Name, username, email and password are required"
                });

            }


            if (
                password.length < 6
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Password must be at least 6 characters"
                });

            }


            const existing =
                await pool.query(
                    `
                    SELECT
                        id,
                        username,
                        email
                    FROM users
                    WHERE
                        LOWER(username) = LOWER($1)
                        OR
                        LOWER(email) = LOWER($2)
                    LIMIT 1
                    `,
                    [
                        username,
                        email
                    ]
                );


            if (
                existing.rows.length
            ) {

                const row =
                    existing.rows[0];


                if (
                    String(
                        row.username
                    )
                    .toLowerCase() ===
                    username.toLowerCase()
                ) {

                    return res.status(409).json({
                        success: false,
                        message:
                            "Username already exists"
                    });

                }


                return res.status(409).json({
                    success: false,
                    message:
                        "Email already exists"
                });

            }


            const passwordHash =
                hashPassword(
                    password
                );


            const client =
                await pool.connect();


            try {

                await client.query(
                    "BEGIN"
                );


                const userResult =
                    await client.query(
                        `
                        INSERT INTO users
                            (
                                name,
                                username,
                                email,
                                password_hash,
                                created_at
                            )
                        VALUES
                            ($1,$2,$3,$4,CURRENT_TIMESTAMP)
                        RETURNING
                            id,
                            name,
                            username,
                            email,
                            created_at
                        `,
                        [
                            name,
                            username,
                            email,
                            passwordHash
                        ]
                    );


                const user =
                    userResult.rows[0];


                await client.query(
                    `
                    INSERT INTO profiles
                        (
                            user_id,
                            bio,
                            profile_picture,
                            updated_at
                        )
                    VALUES
                        ($1,'','',CURRENT_TIMESTAMP)
                    ON CONFLICT (user_id)
                    DO NOTHING
                    `,
                    [
                        user.id
                    ]
                );


                await client.query(
                    "COMMIT"
                );


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
                            created_at,
                            expires_at
                        )
                    VALUES
                        (
                            $1,
                            $2,
                            CURRENT_TIMESTAMP,
                            CURRENT_TIMESTAMP + INTERVAL '30 days'
                        )
                    `,
                    [
                        user.id,
                        tokenHash
                    ]
                );


                res.status(201).json({
                    success: true,

                    user,

                    token,

                    accessToken:
                        token,

                    authToken:
                        token,

                    message:
                        "Account created successfully"
                });


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


        } catch (error) {

            console.error(
                "Verified signup error:",
                error
            );


            res.status(500).json({
                success: false,
                message:
                    "Unable to create account"
            });

        }

    }
);


/* =========================================================
   STANDARD LOGIN
========================================================= */

app.post(
    "/api/login",
    async (req, res) => {

        try {

            if (!pool) {

                return res.status(503).json({
                    success: false,
                    message:
                        "Database is not configured"
                });

            }


            const identifier =
                String(
                    req.body?.email ||
                    req.body?.username ||
                    req.body?.identifier ||
                    ""
                )
                .trim()
                .toLowerCase();


            const password =
                String(
                    req.body?.password ||
                    ""
                );


            if (
                !identifier ||
                !password
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Email/username and password are required"
                });

            }


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
                        LOWER(email) = LOWER($1)
                        OR
                        LOWER(username) = LOWER($1)
                    LIMIT 1
                    `,
                    [
                        identifier
                    ]
                );


            if (
                !result.rows.length
            ) {

                return res.status(401).json({
                    success: false,
                    message:
                        "Invalid email/username or password"
                });

            }


            const user =
                result.rows[0];


            const valid =
                hashPassword(
                    password
                ) ===
                user.password_hash;


            if (!valid) {

                return res.status(401).json({
                    success: false,
                    message:
                        "Invalid email/username or password"
                });

            }


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
                        created_at,
                        expires_at
                    )
                VALUES
                    (
                        $1,
                        $2,
                        CURRENT_TIMESTAMP,
                        CURRENT_TIMESTAMP + INTERVAL '30 days'
                    )
                `,
                [
                    user.id,
                    tokenHash
                ]
            );


            delete user.password_hash;


            res.json({
              success: true,

                user,

                token,

                accessToken:
                    token,

                authToken:
                    token
            });


        } catch (error) {

            console.error(
                "POST /api/login error:",
                error
            );


            res.status(500).json({
                success: false,
                message:
                    "Login failed"
            });

        }

    }
);
/* =========================================================
   LOGIN COMPATIBILITY ALIAS
========================================================= */

app.post(
    "/api/auth/login",
    async (req, res) => {

        try {

            if (!pool) {

                return res.status(503).json({
                    success: false,
                    message:
                        "Database is not configured"
                });

            }


            const identifier =
                String(
                    req.body?.email ||
                    req.body?.username ||
                    req.body?.identifier ||
                    ""
                )
                .trim()
                .toLowerCase();


            const password =
                String(
                    req.body?.password ||
                    ""
                );


            if (
                !identifier ||
                !password
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Email/username and password are required"
                });

            }


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
                        LOWER(email) = LOWER($1)
                        OR
                        LOWER(username) = LOWER($1)
                    LIMIT 1
                    `,
                    [
                        identifier
                    ]
                );


            if (
                !result.rows.length
            ) {

                return res.status(401).json({
                    success: false,
                    message:
                        "Invalid email/username or password"
                });

            }


            const user =
                result.rows[0];


            const valid =
                hashPassword(
                    password
                ) ===
                user.password_hash;


            if (!valid) {

                return res.status(401).json({
                    success: false,
                    message:
                        "Invalid email/username or password"
                });

            }


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
                        created_at,
                        expires_at
                    )
                VALUES
                    (
                        $1,
                        $2,
                        CURRENT_TIMESTAMP,
                        CURRENT_TIMESTAMP + INTERVAL '30 days'
                    )
                `,
                [
                    user.id,
                    tokenHash
                ]
            );


            delete user.password_hash;


            res.json({
                success: true,

                user,

                token,

                accessToken:
                    token,

                authToken:
                    token
            });


        } catch (error) {

            console.error(
                "POST /api/auth/login error:",
                error
            );


            res.status(500).json({
                success: false,
                message:
                    "Login failed"
            });

        }

    }
);


/* =========================================================
   CURRENT USER
========================================================= */

app.get(
    "/api/me",
    authenticateUser,
    async (req, res) => {

        try {

            if (!req.user) {

                return res.status(401).json({
                    success: false,
                    message:
                        "Authentication required"
                });

            }


            let profile = {
                bio: "",
                profile_picture: ""
            };


            if (pool) {

                try {

                    const result =
                        await pool.query(
                            `
                            SELECT
                                bio,
                                profile_picture,
                                updated_at
                            FROM profiles
                            WHERE
                                user_id = $1
                            LIMIT 1
                            `,
                            [
                                req.userId
                            ]
                        );


                    if (
                        result.rows.length
                    ) {

                        profile =
                            result.rows[0];

                    }

                } catch (error) {

                    console.error(
                        "Profile lookup in /api/me error:",
                        error
                    );

                }

            }


            res.json({
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
                        req.user.created_at,

                    bio:
                        profile.bio || "",

                    profile_picture:
                        profile.profile_picture || ""
                }
            });


        } catch (error) {

            console.error(
                "GET /api/me error:",
                error
            );


            res.status(500).json({
                success: false,
                message:
                    "Unable to load user"
            });

        }

    }
);


/* =========================================================
   GET PROFILE
========================================================= */

app.get(
    "/api/profile",
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


            const result =
                await pool.query(
                    `
                    SELECT
                        u.id,
                        u.name,
                        u.username,
                        u.email,
                        u.created_at,

                        p.bio,
                        p.profile_picture,
                        p.updated_at

                    FROM users u

                    LEFT JOIN profiles p
                        ON p.user_id = u.id

                    WHERE
                        u.id = $1

                    LIMIT 1
                    `,
                    [
                        req.userId
                    ]
                );


            if (
                !result.rows.length
            ) {

                return res.status(404).json({
                    success: false,
                    message:
                        "Profile not found"
                });

            }


            const user =
                result.rows[0];


            const counts =
                await getFollowCounts(
                    req.userId
                );


            res.json({
                success: true,

                profile: {
                    id:
                        user.id,

                    name:
                        user.name,

                    username:
                        user.username,

                    email:
                        user.email,

                    bio:
                        user.bio || "",

                    profile_picture:
                        user.profile_picture || "",

                    created_at:
                        user.created_at,

                    updated_at:
                        user.updated_at,

                    followers:
                        counts.followers,

                    following:
                        counts.following
                }
            });


        } catch (error) {

            console.error(
                "GET /api/profile error:",
                error
            );


            res.status(500).json({
                success: false,
                message:
                    "Unable to load profile"
            });

        }

    }
);


/* =========================================================
   GET PUBLIC PROFILE
========================================================= */

app.get(
    "/api/profile/:id",
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


            const userId =
                Number(
                    req.params.id
                );


            if (
                !Number.isInteger(
                    userId
                ) ||
                userId <= 0
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Invalid profile ID"
                });

            }


            const result =
                await pool.query(
                    `
                    SELECT
                        u.id,
                        u.name,
                        u.username,
                        u.created_at,

                        p.bio,
                        p.profile_picture,
                        p.updated_at

                    FROM users u

                    LEFT JOIN profiles p
                        ON p.user_id = u.id

                    WHERE
                        u.id = $1

                    LIMIT 1
                    `,
                    [
                        userId
                    ]
                );


            if (
                !result.rows.length
            ) {

                return res.status(404).json({
                    success: false,
                    message:
                        "Profile not found"
                });

            }


            const profile =
                result.rows[0];


            const counts =
                await getFollowCounts(
                    userId
                );


            let following = false;


            if (
                req.userId
            ) {

                const followResult =
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
                            req.userId,
                            userId
                        ]
                    );


                following =
                    followResult.rows.length > 0;

            }


            res.json({
                success: true,

                profile: {
                    id:
                        profile.id,

                    name:
                        profile.name,

                    username:
                        profile.username,

                    bio:
                        profile.bio || "",

                    profile_picture:
                        profile.profile_picture || "",

                    created_at:
                        profile.created_at,

                    updated_at:
                        profile.updated_at,

                    followers:
                        counts.followers,

                    following:
                        counts.following,

                    isFollowing:
                        following,

                    followingUser:
                        following
                }
            });


        } catch (error) {

            console.error(
                "GET public profile error:",
                error
            );


            res.status(500).json({
                success: false,
                message:
                    "Unable to load profile"
            });

        }

    }
);


/* =========================================================
   CREATE / UPDATE PROFILE
========================================================= */

app.put(
    "/api/profile",
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


            const name =
                String(
                    req.body?.name ||
                    req.body?.displayName ||
                    req.user?.name ||
                    ""
                )
                .trim()
                .slice(
                    0,
                    100
                );


            const username =
                cleanUsername(
                    req.body?.username ||
                    req.user?.username
                );


            const bio =
                String(
                    req.body?.bio ||
                    ""
                )
                .trim()
                .slice(
                    0,
                    500
                );


            const profilePicture =
                String(
                    req.body?.profile_picture ||
                    req.body?.profilePicture ||
                    req.body?.avatar ||
                    ""
                )
                .trim();


            if (
                !name ||
                !username
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Name and username are required"
                });

            }


            const usernameCheck =
                await pool.query(
                    `
                    SELECT
                        id
                    FROM users
                    WHERE
                        LOWER(username) = LOWER($1)
                        AND
                        id <> $2
                    LIMIT 1
                    `,
                    [
                        username,
                        req.userId
                    ]
                );


            if (
                usernameCheck.rows.length
            ) {

                return res.status(409).json({
                    success: false,
                    message:
                        "Username already exists"
                });

            }


            await pool.query(
                `
                UPDATE users
                SET
                    name = $1,
                    username = $2
                WHERE
                    id = $3
                `,
                [
                    name,
                    username,
                    req.userId
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
                ON CONFLICT (
                    user_id
                )
                DO UPDATE SET
                    bio =
                        EXCLUDED.bio,

                    profile_picture =
                        EXCLUDED.profile_picture,

                    updated_at =
                        CURRENT_TIMESTAMP
                `,
                [
                    req.userId,
                    bio,
                    profilePicture
                ]
            );


            const result =
                await pool.query(
                    `
                    SELECT
                        u.id,
                        u.name,
                        u.username,
                        u.email,
                        u.created_at,

                        p.bio,
                        p.profile_picture,
                        p.updated_at

                    FROM users u

                    LEFT JOIN profiles p
                        ON p.user_id = u.id

                    WHERE
                        u.id = $1

                    LIMIT 1
                    `,
                    [
                        req.userId
                    ]
                );


            const user =
                result.rows[0];


            const counts =
                await getFollowCounts(
                    req.userId
                );


            res.json({
                success: true,

                profile: {
                    id:
                        user.id,

                    name:
                        user.name,

                    username:
                        user.username,

                    email:
                        user.email,

                    bio:
                        user.bio || "",

                    profile_picture:
                        user.profile_picture || "",

                    created_at:
                        user.created_at,

                    updated_at:
                        user.updated_at,

                    followers:
                        counts.followers,

                    following:
                        counts.following
                }
            });


        } catch (error) {

            console.error(
                "PUT /api/profile error:",
                error
            );


            res.status(500).json({
                success: false,
                message:
                    "Unable to save profile"
            });

        }

    }
);


/* =========================================================
   DATABASE TEST
========================================================= */

app.get(
    "/api/database-test",
    async (req, res) => {

        try {

            if (!pool) {

                return res.status(503).json({
                    success: false,
                    database:
                        "not-configured"
                });

            }


            const result =
                await pool.query(
                    `
                    SELECT
                        CURRENT_TIMESTAMP
                        AS server_time
                    `
                );


            res.json({
                success: true,

                database:
                    "connected",

                serverTime:
                    result.rows[0]
                        ?.server_time || null
            });
          } catch (error) {

            console.error(
                "Database test error:",
                error
            );


            res.status(500).json({
                success: false,

                database:
                    "error",

                message:
                    "Database connection failed"
            });

        }

    }
);
/* =========================================================
   STREAM RECORDING / STREAM DATA ROUTES
========================================================= */

/*
 * These routes keep the existing Canvas stream/recording
 * functionality compatible while allowing Watch to load
 * stream information without touching the video itself.
 */


/* =========================================================
   GET RECORDINGS
========================================================= */

app.get(
    "/api/recordings",
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


            const limit =
                Math.min(
                    Math.max(
                        Number(
                            req.query.limit ||
                            50
                        ),
                        1
                    ),
                    100
                );


            const result =
                await pool.query(
                    `
                    SELECT
                        id,
                        stream_id,
                        user_id,
                        title,
                        thumbnail,
                        recording_url,
                        created_at
                    FROM stream_recordings
                    ORDER BY
                        created_at DESC,
                        id DESC
                    LIMIT $1
                    `,
                    [
                        limit
                    ]
                );


            res.json({
                success: true,

                recordings:
                    result.rows
            });


        } catch (error) {

            console.error(
                "GET /api/recordings error:",
                error
            );


            res.status(500).json({
                success: false,
                message:
                    "Unable to load recordings"
            });

        }

    }
);


/* =========================================================
   GET RECORDING BY STREAM ID
========================================================= */

app.get(
    "/api/recordings/:streamId",
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
                    req.params.streamId
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
                    SELECT
                        id,
                        stream_id,
                        user_id,
                        title,
                        thumbnail,
                        recording_url,
                        created_at
                    FROM stream_recordings
                    WHERE
                        stream_id = $1
                    ORDER BY
                        created_at DESC,
                        id DESC
                    LIMIT 1
                    `,
                    [
                        streamId
                    ]
                );


            if (
                !result.rows.length
            ) {

                return res.status(404).json({
                    success: false,
                    message:
                        "Recording not found"
                });

            }


            res.json({
                success: true,

                recording:
                    result.rows[0]
            });


        } catch (error) {

            console.error(
                "GET recording error:",
                error
            );


            res.status(500).json({
                success: false,
                message:
                    "Unable to load recording"
            });

        }

    }
);


/* =========================================================
   CREATE RECORDING
========================================================= */

app.post(
    "/api/recordings",
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
                    req.body?.streamId ||
                    req.body?.stream_id
                );


            const title =
                String(
                    req.body?.title ||
                    ""
                )
                .trim()
                .slice(
                    0,
                    200
                );


            const thumbnail =
                String(
                    req.body?.thumbnail ||
                    ""
                )
                .trim();


            const recordingUrl =
                String(
                    req.body?.recordingUrl ||
                    req.body?.recording_url ||
                    req.body?.url ||
                    ""
                )
                .trim();


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
                    INSERT INTO stream_recordings
                        (
                            stream_id,
                            user_id,
                            title,
                            thumbnail,
                            recording_url,
                            created_at
                        )
                    VALUES
                        (
                            $1,
                            $2,
                            $3,
                            $4,
                            $5,
                            CURRENT_TIMESTAMP
                        )
                    RETURNING
                        id,
                        stream_id,
                        user_id,
                        title,
                        thumbnail,
                        recording_url,
                        created_at
                    `,
                    [
                        streamId,
                        req.userId,
                        title,
                        thumbnail,
                        recordingUrl
                    ]
                );


            res.status(201).json({
                success: true,

                recording:
                    result.rows[0]
            });


        } catch (error) {

            console.error(
                "POST /api/recordings error:",
                error
            );


            res.status(500).json({
                success: false,
                message:
                    "Unable to create recording"
            });

        }

    }
);


/* =========================================================
   STREAM VIEWER COUNT API
========================================================= */

app.get(
    "/api/streams/:id/viewers",
    async (req, res) => {

        try {

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


            const count =
                getViewerCount(
                    streamId
                );


            res.json({
                success: true,

                streamId,

                count,

                viewers:
                    count
            });


        } catch (error) {

            console.error(
                "Viewer count error:",
                error
            );


            res.status(500).json({
                success: false,
                message:
                    "Unable to load viewer count"
            });

        }

    }
);


/* =========================================================
   STREAM SOCKET STATUS
========================================================= */

app.get(
    "/api/streams/:id/status",
    async (req, res) => {

        try {

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


            const count =
                getViewerCount(
                    streamId
                );


            const room =
                getStreamRoom(
                    streamId
                );


            const viewers =
                streamRooms.has(
                    streamId
                )
                    ? streamRooms
                        .get(streamId)
                        .size
                    : 0;


            res.json({
                success: true,

                streamId,

                room,

                viewers,

                count
            });


        } catch (error) {

            console.error(
                "Stream status error:",
                error
            );


            res.status(500).json({
                success: false,
                message:
                    "Unable to load stream status"
            });

        }

    }
);


/* =========================================================
   STREAM CHAT DELETE
========================================================= */

app.delete(
    "/api/streams/:id/chat/:messageId",
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
                    success: false,
                    message:
                        "Invalid stream or message ID"
                });

            }


            /*
             * Only the user who created the message
             * can remove their own message.
             */

            const result =
                await pool.query(
                    `
                    DELETE FROM chat_messages
                    WHERE
                        id = $1
                        AND
                        stream_id = $2
                        AND
                        user_id = $3
                    RETURNING
                        id,
                        stream_id
                    `,
                    [
                        messageId,
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
                        "Chat message not found"
                });

            }


            io.to(
                getStreamRoom(
                    streamId
                )
            ).emit(
                "chat-message-deleted",
                {
                    id:
                        messageId,

                    streamId
                }
            );


            res.json({
                success: true,

                message:
                    "Chat message deleted"
            });


        } catch (error) {

            console.error(
                "Delete chat message error:",
                error
            );


            res.status(500).json({
                success: false,
                message:
                    "Unable to delete chat message"
            });

        }

    }
);


/* =========================================================
   STREAM ROOM BROADCAST HELPER
========================================================= */

function broadcastStreamEvent(
    streamId,
    event,
    data = {}
) {

    const id =
        normalizeStreamId(
            streamId
        );


    if (!id) {
        return;
    }


    io.to(
        getStreamRoom(
            id
        )
    ).emit(
        event,
        {
            streamId: id,
            ...data
        }
    );

}


/* =========================================================
   LIVE STREAM ENDED EVENT
========================================================= */

app.post(
    "/api/streams/:id/end",
    optionalAuthenticateUser,
    async (req, res) => {

        try {

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
             * Notify every current viewer that the
             * stream has ended.
             *
             * Existing stream-management logic can
             * continue to handle its own database state.
             */

            broadcastStreamEvent(
                streamId,
                "stream-ended",
                {
                    ended: true
                }
            );


            /*
             * Clear the in-memory viewer state for
             * this stream. Persistent chat remains untouched.
             */

            const room =
                getStreamRoom(
                    streamId
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
                                room
                            );

                        } catch (_) {}

                        if (
                            viewerSocket.data
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


            res.json({
                success: true,

                streamId,

                ended: true
            });


        } catch (error) {

            console.error(
                "End stream error:",
                error
            );


            res.status(500).json({
                success: false,
                message:
                    "Unable to end stream"
            });

        }

    }
);


/* =========================================================
   SUPPORT / GIFT EVENT FOUNDATION
========================================================= */

/*
 * Real payment processing is intentionally NOT handled here.
 *
 * This endpoint only broadcasts a support/gift event to
 * viewers. Payment verification can be connected later
 * without changing the Watch Socket.IO structure.
 */

app.post(
    "/api/streams/:id/support",
    authenticateUser,
    async (req, res) => {

        try {

            const streamId =
                normalizeStreamId(
                    req.params.id
                );


            const gift =
                String(
                    req.body?.gift ||
                    req.body?.type ||
                    "support"
                )
                .trim()
                .slice(
                    0,
                    50
                );


            if (!streamId) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Stream ID is required"
                });

            }


            const sender =
                String(
                    req.user?.username ||
                    req.user?.name ||
                    "User"
                )
                .trim()
                .slice(
                    0,
                    80
                );


            const event = {

                streamId,

                userId:
                    req.userId,

                username:
                    sender,

                gift,

                createdAt:
                    new Date().toISOString()

            };


            io.to(
                getStreamRoom(
                    streamId
                )
            ).emit(
                "support-event",
                event
            );


            res.json({
                success: true,

                event
            });


        } catch (error) {

            console.error(
                "Support event error:",
                error
            );


            res.status(500).json({
                success: false,
                message:
                    "Unable to send support event"
            });

        }

    }
);
/* =========================================
   HEALTH / STATUS ROUTES
========================================= */

app.get("/health", async (req, res) => {

    let database = "disconnected";

    try {

        await pool.query("SELECT 1");

        database = "connected";

    } catch (error) {

        console.error(
            "Health database check failed:",
            error.message
        );

    }

    res.json({
        success: true,
        status: "online",
        database,
        timestamp: new Date().toISOString()
    });

});


app.get("/api/health", async (req, res) => {

    let database = "disconnected";

    try {

        await pool.query("SELECT 1");

        database = "connected";

    } catch (error) {

        console.error(
            "API health database check failed:",
            error.message
        );

    }

    res.json({
        success: true,
        status: "online",
        database,
        timestamp: new Date().toISOString()
    });

});


/* =========================================
   STREAM SOCKET STATUS
========================================= */

app.get("/api/streams/:id/socket-status", (req, res) => {

    const streamId = normalizeStreamId(req.params.id);

    if (!streamId) {

        return res.status(400).json({
            success: false,
            message: "Invalid stream ID"
        });

    }

    const room = getStreamRoom(streamId);

    const sockets = streamRooms.get(streamId);

    res.json({
        success: true,
        streamId,
        room,
        connectedViewers: sockets
            ? sockets.size
            : 0,
        viewerCount: getViewerCount(streamId)
    });

});


/* =========================================
   STREAM ROOM BROADCAST HELPER
========================================= */

function notifyStreamViewers(streamId, event, data = {}) {

    const normalizedId = normalizeStreamId(streamId);

    if (!normalizedId) {
        return;
    }

    io
        .to(getStreamRoom(normalizedId))
        .emit(event, {
            streamId: normalizedId,
            ...data
        });

}


/* =========================================
   STREAM TITLE / INFORMATION EVENT
========================================= */

app.post(
    "/api/streams/:id/event",
    authenticateUser,
    async (req, res) => {

        try {

            const streamId =
                normalizeStreamId(req.params.id);

            if (!streamId) {

                return res.status(400).json({
                    success: false,
                    message: "Invalid stream ID"
                });

            }

            const eventType =
                typeof req.body?.event === "string"
                    ? req.body.event.trim()
                    : "";

            if (!eventType) {

                return res.status(400).json({
                    success: false,
                    message: "Event type is required"
                });

            }

            const allowedEvents = new Set([
                "stream-started",
                "stream-updated",
                "stream-title-updated",
                "stream-thumbnail-updated"
            ]);

            if (!allowedEvents.has(eventType)) {

                return res.status(400).json({
                    success: false,
                    message: "Unsupported stream event"
                });

            }

            const eventData =
                req.body?.data &&
                typeof req.body.data === "object"
                    ? req.body.data
                    : {};

            notifyStreamViewers(
                streamId,
                eventType,
                eventData
            );

            res.json({
                success: true,
                streamId,
                event: eventType
            });

        } catch (error) {

            console.error(
                "Stream event error:",
                error
            );

            res.status(500).json({
                success: false,
                message: "Unable to send stream event"
            });

        }

    }
);


/* =========================================
   VIEWER COUNT BROADCAST
========================================= */

function broadcastViewerCount(streamId) {

    const normalizedId =
        normalizeStreamId(streamId);

    if (!normalizedId) {
        return;
    }

    const count =
        getViewerCount(normalizedId);

    io
        .to(getStreamRoom(normalizedId))
        .emit("viewer-count", {
            streamId: normalizedId,
            count
        });

}


/* =========================================
   FOLLOW UPDATE BROADCAST
========================================= */

function broadcastFollowUpdate(
    followerId,
    followingId,
    following,
    counts = {}
) {

    const payload = {
        followerId: Number(followerId),
        followingId: Number(followingId),
        following: Boolean(following),
        followerCount:
            Number(counts.followerCount || 0),
        followingCount:
            Number(counts.followingCount || 0),
        timestamp:
            new Date().toISOString()
    };

    io.emit(
        "follow-updated",
        payload
    );

}


/* =========================================
   SOCKET.IO FOLLOW SYNC
========================================= */

io.on("connection", (socket) => {

    socket.on(
        "sync-follow",
        async (data = {}) => {

            try {

                if (!socket.data.userId) {

                    return socket.emit(
                        "follow-error",
                        {
                            message:
                                "Authentication required"
                        }
                    );

                }

                const followingId =
                    Number(
                        data.followingId ||
                        data.userId ||
                        data.creatorId
                    );

                if (
                    !Number.isInteger(followingId) ||
                    followingId <= 0
                ) {

                    return socket.emit(
                        "follow-error",
                        {
                            message:
                                "Invalid user ID"
                        }
                    );

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
                            socket.data.userId,
                            followingId
                        ]
                    );

                const counts =
                    await getFollowCounts(
                        followingId
                    );

                socket.emit(
                    "follow-status",
                    {
                        following:
                            result.rows.length > 0,
                        followerCount:
                            counts.followerCount,
                        followingCount:
                            counts.followingCount
                    }
                );

            } catch (error) {

                console.error(
                    "Socket follow sync error:",
                    error
                );

                socket.emit(
                    "follow-error",
                    {
                        message:
                            "Unable to sync follow status"
                    }
                );

            }

        }
    );

});


/* =========================================
   API FALLBACK
========================================= */

app.get("/api", (req, res) => {

    res.json({
        success: true,
        name: "Canvas API",
        status: "online"
    });

});


/* =========================================
   END OF PART 7
   PART 8 CONTINUES FROM HERE
========================================= */
/* =========================================
   API 404 HANDLER
========================================= */

app.use("/api", (req, res) => {

    res.status(404).json({
        success: false,
        message: "Canvas API endpoint not found"
    });

});


/* =========================================
   GLOBAL ERROR HANDLER
========================================= */

app.use((err, req, res, next) => {

    console.error(
        "Canvas server error:",
        err
    );

    if (res.headersSent) {
        return next(err);
    }

    res.status(err.status || 500).json({
        success: false,
        message:
            err.message ||
            "Internal server error"
    });

});


/* =========================================
   PERIODIC SESSION CLEANUP
========================================= */

const SESSION_CLEANUP_INTERVAL =
    1000 * 60 * 60;

const sessionCleanupTimer =
    setInterval(async () => {

        try {

            await pool.query(`
                DELETE FROM sessions
                WHERE expires_at < CURRENT_TIMESTAMP
            `);

        } catch (error) {

            console.error(
                "Session cleanup error:",
                error.message
            );

        }

    }, SESSION_CLEANUP_INTERVAL);

if (
    sessionCleanupTimer &&
    typeof sessionCleanupTimer.unref === "function"
) {
    sessionCleanupTimer.unref();
}


/* =========================================
   SIGNUP VERIFICATION CLEANUP
========================================= */

const VERIFICATION_CLEANUP_INTERVAL =
    1000 * 60 * 5;

const verificationCleanupTimer =
    setInterval(() => {

        const now = Date.now();

        for (
            const [email, data]
            of signupVerificationCodes.entries()
        ) {

            if (
                !data ||
                !data.expiresAt ||
                data.expiresAt <= now
            ) {

                signupVerificationCodes.delete(email);

            }

        }

    }, VERIFICATION_CLEANUP_INTERVAL);

if (
    verificationCleanupTimer &&
    typeof verificationCleanupTimer.unref === "function"
) {
    verificationCleanupTimer.unref();
}


/* =========================================
   PROCESS ERROR HANDLERS
========================================= */

process.on(
    "unhandledRejection",
    (reason) => {

        console.error(
            "Unhandled promise rejection:",
            reason
        );

    }
);

process.on(
    "uncaughtException",
    (error) => {

        console.error(
            "Uncaught exception:",
            error
        );

    }
);


/* =========================================
   GRACEFUL SHUTDOWN
========================================= */

async function shutdown(signal) {

    console.log(
        `${signal} received. Shutting down Canvas...`
    );

    try {

        clearInterval(
            sessionCleanupTimer
        );

        clearInterval(
            verificationCleanupTimer
        );

        /*
         * Close Socket.IO/HTTP first.
         * Existing connections are allowed
         * to close cleanly.
         */

        await new Promise((resolve) => {

            httpServer.close(() => {
                resolve();
            });

        });

        /*
         * Close PostgreSQL only after the
         * HTTP server has stopped.
         */

        await pool.end();

        console.log(
            "Canvas server shut down cleanly."
        );

        process.exit(0);

    } catch (error) {

        console.error(
            "Canvas shutdown error:",
            error
        );

        process.exit(1);

    }

}

process.on(
    "SIGTERM",
    () => shutdown("SIGTERM")
);

process.on(
    "SIGINT",
    () => shutdown("SIGINT")
);


/* =========================================
   START SERVER
========================================= */

async function startServer() {

    /*
     * IMPORTANT:
     * The follow and chat tables MUST be
     * initialized before the server starts.
     *
     * Otherwise:
     * - Follow state will not persist
     * - Chat history cannot be stored
     */

    try {

        await initializeDatabase();

        await ensureFollowTable();

        await ensureChatTable();

        await ensureRecordingsTable();

        console.log(
            "Canvas database initialized successfully."
        );

    } catch (error) {

        console.error(
            "Canvas database initialization failed:",
            error
        );

        /*
         * Do NOT start the server when the
         * required database initialization
         * fails.
         *
         * This prevents the Watch page from
         * appearing online while follow/chat
         * functionality is actually broken.
         */

        process.exit(1);

    }

    /*
     * IMPORTANT:
     * Use httpServer, not app.listen(),
     * because Socket.IO is attached to it.
     */

    httpServer.listen(
        PORT,
        "0.0.0.0",
        () => {

            console.log(
                `Canvas server running on port ${PORT}`
            );

            console.log(
                `Socket.IO enabled on port ${PORT}`
            );

        }
    );

}


/* =========================================
   START CANVAS
========================================= */

startServer();


        
