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
                maxDisconnectionDuration:
                    2 * 60 * 1000,

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

    if (
        next === 0
    ) {

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
   RESOLVE USER
   Supports both numeric user IDs and usernames.
========================================================= */

async function resolveUserId(
    target
) {

    if (!pool) {
        return null;
    }


    const value =
        String(
            target || ""
        )
        .trim();


    if (!value) {
        return null;
    }


    if (
        /^\d+$/.test(value)
    ) {

        const result =
            await pool.query(
                `
                SELECT id
                FROM users
                WHERE id = $1
                LIMIT 1
                `,
                [
                    Number(value)
                ]
            );


        if (
            result.rows.length
        ) {

            return Number(
                result.rows[0].id
            );

        }

    }


    const result =
        await pool.query(
            `
            SELECT id
            FROM users
            WHERE LOWER(username) = LOWER($1)
            LIMIT 1
            `,
            [
                value
            ]
        );


    if (
        result.rows.length
    ) {

        return Number(
            result.rows[0].id
        );

    }


    return null;

}


/* =========================================================
   GET STREAM + CREATOR
========================================================= */

async function getStreamWithCreator(
    streamId
) {

    if (!pool) {
        return null;
    }


    const cleanStreamId =
        normalizeStreamId(
            streamId
        );


    if (!cleanStreamId) {
        return null;
    }


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

                users.name AS creator_name,
                users.username AS creator_username,

                profiles.profile_picture
                    AS creator_profile_picture,

                profiles.bio
                    AS creator_bio

            FROM streams

            INNER JOIN users
                ON users.id =
                   streams.user_id

            LEFT JOIN profiles
                ON profiles.user_id =
                   users.id

            WHERE streams.id::TEXT = $1

            LIMIT 1
            `,
            [
                cleanStreamId
            ]
        );


    if (
        result.rows.length === 0
    ) {

        return null;

    }


    const row =
        result.rows[0];


    const counts =
        await getFollowCounts(
            row.user_id
        );


    return {
        id: row.id,

        userId:
            row.user_id,

        title:
            row.title,

        status:
            row.status,

        createdAt:
            row.created_at,

        endedAt:
            row.ended_at,

        creator: {
            id:
                row.user_id,

            name:
                row.creator_name,

            username:
                row.creator_username,

            profilePicture:
                row.creator_profile_picture ||
                "",

            bio:
                row.creator_bio ||
                "",

            followers:
                counts.followers,

            following:
                counts.following
        }
    };

}


/* =========================================================
   STREAM DETAIL
   Compatibility for both:
   /api/streams/:id
   /api/stream/:id
========================================================= */

async function handleGetStream(
    req,
    res
) {

    try {

        const stream =
            await getStreamWithCreator(
                req.params.id
            );


        if (!stream) {

            return res.status(404).json({
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


        return res.status(500).json({
            success: false,
            message:
                "Unable to load stream."
        });

    }

}


app.get(
    "/api/streams/:id",
    handleGetStream
);


app.get(
    "/api/stream/:id",
    handleGetStream
);


/* =========================================================
   FOLLOW STATUS HELPER
========================================================= */

async function getFollowStatus(
    followerId,
    followingId
) {

    if (
        !pool ||
        !followerId ||
        !followingId
    ) {

        return false;

    }


    if (
        Number(followerId) ===
        Number(followingId)
    ) {

        return false;

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
                followerId,
                followingId
            ]
        );


    return result.rows.length > 0;

}


/* =========================================================
   FOLLOW UPDATE BROADCAST
========================================================= */

async function broadcastFollowUpdate(
    userId
) {

    try {

        const counts =
            await getFollowCounts(
                userId
            );


        io.emit(
            "follow-update",
            {
                userId:
                    Number(userId),

                followers:
                    counts.followers,

                following:
                    counts.following
            }
        );


        return counts;


    } catch (error) {

        console.error(
            "Follow update broadcast failed:",
            error.message
        );


        return {
            followers: 0,
            following: 0
        };

    }

}


/* =========================================================
   FOLLOW STATUS
========================================================= */

app.get(
    "/api/follow/status",
    authenticateUser,
    async (req, res) => {

        const target =
            req.query.userId ||
            req.query.creator ||
            req.query.username;


        const targetUserId =
            await resolveUserId(
                target
            );


        if (!targetUserId) {

            return res.status(404).json({
                success: false,
                message:
                    "User not found."
            });

        }


        try {

            const following =
                await getFollowStatus(
                    req.user.id,
                    targetUserId
                );


            const counts =
                await getFollowCounts(
                    targetUserId
                );


            return res.json({
                success: true,

                following,

                isFollowing:
                    following,

                followerCount:
                    counts.followers,

                followingCount:
                    counts.following,

                followers:
                    counts.followers,

                followingUsers:
                    counts.following
            });


        } catch (error) {

            console.error(
                "Follow status failed:",
                error.message
            );


            return res.status(500).json({
                success: false,
                message:
                    "Unable to load follow status."
            });

        }

    }
);


/* =========================================================
   FOLLOW STATUS COMPATIBILITY
   GET /api/follow/:creator
========================================================= */

app.get(
    "/api/follow/:creator",
    authenticateUser,
    async (req, res) => {

        const targetUserId =
            await resolveUserId(
                req.params.creator
            );


        if (!targetUserId) {

            return res.status(404).json({
                success: false,
                message:
                    "Creator not found."
            });

        }


        try {

            const following =
                await getFollowStatus(
                    req.user.id,
                    targetUserId
                );


            const counts =
                await getFollowCounts(
                    targetUserId
                );


            return res.json({
                success: true,

                following,

                isFollowing:
                    following,

                followerCount:
                    counts.followers,

                followingCount:
                    counts.following,

                followers:
                    counts.followers,

                followingCountValue:
                    counts.following
            });


        } catch (error) {

            console.error(
                "Creator follow status failed:",
                error.message
            );


            return res.status(500).json({
                success: false,
                message:
                    "Unable to load follow status."
            });

        }

    }
);


/* =========================================================
   FOLLOW / UNFOLLOW
========================================================= */

async function setFollowState(
    followerId,
    followingId,
    shouldFollow
) {

    if (
        Number(followerId) ===
        Number(followingId)
    ) {

        return {
            success: false,
            message:
                "You cannot follow yourself."
        };

    }


    if (shouldFollow) {

        await pool.query(
            `
            INSERT INTO follows
            (
                follower_id,
                following_id
            )
            VALUES ($1, $2)
            ON CONFLICT DO NOTHING
            `,
            [
                followerId,
                followingId
            ]
        );

    } else {

        await pool.query(
            `
            DELETE FROM follows
            WHERE follower_id = $1
              AND following_id = $2
            `,
            [
                followerId,
                followingId
            ]
        );

    }


    const counts =
        await getFollowCounts(
            followingId
        );


    return {
        success: true,

        following:
            shouldFollow,

        isFollowing:
            shouldFollow,

        followerCount:
            counts.followers,

        followingCount:
            counts.following,

        followers:
            counts.followers
    };

}


/* =========================================================
   MAIN FOLLOW ROUTE
========================================================= */

app.post(
    "/api/follow",
    authenticateUser,
    async (req, res) => {

        try {

            const target =
                req.body?.userId ||
                req.body?.creator ||
                req.body?.username;


            const targetUserId =
                await resolveUserId(
                    target
                );


            if (!targetUserId) {

                return res.status(404).json({
                    success: false,
                    message:
                        "User not found."
                });

            }


            let shouldFollow;


            if (
                typeof req.body?.following ===
                "boolean"
            ) {

                shouldFollow =
                    req.body.following;

            } else if (
                typeof req.body?.isFollowing ===
                "boolean"
            ) {

                shouldFollow =
                    req.body.isFollowing;

            } else {

                const current =
                    await getFollowStatus(
                        req.user.id,
                        targetUserId
                    );

                shouldFollow =
                    !current;

            }


            const result =
                await setFollowState(
                    req.user.id,
                    targetUserId,
                    shouldFollow
                );


            if (!result.success) {

                return res.status(400).json(
                    result
                );

            }


            const creatorCounts =
                await broadcastFollowUpdate(
                    targetUserId
                );


            return res.json({
                ...result,

                followerCount:
                    creatorCounts.followers,

                followingCount:
                    creatorCounts.following
            });


        } catch (error) {

            console.error(
                "Follow update failed:",
                error.message
            );


            return res.status(500).json({
                success: false,
                message:
                    "Unable to update follow status."
            });

        }

    }
);


/* =========================================================
   FORCE FOLLOW COMPATIBILITY
   POST /api/follow/:creator
========================================================= */

app.post(
    "/api/follow/:creator",
    authenticateUser,
    async (req, res) => {

        try {

            const targetUserId =
                await resolveUserId(
                    req.params.creator
                );


            if (!targetUserId) {

                return res.status(404).json({
                    success: false,
                    message:
                        "Creator not found."
                });

            }


            const result =
                await setFollowState(
                    req.user.id,
                    targetUserId,
                    true
                );


            if (!result.success) {

                return res.status(400).json(
                    result
                );

            }


            const counts =
                await broadcastFollowUpdate(
                    targetUserId
                );


            return res.json({
                success: true,

                following: true,

                isFollowing: true,

                followerCount:
                    counts.followers,

                followingCount:
                    counts.following
            });


        } catch (error) {

            console.error(
                "Force follow failed:",
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


/* =========================================================
   FORCE UNFOLLOW COMPATIBILITY
   DELETE /api/follow/:creator
========================================================= */

app.delete(
    "/api/follow/:creator",
    authenticateUser,
    async (req, res) => {

        try {

            const targetUserId =
                await resolveUserId(
                    req.params.creator
                );


            if (!targetUserId) {

                return res.status(404).json({
                    success: false,
                    message:
                        "Creator not found."
                });

            }


            const result =
                await setFollowState(
                    req.user.id,
                    targetUserId,
                    false
                );


            if (!result.success) {

                return res.status(400).json(
                    result
                );

            }


            const counts =
                await broadcastFollowUpdate(
                    targetUserId
                );


            return res.json({
                success: true,

                following: false,

                isFollowing: false,

                followerCount:
                    counts.followers,

                followingCount:
                    counts.following
            });


        } catch (error) {

            console.error(
                "Force unfollow failed:",
                error.message
            );


            return res.status(500).json({
                success: false,
                message:
                    "Unable to unfollow creator."
            });

        }

    }
);


/* =========================================================
   FOLLOWERS LIST
========================================================= */

app.get(
    "/api/users/:id/followers",
    async (req, res) => {

        try {

            const userId =
                await resolveUserId(
                    req.params.id
                );


            if (!userId) {

                return res.status(404).json({
                    success: false,
                    message:
                        "User not found."
                });

            }


            const result =
                await pool.query(
                    `
                    SELECT
                        users.id,
                        users.name,
                        users.username,
                        profiles.profile_picture
                            AS profile_picture

                    FROM follows

                    INNER JOIN users
                        ON users.id =
                           follows.follower_id

                    LEFT JOIN profiles
                        ON profiles.user_id =
                           users.id

                    WHERE follows.following_id = $1

                    ORDER BY
                        follows.created_at DESC
                    `,
                    [
                        userId
                    ]
                );


            return res.json({
                success: true,
                followers:
                    result.rows
            });


        } catch (error) {

            console.error(
                "Get followers failed:",
                error.message
            );


            return res.status(500).json({
                success: false,
                message:
                    "Unable to load followers."
            });

        }

    }
);
 /* =========================================================
    CHAT HISTORY
 ========================================================= */

async function getChatHistory(
    streamId,
    limit = 100
) {

    if (!pool) {
        return [];
    }


    const cleanStreamId =
        normalizeStreamId(
            streamId
        );


    if (!cleanStreamId) {
        return [];
    }


    const safeLimit =
        Math.min(
            Math.max(
                Number(limit) || 100,
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
                username,
                message,
                created_at
            FROM chat_messages
            WHERE stream_id = $1
            ORDER BY
                created_at DESC,
                id DESC
            LIMIT $2
            `,
            [
                cleanStreamId,
                safeLimit
            ]
        );


    return result.rows
        .reverse()
        .map(
            formatChatMessage
        );

}


/* =========================================================
   SAVE CHAT MESSAGE
 ========================================================= */

async function saveChatMessage(
    streamId,
    userId,
    username,
    message
) {

    if (!pool) {
        return null;
    }


    const cleanStreamId =
        normalizeStreamId(
            streamId
        );


    const cleanMessage =
        normalizeChatMessage(
            message
        );


    if (
        !cleanStreamId ||
        !cleanMessage
    ) {

        return null;

    }


    const cleanUsername =
        String(
            username ||
            "Canvas User"
        )
        .trim()
        .slice(
            0,
            50
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
            VALUES ($1, $2, $3, $4)
            RETURNING
                id,
                stream_id,
                user_id,
                username,
                message,
                created_at
            `,
            [
                cleanStreamId,
                userId || null,
                cleanUsername,
                cleanMessage
            ]
        );


    if (
        result.rows.length === 0
    ) {

        return null;

    }


    return formatChatMessage(
        result.rows[0]
    );

}


/* =========================================================
   RECENT CHAT DEDUPE
   Protects against Watch sending the same chat through
   both Socket.IO and the HTTP API.
 ========================================================= */

const recentChatMessages =
    new Map();


function getChatDedupeKey(
    streamId,
    userId,
    message
) {

    return [
        String(streamId),
        String(userId || ""),
        String(message)
    ]
    .join("|");

}


function isRecentDuplicateChat(
    streamId,
    userId,
    message
) {

    const key =
        getChatDedupeKey(
            streamId,
            userId,
            message
        );


    const previous =
        recentChatMessages.get(
            key
        );


    const now =
        Date.now();


    if (
        previous &&
        now - previous < 2500
    ) {

        return true;

    }


    recentChatMessages.set(
        key,
        now
    );


    return false;

}


setInterval(
    () => {

        const now =
            Date.now();


        for (
            const [
                key,
                timestamp
            ]
            of recentChatMessages
        ) {

            if (
                now - timestamp >
                10000
            ) {

                recentChatMessages.delete(
                    key
                );

            }

        }

    },
    10000
);


/* =========================================================
   BROADCAST CHAT MESSAGE
 ========================================================= */

function broadcastChatMessage(
    streamId,
    chatMessage
) {

    if (
        !streamId ||
        !chatMessage
    ) {

        return;

    }


    const room =
        getStreamRoom(
            streamId
        );


    io.to(
        room
    ).emit(
        "chat-message",
        chatMessage
    );

}


/* =========================================================
   GET CHAT
   Plural + singular compatibility.
 ========================================================= */

async function handleGetChat(
    req,
    res
) {

    try {

        const streamId =
            normalizeStreamId(
                req.params.id
            );


        if (!streamId) {

            return res.status(400).json({
                success: false,
                message:
                    "Stream ID is required."
            });

        }


        const messages =
            await getChatHistory(
                streamId,
                req.query.limit
            );


        return res.json({
            success: true,
            messages,
            chat: messages
        });


    } catch (error) {

        console.error(
            "Get chat failed:",
            error.message
        );


        return res.status(500).json({
            success: false,
            message:
                "Unable to load chat."
        });

    }

}


app.get(
    "/api/streams/:id/chat",
    handleGetChat
);


app.get(
    "/api/stream/:id/chat",
    handleGetChat
);


/* =========================================================
   POST CHAT
   Plural + singular compatibility.
 ========================================================= */

async function handlePostChat(
    req,
    res
) {

    try {

        if (!req.user) {

            return res.status(401).json({
                success: false,
                message:
                    "Login required to send chat."
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
                    "Stream ID is required."
            });

        }


        if (!message) {

            return res.status(400).json({
                success: false,
                message:
                    "Message cannot be empty."
            });

        }


        /*
         * If the exact same message was just sent through
         * Socket.IO, return the existing recent message
         * instead of creating a duplicate row.
         */

        if (
            isRecentDuplicateChat(
                streamId,
                req.user.id,
                message
            )
        ) {

            return res.json({
                success: true,
                duplicate: true,
                message:
                    "Message already sent."
            });

        }


        const chatMessage =
            await saveChatMessage(
                streamId,
                req.user.id,
                req.user.username,
                message
            );


        if (!chatMessage) {

            return res.status(500).json({
                success: false,
                message:
                    "Unable to save chat message."
            });

        }


        broadcastChatMessage(
            streamId,
            chatMessage
        );


        return res.status(201).json({
            success: true,
            message: chatMessage,
            chatMessage
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


app.post(
    "/api/streams/:id/chat",
    authenticateUser,
    handlePostChat
);


app.post(
    "/api/stream/:id/chat",
    authenticateUser,
    handlePostChat
);


/* =========================================================
   SOCKET STREAM ROOM HELPERS
 ========================================================= */

async function sendChatHistory(
    socket,
    streamId
) {

    try {

        const messages =
            await getChatHistory(
                streamId,
                100
            );


        socket.emit(
            "chat-history",
            {
                streamId:
                    String(streamId),

                messages
            }
        );


    } catch (error) {

        console.error(
            "Socket chat history failed:",
            error.message
        );


        socket.emit(
            "chat-history",
            {
                streamId:
                    String(streamId),

                messages: []
            }
        );

    }

}


async function joinStreamRoom(
    socket,
    streamId
) {

    const cleanStreamId =
        normalizeStreamId(
            streamId
        );


    if (!cleanStreamId) {
        return 0;
    }


    /*
     * Important:
     * Joining the same room twice must NOT increase
     * the viewer count twice.
     */

    if (
        socket.data.streamId ===
        cleanStreamId
    ) {

        const count =
            getViewerCount(
                cleanStreamId
            );


        socket.emit(
            "viewer-count",
            {
                streamId:
                    cleanStreamId,

                count
            }
        );


        await sendChatHistory(
            socket,
            cleanStreamId
        );


        return count;

    }


    if (
        socket.data.streamId
    ) {

        await leaveStreamRoom(
            socket
        );

    }


    const room =
        getStreamRoom(
            cleanStreamId
        );


    socket.join(
        room
    );


    socket.data.streamId =
        cleanStreamId;


    if (!streamRooms.has(
        cleanStreamId
    )) {

        streamRooms.set(
            cleanStreamId,
            new Set()
        );

    }


    const viewers =
        streamRooms.get(
            cleanStreamId
        );


    viewers.add(
        socket.id
    );


    const count =
        addViewer(
            cleanStreamId
        );


    socket.emit(
        "viewer-count",
        {
            streamId:
                cleanStreamId,

            count
        }
    );


    io.to(
        room
    ).emit(
        "viewer-count",
        {
            streamId:
                cleanStreamId,

            count
        }
    );


    await sendChatHistory(
        socket,
        cleanStreamId
    );


    return count;

}


async function leaveStreamRoom(
    socket,
    specificStreamId = null
) {

    const streamId =
        normalizeStreamId(
            specificStreamId ||
            socket.data.streamId
        );


    if (!streamId) {
        return 0;
    }


    const room =
        getStreamRoom(
            streamId
        );


    const viewers =
        streamRooms.get(
            streamId
        );


    let shouldRemove =
        true;


    if (viewers) {

        if (
            viewers.has(
                socket.id
            )
        ) {

            viewers.delete(
                socket.id
            );

        } else {

            shouldRemove =
                false;

        }


        if (
            viewers.size === 0
        ) {

            streamRooms.delete(
                streamId
            );

        }

    }


    if (
        shouldRemove
    ) {

        const count =
            removeViewer(
                streamId
            );


        io.to(
            room
        ).emit(
            "viewer-count",
            {
                streamId,

                count
            }
        );


        socket.leave(
            room
        );


        if (
            socket.data.streamId ===
            streamId
        ) {

            socket.data.streamId =
                null;

        }


        return count;

    }


    return getViewerCount(
        streamId
    );

}


/* =========================================================
   BROADCAST VIEWER COUNT
 ========================================================= */

function broadcastViewerCount(
    streamId
) {

    const cleanStreamId =
        normalizeStreamId(
            streamId
        );


    if (!cleanStreamId) {
        return 0;
    }


    const count =
        getViewerCount(
            cleanStreamId
        );


    io.to(
        getStreamRoom(
            cleanStreamId
        )
    ).emit(
        "viewer-count",
        {
            streamId:
                cleanStreamId,

            count
        }
    );


    return count;

}


/* =========================================================
   SOCKET.IO CONNECTION
 ========================================================= */

io.on(
    "connection",
    (socket) => {

        console.log(
            "Canvas socket connected:",
            socket.id
        );


        socket.data.userId =
            null;

        socket.data.username =
            null;

        socket.data.streamId =
            null;


        /* =========================================
           SOCKET AUTHENTICATE
        ========================================= */

        socket.on(
            "authenticate",
            async (payload = {}) => {

                try {

                    const token =
                        String(
                            payload.token ||
                            payload.authToken ||
                            ""
                        )
                        .trim();


                    if (!token) {

                        socket.emit(
                            "authentication-error",
                            {
                                success: false,
                                message:
                                    "Authentication token required."
                            }
                        );

                        return;

                    }


                    if (!pool) {

                        socket.emit(
                            "authentication-error",
                            {
                                success: false,
                                message:
                                    "Database is not configured."
                            }
                        );

                        return;

                    }


                    const result =
                        await pool.query(
                            `
                            SELECT
                                u.id,
                                u.name,
                                u.username,
                                u.email
                            FROM sessions s
                            INNER JOIN users u
                                ON u.id = s.user_id
                            WHERE
                                s.token_hash = $1
                                AND
                                s.expires_at >
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
                        result.rows.length === 0
                    ) {

                        socket.emit(
                            "authentication-error",
                            {
                                success: false,
                                message:
                                    "Invalid or expired session."
                            }
                        );

                        return;

                    }


                    const user =
                        result.rows[0];


                    socket.data.userId =
                        user.id;

                    socket.data.username =
                        user.username;


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
                        "Socket authentication failed:",
                        error.message
                    );


                    socket.emit(
                        "authentication-error",
                        {
                            success: false,
                            message:
                                "Socket authentication failed."
                        }
                    );

                }

            }
        );


        /* =========================================
           JOIN STREAM
        ========================================= */

        socket.on(
            "join-stream",
            async (payload = {}) => {

                const streamId =
                    payload.streamId ||
                    payload.id;


                if (!streamId) {

                    socket.emit(
                        "stream-error",
                        {
                            success: false,
                            message:
                                "Stream ID is required."
                        }
                    );

                    return;

                }


                try {

                    await joinStreamRoom(
                        socket,
                        streamId
                    );


                } catch (error) {

                    console.error(
                        "Join stream failed:",
                        error.message
                    );


                    socket.emit(
                        "stream-error",
                        {
                            success: false,
                            message:
                                "Unable to join stream."
                        }
                    );

                }

            }
        );


        /* =========================================
           LEAVE STREAM
        ========================================= */

        socket.on(
            "leave-stream",
            async () => {

                try {

                    await leaveStreamRoom(
                        socket
                    );


                } catch (error) {

                    console.error(
                        "Leave stream failed:",
                        error.message
                    );

                }

            }
        );


        /* =========================================
           GET CHAT HISTORY
        ========================================= */

        socket.on(
            "get-chat-history",
            async (payload = {}) => {

                const streamId =
                    payload.streamId ||
                    payload.id;


                if (!streamId) {
                    return;
                }


                await sendChatHistory(
                    socket,
                    streamId
                );

            }
        );
              /* =========================================
           SEND CHAT
           Supports:
           - "send-chat"
           - "chat-message"
        ========================================= */

        const handleSocketChat =
            async (
                payload = {}
            ) => {

                try {

                    const streamId =
                        normalizeStreamId(
                            payload.streamId ||
                            payload.id
                        );


                    const message =
                        normalizeChatMessage(
                            payload.message ||
                            payload.text
                        );


                    if (!streamId) {

                        socket.emit(
                            "chat-error",
                            {
                                success: false,
                                message:
                                    "Stream ID is required."
                            }
                        );

                        return;

                    }


                    if (!message) {

                        socket.emit(
                            "chat-error",
                            {
                                success: false,
                                message:
                                    "Message cannot be empty."
                            }
                        );

                        return;

                    }


                    /*
                     * Socket must be authenticated before
                     * saving a permanent chat message.
                     */

                    if (!socket.data.userId) {

                        socket.emit(
                            "chat-error",
                            {
                                success: false,
                                message:
                                    "Login required to send chat."
                            }
                        );

                        return;

                    }


                    /*
                     * Make sure this socket is actually inside
                     * the requested stream room.
                     */

                    if (
                        socket.data.streamId !==
                        streamId
                    ) {

                        await joinStreamRoom(
                            socket,
                            streamId
                        );

                    }


                    /*
                     * Prevent the same message from being
                     * stored twice when Watch sends it through
                     * both Socket.IO and HTTP.
                     */

                    if (
                        isRecentDuplicateChat(
                            streamId,
                            socket.data.userId,
                            message
                        )
                    ) {

                        socket.emit(
                            "chat-sent",
                            {
                                success: true,
                                duplicate: true
                            }
                        );

                        return;

                    }


                    const chatMessage =
                        await saveChatMessage(
                            streamId,
                            socket.data.userId,
                            socket.data.username,
                            message
                        );


                    if (!chatMessage) {

                        socket.emit(
                            "chat-error",
                            {
                                success: false,
                                message:
                                    "Unable to save chat message."
                            }
                        );

                        return;

                    }


                    broadcastChatMessage(
                        streamId,
                        chatMessage
                    );


                    socket.emit(
                        "chat-sent",
                        {
                            success: true,

                            message:
                                chatMessage,

                            chatMessage
                        }
                    );


                } catch (error) {

                    console.error(
                        "Socket send chat failed:",
                        error.message
                    );


                    socket.emit(
                        "chat-error",
                        {
                            success: false,
                            message:
                                "Unable to send chat message."
                        }
                    );

                }

            };


        socket.on(
            "send-chat",
            handleSocketChat
        );


        /*
         * Watch compatibility:
         * some versions of Watch use "chat-message"
         * as the outgoing Socket.IO event.
         */

        socket.on(
            "chat-message",
            handleSocketChat
        );


        /* =========================================
           GET VIEWER COUNT
        ========================================= */

        socket.on(
            "get-viewer-count",
            (payload = {}) => {

                const streamId =
                    normalizeStreamId(
                        payload.streamId ||
                        payload.id
                    );


                if (!streamId) {

                    socket.emit(
                        "viewer-count",
                        {
                            streamId: "",
                            count: 0
                        }
                    );

                    return;

                }


                socket.emit(
                    "viewer-count",
                    {
                        streamId,

                        count:
                            getViewerCount(
                                streamId
                            )
                    }
                );

            }
        );


        /* =========================================
           SYNC FOLLOW
           Used by Watch/profile pages to refresh
           creator follower/following counts.
        ========================================= */

        socket.on(
            "sync-follow",
            async (payload = {}) => {

                try {

                    const target =
                        payload.userId ||
                        payload.creator ||
                        payload.username;


                    const targetUserId =
                        await resolveUserId(
                            target
                        );


                    if (!targetUserId) {

                        socket.emit(
                            "follow-sync",
                            {
                                success: false,

                                message:
                                    "User not found."
                            }
                        );

                        return;

                    }


                    const counts =
                        await getFollowCounts(
                            targetUserId
                        );


                    const following =
                        socket.data.userId
                            ? await getFollowStatus(
                                socket.data.userId,
                                targetUserId
                            )
                            : false;


                    socket.emit(
                        "follow-sync",
                        {
                            success: true,

                            userId:
                                Number(
                                    targetUserId
                                ),

                            following,

                            isFollowing:
                                following,

                            followers:
                                counts.followers,

                            following:
                                counts.following,

                            followerCount:
                                counts.followers,

                            followingCount:
                                counts.following
                        }
                    );


                } catch (error) {

                    console.error(
                        "Sync follow failed:",
                        error.message
                    );


                    socket.emit(
                        "follow-sync",
                        {
                            success: false,

                            message:
                                "Unable to sync follow status."
                        }
                    );

                }

            }
        );


        /* =========================================
           DISCONNECT
        ========================================= */

        socket.on(
            "disconnect",
            async (
                reason
            ) => {

                try {

                    await leaveStreamRoom(
                        socket
                    );

                } catch (error) {

                    console.error(
                        "Socket disconnect cleanup failed:",
                        error.message
                    );

                }


                console.log(
                    "Canvas socket disconnected:",
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

            const email =
                normalizeEmail(
                    req.body?.email
                );


            if (!email) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Email is required."
                });

            }


            if (!pool) {

                return res.status(503).json({
                    success: false,
                    message:
                        "Database is not configured."
                });

            }


            const existing =
                await pool.query(
                    `
                    SELECT id
                    FROM users
                    WHERE email = $1
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
                        "An account with this email already exists."
                });

            }


            const code =
                String(
                    crypto.randomInt(
                        100000,
                        1000000
                    )
                );


            signupVerificationCodes.set(
                email,
                {
                    code,

                    expiresAt:
                        Date.now() +
                        10 * 60 * 1000
                }
            );


            /*
             * Resend configuration.
             * Keep the existing environment-variable
             * names compatible with the current deployment.
             */

            const resendApiKey =
                process.env.RESEND_API_KEY ||
                process.env.resendApiKey ||
                process.env.RESEND_API;


            const resendFromEmail =
                process.env.RESEND_FROM_EMAIL ||
                process.env.resendFromEmail ||
                process.env.RESEND_FROM;


            if (
                !resendApiKey ||
                !resendFromEmail
            ) {

                console.log(
                    "Signup verification code:",
                    email,
                    code
                );


                return res.json({
                    success: true,

                    message:
                        "Verification code generated.",

                    development:
                        true
                });

            }


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

                                text:
                                    `Your Canvas verification code is ${code}. It expires in 10 minutes.`
                            })
                    }
                );


            if (!response.ok) {

                const errorText =
                    await response.text();


                console.error(
                    "Resend error:",
                    errorText
                );


                return res.status(500).json({
                    success: false,
                    message:
                        "Unable to send verification code."
                });

            }


            return res.json({
                success: true,

                message:
                    "Verification code sent."
            });


        } catch (error) {

            console.error(
                "Send signup code failed:",
                error
            );


            return res.status(500).json({
                success: false,
                message:
                    "Unable to send verification code."
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
                        "Email and verification code are required."
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
                        "Verification code not found or expired."
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
                        "Verification code expired."
                });

            }


            if (
                String(saved.code) !==
                code
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Invalid verification code."
                });

            }


            return res.json({
                success: true,

                verified: true,

                email
            });


        } catch (error) {

            console.error(
                "Verify signup code failed:",
                error
            );


            return res.status(500).json({
                success: false,
                message:
                    "Unable to verify code."
            });

        }

    }
);
/* =========================================================
   SIGNUP - CREATE ACCOUNT AFTER VERIFICATION
========================================================= */

app.post(
    "/api/signup",
    async (req, res) => {

        try {

            if (!pool) {

                return res.status(503).json({
                    success: false,
                    message:
                        "Database is not configured."
                });

            }


            const name =
                String(
                    req.body?.name ||
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


            const code =
                String(
                    req.body?.code ||
                    req.body?.verificationCode ||
                    ""
                )
                .trim();


            if (
                !name ||
                !username ||
                !email ||
                !password
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Name, username, email and password are required."
                });

            }


            if (
                password.length < 6
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Password must be at least 6 characters."
                });

            }


            /*
             * The account must have a valid verification
             * code before it can be created.
             */

            const saved =
                signupVerificationCodes.get(
                    email
                );


            if (!saved) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Email verification is required."
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
                        "Verification code expired."
                });

            }


            if (
                String(saved.code) !==
                code
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Invalid verification code."
                });

            }


            const existingEmail =
                await pool.query(
                    `
                    SELECT id
                    FROM users
                    WHERE email = $1
                    LIMIT 1
                    `,
                    [
                        email
                    ]
                );


            if (
                existingEmail.rows.length
            ) {

                signupVerificationCodes.delete(
                    email
                );


                return res.status(409).json({
                    success: false,
                    message:
                        "An account with this email already exists."
                });

            }


            const existingUsername =
                await pool.query(
                    `
                    SELECT id
                    FROM users
                    WHERE LOWER(username) = LOWER($1)
                    LIMIT 1
                    `,
                    [
                        username
                    ]
                );


            if (
                existingUsername.rows.length
            ) {

                return res.status(409).json({
                    success: false,
                    message:
                        "Username is already taken."
                });

            }


            const passwordHash =
                hashPassword(
                    password
                );


            const client =
                await pool.connect();


            let user;


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
                            password_hash
                        )
                        VALUES ($1, $2, $3, $4)
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


                user =
                    userResult.rows[0];


                await client.query(
                    `
                    INSERT INTO profiles
                    (
                        user_id,
                        bio,
                        profile_picture
                    )
                    VALUES ($1, '', '')
                    ON CONFLICT (user_id)
                    DO NOTHING
                    `,
                    [
                        user.id
                    ]
                );


                const authToken =
                    createAuthToken();


                const tokenHash =
                    hashToken(
                        authToken
                    );


                await client.query(
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
                        CURRENT_TIMESTAMP +
                        INTERVAL '30 days'
                    )
                    `,
                    [
                        user.id,
                        tokenHash
                    ]
                );


                await client.query(
                    "COMMIT"
                );


                signupVerificationCodes.delete(
                    email
                );


                return res.status(201).json({
                    success: true,

                    message:
                        "Account created successfully.",

                    token:
                        authToken,

                    authToken:
                        authToken,

                    user
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
                "Signup failed:",
                error
            );


            if (
                error.code ===
                "23505"
            ) {

                return res.status(409).json({
                    success: false,
                    message:
                        "Email or username is already in use."
                });

            }


            return res.status(500).json({
                success: false,
                message:
                    "Unable to create account."
            });

        }

    }
);


/* =========================================================
   SIGNUP COMPATIBILITY
   Some older frontend versions use:
   /api/signup/complete
========================================================= */

app.post(
    "/api/signup/complete",
    async (req, res) => {

        /*
         * Keep the same signup logic available through
         * the compatibility endpoint.
         */

        req.url =
            "/api/signup";


        const handler =
            app._router?.stack
                ?.find(
                    layer =>
                        layer.route &&
                        layer.route.path ===
                            "/api/signup" &&
                        layer.route.methods.post
                );


        if (
            handler?.route?.stack?.[0]?.handle
        ) {

            return handler
                .route
                .stack[0]
                .handle(
                    req,
                    res
                );

        }


        return res.status(500).json({
            success: false,
            message:
                "Signup endpoint unavailable."
        });

    }
);


/* =========================================================
   LOGIN HELPER
========================================================= */

async function loginUser(
    email,
    password
) {

    if (!pool) {

        return {
            success: false,
            status: 503,
            message:
                "Database is not configured."
        };

    }


    const normalizedEmail =
        normalizeEmail(
            email
        );


    const passwordHash =
        hashPassword(
            password
        );


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
            WHERE email = $1
            LIMIT 1
            `,
            [
                normalizedEmail
            ]
        );


    if (
        result.rows.length === 0
    ) {

        return {
            success: false,
            status: 401,
            message:
                "Invalid email or password."
        };

    }


    const user =
        result.rows[0];


    if (
        user.password_hash !==
        passwordHash
    ) {

        return {
            success: false,
            status: 401,
            message:
                "Invalid email or password."
        };

    }


    const authToken =
        createAuthToken();


    const tokenHash =
        hashToken(
            authToken
        );


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
            CURRENT_TIMESTAMP +
            INTERVAL '30 days'
        )
        `,
        [
            user.id,
            tokenHash
        ]
    );


    delete user.password_hash;


    return {
        success: true,

        token:
            authToken,

        authToken:
            authToken,

        user
    };

}


/* =========================================================
   LOGIN
========================================================= */

app.post(
    "/api/login",
    async (req, res) => {

        try {

            const email =
                req.body?.email ||
                req.body?.username;


            const password =
                String(
                    req.body?.password ||
                    ""
                );


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


            const result =
                await loginUser(
                    email,
                    password
                );


            if (
                !result.success
            ) {

                return res.status(
                    result.status || 401
                ).json({
                    success: false,
                    message:
                        result.message
                });

            }


            return res.json(
                result
            );


        } catch (error) {

            console.error(
                "Login failed:",
                error
            );


            return res.status(500).json({
                success: false,
                message:
                    "Unable to login."
            });

        }

    }
);


/* =========================================================
   AUTH LOGIN COMPATIBILITY
========================================================= */

app.post(
    "/api/auth/login",
    async (req, res) => {

        try {

            const email =
                req.body?.email ||
                req.body?.username;


            const password =
                String(
                    req.body?.password ||
                    ""
                );


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


            const result =
                await loginUser(
                    email,
                    password
                );


            if (
                !result.success
            ) {

                return res.status(
                    result.status || 401
                ).json({
                    success: false,
                    message:
                        result.message
                });

            }


            return res.json(
                result
            );


        } catch (error) {

            console.error(
                "Auth login failed:",
                error
            );


            return res.status(500).json({
                success: false,
                message:
                    "Unable to login."
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

            const counts =
                await getFollowCounts(
                    req.user.id
                );


            const profileResult =
                await pool.query(
                    `
                    SELECT
                        bio,
                        profile_picture,
                        updated_at
                    FROM profiles
                    WHERE user_id = $1
                    LIMIT 1
                    `,
                    [
                        req.user.id
                    ]
                );


            const profile =
                profileResult.rows[0] ||
                {
                    bio: "",
                    profile_picture: "",
                    updated_at: null
                };


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

                    createdAt:
                        req.user.created_at,

                    bio:
                        profile.bio || "",

                    profilePicture:
                        profile.profile_picture ||
                        "",

                    followers:
                        counts.followers,

                    following:
                        counts.following,

                    followerCount:
                        counts.followers,

                    followingCount:
                        counts.following
                }
            });


        } catch (error) {

            console.error(
                "Get current user failed:",
                error
            );


            return res.status(500).json({
                success: false,
                message:
                    "Unable to load current user."
            });

        }

    }
);
/* =========================================================
   PROFILE
========================================================= */

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
                        u.created_at,

                        p.bio,
                        p.profile_picture,
                        p.updated_at

                    FROM users u

                    LEFT JOIN profiles p
                        ON p.user_id = u.id

                    WHERE u.id = $1

                    LIMIT 1
                    `,
                    [
                        req.user.id
                    ]
                );


            if (
                result.rows.length === 0
            ) {

                return res.status(404).json({
                    success: false,
                    message:
                        "Profile not found."
                });

            }


            const row =
                result.rows[0];


            const counts =
                await getFollowCounts(
                    row.id
                );


            return res.json({
                success: true,

                profile: {
                    id:
                        row.id,

                    userId:
                        row.id,

                    name:
                        row.name,

                    username:
                        row.username,

                    email:
                        row.email,

                    bio:
                        row.bio || "",

                    profilePicture:
                        row.profile_picture ||
                        "",

                    followers:
                        counts.followers,

                    following:
                        counts.following,

                    followerCount:
                        counts.followers,

                    followingCount:
                        counts.following,

                    createdAt:
                        row.created_at,

                    updatedAt:
                        row.updated_at
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
                    "Unable to load profile."
            });

        }

    }
);


/* =========================================================
   PUBLIC PROFILE
   Supports numeric ID and username.
========================================================= */

app.get(
    "/api/profile/:id",
    async (req, res) => {

        try {

            const userId =
                await resolveUserId(
                    req.params.id
                );


            if (!userId) {

                return res.status(404).json({
                    success: false,
                    message:
                        "Profile not found."
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

                    WHERE u.id = $1

                    LIMIT 1
                    `,
                    [
                        userId
                    ]
                );


            if (
                result.rows.length === 0
            ) {

                return res.status(404).json({
                    success: false,
                    message:
                        "Profile not found."
                });

            }


            const row =
                result.rows[0];


            const counts =
                await getFollowCounts(
                    row.id
                );


            return res.json({
                success: true,

                profile: {
                    id:
                        row.id,

                    userId:
                        row.id,

                    name:
                        row.name,

                    username:
                        row.username,

                    bio:
                        row.bio || "",

                    profilePicture:
                        row.profile_picture ||
                        "",

                    followers:
                        counts.followers,

                    following:
                        counts.following,

                    followerCount:
                        counts.followers,

                    followingCount:
                        counts.following,

                    createdAt:
                        row.created_at,

                    updatedAt:
                        row.updated_at
                }
            });


        } catch (error) {

            console.error(
                "Get public profile failed:",
                error.message
            );


            return res.status(500).json({
                success: false,
                message:
                    "Unable to load profile."
            });

        }

    }
);


/* =========================================================
   SAVE / UPDATE PROFILE
========================================================= */

app.put(
    "/api/profile",
    authenticateUser,
    async (req, res) => {

        try {

            const name =
                String(
                    req.body?.name ||
                    req.user.name ||
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
                    req.user.username
                );


            const bio =
                String(
                    req.body?.bio ||
                    ""
                )
                .trim()
                .slice(
                    0,
                    1000
                );


            const profilePicture =
                String(
                    req.body?.profilePicture ??
                    req.body?.profile_picture ??
                    ""
                )
                .trim()
                .slice(
                    0,
                    10 * 1024 * 1024
                );


            if (!name) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Name is required."
                });

            }


            if (!username) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Username is required."
                });

            }


            const usernameCheck =
                await pool.query(
                    `
                    SELECT id
                    FROM users
                    WHERE
                        LOWER(username) =
                        LOWER($1)
                        AND id <> $2
                    LIMIT 1
                    `,
                    [
                        username,
                        req.user.id
                    ]
                );


            if (
                usernameCheck.rows.length
            ) {

                return res.status(409).json({
                    success: false,
                    message:
                        "Username is already taken."
                });

            }


            await pool.query(
                `
                UPDATE users
                SET
                    name = $1,
                    username = $2
                WHERE id = $3
                `,
                [
                    name,
                    username,
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
                    bio = EXCLUDED.bio,
                    profile_picture =
                        EXCLUDED.profile_picture,
                    updated_at =
                        CURRENT_TIMESTAMP
                `,
                [
                    req.user.id,
                    bio,
                    profilePicture
                ]
            );


            const counts =
                await getFollowCounts(
                    req.user.id
                );


            return res.json({
                success: true,

                message:
                    "Profile saved successfully.",

                profile: {
                    id:
                        req.user.id,

                    userId:
                        req.user.id,

                    name,

                    username,

                    bio,

                    profilePicture,

                    followers:
                        counts.followers,

                    following:
                        counts.following,

                    followerCount:
                        counts.followers,

                    followingCount:
                        counts.following
                }
            });


        } catch (error) {

            console.error(
                "Save profile failed:",
                error.message
            );


            if (
                error.code ===
                "23505"
            ) {

                return res.status(409).json({
                    success: false,
                    message:
                        "Username is already taken."
                });

            }


            return res.status(500).json({
                success: false,
                message:
                    "Unable to save profile."
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
                        false,

                    message:
                        "Database is not configured."
                });

            }


            const result =
                await pool.query(
                    "SELECT NOW() AS now"
                );


            return res.json({
                success: true,

                database:
                    true,

                connected:
                    true,

                time:
                    result.rows[0]?.now ||
                    null
            });


        } catch (error) {

            console.error(
                "Database test failed:",
                error.message
            );


            return res.status(500).json({
                success: false,

                database:
                    false,

                connected:
                    false,

                message:
                    "Database connection failed."
            });

        }

    }
);


/* =========================================================
   LIVE STREAMS
========================================================= */

app.get(
    "/api/streams/live",
    async (req, res) => {

        try {

            if (!pool) {

                return res.status(503).json({
                    success: false,
                    message:
                        "Database is not configured."
                });

            }


            const result =
                await pool.query(
                    `
                    SELECT
                        streams.id,
                        streams.user_id,
                        streams.title,
                        streams.status,
                        streams.created_at,

                        users.name
                            AS creator_name,

                        users.username
                            AS creator_username,

                        profiles.profile_picture
                            AS creator_profile_picture

                    FROM streams

                    INNER JOIN users
                        ON users.id =
                           streams.user_id

                    LEFT JOIN profiles
                        ON profiles.user_id =
                           users.id

                    WHERE
                        LOWER(
                            COALESCE(
                                streams.status,
                                ''
                            )
                        ) = 'live'

                    ORDER BY
                        streams.created_at DESC
                    `
                );


            const streams =
                await Promise.all(
                    result.rows.map(
                        async (
                            row
                        ) => {

                            const counts =
                                await getFollowCounts(
                                    row.user_id
                                );


                            return {
                                id:
                                    row.id,

                                userId:
                                    row.user_id,

                                title:
                                    row.title ||
                                    "Live Stream",

                                status:
                                    row.status,

                                createdAt:
                                    row.created_at,

                                creator: {
                                    id:
                                        row.user_id,

                                    name:
                                        row.creator_name,

                                    username:
                                        row.creator_username,

                                    profilePicture:
                                        row.creator_profile_picture ||
                                        "",

                                    followers:
                                        counts.followers,

                                    following:
                                        counts.following
                                },

                                viewerCount:
                                    getViewerCount(
                                        row.id
                                    )
                            };

                        }
                    )
                );


            return res.json({
                success: true,

                streams
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


/* =========================================================
   MY STREAMS
========================================================= */

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

                    WHERE user_id = $1

                    ORDER BY
                        created_at DESC
                    `,
                    [
                        req.user.id
                    ]
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
                    "Unable to load your streams."
            });

        }

    }
);
/* =========================================================
   CREATE STREAM
========================================================= */

app.post(
    "/api/streams",
    authenticateUser,
    async (req, res) => {

        try {

            const title =
                String(
                    req.body?.title ||
                    "Live Stream"
                )
                .trim()
                .slice(
                    0,
                    200
                );


            if (!title) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Stream title is required."
                });

            }


            const result =
                await pool.query(
                    `
                    INSERT INTO streams
                    (
                        user_id,
                        title,
                        status,
                        created_at
                    )
                    VALUES (
                        $1,
                        $2,
                        'live',
                        CURRENT_TIMESTAMP
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

                stream: {
                    ...stream,

                    viewerCount:
                        getViewerCount(
                            stream.id
                        )
                }
            });


        } catch (error) {

            console.error(
                "Create stream failed:",
                error.message
            );


            return res.status(500).json({
                success: false,
                message:
                    "Unable to create stream."
            });

        }

    }
);


/* =========================================================
   END STREAM
========================================================= */

async function endStream(
    streamId,
    userId = null
) {

    const cleanStreamId =
        normalizeStreamId(
            streamId
        );


    if (!cleanStreamId) {

        return {
            success: false,
            message:
                "Stream ID is required."
        };

    }


    if (!pool) {

        return {
            success: false,
            message:
                "Database is not configured."
        };

    }


    let result;


    if (userId) {

        result =
            await pool.query(
                `
                UPDATE streams
                SET
                    status = 'ended',
                    ended_at = CURRENT_TIMESTAMP
                WHERE
                    id::TEXT = $1
                    AND user_id = $2
                    AND LOWER(
                        COALESCE(status, '')
                    ) = 'live'
                RETURNING
                    id,
                    user_id,
                    title,
                    status,
                    created_at,
                    ended_at
                `,
                [
                    cleanStreamId,
                    userId
                ]
            );

    } else {

        result =
            await pool.query(
                `
                UPDATE streams
                SET
                    status = 'ended',
                    ended_at = CURRENT_TIMESTAMP
                WHERE
                    id::TEXT = $1
                    AND LOWER(
                        COALESCE(status, '')
                    ) = 'live'
                RETURNING
                    id,
                    user_id,
                    title,
                    status,
                    created_at,
                    ended_at
                `,
                [
                    cleanStreamId
                ]
            );

    }


    /*
     * If the stream is already ended, return its current
     * database state instead of treating it as a hard error.
     */

    if (
        result.rows.length === 0
    ) {

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
                WHERE id::TEXT = $1
                LIMIT 1
                `,
                [
                    cleanStreamId
                ]
            );


        if (
            existing.rows.length === 0
        ) {

            return {
                success: false,
                message:
                    "Stream not found."
            };

        }


        const existingStream =
            existing.rows[0];


        if (
            userId &&
            Number(
                existingStream.user_id
            ) !== Number(userId)
        ) {

            return {
                success: false,
                message:
                    "You do not own this stream."
            };

        }


        return {
            success: true,

            alreadyEnded:
                true,

            stream:
                existingStream
        };

    }


    const stream =
        result.rows[0];


    /*
     * Remove all in-memory viewers for this stream.
     */

    const room =
        getStreamRoom(
            cleanStreamId
        );


    const viewers =
        streamRooms.get(
            cleanStreamId
        );


    if (viewers) {

        for (
            const socketId
            of viewers
        ) {

            const socket =
                io.sockets.sockets.get(
                    socketId
                );


            if (socket) {

                socket.data.streamId =
                    null;

                socket.leave(
                    room
                );

            }

        }

    }


    streamRooms.delete(
        cleanStreamId
    );


    streamViewerCounts.delete(
        cleanStreamId
    );


    io.to(
        room
    ).emit(
        "stream-ended",
        {
            streamId:
                cleanStreamId
        }
    );


    io.to(
        room
    ).emit(
        "viewer-count",
        {
            streamId:
                cleanStreamId,

            count: 0
        }
    );


    io.emit(
        "stream-ended",
        {
            streamId:
                cleanStreamId
        }
    );


    return {
        success: true,

        stream
    };

}


app.put(
    "/api/streams/:id/end",
    authenticateUser,
    async (req, res) => {

        try {

            const result =
                await endStream(
                    req.params.id,
                    req.user.id
                );


            if (!result.success) {

                return res.status(404).json(
                    result
                );

            }


            return res.json(
                result
            );


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


/* =========================================================
   STREAM EVENT
   Generic compatibility endpoint for Go Live / Watch.
========================================================= */

app.post(
    "/api/streams/:id/event",
    optionalAuthenticateUser,
    async (req, res) => {

        try {

            const streamId =
                normalizeStreamId(
                    req.params.id
                );


            const event =
                String(
                    req.body?.event ||
                    req.body?.type ||
                    ""
                )
                .trim()
                .toLowerCase();


            if (!streamId) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Stream ID is required."
                });

            }


            if (
                event === "end" ||
                event === "ended" ||
                event === "stop" ||
                event === "stop-stream"
            ) {

                const result =
                    await endStream(
                        streamId,
                        req.userId || null
                    );


                if (!result.success) {

                    return res.status(400).json(
                        result
                    );

                }


                return res.json(
                    result
                );

            }


            if (
                event === "viewer-count" ||
                event === "viewers"
            ) {

                const count =
                    broadcastViewerCount(
                        streamId
                    );


                return res.json({
                    success: true,

                    streamId,

                    viewerCount:
                        count
                });

            }


            /*
             * Generic events are broadcast to the stream room.
             * This keeps the endpoint compatible with older
             * Canvas frontend versions.
             */

            const payload = {
                streamId,

                event,

                data:
                    req.body?.data ??
                    null
            };


            io.to(
                getStreamRoom(
                    streamId
                )
            ).emit(
                "stream-event",
                payload
            );


            return res.json({
                success: true,

                event:
                    payload
            });


        } catch (error) {

            console.error(
                "Stream event failed:",
                error.message
            );


            return res.status(500).json({
                success: false,
                message:
                    "Unable to process stream event."
            });

        }

    }
);


/* =========================================================
   SOCKET STATUS
========================================================= */

app.get(
    "/api/streams/:id/socket-status",
    async (req, res) => {

        const streamId =
            normalizeStreamId(
                req.params.id
            );


        if (!streamId) {

            return res.status(400).json({
                success: false,
                message:
                    "Stream ID is required."
            });

        }


        const room =
            getStreamRoom(
                streamId
            );


        const viewers =
            streamRooms.get(
                streamId
            );


        return res.json({
            success: true,

            socket: {
                enabled: true,

                room,

                viewerCount:
                    getViewerCount(
                        streamId
                    ),

                connectedViewers:
                    viewers
                        ? viewers.size
                        : 0
            }
        });

    }
);


/* =========================================================
   RECORDINGS
========================================================= */

app.get(
    "/api/recordings",
    async (req, res) => {

        try {

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

                        u.name
                            AS creator_name,

                        u.username
                            AS creator_username

                    FROM stream_recordings r

                    LEFT JOIN users u
                        ON u.id = r.user_id

                    ORDER BY
                        r.created_at DESC

                    LIMIT 100
                    `
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
                    "Unable to load recordings."
            });

        }

    }
);


/* =========================================================
   MY RECORDINGS
========================================================= */

app.get(
    "/api/recordings/my",
    authenticateUser,
    async (req, res) => {

        try {

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

                    WHERE user_id = $1

                    ORDER BY
                        created_at DESC
                    `,
                    [
                        req.user.id
                    ]
                );


            return res.json({
                success: true,

                recordings:
                    result.rows
            });


        } catch (error) {

            console.error(
                "Get my recordings failed:",
                error.message
            );


            return res.status(500).json({
                success: false,
                message:
                    "Unable to load recordings."
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

            const streamId =
                normalizeStreamId(
                    req.body?.streamId
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
                .trim()
                .slice(
                    0,
                    10 * 1024 * 1024
                );


            const recordingUrl =
                String(
                    req.body?.recordingUrl ||
                    req.body?.recording_url ||
                    ""
                )
                .trim()
                .slice(
                    0,
                    5000
                );


            if (!streamId) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Stream ID is required."
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
                        recording_url
                    )
                    VALUES (
                        $1,
                        $2,
                        $3,
                        $4,
                        $5
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
                "Create recording failed:",
                error.message
            );


            return res.status(500).json({
                success: false,
                message:
                    "Unable to save recording."
            });

        }

    }
);
/* =========================================================
   DELETE CHAT MESSAGE
========================================================= */

app.delete(
    "/api/streams/:id/chat/:messageId",
    authenticateUser,
    async (req, res) => {

        try {

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
                !Number.isFinite(
                    messageId
                )
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Invalid stream or message ID."
                });

            }


            const result =
                await pool.query(
                    `
                    DELETE FROM chat_messages
                    WHERE
                        id = $1
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


            if (
                result.rows.length === 0
            ) {

                return res.status(404).json({
                    success: false,
                    message:
                        "Message not found."
                });

            }


            io.to(
                getStreamRoom(
                    streamId
                )
            ).emit(
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
                "Delete chat message failed:",
                error.message
            );


            return res.status(500).json({
                success: false,
                message:
                    "Unable to delete chat message."
            });

        }

    }
);


/* =========================================================
   SUPPORT / GIFT FOUNDATION
   Kept for existing frontend compatibility.
========================================================= */

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
                        "Stream ID is required."
                });

            }


            const payload = {
                streamId,

                userId:
                    req.user.id,

                username:
                    req.user.username,

                gift
            };


            io.to(
                getStreamRoom(
                    streamId
                )
            ).emit(
                "support",
                payload
            );


            return res.json({
                success: true,

                support:
                    payload
            });


        } catch (error) {

            console.error(
                "Support failed:",
                error.message
            );


            return res.status(500).json({
                success: false,
                message:
                    "Unable to send support."
            });

        }

    }
);


/* =========================================================
   GLOBAL STREAM BROADCAST HELPER
========================================================= */

function broadcastStreamUpdate(
    streamId,
    event,
    data = {}
) {

    const cleanStreamId =
        normalizeStreamId(
            streamId
        );


    if (!cleanStreamId) {
        return;
    }


    const payload = {
        streamId:
            cleanStreamId,

        ...data
    };


    io.to(
        getStreamRoom(
            cleanStreamId
        )
    ).emit(
        event,
        payload
    );


    return payload;

}


/* =========================================================
   HEALTH CHECK
========================================================= */

app.get(
    "/",
    (req, res) => {

        res.json({
            success: true,

            app:
                "Canvas",

            status:
                "online",

            socket:
                true
        });

    }
);


app.get(
    "/health",
    (req, res) => {

        res.json({
            success: true,

            status:
                "ok",

            database:
                Boolean(pool),

            socket:
                true
        });

    }
);


/* =========================================================
   API FALLBACK
========================================================= */

app.get(
    "/api",
    (req, res) => {

        res.json({
            success: true,

            message:
                "Canvas API is online.",

            socket:
                true
        });

    }
);


/* =========================================================
   API 404
========================================================= */

app.use(
    "/api",
    (req, res) => {

        res.status(404).json({
            success: false,

            message:
                "API endpoint not found.",

            path:
                req.originalUrl
        });

    }
);


/* =========================================================
   GLOBAL ERROR HANDLER
========================================================= */

app.use(
    (
        error,
        req,
        res,
        next
    ) => {

        console.error(
            "Unhandled Express error:",
            error
        );


        if (
            res.headersSent
        ) {

            return next(
                error
            );

        }


        return res.status(500).json({
            success: false,

            message:
                "Internal server error."
        });

    }
);


/* =========================================================
   SESSION CLEANUP
========================================================= */

const sessionCleanupTimer =
    setInterval(
        async () => {

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

        },
        60 * 60 * 1000
    );


/* =========================================================
   VERIFICATION CODE CLEANUP
========================================================= */

const verificationCleanupTimer =
    setInterval(
        () => {

            const now =
                Date.now();


            for (
                const [
                    email,
                    data
                ]
                of signupVerificationCodes
            ) {

                if (
                    !data ||
                    now >
                    data.expiresAt
                ) {

                    signupVerificationCodes.delete(
                        email
                    );

                }

            }

        },
        60 * 1000
    );


/* =========================================================
   PROCESS ERROR HANDLERS
========================================================= */

process.on(
    "uncaughtException",
    (error) => {

        console.error(
            "Uncaught exception:",
            error
        );

    }
);


process.on(
    "unhandledRejection",
    (error) => {

        console.error(
            "Unhandled rejection:",
            error
        );

    }
);


/* =========================================================
   GRACEFUL SHUTDOWN
========================================================= */

let isShuttingDown =
    false;


async function shutdown(
    signal
) {

    if (isShuttingDown) {
        return;
    }


    isShuttingDown =
        true;


    console.log(
        `${signal} received. Shutting down Canvas...`
    );


    clearInterval(
        sessionCleanupTimer
    );


    clearInterval(
        verificationCleanupTimer
    );


    /*
     * Tell connected Watch clients that the socket
     * server is shutting down.
     */

    io.emit(
        "server-shutdown",
        {
            message:
                "Canvas server is shutting down."
        }
    );


    try {

        await new Promise(
            (
                resolve
            ) => {

                io.close(
                    () => {
                        resolve();
                    }
                );

            }
        );

    } catch (error) {

        console.error(
            "Socket shutdown failed:",
            error.message
        );

    }


    try {

        if (pool) {

            await pool.end();

        }

    } catch (error) {

        console.error(
            "Database shutdown failed:",
            error.message
        );

    }


    try {

        httpServer.close(
            () => {

                console.log(
                    "Canvas server stopped."
                );

                process.exit(
                    0
                );

            }
        );

    } catch (error) {

        console.error(
            "HTTP shutdown failed:",
            error.message
        );

        process.exit(
            0
        );

    }


    setTimeout(
        () => {
            process.exit(
                0
            );
        },
        5000
    );

}


process.on(
    "SIGTERM",
    () => {
        shutdown(
            "SIGTERM"
        );
    }
);


process.on(
    "SIGINT",
    () => {
        shutdown(
            "SIGINT"
        );
    }
);


/* =========================================================
   START SERVER
========================================================= */

async function startServer() {

    try {

        await initializeDatabase();

        await ensureFollowTable();

        await ensureChatTable();

        await ensureRecordingsTable();


        /*
         * The streams table may already exist from the
         * existing Canvas Go Live implementation.
         *
         * Create it only if it does not exist so the server
         * can start cleanly on a fresh PostgreSQL database.
         */

        if (pool) {

            await pool.query(
                `
                CREATE TABLE IF NOT EXISTS streams (
                    id BIGSERIAL PRIMARY KEY,

                    user_id INTEGER NOT NULL
                        REFERENCES users(id)
                        ON DELETE CASCADE,

                    title TEXT DEFAULT '',

                    status TEXT DEFAULT 'live',

                    created_at TIMESTAMP
                        DEFAULT CURRENT_TIMESTAMP,

                    ended_at TIMESTAMP
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
                idx_streams_status
                ON streams(status)
                `
            );

        }


        httpServer.listen(
            PORT,
            "0.0.0.0",
            () => {

                console.log(
                    "========================================"
                );

                console.log(
                    "Canvas server is running"
                );

                console.log(
                    `Port: ${PORT}`
                );

                console.log(
                    `Database: ${
                        pool
                            ? "configured"
                            : "not configured"
                    }`
                );

                console.log(
                    "Socket.IO: enabled"
                );

                console.log(
                    "========================================"
                );

            }
        );


    } catch (error) {

        console.error(
            "Failed to start Canvas server:",
            error
        );


        process.exit(
            1
        );

    }

}


startServer();


  
