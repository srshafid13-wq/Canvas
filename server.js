const express = require("express");
const { Pool } = require("pg");
const crypto = require("crypto");
const http = require("http");
const { Server } = require("socket.io");

const app = express();
const httpServer = http.createServer(app);

const PORT = process.env.PORT || 3000;


/* =========================================
   CANVAS SOCKET.IO
========================================= */

const io = new Server(httpServer, {

    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }

});


/* =========================================
   BASIC APP CONFIG
========================================= */

app.use(express.json({
    limit: "50mb"
}));

app.use((req, res, next) => {

    res.header("Access-Control-Allow-Origin", "*");

    res.header(
        "Access-Control-Allow-Methods",
        "GET,POST,PUT,DELETE,OPTIONS"
    );

    res.header(
        "Access-Control-Allow-Headers",
        "Content-Type, Authorization"
    );

    if (req.method === "OPTIONS") {
        return res.sendStatus(200);
    }

    next();

});


/* =========================================
   DATABASE
========================================= */

let pool = null;

if (process.env.canvas_db_r13t) {

    pool = new Pool({
        connectionString: process.env.canvas_db_r13t,

        ssl: {
            rejectUnauthorized: false
        }
    });

}


/* =========================================
   HELPERS
========================================= */

function hashToken(token) {

    return crypto
        .createHash("sha256")
        .update(token)
        .digest("hex");

}


function cleanUsername(username) {

    return String(username || "")
        .replace(/^@/, "")
        .trim()
        .toLowerCase();

}


/* =========================================
   AUTHENTICATE USER
========================================= */

async function authenticateUser(req, res, next) {

    try {

        const header =
            req.headers.authorization || "";

        const token =
            header.startsWith("Bearer ")
                ? header.slice(7).trim()
                : "";

        if (!token) {

            return res.status(401).json({
                success: false,
                message: "Authentication required"
            });

        }

        if (!pool) {

            return res.status(500).json({
                success: false,
                message: "Database unavailable"
            });

        }

        const tokenHash =
            hashToken(token);

        const result = await pool.query(
            `
            SELECT
                u.id,
                u.name,
                u.username,
                u.email
            FROM sessions s
            INNER JOIN users u
                ON u.id = s.user_id
            WHERE s.token_hash = $1
              AND s.expires_at > CURRENT_TIMESTAMP
            LIMIT 1
            `,
            [tokenHash]
        );

        if (!result.rows.length) {

            return res.status(401).json({
                success: false,
                message: "Invalid or expired session"
            });

        }

        req.user = result.rows[0];

        next();

    } catch (error) {

        console.error(
            "Authentication error:",
            error
        );

        return res.status(500).json({
            success: false,
            message: "Authentication failed"
        });

    }

}


/* =========================================
   GET USER BY USERNAME
========================================= */

async function getUserByUsername(username) {

    if (!pool) {
        return null;
    }

    const cleaned =
        cleanUsername(username);

    if (!cleaned) {
        return null;
    }

    const result = await pool.query(
        `
        SELECT
            u.id,
            u.name,
            u.username,
            u.email
        FROM users u
        WHERE LOWER(u.username) = $1
        LIMIT 1
        `,
        [cleaned]
    );

    return result.rows[0] || null;

}


/* =========================================
   SOCKET.IO AUTHENTICATION
========================================= */

async function authenticateSocket(socket) {

    try {

        const token =
            socket.handshake.auth?.token ||
            socket.handshake.query?.token ||
            "";

        if (!token || !pool) {
            return null;
        }

        const tokenHash =
            hashToken(token);

        const result = await pool.query(
            `
            SELECT
                u.id,
                u.name,
                u.username,
                u.email
            FROM sessions s
            INNER JOIN users u
                ON u.id = s.user_id
            WHERE s.token_hash = $1
              AND s.expires_at > CURRENT_TIMESTAMP
            LIMIT 1
            `,
            [tokenHash]
        );

        return result.rows[0] || null;

    } catch (error) {

        console.error(
            "Socket authentication error:",
            error
        );

        return null;

    }

}


/* =========================================
   VIEWER ROOMS
========================================= */

const viewerRooms = new Map();


/* =========================================
   CHAT ROOMS
========================================= */

const chatRooms = new Map();

const MAX_CHAT_MESSAGES = 100;


function getChatMessages(streamId) {

    const key = String(streamId);

    if (!chatRooms.has(key)) {
        chatRooms.set(key, []);
    }

    return chatRooms.get(key);

}


function addChatMessage(streamId, message) {

    const messages =
        getChatMessages(streamId);

    messages.push(message);

    if (messages.length > MAX_CHAT_MESSAGES) {

        messages.splice(
            0,
            messages.length - MAX_CHAT_MESSAGES
        );

    }

}


/* =========================================
   STREAM ROOM NAME
========================================= */

function getStreamRoom(streamId) {

    return `stream:${String(streamId)}`;

      }
/* =========================================
   DATABASE TABLE SETUP
========================================= */

async function initializeDatabase() {

    if (!pool) {

        console.log(
            "Database: NOT CONFIGURED"
        );

        return;

    }

    try {

        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);


        await pool.query(`
            CREATE TABLE IF NOT EXISTS profiles (
                user_id INTEGER PRIMARY KEY
                    REFERENCES users(id)
                    ON DELETE CASCADE,

                bio TEXT DEFAULT '',
                profile_picture TEXT DEFAULT '',

                created_at TIMESTAMP
                    DEFAULT CURRENT_TIMESTAMP,

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

                expires_at TIMESTAMP NOT NULL,

                created_at TIMESTAMP
                    DEFAULT CURRENT_TIMESTAMP
            )
        `);


        await pool.query(`
            CREATE TABLE IF NOT EXISTS streams (
                id SERIAL PRIMARY KEY,

                user_id INTEGER NOT NULL
                    REFERENCES users(id)
                    ON DELETE CASCADE,

                title TEXT DEFAULT 'Canvas Live Stream',

                category TEXT DEFAULT 'Entertainment',

                thumbnail TEXT DEFAULT '',

                status TEXT DEFAULT 'live',

                is_live BOOLEAN DEFAULT TRUE,

                viewer_count INTEGER DEFAULT 0,

                created_at TIMESTAMP
                    DEFAULT CURRENT_TIMESTAMP,

                ended_at TIMESTAMP
            )
        `);


        /*
         * IMPORTANT:
         *
         * Self-follow is intentionally allowed.
         *
         * Do NOT add:
         *
         * CHECK (follower_id <> following_id)
         *
         * because the Canvas requirement now allows
         * a user to follow their own profile.
         */

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
                )
            )
        `);


        /*
         * Existing Canvas databases may already have
         * the old self-follow CHECK constraint.
         *
         * Remove only that restriction.
         */

        try {

            const constraints =
                await pool.query(`
                    SELECT
                        c.conname,
                        pg_get_constraintdef(c.oid)
                            AS definition
                    FROM pg_constraint c
                    INNER JOIN pg_class t
                        ON t.oid = c.conrelid
                    WHERE t.relname = 'follows'
                      AND c.contype = 'c'
                `);


            for (const constraint
                of constraints.rows) {

                const definition =
                    String(
                        constraint.definition || ""
                    ).toLowerCase();


                const isSelfFollowConstraint =
                    definition.includes("follower_id") &&
                    definition.includes("following_id") &&
                    (
                        definition.includes("<>") ||
                        definition.includes("!=")
                    );


                if (isSelfFollowConstraint) {

                    await pool.query(`
                        ALTER TABLE follows
                        DROP CONSTRAINT IF EXISTS
                        "${constraint.conname}"
                    `);

                    console.log(
                        "Removed old self-follow restriction:",
                        constraint.conname
                    );

                }

            }

        } catch (constraintError) {

            console.error(
                "Self-follow migration error:",
                constraintError
            );

        }


        console.log(
            "Database tables initialized"
        );

    } catch (error) {

        console.error(
            "Database initialization error:",
            error
        );

    }

}


/* =========================================
   FOLLOW COUNT HELPER
========================================= */

async function getFollowCounts(userId) {

    if (!pool) {

        return {
            followers_count: 0,
            following_count: 0
        };

    }


    const result = await pool.query(
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


    const row =
        result.rows[0] || {};


    return {

        followers_count:
            Number(
                row.followers_count || 0
            ),

        following_count:
            Number(
                row.following_count || 0
            )

    };

}


/* =========================================
   FOLLOW STATE HELPER
========================================= */

async function getFollowState(
    followerId,
    followingId
) {

    if (!pool) {

        return false;

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
            followerId,
            followingId
        ]
    );


    return result.rows.length > 0;

}
/* =========================================
   STREAM LOOKUP
========================================= */

async function getStreamById(streamId) {

    if (!pool) {
        return null;
    }

    const result = await pool.query(
        `
        SELECT
            s.id,
            s.title,
            s.category,
            s.thumbnail,
            s.status,
            s.is_live,
            s.created_at,
            s.ended_at,
            s.user_id,

            u.name AS creator_name,
            u.username AS creator_username,

            p.profile_picture AS creator_picture

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

    if (!result.rows.length) {
        return null;
    }

    const stream = result.rows[0];

    const counts =
        await getFollowCounts(
            stream.user_id
        );

    const viewers =
        viewerRooms.get(
            String(stream.id)
        );

    const viewerCount =
        viewers ? viewers.size : 0;


    return {

        id: stream.id,

        title:
            stream.title ||
            "Canvas Live Stream",

        category:
            stream.category ||
            "Entertainment",

        thumbnail:
            stream.thumbnail || "",

        status:
            stream.status,

        is_live:
            stream.is_live,

        created_at:
            stream.created_at,

        ended_at:
            stream.ended_at,

        user_id:
            stream.user_id,

        viewer_count:
            viewerCount,

        creator: {

            id:
                stream.user_id,

            userId:
                stream.user_id,

            name:
                stream.creator_name ||
                stream.creator_username ||
                "Canvas User",

            displayName:
                stream.creator_name ||
                stream.creator_username ||
                "Canvas User",

            username:
                stream.creator_username || "",

            profile_picture:
                stream.creator_picture || "",

            profilePicture:
                stream.creator_picture || "",

            followers_count:
                counts.followers_count,

            following_count:
                counts.following_count

        },

        creator_name:
            stream.creator_name || "",

        creator_username:
            stream.creator_username || "",

        creator_picture:
            stream.creator_picture || "",

        followers_count:
            counts.followers_count,

        following_count:
            counts.following_count

    };

}


/* =========================================
   BROADCAST VIEWER COUNT
========================================= */

function broadcastViewerCount(streamId) {

    const key =
        String(streamId);

    const viewers =
        viewerRooms.get(key);

    const count =
        viewers ? viewers.size : 0;

    const room =
        getStreamRoom(key);


    io.to(room).emit(
        "viewer-count",
        {
            streamId: key,
            stream_id: key,
            viewerCount: count,
            viewer_count: count,
            watching: count
        }
    );


    /*
     * Keep the second event because the
     * existing Watch page listens for both
     * naming styles.
     */

    io.to(room).emit(
        "watching-count",
        {
            streamId: key,
            stream_id: key,
            viewerCount: count,
            viewer_count: count,
            watching: count
        }
    );

}


/* =========================================
   REMOVE SOCKET FROM VIEWER ROOM
========================================= */

function removeSocketFromViewerRoom(socket) {

    const streamId =
        socket.currentStreamId;

    if (!streamId) {
        return;
    }

    const key =
        String(streamId);

    const viewers =
        viewerRooms.get(key);


    if (viewers) {

        viewers.delete(
            socket.id
        );


        if (viewers.size === 0) {

            viewerRooms.delete(
                key
            );

        }

    }


    socket.leave(
        getStreamRoom(key)
    );

    socket.currentStreamId = null;

    broadcastViewerCount(
        key
    );

}


/* =========================================
   ADD SOCKET TO VIEWER ROOM
========================================= */

function addSocketToViewerRoom(
    socket,
    streamId
) {

    const key =
        String(streamId);


    if (!viewerRooms.has(key)) {

        viewerRooms.set(
            key,
            new Set()
        );

    }


    const viewers =
        viewerRooms.get(key);


    /*
     * Set prevents the same socket from
     * being counted more than once.
     */

    viewers.add(
        socket.id
    );


    socket.currentStreamId =
        key;

}
/* =========================================
   FOLLOW STATUS
========================================= */

app.get(
    "/api/account/follows/:username",
    authenticateUser,
    async (req, res) => {

        try {

            const target =
                await getUserByUsername(
                    req.params.username
                );

            if (!target) {

                return res.status(404).json({
                    success: false,
                    message: "User not found"
                });

            }


            const following =
                await getFollowState(
                    req.user.id,
                    target.id
                );


            const counts =
                await getFollowCounts(
                    target.id
                );


            return res.json({

                success: true,

                following: following,

                isFollowing: following,

                /*
                 * Self-follow is intentionally allowed.
                 * Therefore this is NOT used to block
                 * the follow button.
                 */

                isSelf:
                    Number(req.user.id) ===
                    Number(target.id),

                username:
                    target.username,

                userId:
                    target.id,

                followers_count:
                    counts.followers_count,

                following_count:
                    counts.following_count

            });

        } catch (error) {

            console.error(
                "Follow status error:",
                error
            );

            return res.status(500).json({
                success: false,
                message: "Unable to load follow status"
            });

        }

    }
);


/* =========================================
   FOLLOW USER
========================================= */

app.post(
    "/api/follow/:username",
    authenticateUser,
    async (req, res) => {

        try {

            const target =
                await getUserByUsername(
                    req.params.username
                );


            if (!target) {

                return res.status(404).json({
                    success: false,
                    message: "User not found"
                });

            }


            /*
             * IMPORTANT:
             *
             * There is deliberately NO:
             *
             * if (req.user.id === target.id)
             *
             * because Canvas allows self-follow.
             */


            await pool.query(
                `
                INSERT INTO follows (
                    follower_id,
                    following_id
                )
                VALUES ($1, $2)

                ON CONFLICT (
                    follower_id,
                    following_id
                )

                DO NOTHING
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


            const myCounts =
                await getFollowCounts(
                    req.user.id
                );


            const payload = {

                username:
                    target.username,

                userId:
                    target.id,

                following: true,

                isFollowing: true,

                followers_count:
                    counts.followers_count,

                following_count:
                    counts.following_count,

                my_followers_count:
                    myCounts.followers_count,

                my_following_count:
                    myCounts.following_count

            };


            /*
             * Update everyone watching this creator's
             * stream/profile in real time.
             */

            io.emit(
                "follow-count-update",
                payload
            );


            return res.json({

                success: true,

                message: "Following",

                ...payload

            });

        } catch (error) {

            console.error(
                "Follow error:",
                error
            );

            return res.status(500).json({
                success: false,
                message: "Unable to follow user"
            });

        }

    }
);


/* =========================================
   UNFOLLOW USER
========================================= */

app.delete(
    "/api/follow/:username",
    authenticateUser,
    async (req, res) => {

        try {

            const target =
                await getUserByUsername(
                    req.params.username
                );


            if (!target) {

                return res.status(404).json({
                    success: false,
                    message: "User not found"
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
                    target.id
                ]
            );


            const counts =
                await getFollowCounts(
                    target.id
                );


            const myCounts =
                await getFollowCounts(
                    req.user.id
                );


            const payload = {

                username:
                    target.username,

                userId:
                    target.id,

                following: false,

                isFollowing: false,

                followers_count:
                    counts.followers_count,

                following_count:
                    counts.following_count,

                my_followers_count:
                    myCounts.followers_count,

                my_following_count:
                    myCounts.following_count

            };


            io.emit(
                "follow-count-update",
                payload
            );


            return res.json({

                success: true,

                message: "Unfollowed",

                ...payload

            });

        } catch (error) {

            console.error(
                "Unfollow error:",
                error
            );

            return res.status(500).json({
                success: false,
                message: "Unable to unfollow user"
            });

        }

    }
);


/* =========================================
   FOLLOW LOOKUP
========================================= */

app.get(
    "/api/follow/:username",
    authenticateUser,
    async (req, res) => {

        try {

            const target =
                await getUserByUsername(
                    req.params.username
                );


            if (!target) {

                return res.status(404).json({
                    success: false,
                    message: "User not found"
                });

            }


            const following =
                await getFollowState(
                    req.user.id,
                    target.id
                );


            const counts =
                await getFollowCounts(
                    target.id
                );


            return res.json({

                success: true,

                following: following,

                isFollowing: following,

                is_following: following,

                isSelf:
                    Number(req.user.id) ===
                    Number(target.id),

                followers_count:
                    counts.followers_count,

                following_count:
                    counts.following_count

            });

        } catch (error) {

            console.error(
                "Follow lookup error:",
                error
            );

            return res.status(500).json({
                success: false,
                message: "Unable to check follow status"
            });

        }

    }
);
/* =========================================
   SOCKET.IO CONNECTION
========================================= */

io.on("connection", async (socket) => {

    console.log(
        "Socket connected:",
        socket.id
    );


    /* -----------------------------------------
       AUTHENTICATE SOCKET
    ----------------------------------------- */

    socket.user =
        await authenticateSocket(socket);


    if (socket.user) {

        console.log(
            "Socket user:",
            socket.user.username ||
            socket.user.id
        );

    }


    socket.currentStreamId = null;


    /* =========================================
       JOIN STREAM
    ========================================= */

    socket.on(
        "join-stream",
        async (data = {}) => {

            try {

                const streamId =
                    data.streamId ||
                    data.stream_id ||
                    data.id ||
                    "";


                if (!streamId) {

                    socket.emit(
                        "stream-error",
                        {
                            message:
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
                            message:
                                "Stream not found"
                        }
                    );

                    return;

                }


                /*
                 * If this socket was already watching
                 * another stream, remove it first.
                 */

                if (
                    socket.currentStreamId &&
                    String(
                        socket.currentStreamId
                    ) !== String(streamId)
                ) {

                    removeSocketFromViewerRoom(
                        socket
                    );

                }


                const key =
                    String(streamId);

                const room =
                    getStreamRoom(key);


                /*
                 * Join the actual Socket.IO room.
                 */

                socket.join(room);


                /*
                 * Add this socket to the viewer Set.
                 *
                 * Set prevents duplicate counting if
                 * join-stream is emitted twice.
                 */

                addSocketToViewerRoom(
                    socket,
                    key
                );


                /*
                 * Tell this viewer that joining succeeded.
                 */

                socket.emit(
                    "stream-joined",
                    {
                        success: true,

                        streamId: key,

                        stream_id: key,

                        viewerCount:
                            viewerRooms.get(key)?.size || 0,

                        viewer_count:
                            viewerRooms.get(key)?.size || 0
                    }
                );


                /*
                 * Update everyone watching this stream.
                 */

                broadcastViewerCount(
                    key
                );


                /* =================================
                   SEND CHAT HISTORY
                ================================= */

                const history =
                    getChatMessages(key);


                socket.emit(
                    "chat-history",
                    {
                        streamId: key,

                        stream_id: key,

                        messages: history
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
                        message:
                            "Unable to join stream"
                    }
                );

            }

        }
    );


    /* =========================================
       JOIN STREAM ALIASES
    ========================================= */

    socket.on(
        "joinStream",
        async (data = {}) => {

            socket.emit(
                "join-stream",
                data
            );

        }
    );


    socket.on(
        "watch-stream",
        async (data = {}) => {

            socket.emit(
                "join-stream",
                data
            );

        }
    );


    /* =========================================
       LEAVE STREAM
    ========================================= */

    socket.on(
        "leave-stream",
        () => {

            removeSocketFromViewerRoom(
                socket
            );

        }
    );


    socket.on(
        "leaveStream",
        () => {

            removeSocketFromViewerRoom(
                socket
            );

        }
    );


    /* =========================================
       DISCONNECT
    ========================================= */

    socket.on(
        "disconnect",
        (reason) => {

            console.log(
                "Socket disconnected:",
                socket.id,
                reason
            );


            /*
             * Remove the viewer before the socket
             * disappears so everyone still watching
             * receives the correct count.
             */

            removeSocketFromViewerRoom(
                socket
            );

        }
    );

});
/* =========================================
   CHAT MESSAGE HANDLER
========================================= */

async function handleChatMessage(
    socket,
    data = {}
) {

    try {

        const streamId =
            data.streamId ||
            data.stream_id ||
            socket.currentStreamId ||
            "";


        if (!streamId) {

            socket.emit(
                "chat-error",
                {
                    message:
                        "You are not watching a stream"
                }
            );

            return;

        }


        const key =
            String(streamId);


        /*
         * Only allow messages from a socket that
         * actually joined this stream.
         */

        if (
            !socket.currentStreamId ||
            String(
                socket.currentStreamId
            ) !== key
        ) {

            socket.emit(
                "chat-error",
                {
                    message:
                        "Join the stream before chatting"
                }
            );

            return;

        }


        let messageText =
            data.message ??
            data.text ??
            data.content ??
            "";


        messageText =
            String(messageText)
                .trim();


        if (!messageText) {
            return;
        }


        /*
         * Prevent extremely large chat messages.
         */

        if (messageText.length > 500) {

            messageText =
                messageText.slice(
                    0,
                    500
                );

        }


        /*
         * IMPORTANT:
         *
         * Sender identity comes from the
         * authenticated Socket.IO session.
         *
         * We do NOT trust the username/name
         * sent by the browser.
         */

        const user =
            socket.user || null;


        const username =
            user?.username ||
            data.username ||
            data.userName ||
            "Viewer";


        const displayName =
            user?.name ||
            data.name ||
            data.displayName ||
            username;


        const messageId =
            crypto.randomUUID
                ? crypto.randomUUID()
                : crypto
                    .randomBytes(16)
                    .toString("hex");


        const message = {

            id:
                messageId,

            streamId:
                key,

            stream_id:
                key,

            userId:
                user?.id ||
                data.userId ||
                data.user_id ||
                null,

            user_id:
                user?.id ||
                data.userId ||
                data.user_id ||
                null,

            username:
                username,

            name:
                displayName,

            displayName:
                displayName,

            message:
                messageText,

            text:
                messageText,

            createdAt:
                new Date().toISOString(),

            created_at:
                new Date().toISOString()

        };


        /*
         * Keep recent messages in memory so a new
         * viewer can receive chat history.
         */

        addChatMessage(
            key,
            message
        );


        const room =
            getStreamRoom(key);


        /*
         * THIS is the important fix:
         *
         * Broadcast to the entire stream room,
         * not only to the sender.
         */

        io.to(room).emit(
            "chat-message",
            message
        );


    } catch (error) {

        console.error(
            "Chat message error:",
            error
        );


        socket.emit(
            "chat-error",
            {
                message:
                    "Unable to send message"
            }
        );

    }

}


/* =========================================
   CHAT SOCKET EVENTS
========================================= */

/*
 * Watch currently emits "chat-message".
 */

io.on("connection", (socket) => {

    socket.on(
        "chat-message",
        async (data = {}) => {

            await handleChatMessage(
                socket,
                data
            );

        }
    );


    /*
     * Keep send-chat supported as well.
     * Other Canvas pages can use this event.
     */

    socket.on(
        "send-chat",
        async (data = {}) => {

            await handleChatMessage(
                socket,
                data
            );

        }
    );

});
/* =========================================
   GET CHAT HISTORY
========================================= */

app.get(
    "/api/streams/:streamId/chat",
    async (req, res) => {

        try {

            const streamId =
                String(
                    req.params.streamId || ""
                ).trim();


            if (!streamId) {

                return res.status(400).json({
                    success: false,
                    message: "Stream ID is required"
                });

            }


            /*
             * Make sure the stream actually exists.
             */

            const stream =
                await getStreamById(
                    streamId
                );


            if (!stream) {

                return res.status(404).json({
                    success: false,
                    message: "Stream not found"
                });

            }


            const messages =
                getChatMessages(
                    streamId
                );


            return res.json({

                success: true,

                streamId:
                    streamId,

                stream_id:
                    streamId,

                messages:
                    messages

            });

        } catch (error) {

            console.error(
                "Load chat history error:",
                error
            );

            return res.status(500).json({
                success: false,
                message:
                    "Unable to load chat history"
            });

        }

    }
);


/* =========================================
   LEGACY CHAT HISTORY ROUTE
========================================= */

app.get(
    "/api/chat/:streamId",
    async (req, res) => {

        try {

            const streamId =
                String(
                    req.params.streamId || ""
                ).trim();


            if (!streamId) {

                return res.status(400).json({
                    success: false,
                    message: "Stream ID is required"
                });

            }


            const stream =
                await getStreamById(
                    streamId
                );


            if (!stream) {

                return res.status(404).json({
                    success: false,
                    message: "Stream not found"
                });

            }


            const messages =
                getChatMessages(
                    streamId
                );


            return res.json({

                success: true,

                streamId:
                    streamId,

                stream_id:
                    streamId,

                messages:
                    messages

            });

        } catch (error) {

            console.error(
                "Legacy chat history error:",
                error
            );

            return res.status(500).json({
                success: false,
                message:
                    "Unable to load chat history"
            });

        }

    }
);


/* =========================================
   CHAT CLEAR HELPER
========================================= */

function clearChatRoom(streamId) {

    const key =
        String(streamId);


    chatRooms.delete(key);

}
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

            socketio: true,

            database:
                pool
                    ? "CONFIGURED"
                    : "NOT CONFIGURED"

        });

    }
);


/* =========================================
   SERVER HEALTH
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

                console.error(
                    "Health database check error:",
                    error
                );

            }

        }


        return res.json({

            success: true,

            server: "online",

            socketio: true,

            database: database

        });

    }
);


/* =========================================
   INITIALIZE DATABASE
========================================= */

(async () => {

    try {

        await initializeDatabase();

    } catch (error) {

        console.error(
            "Startup database error:",
            error
        );

    }

})();


/* =========================================
   START SERVER
========================================= */

httpServer.listen(
    PORT,
    () => {

        console.log(
            `Canvas server running on port ${PORT}`
        );

    }
);
