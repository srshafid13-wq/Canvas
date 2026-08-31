const express = require("express");
const { Pool } = require("pg");
const crypto = require("crypto");
const http = require("http");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);

const PORT = process.env.PORT || 3000;

const io = new Server(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
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

const pool =
    databaseUrl
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
   TOKEN
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
                    users.id,
                    users.name,
                    users.username,
                    users.email,
                    users.created_at
                FROM sessions
                INNER JOIN users
                    ON users.id =
                       sessions.user_id
                WHERE sessions.token_hash = $1
                  AND sessions.expires_at >
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
                created_at TIMESTAMP
                    DEFAULT CURRENT_TIMESTAMP,
                ended_at TIMESTAMP
            );
        `);


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
            );
        `);


        await pool.query(`
            CREATE TABLE IF NOT EXISTS supports (
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


/* =========================================
   BASIC STATUS
========================================= */

app.get("/", (req, res) => {

    res.json({
        status: "online",
        message:
            "Canvas backend is running."
    });

});


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

            res.json({
                success: true,
                status: "healthy",
                database:
                    "connected"
            });

        } catch (error) {

            res.status(500).json({
                success: false,
                status: "unhealthy",
                database:
                    "connection failed"
            });

        }

    }
);


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

            res.json({
                success: true,
                database:
                    "connected",
                message:
                    "Canvas database connection is working.",
                server_time:
                    result.rows[0].now
            });

        } catch (error) {

            res.status(500).json({
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

            if (
                existing.rows.length > 0
            ) {

                const old =
                    existing.rows[0];

                if (
                    String(old.username)
                        .toLowerCase() ===
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

            return res.status(201)
                .json({
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
                hashPassword(password)
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
                    username:
                        user.username,
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
   PART 2/3 — STREAM + CHAT + SOCKET.IO
========================================= */


/* =========================================
   GET SINGLE LIVE STREAM
========================================= */

app.get(
    "/api/streams/:streamId",
    async (req,res)=>{

        try{

            const streamId =
                req.params.streamId;


            const result =
                await pool.query(
                    `
                    SELECT
                        s.*,
                        u.username,
                        u.name,
                        u.profile_picture
                    FROM streams s
                    LEFT JOIN users u
                        ON u.id = s.user_id
                    WHERE s.id = $1
                    AND s.is_live = true
                    LIMIT 1
                    `,
                    [streamId]
                );


            if(result.rows.length === 0){

                return res.status(404).json({
                    message:
                        "Live stream not found."
                });

            }


            const stream =
                result.rows[0];


            res.json({
                stream: stream
            });

        }

        catch(error){

            console.error(
                "Get stream error:",
                error
            );


            res.status(500).json({
                message:
                    "Unable to load stream."
            });

        }

    }
);


/* =========================================
   START STREAM
========================================= */

app.post(
    "/api/streams",
    authMiddleware,
    async (req,res)=>{

        try{

            const {
                title,
                category,
                description,
                thumbnail
            } = req.body;


            if(!title){

                return res.status(400).json({
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
                    AND is_live = true
                    LIMIT 1
                    `,
                    [req.user.id]
                );


            if(existing.rows.length > 0){

                return res.status(409).json({
                    message:
                        "You already have a live stream."
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
                        category,
                        description,
                        thumbnail,
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
                        true,
                        0,
                        NOW()
                    )
                    RETURNING *
                    `,
                    [
                        req.user.id,
                        title,
                        category ||
                            "Entertainment",
                        description || "",
                        thumbnail || null
                    ]
                );


            const stream =
                result.rows[0];


            /* -----------------------------
               SOCKET UPDATE
            ----------------------------- */

            io.emit(
                "stream-updated",
                stream
            );


            res.status(201).json({
                stream: stream
            });

        }

        catch(error){

            console.error(
                "Start stream error:",
                error
            );


            res.status(500).json({
                message:
                    "Unable to start stream."
            });

        }

    }
);


/* =========================================
   END STREAM
========================================= */

app.post(
    "/api/streams/:streamId/end",
    authMiddleware,
    async (req,res)=>{

        try{

            const streamId =
                req.params.streamId;


            const result =
                await pool.query(
                    `
                    UPDATE streams
                    SET
                        is_live = false,
                        ended_at = NOW()
                    WHERE id = $1
                    AND user_id = $2
                    AND is_live = true
                    RETURNING *
                    `,
                    [
                        streamId,
                        req.user.id
                    ]
                );


            if(result.rows.length === 0){

                return res.status(404).json({
                    message:
                        "Live stream not found."
                });

            }


            const stream =
                result.rows[0];


            io.to(
                "stream:" + streamId
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
                stream: stream
            });

        }

        catch(error){

            console.error(
                "End stream error:",
                error
            );


            res.status(500).json({
                message:
                    "Unable to end stream."
            });

        }

    }
);


/* =========================================
   CHAT TABLE
========================================= */

async function ensureChatTable(){

    try{

        await pool.query(
            `
            CREATE TABLE IF NOT EXISTS
            stream_chat
            (
                id SERIAL PRIMARY KEY,

                stream_id INTEGER NOT NULL,

                user_id INTEGER NOT NULL,

                message TEXT NOT NULL,

                created_at TIMESTAMP
                    DEFAULT NOW()
            )
            `
        );


        console.log(
            "Chat table ready."
        );

    }

    catch(error){

        console.error(
            "Chat table error:",
            error
        );

    }

}


ensureChatTable();


/* =========================================
   SEND CHAT MESSAGE
========================================= */

app.post(
    "/api/streams/:streamId/chat",
    authMiddleware,
    async (req,res)=>{

        try{

            const streamId =
                req.params.streamId;


            const message =
                String(
                    req.body.message || ""
                ).trim();


            if(!message){

                return res.status(400).json({
                    message:
                        "Message cannot be empty."
                });

            }


            if(message.length > 500){

                return res.status(400).json({
                    message:
                        "Message is too long."
                });

            }


            /* -----------------------------
               VERIFY LIVE STREAM
            ----------------------------- */

            const streamResult =
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


            if(
                streamResult.rows.length === 0
            ){

                return res.status(404).json({
                    message:
                        "This stream is no longer live."
                });

            }


            /* -----------------------------
               SAVE CHAT
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
                    RETURNING *
                    `,
                    [
                        streamId,
                        req.user.id,
                        message
                    ]
                );


            const chatRow =
                result.rows[0];


            /* -----------------------------
               GET USER INFO
            ----------------------------- */

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
                    [req.user.id]
                );


            const user =
                userResult.rows[0] || {};


            const chatMessage = {

                id:
                    chatRow.id,

                streamId:
                    Number(streamId),

                userId:
                    req.user.id,

                username:
                    user.username ||
                    "User",

                name:
                    user.name ||
                    user.username ||
                    "User",

                message:
                    chatRow.message,

                created_at:
                    chatRow.created_at

            };


            /* -----------------------------
               BROADCAST
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

        }

        catch(error){

            console.error(
                "Send chat error:",
                error
            );


            res.status(500).json({
                message:
                    "Unable to send chat message."
            });

        }

    }
);


/* =========================================
   GET CHAT HISTORY
========================================= */

app.get(
    "/api/streams/:streamId/chat",
    async (req,res)=>{

        try{

            const streamId =
                req.params.streamId;


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
                    [streamId]
                );


            const messages =
                result.rows.map(row => ({

                    id:
                        row.id,

                    streamId:
                        Number(row.stream_id),

                    userId:
                        row.user_id,

                    username:
                        row.username ||
                        "User",

                    name:
                        row.name ||
                        row.username ||
                        "User",

                    message:
                        row.message,

                    created_at:
                        row.created_at

                }));


            res.json({
                messages:
                    messages
            });

        }

        catch(error){

            console.error(
                "Chat history error:",
                error
            );


            res.status(500).json({
                message:
                    "Unable to load chat."
            });

        }

    }
);


/* =========================================
   FOLLOW CREATOR
========================================= */

async function ensureFollowTable(){

    try{

        await pool.query(
            `
            CREATE TABLE IF NOT EXISTS
            follows
            (
                id SERIAL PRIMARY KEY,

                follower_id INTEGER NOT NULL,

                following_id INTEGER NOT NULL,

                created_at TIMESTAMP
                    DEFAULT NOW(),

                UNIQUE
                (
                    follower_id,
                    following_id
                )
            )
            `
        );

        console.log(
            "Follow table ready."
        );

    }

    catch(error){

        console.error(
            "Follow table error:",
            error
        );

    }

}


ensureFollowTable();


app.post(
    "/api/follow",
    authMiddleware,
    async (req,res)=>{

        try{

            const creatorId =
                req.body.userId;


            if(!creatorId){

                return res.status(400).json({
                    message:
                        "Creator ID is required."
                });

            }


            if(
                Number(creatorId) ===
                Number(req.user.id)
            ){

                return res.status(400).json({
                    message:
                        "You cannot follow yourself."
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
                    creatorId
                ]
            );


            res.json({
                success: true,
                following: true
            });

        }

        catch(error){

            console.error(
                "Follow error:",
                error
            );


            res.status(500).json({
                message:
                    "Unable to follow creator."
            });

        }

    }
);


/* =========================================
   SOCKET.IO
========================================= */

io.on(
    "connection",
    function(socket){

        console.log(
            "Canvas socket connected:",
            socket.id
        );


        /* ================================
           JOIN STREAM
        ================================= */

        socket.on(
            "join-stream",
            async function(data){

                try{

                    if(!data) return;


                    const streamId =
                        data.streamId;


                    if(!streamId) return;


                    const room =
                        "stream:" +
                        streamId;


                    socket.join(
                        room
                    );


                    /* -------------------------
                       INCREASE VIEWERS
                    ------------------------- */

                    const result =
                        await pool.query(
                            `
                            UPDATE streams
                            SET viewer_count =
                                COALESCE(
                                    viewer_count,
                                    0
                                ) + 1
                            WHERE id = $1
                            AND is_live = true
                            RETURNING
                                id,
                                viewer_count
                            `,
                            [streamId]
                        );


                    if(
                        result.rows.length > 0
                    ){

                        io.to(room).emit(
                            "viewer-count",
                            {
                                streamId:
                                    streamId,

                                count:
                                    result.rows[0]
                                        .viewer_count
                            }
                        );

                    }

                }

                catch(error){

                    console.error(
                        "Join stream error:",
                        error
                    );

                }

            }
        );


        /* ================================
           LEAVE STREAM
        ================================= */

        socket.on(
            "leave-stream",
            async function(data){

                try{

                    if(!data) return;


                    const streamId =
                        data.streamId;


                    if(!streamId) return;


                    const room =
                        "stream:" +
                        streamId;


                    socket.leave(
                        room
                    );


                    const result =
                        await pool.query(
                            `
                            UPDATE streams
                            SET viewer_count =
                                GREATEST(
                                    COALESCE(
                                        viewer_count,
                                        0
                                    ) - 1,
                                    0
                                )
                            WHERE id = $1
                            AND is_live = true
                            RETURNING
                                id,
                                viewer_count
                            `,
                            [streamId]
                        );


                    if(
                        result.rows.length > 0
                    ){

                        io.to(room).emit(
                            "viewer-count",
                            {
                                streamId:
                                    streamId,

                                count:
                                    result.rows[0]
                                        .viewer_count
                            }
                        );

                    }

                }

                catch(error){

                    console.error(
                        "Join stream error:",
                        error
                    );

                }

            }
        );


        /* ================================
           LEAVE STREAM
        ================================= */

        socket.on(
            "leave-stream",
            async function(data){

                try{

                    if(!data) return;


                    const streamId =
                        data.streamId;


                    if(!streamId) return;


                    const room =
                        "stream:" +
                        streamId;


                    socket.leave(
                        room
                    );


                    const result =
                        await pool.query(
                            `
                            UPDATE streams
                            SET viewer_count =
                                GREATEST(
                                    COALESCE(
                                        viewer_count,
                                        0
                                    ) - 1,
                                    0
                                )
                            WHERE id = $1
                            AND is_live = true
                            RETURNING
                                id,
                                viewer_count
                            `,
                            [streamId]
                        );


                    if(
                        result.rows.length > 0
                    ){

                        io.to(room).emit(
                            "viewer-count",
                            {
                                streamId:
                                    streamId,

                                count:
                                    result.rows[0]
                                        .viewer_count
                            }
                        );

                    }

                }

                catch(error){

                    console.error(
                        "Leave stream error:",
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
            function(){

                console.log(
                    "Canvas socket disconnected:",
                    socket.id
                );

            }
        );

    }
);
/* =========================================
   PART 3/3 — SUPPORT + DISCOVERY + SERVER
========================================= */


/* =========================================
   SUPPORT TABLE
========================================= */

async function ensureSupportTable(){

    try{

        await pool.query(
            `
            CREATE TABLE IF NOT EXISTS
            stream_support
            (
                id SERIAL PRIMARY KEY,

                sender_id INTEGER NOT NULL,

                creator_id INTEGER NOT NULL,

                stream_id INTEGER,

                amount NUMERIC(12,2)
                    NOT NULL,

                type VARCHAR(20)
                    DEFAULT 'money',

                gift VARCHAR(100),

                emoji VARCHAR(20),

                created_at TIMESTAMP
                    DEFAULT NOW()
            )
            `
        );


        console.log(
            "Support table ready."
        );

    }

    catch(error){

        console.error(
            "Support table error:",
            error
        );

    }

}


ensureSupportTable();


/* =========================================
   SEND SUPPORT / GIFT
========================================= */

app.post(
    "/api/support",
    authMiddleware,
    async (req,res)=>{

        try{

            const {
                creatorId,
                streamId,
                amount,
                type,
                gift,
                emoji
            } = req.body;


            const creator =
                Number(creatorId);


            const value =
                Number(amount);


            if(!creator){

                return res.status(400).json({
                    message:
                        "Creator information is required."
                });

            }


            if(
                !Number.isFinite(value) ||
                value <= 0
            ){

                return res.status(400).json({
                    message:
                        "Invalid support amount."
                });

            }


            if(
                value > 10000
            ){

                return res.status(400).json({
                    message:
                        "Support amount is too large."
                });

            }


            /* -----------------------------
               VERIFY CREATOR
            ----------------------------- */

            const creatorResult =
                await pool.query(
                    `
                    SELECT id
                    FROM users
                    WHERE id = $1
                    LIMIT 1
                    `,
                    [creator]
                );


            if(
                creatorResult.rows.length === 0
            ){

                return res.status(404).json({
                    message:
                        "Creator not found."
                });

            }


            /* -----------------------------
               VERIFY STREAM
            ----------------------------- */

            if(streamId){

                const streamResult =
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
                            creator
                        ]
                    );


                if(
                    streamResult.rows.length === 0
                ){

                    return res.status(404).json({
                        message:
                            "Stream not found."
                    });

                }

            }


            /* -----------------------------
               SAVE SUPPORT
            ----------------------------- */

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
                    VALUES
                    (
                        $1,
                        $2,
                        $3,
                        $4,
                        $5,
                        $6,
                        $7
                    )
                    RETURNING *
                    `,
                    [
                        req.user.id,
                        creator,
                        streamId || null,
                        value,
                        type === "gift"
                            ? "gift"
                            : "money",
                        gift || null,
                        emoji || null
                    ]
                );


            const support =
                result.rows[0];


            /* -----------------------------
               REAL-TIME SUPPORT EVENT
            ----------------------------- */

            if(streamId){

                io.to(
                    "stream:" + streamId
                ).emit(
                    "support-received",
                    {
                        id:
                            support.id,

                        streamId:
                            streamId,

                        creatorId:
                            creator,

                        amount:
                            Number(
                                support.amount
                            ),

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
                    id:
                        support.id,

                    amount:
                        Number(
                            support.amount
                        ),

                    type:
                        support.type,

                    gift:
                        support.gift,

                    emoji:
                        support.emoji
                }

            });

        }

        catch(error){

            console.error(
                "Support error:",
                error
            );


            res.status(500).json({
                message:
                    "Unable to send support."
            });

        }

    }
);


/* =========================================
   LIVE STREAM DISCOVERY
========================================= */

app.get(
    "/api/streams",
    async (req,res)=>{

        try{

            const result =
                await pool.query(
                    `
                    SELECT
                        s.*,

                        u.username,

                        u.name,

                        u.profile_picture

                    FROM streams s

                    LEFT JOIN users u
                        ON u.id = s.user_id

                    WHERE s.is_live = true

                    ORDER BY
                        s.created_at DESC

                    LIMIT 100
                    `
                );


            res.json({
                streams:
                    result.rows
            });

        }

        catch(error){

            console.error(
                "Stream discovery error:",
                error
            );


            res.status(500).json({
                message:
                    "Unable to load live streams."
            });

        }

    }
);


/* =========================================
   STREAM SEARCH
========================================= */

app.get(
    "/api/search/streams",
    async (req,res)=>{

        try{

            const query =
                String(
                    req.query.q || ""
                ).trim();


            if(!query){

                return res.json({
                    streams: []
                });

            }


            const search =
                "%" +
                query +
                "%";
          const result =
                await pool.query(
                    `
                    SELECT
                        s.*,

                        u.username,

                        u.name,

                        u.profile_picture

                    FROM streams s

                    LEFT JOIN users u
                        ON u.id = s.user_id

                    WHERE
                        s.is_live = true

                    AND
                    (
                        s.title ILIKE $1

                        OR
                        s.category ILIKE $1

                        OR
                        u.username ILIKE $1

                        OR
                        u.name ILIKE $1
                    )

                    ORDER BY
                        s.created_at DESC

                    LIMIT 50
                    `,
                    [search]
                );


            res.json({
                streams:
                    result.rows
            });

        }

        catch(error){

            console.error(
                "Stream search error:",
                error
            );


            res.status(500).json({
                message:
                    "Unable to search streams."
            });

        }

    }
);


/* =========================================
   CURRENT USER FOLLOWING STATUS
========================================= */

app.get(
    "/api/follow/:creatorId",
    authMiddleware,
    async (req,res)=>{

        try{

            const creatorId =
                req.params.creatorId;


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
                        creatorId
                    ]
                );


            res.json({
                following:
                    result.rows.length > 0
            });

        }

        catch(error){

            console.error(
                "Follow status error:",
                error
            );


            res.status(500).json({
                message:
                    "Unable to check follow status."
            });

        }

    }
);


/* =========================================
   REMOVE FOLLOW
========================================= */

app.delete(
    "/api/follow/:creatorId",
    authMiddleware,
    async (req,res)=>{

        try{

            const creatorId =
                req.params.creatorId;


            await pool.query(
                `
                DELETE FROM follows
                WHERE follower_id = $1
                AND following_id = $2
                `,
                [
                    req.user.id,
                    creatorId
                ]
            );


            res.json({
                success: true,
                following: false
            });

        }

        catch(error){

            console.error(
                "Unfollow error:",
                error
            );


            res.status(500).json({
                message:
                    "Unable to unfollow creator."
            });

        }

    }
);


/* =========================================
   HEALTH CHECK
========================================= */

app.get(
    "/",
    function(req,res){

        res.json({
            success: true,

            message:
                "Canvas server is running.",

            socket:
                "enabled"

        });

    }
);


/* =========================================
   API HEALTH
========================================= */

app.get(
    "/api/health",
    async function(req,res){

        try{

            await pool.query(
                "SELECT 1"
            );


            res.json({

                success: true,

                server:
                    "online",

                database:
                    "connected",

                socket:
                    "enabled"

            });

        }

        catch(error){

            console.error(
                "Health check error:",
                error
            );


            res.status(500).json({

                success: false,

                server:
                    "online",

                database:
                    "error"

            });

        }

    }
);


/* =========================================
   404 API HANDLER
========================================= */

app.use(
    "/api",
    function(req,res){

        res.status(404).json({

            success: false,

            message:
                "Canvas API endpoint not found.",

            path:
                req.originalUrl

        });

    }
);


/* =========================================
   GLOBAL ERROR HANDLER
========================================= */

app.use(
    function(error,req,res,next){

        console.error(
            "Canvas server error:",
            error
        );


        if(res.headersSent){

            return next(error);

        }


        res.status(500).json({

            success: false,

            message:
                "Canvas server error."

        });

    }
);


/* =========================================
   START SERVER
========================================= */

const PORT =
    process.env.PORT ||
    10000;


server.listen(
    PORT,
    function(){

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
            "================================="
        );

    }
);
