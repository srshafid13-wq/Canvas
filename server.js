/* =========================================
   CANVAS SERVER — PART 1/8
========================================= */

const express = require("express");
const { Pool } = require("pg");
const crypto = require("crypto");
const http = require("http");
const { Server } = require("socket.io");

const app = express();
const httpServer = http.createServer(app);

const io = new Server(httpServer, {
    cors: {
        origin: "*",
        methods: [
            "GET",
            "POST",
            "PUT",
            "DELETE"
        ]
    }
});

const PORT =
    process.env.PORT || 3000;


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

    if(req.method === "OPTIONS"){
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
            connectionString:
                databaseUrl,

            ssl: {
                rejectUnauthorized:
                    false
            }
        })
        : null;


/* =========================================
   PASSWORD HASH
========================================= */

function hashPassword(password){

    return crypto
        .createHash("sha256")
        .update(String(password))
        .digest("hex");

}


/* =========================================
   USERNAME CLEANER
========================================= */

function cleanUsername(username){

    return String(username || "")
        .trim()
        .replace(/^@/, "")
        .toLowerCase();

}


/* =========================================
   AUTH TOKEN
========================================= */

function createAuthToken(){

    return crypto
        .randomBytes(32)
        .toString("hex");

}


function hashToken(token){

    return crypto
        .createHash("sha256")
        .update(String(token))
        .digest("hex");

}


/* =========================================
   AUTHENTICATION
========================================= */

async function authenticateUser(
    req,
    res,
    next
){

    if(!pool){

        return res.status(500).json({
            success: false,
            message:
                "Database is not configured."
        });

    }


    const authorization =
        req.headers.authorization || "";


    if(
        !authorization.startsWith(
            "Bearer "
        )
    ){

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


    if(!token){

        return res.status(401).json({
            success: false,
            message:
                "Authentication token is missing."
        });

    }


    try{

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

                WHERE sessions.token_hash = $1

                AND sessions.expires_at >
                    CURRENT_TIMESTAMP

                LIMIT 1
                `,
                [tokenHash]
            );


        if(
            result.rows.length === 0
        ){

            return res.status(401).json({
                success: false,
                message:
                    "Invalid or expired authentication token."
            });

        }


        req.user =
            result.rows[0];

        next();

    }

    catch(error){

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
   BASIC SERVER TEST
========================================= */

app.get("/", (req,res) => {

    res.json({

        status:
            "online",

        message:
            "Canvas backend is running."

    });

});


/* =========================================
   DATABASE TEST
========================================= */

app.get(
    "/api/database-test",
    async (req,res) => {

        if(!pool){

            return res.status(500).json({

                success:false,

                database:
                    "not connected",

                message:
                    "Database environment variable was not found."

            });

        }


        try{

            const result =
                await pool.query(
                    "SELECT NOW()"
                );


            res.json({

                success:true,

                database:
                    "connected",

                message:
                    "Canvas database connection is working.",

                server_time:
                    result.rows[0].now

            });

        }

        catch(error){

            console.error(
                "Database test failed:",
                error.message
            );


            res.status(500).json({

                success:false,

                database:
                    "connection failed",

                message:
                    error.message

            });

        }

    }
);
<!-- =========================================
     CANVAS SERVER — PART 2/8
========================================= -->

/* =========================================
   DATABASE INITIALIZATION
========================================= */

async function initializeDatabase(){

    if(!pool){

        console.log(
            "Database environment variable not found."
        );

        return;

    }

    try{

        /* USERS */

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


        /* PROFILES */

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


        /* SESSIONS */

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


        /* STREAMS */

        await pool.query(`
            CREATE TABLE IF NOT EXISTS streams (

                id SERIAL PRIMARY KEY,

                user_id INTEGER
                    REFERENCES users(id)
                    ON DELETE CASCADE,

                title VARCHAR(255)
                    DEFAULT 'Canvas Live Stream',

                status VARCHAR(30)
                    DEFAULT 'live',

                created_at TIMESTAMP
                    DEFAULT CURRENT_TIMESTAMP,

                ended_at TIMESTAMP
            );
        `);


        /* RECORDINGS */

        await pool.query(`
            CREATE TABLE IF NOT EXISTS stream_recordings (

                id SERIAL PRIMARY KEY,

                stream_id INTEGER UNIQUE NOT NULL
                    REFERENCES streams(id)
                    ON DELETE CASCADE,

                user_id INTEGER NOT NULL
                    REFERENCES users(id)
                    ON DELETE CASCADE,

                recording_url TEXT DEFAULT '',

                duration_seconds INTEGER
                    DEFAULT 0,

                created_at TIMESTAMP
                    DEFAULT CURRENT_TIMESTAMP
            );
        `);


        console.log(
            "Canvas database initialized."
        );

    }

    catch(error){

        console.error(
            "Database initialization failed:",
            error.message
        );

    }

}


/* =========================================
   FEATURE TABLES
========================================= */

async function initializeFeatureTables(){

    if(!pool){
        return;
    }

    try{

        /* CHAT */

        await pool.query(`
            CREATE TABLE IF NOT EXISTS stream_messages (

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


        /* FOLLOWS */

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


        /* SUPPORT / GIFTS */

        await pool.query(`
            CREATE TABLE IF NOT EXISTS stream_support (

                id SERIAL PRIMARY KEY,

                stream_id INTEGER NOT NULL
                    REFERENCES streams(id)
                    ON DELETE CASCADE,

                sender_id INTEGER NOT NULL
                    REFERENCES users(id)
                    ON DELETE CASCADE,

                creator_id INTEGER NOT NULL
                    REFERENCES users(id)
                    ON DELETE CASCADE,

                amount NUMERIC(12,2)
                    DEFAULT 0,

                support_type VARCHAR(30)
                    DEFAULT 'money',

                gift_name VARCHAR(100)
                    DEFAULT '',

                gift_emoji VARCHAR(20)
                    DEFAULT '',

                created_at TIMESTAMP
                    DEFAULT CURRENT_TIMESTAMP
            );
        `);


        console.log(
            "Canvas feature tables initialized."
        );

    }

    catch(error){

        console.error(
            "Feature tables failed:",
            error.message
        );

    }

  }
/* =========================================
   CANVAS SERVER — PART 3/8
========================================= */


/* =========================================
   SIGNUP
========================================= */

app.post(
    "/api/signup",
    async (req,res) => {

        const {
            name,
            username,
            email,
            password
        } = req.body;


        if(
            !name ||
            !username ||
            !email ||
            !password
        ){

            return res.status(400).json({

                success:false,

                message:
                    "All fields are required."

            });

        }


        if(
            String(password).length < 8
        ){

            return res.status(400).json({

                success:false,

                message:
                    "Password must be at least 8 characters."

            });

        }


        if(!pool){

            return res.status(500).json({

                success:false,

                message:
                    "Database is not configured."

            });

        }


        try{

            const cleanName =
                String(name).trim();

            const cleanUser =
                cleanUsername(username);

            const cleanEmail =
                String(email)
                    .trim()
                    .toLowerCase();


            if(
                !/^[a-zA-Z0-9_.]+$/.test(
                    cleanUser
                )
            ){

                return res.status(400).json({

                    success:false,

                    message:
                        "Invalid username."

                });

            }


            const existing =
                await pool.query(
                    `
                    SELECT id,username,email
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


            if(existing.rows.length){

                const old =
                    existing.rows[0];


                if(
                    old.username.toLowerCase()
                    === cleanUser
                ){

                    return res.status(409).json({

                        success:false,

                        message:
                            "Username already exists."

                    });

                }


                return res.status(409).json({

                    success:false,

                    message:
                        "Email already exists."

                });

            }


            const passwordHash =
                hashPassword(password);


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

                    VALUES($1,$2,$3,$4)

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
                result.rows[0];


            await pool.query(
                `
                INSERT INTO profiles
                (
                    user_id,
                    bio,
                    profile_picture
                )

                VALUES($1,'','')

                ON CONFLICT(user_id)
                DO NOTHING
                `,
                [user.id]
            );


            const token =
                createAuthToken();

            const tokenHash =
                hashToken(token);


            await pool.query(
                `
                INSERT INTO sessions
                (
                    user_id,
                    token_hash,
                    expires_at
                )

                VALUES(
                    $1,
                    $2,
                    CURRENT_TIMESTAMP
                    + INTERVAL '30 days'
                )
                `,
                [
                    user.id,
                    tokenHash
                ]
            );


            res.status(201).json({

                success:true,

                message:
                    "Canvas account created successfully.",

                token:token,

                user:user

            });

        }

        catch(error){

            console.error(
                "Signup failed:",
                error.message
            );

            res.status(500).json({

                success:false,

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
    async (req,res) => {

        const {
            email,
            username,
            password
        } = req.body;


        const loginValue =
            String(
                email ||
                username ||
                ""
            )
            .trim()
            .toLowerCase()
            .replace(/^@/,"");


        if(!loginValue || !password){

            return res.status(400).json({

                success:false,

                message:
                    "Email/username and password are required."

            });

        }


        if(!pool){

            return res.status(500).json({

                success:false,

                message:
                    "Database is not configured."

            });

        }


        try{

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
                    OR LOWER(username) = $1

                    LIMIT 1
                    `,
                    [loginValue]
                );


            if(
                result.rows.length === 0
            ){

                return res.status(401).json({

                    success:false,

                    message:
                        "Email or password is incorrect."

                });

            }


            const user =
                result.rows[0];


            if(
                hashPassword(password) !==
                user.password_hash
            ){

                return res.status(401).json({

                    success:false,

                    message:
                        "Email or password is incorrect."

                });

            }


            const token =
                createAuthToken();

            const tokenHash =
                hashToken(token);


            await pool.query(
                `
                INSERT INTO sessions
                (
                    user_id,
                    token_hash,
                    expires_at
                )

                VALUES(
                    $1,
                    $2,
                    CURRENT_TIMESTAMP
                    + INTERVAL '30 days'
                )
                `,
                [
                    user.id,
                    tokenHash
                ]
            );


            res.json({

                success:true,

                message:
                    "Login successful.",

                token:token,

                user:{

                    id:user.id,

                    name:user.name,

                    username:user.username,

                    email:user.email,

                    created_at:
                        user.created_at

                }

            });

        }

        catch(error){

            console.error(
                "Login failed:",
                error.message
            );

            res.status(500).json({

                success:false,

                message:
                    "Unable to log in to Canvas."

            });

        }

    }
);
/* =========================================
   CANVAS SERVER — PART 4/8
   STREAM ROUTES
========================================= */


/* =========================================
   CREATE STREAM
========================================= */

app.post(
    "/api/streams",
    authenticateUser,
    async (req,res) => {

        const title =
            String(
                req.body.title ||
                "Canvas Live Stream"
            ).trim();


        if(!title){

            return res.status(400).json({
                success:false,
                message:
                    "Stream title is required."
            });

        }


        try{

            const existing =
                await pool.query(
                    `
                    SELECT
                        id,
                        title,
                        status,
                        created_at

                    FROM streams

                    WHERE user_id = $1

                    AND status = 'live'

                    LIMIT 1
                    `,
                    [req.user.id]
                );


            if(existing.rows.length){

                return res.status(409).json({

                    success:false,

                    message:
                        "You already have a live stream.",

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
                        status
                    )

                    VALUES
                    (
                        $1,
                        $2,
                        'live'
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


            res.status(201).json({

                success:true,

                message:
                    "Canvas stream started.",

                stream:
                    result.rows[0]

            });

        }

        catch(error){

            console.error(
                "Create stream failed:",
                error.message
            );

            res.status(500).json({

                success:false,

                message:
                    "Unable to start stream."

            });

        }

    }
);


/* =========================================
   GET LIVE STREAMS
========================================= */

app.get(
    "/api/streams/live",
    async (req,res) => {

        try{

            const result =
                await pool.query(
                    `
                    SELECT

                        streams.id,

                        streams.user_id,

                        streams.title,

                        streams.status,

                        streams.created_at,

                        users.name,

                        users.username,

                        profiles.profile_picture

                    FROM streams

                    INNER JOIN users
                        ON users.id =
                           streams.user_id

                    LEFT JOIN profiles
                        ON profiles.user_id =
                           users.id

                    WHERE streams.status = 'live'

                    ORDER BY
                        streams.created_at DESC
                    `
                );


            res.json({

                success:true,

                streams:
                    result.rows

            });

        }

        catch(error){

            console.error(
                "Live streams failed:",
                error.message
            );

            res.status(500).json({

                success:false,

                message:
                    "Unable to load live streams."

            });

        }

    }
);


/* =========================================
   GET STREAM BY ID
========================================= */

app.get(
    "/api/streams/:id",
    async (req,res) => {

        try{

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

                        users.name,

                        users.username,

                        profiles.profile_picture

                    FROM streams

                    INNER JOIN users
                        ON users.id =
                           streams.user_id

                    LEFT JOIN profiles
                        ON profiles.user_id =
                           users.id

                    WHERE streams.id = $1

                    LIMIT 1
                    `,
                    [req.params.id]
                );


            if(!result.rows.length){

                return res.status(404).json({

                    success:false,

                    message:
                        "Canvas stream not found."

                });

            }


            const stream =
                result.rows[0];


            res.json({

                success:true,

                stream:{

                    id:
                        stream.id,

                    user_id:
                        stream.user_id,

                    title:
                        stream.title,

                    status:
                        stream.status,

                    created_at:
                        stream.created_at,

                    ended_at:
                        stream.ended_at,

                    name:
                        stream.name,

                    username:
                        stream.username,

                    profile_picture:
                        stream.profile_picture || ""

                }

            });

        }

        catch(error){

            console.error(
                "Get stream failed:",
                error.message
            );

            res.status(500).json({

                success:false,

                message:
                    "Unable to load Canvas stream."

            });

        }

    }
);


/* =========================================
   END STREAM
========================================= */

app.put(
    "/api/streams/:id/end",
    authenticateUser,
    async (req,res) => {

        try{

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

                    RETURNING
                        id,
                        user_id,
                        title,
                        status,
                        created_at,
                        ended_at
                    `,
                    [
                        req.params.id,
                        req.user.id
                    ]
                );


            if(!result.rows.length){

                return res.status(404).json({

                    success:false,

                    message:
                        "Live stream not found."

                });

            }


            io.to(
                String(req.params.id)
            ).emit(
                "stream-ended",
                result.rows[0]
            );


            res.json({

                success:true,

                message:
                    "Canvas stream ended.",

                stream:
                    result.rows[0]

            });

        }

        catch(error){

            console.error(
                "End stream failed:",
                error.message
            );

            res.status(500).json({

                success:false,

                message:
                    "Unable to end stream."

            });

        }

    }
);


/* =========================================
   DELETE STREAM
========================================= */

app.delete(
    "/api/streams/:id",
    authenticateUser,
    async (req,res) => {

        try{

            const result =
                await pool.query(
                    `
                    DELETE FROM streams

                    WHERE id = $1

                    AND user_id = $2

                    RETURNING id
                    `,
                    [
                        req.params.id,
                        req.user.id
                    ]
                );


            if(!result.rows.length){

                return res.status(404).json({

                    success:false,

                    message:
                        "Stream not found."

                });

            }


            res.json({

                success:true,

                message:
                    "Stream deleted successfully."

            });

        }

        catch(error){

            console.error(
                "Delete stream failed:",
                error.message
            );

            res.status(500).json({

                success:false,

                message:
                    "Unable to delete stream."

            });

        }

    }
);
/* =========================================
   CANVAS SERVER — PART 5/8
   CHAT SYSTEM
========================================= */


/* =========================================
   CHAT TABLE
========================================= */

async function initializeChatTable(){

    if(!pool) return;

    try{

        await pool.query(`
            CREATE TABLE IF NOT EXISTS stream_messages (

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

    }

    catch(error){

        console.error(
            "Chat table failed:",
            error.message
        );

    }

}


/* =========================================
   SEND CHAT MESSAGE
========================================= */

app.post(
    "/api/streams/:id/chat",
    authenticateUser,
    async (req,res) => {

        const streamId =
            req.params.id;

        const message =
            String(
                req.body.message || ""
            ).trim();


        if(!message){

            return res.status(400).json({

                success:false,

                message:
                    "Message cannot be empty."

            });

        }


        if(message.length > 500){

            return res.status(400).json({

                success:false,

                message:
                    "Message is too long."

            });

        }


        try{

            const stream =
                await pool.query(
                    `
                    SELECT id

                    FROM streams

                    WHERE id = $1

                    AND status = 'live'

                    LIMIT 1
                    `,
                    [streamId]
                );


            if(!stream.rows.length){

                return res.status(404).json({

                    success:false,

                    message:
                        "This live stream is no longer active."

                });

            }


            const result =
                await pool.query(
                    `
                    INSERT INTO stream_messages
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


            const chatMessage = {

                id:
                    result.rows[0].id,

                streamId:
                    result.rows[0].stream_id,

                userId:
                    result.rows[0].user_id,

                name:
                    req.user.name,

                username:
                    req.user.username,

                message:
                    result.rows[0].message,

                createdAt:
                    result.rows[0].created_at

            };


            io.to(
                String(streamId)
            ).emit(
                "chat-message",
                chatMessage
            );


            res.status(201).json({

                success:true,

                message:
                    chatMessage

            });

        }

        catch(error){

            console.error(
                "Send chat failed:",
                error.message
            );

            res.status(500).json({

                success:false,

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
    "/api/streams/:id/chat",
    async (req,res) => {

        try{

            const result =
                await pool.query(
                    `
                    SELECT

                        stream_messages.id,

                        stream_messages.stream_id,

                        stream_messages.user_id,

                        stream_messages.message,

                        stream_messages.created_at,

                        users.name,

                        users.username

                    FROM stream_messages

                    INNER JOIN users
                        ON users.id =
                           stream_messages.user_id

                    WHERE stream_messages.stream_id = $1

                    ORDER BY
                        stream_messages.created_at ASC

                    LIMIT 100
                    `,
                    [req.params.id]
                );


            const messages =
                result.rows.map(
                    row => ({

                        id:
                            row.id,

                        streamId:
                            row.stream_id,

                        userId:
                            row.user_id,

                        name:
                            row.name,

                        username:
                            row.username,

                        message:
                            row.message,

                        createdAt:
                            row.created_at

                    })
                );


            res.json({

                success:true,

                messages:
                    messages

            });

        }

        catch(error){

            console.error(
                "Chat history failed:",
                error.message
            );

            res.status(500).json({

                success:false,

                message:
                    "Unable to load chat."

            });

        }

    }
);


/* =========================================
   CHAT SOCKET ROOM
========================================= */

io.on(
    "connection",
    socket => {

        socket.on(
            "join-chat",
            streamId => {

                if(!streamId) return;

                socket.join(
                    String(streamId)
                );

            }
        );


        socket.on(
            "leave-chat",
            streamId => {

                if(!streamId) return;

                socket.leave(
                    String(streamId)
                );

            }
        );

    }
);


/* =========================================
   INITIALIZE CHAT
========================================= */

initializeChatTable();
/* =========================================
   CANVAS SERVER — PART 6/8
   FOLLOW + VIEWERS
========================================= */


/* =========================================
   FOLLOWS TABLE
========================================= */

async function initializeFollowTable(){

    if(!pool) return;

    try{

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

        console.log(
            "Canvas follows table ready."
        );

    }

    catch(error){

        console.error(
            "Follow table failed:",
            error.message
        );

    }

}


/* =========================================
   FOLLOW CREATOR
========================================= */

app.post(
    "/api/follow",
    authenticateUser,
    async (req,res) => {

        const creatorId =
            Number(
                req.body.userId
            );


        if(!creatorId){

            return res.status(400).json({

                success:false,

                message:
                    "Creator ID is required."

            });

        }


        if(
            creatorId ===
            Number(req.user.id)
        ){

            return res.status(400).json({

                success:false,

                message:
                    "You cannot follow yourself."

            });

        }


        try{

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


            if(!creator.rows.length){

                return res.status(404).json({

                    success:false,

                    message:
                        "Creator not found."

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

                success:true,

                following:true,

                message:
                    "Creator followed."

            });

        }

        catch(error){

            console.error(
                "Follow failed:",
                error.message
            );

            res.status(500).json({

                success:false,

                message:
                    "Unable to follow creator."

            });

        }

    }
);


/* =========================================
   UNFOLLOW CREATOR
========================================= */

app.delete(
    "/api/follow/:userId",
    authenticateUser,
    async (req,res) => {

        try{

            await pool.query(
                `
                DELETE FROM follows

                WHERE follower_id = $1

                AND following_id = $2
                `,
                [
                    req.user.id,
                    req.params.userId
                ]
            );


            res.json({

                success:true,

                following:false,

                message:
                    "Creator unfollowed."

            });

        }

        catch(error){

            console.error(
                "Unfollow failed:",
                error.message
            );

            res.status(500).json({

                success:false,

                message:
                    "Unable to unfollow creator."

            });

        }

    }
);


/* =========================================
   CHECK FOLLOW
========================================= */

app.get(
    "/api/follow/:userId",
    authenticateUser,
    async (req,res) => {

        try{

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
                        req.params.userId
                    ]
                );


            res.json({

                success:true,

                following:
                    result.rows.length > 0

            });

        }

        catch(error){

            console.error(
                "Follow check failed:",
                error.message
            );

            res.status(500).json({

                success:false,

                message:
                    "Unable to check follow status."

            });

        }

    }
);


/* =========================================
   LIVE VIEWER COUNTS
========================================= */

function getViewerCount(streamId){

    const room =
        streamRooms.get(
            String(streamId)
        );


    if(!room){

        return 0;

    }


    return room.size;

}


/* =========================================
   BROADCAST VIEWER COUNT
========================================= */

function broadcastViewerCount(
    streamId
){

    const count =
        getViewerCount(
            streamId
        );


    io.to(
        String(streamId)
    ).emit(
        "viewer-count",
        {

            streamId:
                String(streamId),

            count:
                count

        }
    );

}


/* =========================================
   VIEWER JOIN TRACKING
========================================= */

function trackViewerJoin(
    socket,
    streamId
){

    const room =
        String(streamId);


    if(
        !streamRooms.has(room)
    ){

        streamRooms.set(
            room,
            new Set()
        );

    }


    streamRooms
        .get(room)
        .add(socket.id);


    socket.streamRoom =
        room;


    broadcastViewerCount(
        room
    );

}


/* =========================================
   VIEWER LEAVE TRACKING
========================================= */

function trackViewerLeave(
    socket
){

    const room =
        socket.streamRoom;


    if(!room) return;


    const clients =
        streamRooms.get(room);


    if(clients){

        clients.delete(
            socket.id
        );


        broadcastViewerCount(
            room
        );


        if(
            clients.size === 0
        ){

            streamRooms.delete(
                room
            );

        }

    }


    socket.streamRoom =
        null;

}


/* =========================================
   FOLLOW TABLE STARTUP
========================================= */

initializeFollowTable();
/* =========================================
   CANVAS SERVER — PART 7/8
   REAL-TIME SOCKET SYSTEM
========================================= */


io.on(
    "connection",
    socket => {

        console.log(
            "Canvas client connected:",
            socket.id
        );


        /* =====================================
           JOIN STREAM
        ===================================== */

        socket.on(
            "join-stream",
            data => {

                if(!data || !data.streamId){
                    return;
                }


                const room =
                    String(
                        data.streamId
                    );


                socket.join(room);


                if(
                    !streamRooms.has(room)
                ){

                    streamRooms.set(
                        room,
                        new Set()
                    );

                }


                const clients =
                    streamRooms.get(room);


                clients.add(
                    socket.id
                );


                socket.streamRoom =
                    room;

                socket.streamRole =
                    data.role ||
                    "viewer";


                const existingPeers =
                    Array.from(clients)
                        .filter(
                            id =>
                                id !== socket.id
                        );


                socket.emit(
                    "existing-peers",
                    existingPeers
                );


                socket.to(room).emit(
                    "peer-joined",
                    {

                        socketId:
                            socket.id,

                        role:
                            socket.streamRole

                    }
                );


                broadcastViewerCount(
                    room
                );


                console.log(
                    `Client ${socket.id} joined ${room} as ${socket.streamRole}`
                );

            }
        );


        /* =====================================
           JOIN CHAT
        ===================================== */

        socket.on(
            "join-chat",
            streamId => {

                if(!streamId) return;

                socket.join(
                    String(streamId)
                );

            }
        );


        /* =====================================
           WEBRTC OFFER
        ===================================== */

        socket.on(
            "webrtc-offer",
            data => {

                if(
                    !data ||
                    !data.target ||
                    !data.offer
                ){

                    return;

                }


                io.to(
                    data.target
                ).emit(
                    "webrtc-offer",
                    {

                        sender:
                            socket.id,

                        offer:
                            data.offer

                    }
                );

            }
        );


        /* =====================================
           WEBRTC ANSWER
        ===================================== */

        socket.on(
            "webrtc-answer",
            data => {

                if(
                    !data ||
                    !data.target ||
                    !data.answer
                ){

                    return;

                }


                io.to(
                    data.target
                ).emit(
                    "webrtc-answer",
                    {

                        sender:
                            socket.id,

                        answer:
                            data.answer

                    }
                );

            }
        );


        /* =====================================
           ICE CANDIDATE
        ===================================== */

        socket.on(
            "webrtc-ice",
            data => {

                if(
                    !data ||
                    !data.target ||
                    !data.candidate
                ){

                    return;

                }


                io.to(
                    data.target
                ).emit(
                    "webrtc-ice",
                    {

                        sender:
                            socket.id,

                        candidate:
                            data.candidate

                    }
                );

            }
        );


        /* =====================================
           LEAVE STREAM
        ===================================== */

        socket.on(
            "leave-stream",
            () => {

                removeSocketFromStream(
                    socket
                );

            }
        );


        /* =====================================
           LEAVE CHAT
        ===================================== */

        socket.on(
            "leave-chat",
            streamId => {

                if(!streamId) return;

                socket.leave(
                    String(streamId)
                );

            }
        );


        /* =====================================
           DISCONNECT
        ===================================== */

        socket.on(
            "disconnect",
            () => {

                removeSocketFromStream(
                    socket
                );


                console.log(
                    "Canvas client disconnected:",
                    socket.id
                );

            }
        );

    }
);


/* =========================================
   REMOVE SOCKET FROM STREAM
========================================= */

function removeSocketFromStream(
    socket
){

    const room =
        socket.streamRoom;


    if(!room){
        return;
    }


    const clients =
        streamRooms.get(
            room
        );


    if(clients){

        clients.delete(
            socket.id
        );


        socket.to(room).emit(
            "peer-left",
            {

                socketId:
                    socket.id

            }
        );


        broadcastViewerCount(
            room
        );


        if(
            clients.size === 0
        ){

            streamRooms.delete(
                room
            );

        }

    }


    socket.leave(
        room
    );


    socket.streamRoom =
        null;

}
/* =========================================
   CANVAS SERVER — PART 8/8
   HEALTH + STARTUP
========================================= */


/* =========================================
   HEALTH CHECK
========================================= */

app.get(
    "/api/health",
    async (req,res) => {

        if(!pool){

            return res.status(500).json({

                success:false,

                status:"unhealthy",

                database:"not configured"

            });

        }


        try{

            await pool.query(
                "SELECT 1"
            );


            res.json({

                success:true,

                status:"healthy",

                database:"connected",

                service:
                    "Canvas Backend"

            });

        }

        catch(error){

            console.error(
                "Health check failed:",
                error.message
            );


            res.status(500).json({

                success:false,

                status:"unhealthy",

                database:
                    "connection failed"

            });

        }

    }
);


/* =========================================
   API 404
========================================= */

app.use(
    (req,res) => {

        res.status(404).json({

            success:false,

            message:
                "Canvas API endpoint not found."

        });

    }
);


/* =========================================
   GLOBAL ERROR
========================================= */

app.use(
    (error,req,res,next) => {

        console.error(
            "Canvas server error:",
            error
        );


        res.status(500).json({

            success:false,

            message:
                "Canvas server encountered an error."

        });

    }
);


/* =========================================
   START CANVAS
========================================= */

async function startServer(){

    try{

        await initializeDatabase();

        await initializeChatTable();

        await initializeFollowTable();


        httpServer.listen(
            PORT,
            () => {

                console.log(
                    `Canvas backend running on port ${PORT}`
                );

            }
        );

    }

    catch(error){

        console.error(
            "Canvas startup failed:",
            error
        );

    }

}


startServer();
