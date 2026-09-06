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
   REAL-TIME VIEWER TRACKING
========================================= */

/*
 * Each stream has a Set of socket IDs.
 *
 * This prevents the same connected viewer
 * from being counted twice.
 *
 * Example:
 *
 * streamViewers.get(15)
 *
 * => Set {
 *      "socketA",
 *      "socketB"
 *    }
 */

const streamViewers = new Map();


function getViewerSet(streamId){

    if(!streamViewers.has(streamId)){

        streamViewers.set(
            streamId,
            new Set()
        );

    }

    return streamViewers.get(streamId);

}


function getViewerCount(streamId){

    const viewers =
        streamViewers.get(streamId);

    if(!viewers){

        return 0;

    }

    return viewers.size;

}


function removeViewerFromStream(
    socket,
    streamId
){

    const viewers =
        streamViewers.get(streamId);

    if(!viewers){

        return false;

    }

    const removed =
        viewers.delete(socket.id);

    if(viewers.size === 0){

        streamViewers.delete(streamId);

    }

    return removed;

}


/* =========================================
   CORS
========================================= */

app.use((req,res,next)=>{

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
        limit:"50mb"
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

            ssl:{
                rejectUnauthorized:false
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
   USERNAME
========================================= */

function cleanUsername(username){

    return String(username || "")
        .trim()
        .replace(/^@/,"")
        .toLowerCase();

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
            success:false,
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
            success:false,
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
            success:false,
            message:
                "Authentication token is missing."
        });

    }


    try{

        const result =
            await pool.query(`
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
            `,[
                hashToken(token)
            ]);


        if(!result.rows.length){

            return res.status(401).json({
                success:false,
                message:
                    "Invalid or expired authentication token."
            });

        }


        req.user =
            result.rows[0];


        next();

    }catch(error){

        console.error(
            "Authentication error:",
            error.message
        );


        return res.status(500).json({
            success:false,
            message:
                "Unable to authenticate user."
        });

    }

}


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

        /* ===============================
           USERS
        =============================== */

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


        /* ===============================
           PROFILES
        =============================== */

        await pool.query(`
            CREATE TABLE IF NOT EXISTS profiles (
                id SERIAL PRIMARY KEY,

                user_id INTEGER
                    UNIQUE NOT NULL
                    REFERENCES users(id)
                    ON DELETE CASCADE,

                bio TEXT DEFAULT '',

                profile_picture TEXT DEFAULT '',

                updated_at TIMESTAMP
                    DEFAULT CURRENT_TIMESTAMP
            )
        `);


        /* ===============================
           SESSIONS
        =============================== */

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
            )
        `);


        /* ===============================
           STREAMS
        =============================== */

        await pool.query(`
            CREATE TABLE IF NOT EXISTS streams (
                id SERIAL PRIMARY KEY,

                user_id INTEGER
                    REFERENCES users(id)
                    ON DELETE CASCADE,

                title VARCHAR(255)
                    DEFAULT 'Canvas Live Stream',

                description TEXT
                    DEFAULT '',

                category VARCHAR(100)
                    DEFAULT 'Entertainment',

                thumbnail TEXT
                    DEFAULT '',

                status VARCHAR(30)
                    DEFAULT 'live',

                is_live BOOLEAN
                    DEFAULT true,

                viewer_count INTEGER
                    DEFAULT 0,

                created_at TIMESTAMP
                    DEFAULT CURRENT_TIMESTAMP,

                ended_at TIMESTAMP
            )
        `);


        /* ===============================
           EXISTING STREAM COLUMNS
        =============================== */

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


        /* ===============================
           FOLLOWS
        =============================== */

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


        /* ===============================
           CHAT
        =============================== */

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


        /* ===============================
           SUPPORT
        =============================== */

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


        console.log(
            "Canvas database initialized."
        );

    }catch(error){

        console.error(
            "Database initialization failed:",
            error.message
        );

    }

}


initializeDatabase();


/* =========================================
   SIGNUP
========================================= */

app.post(
    "/api/signup",
    async(req,res)=>{

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
                !cleanName ||
                !cleanUser ||
                !cleanEmail
            ){

                return res.status(400).json({
                    success:false,
                    message:
                        "Invalid account information."
                });

            }


            const existing =
                await pool.query(`
                    SELECT
                        id,
                        username,
                        email
                    FROM users
                    WHERE LOWER(username) = $1
                    OR LOWER(email) = $2
                    LIMIT 1
                `,[
                    cleanUser,
                    cleanEmail
                ]);


            if(existing.rows.length){

                const old =
                    existing.rows[0];


                if(
                    String(old.username)
                        .toLowerCase()
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


            const result =
                await pool.query(`
                    INSERT INTO users
                    (
                        name,
                        username,
                        email,
                        password_hash
                    )
                    VALUES
                    ($1,$2,$3,$4)
                    RETURNING
                        id,
                        name,
                        username,
                        email,
                        created_at
                `,[
                    cleanName,
                    cleanUser,
                    cleanEmail,
                    hashPassword(password)
                ]);


            const user =
                result.rows[0];


            await pool.query(`
                INSERT INTO profiles
                (
                    user_id,
                    bio,
                    profile_picture
                )
                VALUES
                ($1,'','')
                ON CONFLICT(user_id)
                DO NOTHING
            `,[
                user.id
            ]);


            const token =
                createAuthToken();


            await pool.query(`
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
            `,[
                user.id,
                hashToken(token)
            ]);


            return res.status(201).json({
                success:true,

                message:
                    "Canvas account created successfully.",

                token,

                user
            });
         }catch(error){

            console.error(
                "Signup error:",
                error.message
            );


            return res.status(500).json({
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
    async(req,res)=>{

        const {
            email,
            password
        } = req.body;


        if(!email || !password){

            return res.status(400).json({
                success:false,
                message:
                    "Email and password are required."
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

            const cleanEmail =
                String(email)
                    .trim()
                    .toLowerCase();


            const result =
                await pool.query(`
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
                `,[
                    cleanEmail
                ]);


            if(!result.rows.length){

                return res.status(401).json({
                    success:false,
                    message:
                        "Email or password is incorrect."
                });

            }


            const user =
                result.rows[0];


            if(
                user.password_hash !==
                hashPassword(password)
            ){

                return res.status(401).json({
                    success:false,
                    message:
                        "Email or password is incorrect."
                });

            }


            const token =
                createAuthToken();


            await pool.query(`
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
            `,[
                user.id,
                hashToken(token)
            ]);


            return res.json({

                success:true,

                message:
                    "Login successful.",

                token,

                user:{
                    id:user.id,
                    name:user.name,
                    username:user.username,
                    email:user.email,
                    created_at:user.created_at
                }

            });

        }catch(error){

            console.error(
                "Login error:",
                error.message
            );


            return res.status(500).json({
              success:false,
                message:
                    "Unable to update profile."
            });

        }

    }
);
/* =========================================
   CHANGE PASSWORD
========================================= */

app.put(
    "/api/change-password",
    authenticateUser,
    async(req,res)=>{

        try{

            const {
                currentPassword,
                newPassword
            } = req.body;


            if(
                !currentPassword ||
                !newPassword
            ){

                return res.status(400).json({
                    success:false,
                    message:
                        "Current password and new password are required."
                });

            }


            if(
                String(newPassword).length < 8
            ){

                return res.status(400).json({
                    success:false,
                    message:
                        "Password must be at least 8 characters."
                });

            }


            if(
                currentPassword ===
                newPassword
            ){

                return res.status(400).json({
                    success:false,
                    message:
                        "New password must be different from your current password."
                });

            }


            const result =
                await pool.query(`
                    SELECT
                        password_hash
                    FROM users
                    WHERE id = $1
                    LIMIT 1
                `,[
                    req.user.id
                ]);


            if(!result.rows.length){

                return res.status(404).json({
                    success:false,
                    message:
                        "User not found."
                });

            }


            if(
                result.rows[0].password_hash !==
                hashPassword(currentPassword)
            ){

                return res.status(401).json({
                    success:false,
                    message:
                        "Current password is incorrect."
                });

            }


            await pool.query(`
                UPDATE users
                SET password_hash = $1
                WHERE id = $2
            `,[
                hashPassword(newPassword),
                req.user.id
            ]);


            return res.json({

                success:true,

                message:
                    "Password changed successfully."

            });

        }catch(error){

            console.error(
                "Change password error:",
                error.message
            );


            return res.status(500).json({
                success:false,
                message:
                    "Unable to change password."
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
    async(req,res)=>{

        try{

            const {
                title,
                category,
                description,
                thumbnail
            } = req.body;


            const streamTitle =
                String(
                    title ||
                    "Canvas Live Stream"
                ).trim();


            if(!streamTitle){

                return res.status(400).json({
                    success:false,
                    message:
                        "Stream title is required."
                });

            }


            /*
             * Prevent multiple live streams
             * from the same creator.
             */

            const existing =
                await pool.query(`
                    SELECT
                        id
                    FROM streams
                    WHERE user_id = $1
                    AND is_live = true
                    LIMIT 1
                `,[
                    req.user.id
                ]);


            if(existing.rows.length){

                return res.status(409).json({
                    success:false,
                    message:
                        "You already have a live stream."
                });

            }


            const result =
                await pool.query(`
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
                `,[
                    req.user.id,

                    streamTitle,

                    String(
                        description || ""
                    ),

                    String(
                        category ||
                        "Entertainment"
                    ),

                    String(
                        thumbnail || ""
                    )
                ]);


            const row =
                result.rows[0];


            /* =================================
               CREATOR INFORMATION
            ================================= */

            const creatorResult =
                await pool.query(`
                    SELECT
                        u.id,
                        u.name,
                        u.username,
                        p.profile_picture
                    FROM users u
                    LEFT JOIN profiles p
                        ON p.user_id = u.id
                    WHERE u.id = $1
                    LIMIT 1
                `,[
                    req.user.id
                ]);


            const creator =
                creatorResult.rows[0] || {};


            const stream = {

                ...row,

                user_id:
                    row.user_id,

                userId:
                    row.user_id,

                creator_id:
                    row.user_id,

                creatorId:
                    row.user_id,

                title:
                    row.title,

                description:
                    row.description || "",

                category:
                    row.category ||
                    "Entertainment",

                thumbnail:
                    row.thumbnail || "",

                thumbnail_url:
                    row.thumbnail || "",

                status:
                    row.status,

                is_live:
                    row.is_live,

                viewer_count:
                    0,

                viewers:
                    0,

                created_at:
                    row.created_at,

                ended_at:
                    row.ended_at,

                name:
                    creator.name ||
                    req.user.name ||
                    "Canvas Creator",

                username:
                    creator.username ||
                    req.user.username ||
                    "",

                profile_picture:
                    creator.profile_picture ||
                    ""

            };


            /*
             * Tell Home / Explore immediately.
             */

            io.emit(
                "stream-updated",
                stream
            );


            return res.status(201).json({

                success:true,

                stream

            });

        }catch(error){

            console.error(
                "Create stream error:",
                error.message
            );


            return res.status(500).json({
                success:false,
                message:
                    "Unable to start stream."
            });

        }

    }
);


/* =========================================
   GET SINGLE LIVE STREAM
========================================= */

app.get(
    "/api/streams/:streamId",
    async(req,res)=>{

        try{

            const streamId =
                Number(
                    req.params.streamId
                );


            if(
                !Number.isInteger(streamId) ||
                streamId <= 0
            ){

                return res.status(400).json({
                    success:false,
                    message:
                        "Invalid stream ID."
                });

            }


            const result =
                await pool.query(`
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

                        p.profile_picture

                    FROM streams s

                    LEFT JOIN users u
                        ON u.id = s.user_id

                    LEFT JOIN profiles p
                        ON p.user_id = s.user_id

                    WHERE s.id = $1
                    AND s.is_live = true

                    LIMIT 1
                `,[
                    streamId
                ]);


            if(!result.rows.length){

                return res.status(404).json({
                    success:false,
                    message:
                        "Live stream not found."
                });

            }


            const row =
                result.rows[0];


            /*
             * The database count is used only
             * as an initial fallback.
             *
             * Once Watch connects through
             * Socket.IO, the live Set count
             * becomes authoritative.
             */

            const liveCount =
                getViewerCount(streamId);


            const databaseCount =
                Number(
                    row.viewer_count || 0
                );


            const viewerCount =
                liveCount > 0
                    ? liveCount
                    : databaseCount;


            const stream = {

                id:
                    row.id,

                user_id:
                    row.user_id,

                userId:
                    row.user_id,

                creator_id:
                    row.user_id,

                creatorId:
                    row.user_id,

                title:
                    row.title,

                description:
                    row.description || "",

                category:
                    row.category ||
                    "Entertainment",

                thumbnail:
                    row.thumbnail || "",

                thumbnail_url:
                    row.thumbnail || "",

                status:
                    row.status,

                is_live:
                    row.is_live,

                viewer_count:
                    viewerCount,

                viewers:
                    viewerCount,

                created_at:
                    row.created_at,

                ended_at:
                    row.ended_at,

                name:
                    row.name ||
                    row.username ||
                    "Canvas Creator",

                username:
                    row.username ||
                    "",

                profile_picture:
                    row.profile_picture ||
                    ""

            };


            return res.json({

                success:true,

                stream

            });

        }catch(error){

            console.error(
                "Get stream error:",
                error.message
            );


            return res.status(500).json({
                success:false,
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
    async(req,res)=>{

        try{

            const streamId =
                Number(
                    req.params.streamId
                );


            if(
                !Number.isInteger(streamId) ||
                streamId <= 0
            ){

                return res.status(400).json({
                    success:false,
                    message:
                        "Invalid stream ID."
                });

            }


            const result =
                await pool.query(`
                    UPDATE streams
                    SET
                        is_live = false,

                        status = 'ended',

                        ended_at =
                            CURRENT_TIMESTAMP,

                        viewer_count = 0

                    WHERE id = $1

                    AND user_id = $2

                    AND is_live = true

                    RETURNING *
                `,[
                    streamId,
                    req.user.id
                ]);
                    if(!result.rows.length){

                return res.status(404).json({
                    success:false,
                    message:
                        "Live stream not found."
                });

            }


            const stream =
                result.rows[0];


            /*
             * Tell every current watcher that
             * the stream has ended.
             */

            io.to(
                "stream:" + streamId
            ).emit(
                "stream-ended",
                stream
            );


            /*
             * Remove the in-memory viewer Set.
             */

            streamViewers.delete(
                streamId
            );


            /*
             * Tell Home / Explore immediately.
             */

            io.emit(
                "stream-updated",
                {
                    ...stream,

                    viewer_count:0,

                    viewers:0
                }
            );


            return res.json({

                success:true,

                stream:{

                    ...stream,

                    viewer_count:0,

                    viewers:0

                }

            });

        }catch(error){

            console.error(
                "End stream error:",
                error.message
            );


            return res.status(500).json({
                success:false,
                message:
                    "Unable to end stream."
            });

        }

    }
);


/* =========================================
   STREAM DISCOVERY
========================================= */

app.get(
    "/api/streams",
    async(req,res)=>{

        try{

            const result =
                await pool.query(`
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

                        p.profile_picture

                    FROM streams s

                    LEFT JOIN users u
                        ON u.id = s.user_id

                    LEFT JOIN profiles p
                        ON p.user_id = s.user_id

                    WHERE s.is_live = true

                    ORDER BY
                        s.created_at DESC

                    LIMIT 100
                `);


            const streams =
                result.rows.map(row=>{

                    const liveCount =
                        getViewerCount(
                            Number(row.id)
                        );


                    const databaseCount =
                        Number(
                            row.viewer_count || 0
                        );


                    const viewerCount =
                        liveCount > 0
                            ? liveCount
                            : databaseCount;


                    return {

                        ...row,

                        user_id:
                            row.user_id,

                        userId:
                            row.user_id,

                        creator_id:
                            row.user_id,

                        creatorId:
                            row.user_id,

                        name:
                            row.name ||
                            row.username ||
                            "Canvas Creator",

                        username:
                            row.username ||
                            "",

                        profile_picture:
                            row.profile_picture ||
                            "",

                        viewer_count:
                            viewerCount,

                        viewers:
                            viewerCount

                    };

                });


            return res.json({

                success:true,

                streams

            });

        }catch(error){

            console.error(
                "Stream discovery error:",
                error.message
            );


            return res.status(500).json({
                success:false,
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
    async(req,res)=>{

        try{

            const query =
                String(
                    req.query.q || ""
                ).trim();


            if(!query){

                return res.json({
                    success:true,
                    streams:[]
                });

            }


            const search =
                "%" + query + "%";


            const result =
                await pool.query(`
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

                    ORDER BY
                        s.created_at DESC
                        LIMIT 50
                `,[
                    search
                ]);


            const streams =
                result.rows.map(row=>{

                    const liveCount =
                        getViewerCount(
                            Number(row.id)
                        );


                    const databaseCount =
                        Number(
                            row.viewer_count || 0
                        );


                    const viewerCount =
                        liveCount > 0
                            ? liveCount
                            : databaseCount;


                    return {

                        ...row,

                        user_id:
                            row.user_id,

                        userId:
                            row.user_id,

                        creator_id:
                            row.user_id,

                        creatorId:
                            row.user_id,

                        name:
                            row.name ||
                            row.username ||
                            "Canvas Creator",

                        username:
                            row.username ||
                            "",

                        profile_picture:
                            row.profile_picture ||
                            "",

                        viewer_count:
                            viewerCount,

                        viewers:
                            viewerCount

                    };

                });


            return res.json({

                success:true,

                streams

            });

        }catch(error){

            console.error(
                "Stream search error:",
                error.message
            );


            return res.status(500).json({
                success:false,
                message:
                    "Unable to search streams."
            });

        }

    }
);
/* =========================================
   CHAT TABLE
========================================= */

async function ensureChatTable(){

    if(!pool){

        return;

    }


    try{

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


        console.log(
            "Chat table ready."
        );

    }catch(error){

        console.error(
            "Chat table error:",
            error.message
        );

    }

}


ensureChatTable();


/* =========================================
   SEND CHAT MESSAGE
========================================= */

app.post(
    "/api/streams/:streamId/chat",
    authenticateUser,
    async(req,res)=>{

        try{

            const streamId =
                Number(
                    req.params.streamId
                );


            const message =
                String(
                    req.body.message || ""
                ).trim();


            if(
                !Number.isInteger(streamId) ||
                streamId <= 0
            ){

                return res.status(400).json({
                    success:false,
                    message:
                        "Invalid stream ID."
                });

            }


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


            /* ===============================
               CHECK LIVE STREAM
            =============================== */

            const live =
                await pool.query(`
                    SELECT
                        id,
                        user_id,
                        is_live
                    FROM streams
                    WHERE id = $1
                    AND is_live = true
                    LIMIT 1
                `,[
                    streamId
                ]);


            if(!live.rows.length){

                return res.status(404).json({
                    success:false,
                    message:
                        "This stream is no longer live."
                });

            }


            /* ===============================
               SAVE MESSAGE
            =============================== */

            const result =
                await pool.query(`
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
                `,[
                    streamId,
                    req.user.id,
                    message
                ]);


            const row =
                result.rows[0];


            /* ===============================
               COMPLETE CHAT OBJECT
            =============================== */

            const chatMessage = {

                id:
                    Number(row.id),

                streamId:
                    Number(row.stream_id),

                stream_id:
                    Number(row.stream_id),

                userId:
                    Number(row.user_id),

                user_id:
                    Number(row.user_id),

                username:
                    req.user.username ||
                    "User",

                name:
                    req.user.name ||
                    req.user.username ||
                    "User",

                message:
                    row.message,

                created_at:
                    row.created_at

            };


            /*
             * Broadcast instantly.
             *
             * Socket.IO delivers this to every
             * connected Watch page in the room.
             */

            io.to(
                "stream:" + streamId
            ).emit(
                "chat-message",
                chatMessage
            );


            return res.status(201).json({

                success:true,

                message:
                    chatMessage

            });

        }catch(error){

            console.error(
                "Send chat error:",
                error.message
            );


            return res.status(500).json({
                success:false,
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
    async(req,res)=>{

        try{

            const streamId =
                Number(
                    req.params.streamId
                );


            if(
                !Number.isInteger(streamId) ||
                streamId <= 0
            ){

                return res.status(400).json({
                    success:false,
                    message:
                        "Invalid stream ID."
                });

            }


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

                    ORDER BY
                        c.created_at ASC

                    LIMIT 100
                `,[
                    streamId
                ]);


            const messages =
                result.rows.map(row=>({

                    id:
                        Number(row.id),

                    streamId:
                        Number(
                            row.stream_id
                        ),

                    stream_id:
                        Number(
                            row.stream_id
                        ),

                    userId:
                        Number(
                            row.user_id
                        ),

                    user_id:
                        Number(
                            row.user_id
                        ),

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


            return res.json({

                success:true,

                messages

            });

        }catch(error){

            console.error(
                "Chat history error:",
                error.message
            );


            return res.status(500).json({
                success:false,
                message:
                    "Unable to load chat."
            });

        }

    }
);
/* =========================================
   FOLLOW HELPERS
========================================= */

async function findUserByIdentifier(
    identifier
){

    const value =
        String(
            identifier || ""
        ).trim();


    if(!value){

        return null;

    }


    /*
     * First try numeric user ID.
     */

    if(/^\d+$/.test(value)){

        const result =
            await pool.query(`
                SELECT
                    id,
                    name,
                    username
                FROM users
                WHERE id = $1
                LIMIT 1
            `,[
                Number(value)
            ]);


        if(result.rows.length){

            return result.rows[0];

        }

    }


    /*
     * Then try username.
     */

    const username =
        cleanUsername(value);


    const result =
        await pool.query(`
            SELECT
                id,
                name,
                username
            FROM users
            WHERE LOWER(username) = $1
            LIMIT 1
        `,[
            username
        ]);


    return result.rows[0] || null;

}


/* =========================================
   FOLLOW CREATOR
========================================= */

app.post(
    "/api/follow",
    authenticateUser,
    async(req,res)=>{

        try{

            const identifier =
                req.body.userId ??
                req.body.creatorId ??
                req.body.username ??
                req.body.creatorUsername;


            const creator =
                await findUserByIdentifier(
                    identifier
                );


            if(!creator){

                return res.status(404).json({
                    success:false,
                    message:
                        "Creator not found."
                });

            }


            const creatorId =
                Number(creator.id);


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


            await pool.query(`
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
            `,[
                req.user.id,
                creatorId
            ]);


            /*
             * Get the updated follower count.
             */

            const countResult =
                await pool.query(`
                    SELECT COUNT(*) AS count
                    FROM follows
                    WHERE following_id = $1
                `,[
                    creatorId
                ]);


            const followersCount =
                Number(
                    countResult.rows[0].count || 0
                );


            /*
             * Notify the creator's profile/watch
             * clients immediately.
             */

            io.emit(
                "follow-updated",
                {
                    creatorId,

                    username:
                        creator.username,

                    followersCount
                }
            );


            return res.json({

                success:true,

                following:true,

                creator:{

                    id:
                        creator.id,

                    name:
                        creator.name,

                    username:
                        creator.username

                },

                followersCount

            });

        }catch(error){

            console.error(
                "Follow error:",
                error.message
            );


            return res.status(500).json({
                success:false,
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
    async(req,res)=>{

        try{

            const creator =
                await findUserByIdentifier(
                    req.params.creatorId
                );


            if(!creator){

                return res.status(404).json({
                    success:false,
                    message:
                        "Creator not found."
                });

            }


            const result =
                await pool.query(`
                    SELECT
                        id
                    FROM follows
                    WHERE follower_id = $1
                    AND following_id = $2
                    LIMIT 1
                `,[
                    req.user.id,
                    creator.id
                ]);


            return res.json({

                success:true,

                following:
                    result.rows.length > 0,

                creatorId:
                    Number(creator.id)

            });

        }catch(error){

            console.error(
                "Follow status error:",
                error.message
            );


            return res.status(500).json({
                success:false,
                message:
                    "Unable to check follow status."
            });

        }

    }
);


/* =========================================
   UNFOLLOW CREATOR
========================================= */

app.delete(
    "/api/follow/:creatorId",
    authenticateUser,
    async(req,res)=>{

        try{

            const creator =
                await findUserByIdentifier(
                    req.params.creatorId
                );


            if(!creator){

                return res.status(404).json({
                    success:false,
                    message:
                        "Creator not found."
                });

            }


            await pool.query(`
                DELETE FROM follows
                WHERE follower_id = $1
                AND following_id = $2
            `,[
                req.user.id,
                creator.id
            ]);


            const countResult =
                await pool.query(`
                    SELECT COUNT(*) AS count
                    FROM follows
                    WHERE following_id = $1
                `,[
                    creator.id
                ]);


            const followersCount =
                Number(
                    countResult.rows[0].count || 0
                );


            io.emit(
                "follow-updated",
                {
                    creatorId:
                        Number(creator.id),

                    username:
                        creator.username,

                    followersCount
                }
            );


            return res.json({

                success:true,

                following:false,

                creatorId:
                    Number(creator.id),

                followersCount

            });

        }catch(error){

            console.error(
                "Unfollow error:",
                error.message
            );


            return res.status(500).json({
                success:false,
                message:
                    "Unable to unfollow creator."
            });

        }

    }
);


/* =========================================
   FOLLOW STATUS BY USERNAME
========================================= */

app.get(
    "/api/follow/username/:username",
    authenticateUser,
    async(req,res)=>{

        try{

            const creator =
                await findUserByIdentifier(
                    req.params.username
                );


            if(!creator){

                return res.status(404).json({
                    success:false,
                    message:
                        "Creator not found."
                });

            }


            const result =
                await pool.query(`
                    SELECT id
                    FROM follows
                    WHERE follower_id = $1
                    AND following_id = $2
                    LIMIT 1
                `,[
                    req.user.id,
                    creator.id
                ]);


            return res.json({

                success:true,

                following:
                    result.rows.length > 0,

                creatorId:
                    Number(creator.id),

                username:
                    creator.username

            });

        }catch(error){

            console.error(
                "Username follow status error:",
                error.message
            );


            return res.status(500).json({
                success:false,
                message:
                    "Unable to check follow status."
            });

        }

    }
);


/* =========================================
   FOLLOWERS COUNT
========================================= */

app.get(
    "/api/followers/:creatorId",
    async(req,res)=>{

        try{

            const creator =
                await findUserByIdentifier(
                    req.params.creatorId
                );


            if(!creator){

                return res.status(404).json({
                    success:false,
                    message:
                        "Creator not found."
                });

            }


            const result =
                await pool.query(`
                    SELECT COUNT(*) AS count
                    FROM follows
                    WHERE following_id = $1
                `,[
                    creator.id
                ]);


            return res.json({

                success:true,

                creatorId:
                    Number(creator.id),

                username:
                    creator.username,

                followersCount:
                    Number(
                        result.rows[0].count || 0
                    )

            });

        }catch(error){

            console.error(
                "Followers count error:",
                error.message
            );


            return res.status(500).json({
                success:false,
                message:
                    "Unable to load followers."
            });

        }

    }
);


/* =========================================
   SUPPORT TABLE
========================================= */

async function ensureSupportTable(){

    if(!pool){

        return;

    }


    try{

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


        console.log(
            "Support table ready."
        );

    }catch(error){

        console.error(
            "Support table error:",
            error.message
        );

    }

}


ensureSupportTable();
/* =========================================
   SUPPORT / GIFT
========================================= */

app.post(
    "/api/support",
    authenticateUser,
    async(req,res)=>{

        try{

            const streamId =
                Number(
                    req.body.streamId
                );

            const amount =
                Number(
                    req.body.amount || 0
                );

            const type =
                String(
                    req.body.type || "money"
                ).trim();

            const gift =
                String(
                    req.body.gift || ""
                ).trim();

            const emoji =
                String(
                    req.body.emoji || ""
                ).trim();


            if(
                !Number.isInteger(streamId) ||
                streamId <= 0
            ){

                return res.status(400).json({
                    success:false,
                    message:
                        "Invalid stream ID."
                });

            }


            const streamResult =
                await pool.query(`
                    SELECT
                        id,
                        user_id,
                        is_live
                    FROM streams
                    WHERE id = $1
                    LIMIT 1
                `,[
                    streamId
                ]);


            if(!streamResult.rows.length){

                return res.status(404).json({
                    success:false,
                    message:
                        "Stream not found."
                });

            }


            const stream =
                streamResult.rows[0];


            const creatorId =
                Number(stream.user_id);


            /*
             * Money support can be zero for gifts.
             */

            const safeAmount =
                Number.isFinite(amount) &&
                amount >= 0
                    ? amount
                    : 0;


            const result =
                await pool.query(`
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
                    RETURNING
                        id,
                        sender_id,
                        creator_id,
                        stream_id,
                        amount,
                        type,
                        gift,
                        emoji,
                        created_at
                `,[
                    req.user.id,
                    creatorId,
                    streamId,
                    safeAmount,
                    type,
                    gift,
                    emoji
                ]);


            const support =
                result.rows[0];


            /*
             * Send support event instantly to
             * everyone watching this stream.
             */

            io.to(
                "stream:" + streamId
            ).emit(
                "support-received",
                {

                    id:
                        Number(
                            support.id
                        ),

                    streamId:
                        Number(
                            support.stream_id
                        ),

                    senderId:
                        Number(
                            support.sender_id
                        ),

                    creatorId:
                        Number(
                            support.creator_id
                        ),

                    amount:
                        Number(
                            support.amount || 0
                        ),
              type:
                        support.type,

                    gift:
                        support.gift,

                    emoji:
                        support.emoji,

                    senderName:
                        req.user.name ||
                        req.user.username ||
                        "User",

                    senderUsername:
                        req.user.username ||
                        "User",

                    created_at:
                        support.created_at

                }
            );


            return res.status(201).json({

                success:true,

                support:{

                    id:
                        Number(
                            support.id
                        ),

                    streamId:
                        Number(
                            support.stream_id
                        ),

                    creatorId:
                        Number(
                            support.creator_id
                        ),

                    amount:
                        Number(
                            support.amount || 0
                        ),

                    type:
                        support.type,

                    gift:
                        support.gift,

                    emoji:
                        support.emoji

                }

            });

        }catch(error){

            console.error(
                "Support error:",
                error.message
            );


            return res.status(500).json({
                success:false,
                message:
                    "Unable to send support."
            });

        }

    }
);


/* =========================================
   REAL-TIME VIEWER HELPERS
========================================= */

/*
 * streamViewers was created in Part 1.
 *
 * Each stream gets a Set containing socket IDs.
 *
 * This prevents the same viewer socket from
 * being counted multiple times.
 */

function getStreamViewerSet(
    streamId
){

    const id =
        Number(streamId);


    if(!streamViewers.has(id)){

        streamViewers.set(
            id,
            new Set()
        );

    }


    return streamViewers.get(id);

}


/* =========================================
   SET DATABASE VIEWER COUNT
========================================= */

async function syncViewerCount(
    streamId
){

    const id =
        Number(streamId);


    const viewers =
        getStreamViewerSet(id);


    const count =
        viewers.size;


    try{

        await pool.query(`
            UPDATE streams
            SET viewer_count = $1
            WHERE id = $2
        `,[
            count,
            id
        ]);

    }catch(error){

        console.error(
            "Viewer count sync error:",
            error.message
        );

    }


    io.to(
        "stream:" + id
    ).emit(
        "viewer-count",
        {
            streamId:id,
            viewerCount:count,
            viewers:count
        }
    );


    /*
     * Also tell the whole application that
     * the stream viewer count changed.
     */

    io.emit(
        "stream-viewers-updated",
        {
            streamId:id,
            viewerCount:count,
            viewers:count
        }
    );


    return count;

}


/* =========================================
   REMOVE VIEWER FROM STREAM
========================================= */

async function removeViewerFromStream(
    socket,
    streamId
){

    const id =
        Number(streamId);


    const viewers =
        streamViewers.get(id);


    if(!viewers){

        return 0;

    }


    /*
     * Delete only if this socket was actually
     * inside the Set.
     */

    viewers.delete(
        socket.id
    );


    if(viewers.size === 0){

        streamViewers.delete(id);

    }


    return await syncViewerCount(id);

}


/* =========================================
   SOCKET.IO REAL-TIME CONNECTION
========================================= */

io.on(
    "connection",
    (socket)=>{

        console.log(
            "Socket connected:",
            socket.id
        );


        socket.data.streamId =
            null;


        /* =====================================
           JOIN STREAM
        ===================================== */

        socket.on(
            "join-stream",
            async(payload)=>{

                try{

                    let streamId;


                    /*
                     * Supports both:
                     *
                     * join-stream(123)
                     *
                     * and
                     *
                     * join-stream({
                     *   streamId:123
                     * })
                     */

                    if(
                        typeof payload ===
                        "object" &&
                        payload !== null
                    ){

                        streamId =
                            Number(
                                payload.streamId
                            );

                    }else{

                        streamId =
                            Number(payload);

                    }


                    if(
                        !Number.isInteger(streamId) ||
                        streamId <= 0
                    ){

                        socket.emit(
                            "viewer-error",
                            {
                                message:
                                    "Invalid stream ID."
                            }
                        );

                        return;

                    }


                    /*
                     * Make sure the stream exists.
                     */

                    const streamResult =
                        await pool.query(`
                            SELECT
                                id,
                                is_live
                            FROM streams
                            WHERE id = $1
                            LIMIT 1
                        `,[
                            streamId
                        ]);


                    if(!streamResult.rows.length){

                        socket.emit(
                            "viewer-error",
                            {
                                message:
                                    "Stream not found."
                            }
                        );

                        return;

                    }


                    /*
                     * If the socket is already inside
                     * this exact stream, don't count
                     * it again.
                     */

                    if(
                        Number(
                            socket.data.streamId
                        ) === streamId
                    ){

                        const viewers =
                            getStreamViewerSet(
                                streamId
                            );


                        socket.emit(
                            "viewer-count",
                            {
                                streamId,

                                viewerCount:
                                    viewers.size,

                                viewers:
                                    viewers.size
                            }
                        );


                        return;

                    }


                    /*
                     * If this socket was watching a
                     * different stream, remove it first.
                     */

                    if(
                        socket.data.streamId
                    ){

                        const oldStreamId =
                            Number(
                                socket.data.streamId
                            );


                        socket.leave(
                            "stream:" +
                            oldStreamId
                        );


                        await removeViewerFromStream(
                            socket,
                            oldStreamId
                        );

                    }


                    /*
                     * Join new room.
                     */

                    const room =
                        "stream:" +
                        streamId;


                    socket.join(room);


                    const viewers =
                        getStreamViewerSet(
                            streamId
                        );


                    /*
                     * Set prevents duplicate counting.
                     */

                    viewers.add(
                        socket.id
                    );


                    socket.data.streamId =
                        streamId;


                    /*
                     * Synchronize DB and broadcast
                     * immediately.
                     */

                    const count =
                        await syncViewerCount(
                            streamId
                        );


                    socket.emit(
                        "stream-joined",
                        {

                            streamId,

                            viewerCount:
                                count,

                            viewers:
                                count

                        }
                    );


                }catch(error){

                    console.error(
                        "Join stream error:",
                        error.message
                    );


                    socket.emit(
                        "viewer-error",
                        {
                            message:
                                "Unable to join stream."
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
            async(payload)=>{

                try{

                    let streamId =
                        socket.data.streamId;


                    /*
                     * Allow explicit stream ID too.
                     */

                    if(
                        typeof payload ===
                        "object" &&
                        payload !== null &&
                        payload.streamId
                    ){

                        streamId =
                            Number(
                                payload.streamId
                            );

                    }else if(
                        payload &&
                        !isNaN(Number(payload))
                    ){

                        streamId =
                            Number(payload);

                    }


                    if(
                        !streamId
                    ){

                        return;

                    }


                    streamId =
                        Number(streamId);


                    socket.leave(
                        "stream:" +
                        streamId
                    );


                    await removeViewerFromStream(
                        socket,
                        streamId
                    );


                    /*
                     * Only clear socket's current
                     * stream when it actually matches.
                     */

                    if(
                        Number(
                            socket.data.streamId
                        ) === streamId
                    ){

                        socket.data.streamId =
                            null;

                    }


                }catch(error){

                    console.error(
                        "Leave stream error:",
                        error.message
                    );

                }

            }
        );


        /* =====================================
           DIRECT SOCKET CHAT
        ===================================== */

        socket.on(
            "send-chat-message",
            async(payload)=>{

                /*
                 * This event is intentionally
                 * supported in addition to the
                 * normal HTTP chat endpoint.
                 *
                 * If the current Watch page uses
                 * fetch(), that still works.
                 */

                try{

                    let streamId;

                    let message;


                    if(
                        payload &&
                        typeof payload ===
                        "object"
                    ){

                        streamId =
                            Number(
                                payload.streamId
                            );

                        message =
                            String(
                                payload.message || ""
                            ).trim();

                    }else{

                        return;

                    }


                    if(
                        !Number.isInteger(streamId) ||
                        streamId <= 0 ||
                        !message
                    ){

                        return;

                    }


                    if(
                        message.length > 500
                    ){

                        return;

                    }


                    /*
                     * We only allow socket chat from
                     * a socket that is actually inside
                     * this stream.
                     */

                    if(
                        Number(
                            socket.data.streamId
                        ) !== streamId
                    ){

                        socket.emit(
                            "chat-error",
                            {
                                message:
                                    "Join the stream first."
                            }
                        );

                        return;

                    }


                    /*
                     * The socket itself is not
                     * authenticated in the handshake,
                     * so don't create a DB message
                     * here unless a valid token was
                     * supplied.
                     *
                     * The normal authenticated HTTP
                     * endpoint remains the primary
                     * save path.
                     */

                    if(
                        payload.token
                    ){

                        const token =
                            String(
                                payload.token
                            ).replace(
                                /^Bearer\s+/i,
                                ""
                            ).trim();


                        if(token){

                            const tokenHash =
                                hashToken(token);


                            const session =
                                await pool.query(`
                                    SELECT
                                        s.user_id,
                                        u.id,
                                        u.name,
                 u.username
                                    FROM sessions s

                                    JOIN users u
                                        ON u.id =
                                           s.user_id

                                    WHERE
                                        s.token_hash =
                                        $1

                                    AND
                                        s.expires_at >
                                        CURRENT_TIMESTAMP

                                    LIMIT 1
                                `,[
                                    tokenHash
                                ]);


                            if(
                                session.rows.length
                            ){

                                const user =
                                    session.rows[0];


                                const saved =
                                    await pool.query(`
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
                                    `,[
                                        streamId,
                                        user.id,
                                        message
                                    ]);


                                const row =
                                    saved.rows[0];


                                const chatMessage = {

                                    id:
                                        Number(
                                            row.id
                                        ),

                                    streamId:
                                        streamId,

                                    stream_id:
                                        streamId,

                                    userId:
                                        Number(
                                            row.user_id
                                        ),
                                                                  ),

                                    in
                                    created_at:
                                        row.created_at

                                };


                                io.to(
                                    "stream:" +
                                    streamId
                                ).emit(
                                    "chat-message",
                                    chatMessage
                                );


                                return;

                            }

                        }

                    }


                }catch(error){

                    console.error(
                        "Socket chat error:",
                        error.message
                    );

                }

            }
        );


        /* =====================================
           DISCONNECT
        ===================================== */

        socket.on(
            "disconnect",
            async(reason)=>{

                try{

                    const streamId =
                        socket.data.streamId;


                    console.log(
                        "Socket disconnected:",
                        socket.id,
                        reason
                    );


                    if(streamId){

                        await removeViewerFromStream(
                            socket,
                            streamId
                        );

                    }


                }catch(error){

                    console.error(
                        "Disconnect cleanup error:",
                        error.message
                    );

                }

            }
        );

    }
);
/* =========================================
   SERVER HEALTH
========================================= */

app.get(
    "/",
    (req,res)=>{

        res.json({

            success:true,

            app:
                "Canvas",

            status:
                "online",

            message:
                "Canvas API is running.",

            realtime:
                "Socket.IO online",

            timestamp:
                new Date().toISOString()

        });

    }
);


/* =========================================
   DATABASE TEST
========================================= */

app.get(
    "/api/database-test",
    async(req,res)=>{

        try{

            if(!pool){

                return res.status(500).json({

                    success:false,

                    connected:false,

                    message:
                        "Database pool is not configured."

                });

            }


            const result =
                await pool.query(
                    "SELECT NOW() AS now"
                );


            return res.json({

                success:true,

                connected:true,

                message:
                    "Database connection is working.",

                time:
                    result.rows[0].now

            });

        }catch(error){

            console.error(
                "Database test error:",
                error.message
            );


            return res.status(500).json({

                success:false,

                connected:false,

                message:
                    "Database connection failed.",

                error:
                    error.message

            });

        }

    }
);


/* =========================================
   REAL-TIME STREAM STATUS
========================================= */

app.get(
    "/api/streams/:streamId/realtime",
    async(req,res)=>{

        try{

            const streamId =
                Number(
                    req.params.streamId
                );


            if(
                !Number.isInteger(streamId) ||
                streamId <= 0
            ){

                return res.status(400).json({

                    success:false,

                    message:
                        "Invalid stream ID."

                });

            }


            const result =
                await pool.query(`
                    SELECT
                        s.id,
                        s.user_id,
                        s.title,
                        s.description,
                        s.category,
                        s.thumbnail,
                        s.status,
                        s.is_live,

                        u.name AS creator_name,
                        u.username AS creator_username

                    FROM streams s

                    LEFT JOIN users u
                        ON u.id = s.user_id

                    WHERE s.id = $1

                    LIMIT 1
                `,[
                    streamId
                ]);


            if(!result.rows.length){

                return res.status(404).json({

                    success:false,

                    message:
                        "Stream not found."

                });

            }


            const stream =
                result.rows[0];


            const viewers =
                streamViewers.has(
                    streamId
                )
                    ? streamViewers
                        .get(streamId)
                        .size
                    : 0;


            return res.json({

                success:true,

                stream:{

                    id:
                        Number(
                            stream.id
                        ),

                    userId:
                        Number(
                            stream.user_id
                        ),

                    title:
                        stream.title,

                    description:
                        stream.description,

                    category:
                        stream.category,

                    thumbnail:
                        stream.thumbnail,

                    status:
                        stream.status,

                    isLive:
                        Boolean(
                            stream.is_live
                        ),

                    viewerCount:
                        viewers,

                    viewers,

                    creator:{

                        id:
                            Number(
                                stream.user_id
                            ),

                        name:
                            stream.creator_name ||
                            "Creator",

                        username:
                            stream.creator_username ||
                            ""

                    }

                }

            });

        }catch(error){

            console.error(
                "Realtime stream error:",
                error.message
            );


            return res.status(500).json({

                success:false,

                message:
                    "Unable to load realtime stream."

            });

        }

    }
);


/* =========================================
   GLOBAL API 404
========================================= */

app.use(
    (req,res)=>{

        res.status(404).json({

            success:false,

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
    (error,req,res,next)=>{

        console.error(
            "Canvas server error:",
            error
        );


        if(res.headersSent){

            return next(error);

        }


        res.status(500).json({

            success:false,

            message:
                "Canvas server error."

        });

    }
);


/* =========================================
   START SERVER
========================================= */

async function startServer(){

    try{

        /*
         * Initialize the database before
         * accepting requests.
         */

        await initializeDatabase();


        /*
         * Make sure chat/support tables exist.
         */

        await ensureChatTable();

        await ensureSupportTable();


        /*
         * IMPORTANT:
         *
         * Viewer counts are runtime/socket based.
         * After a server restart there are no connected
         * sockets yet, so old database viewer counts
         * must not remain visible.
         */

        if(pool){

            await pool.query(`
                UPDATE streams
                SET viewer_count = 0
                WHERE is_live = true
            `);

        }


        server.listen(
            PORT,
            "0.0.0.0",
            ()=>{

                console.log(
                    "================================="
                );

                console.log(
                    "Canvas server is running."
                );

                console.log(
                    "Port:",
                    PORT
                );

                console.log(
                    "Realtime:",
                    "Socket.IO"
                );

                console.log(
                    "Database:",
                    pool
                        ? "configured"
                        : "not configured"
                );

                console.log(
                    "================================="
                );

            }
        );


    }catch(error){

        console.error(
            "Canvas startup error:",
            error
        );


        /*
         * Don't silently keep a broken server
         * alive if database initialization fails.
         */

        process.exit(1);

    }

}


startServer();


/* =========================================
   PROCESS CLEANUP
========================================= */

async function shutdown(
    signal
){

    console.log(
        `${signal} received. Shutting down Canvas...`
    );


    try{

        /*
         * Stop accepting new HTTP connections.
         */

        server.close(
            async()=>{

                try{

                    if(pool){

                        await pool.end();

                    }

                }catch(error){

                    console.error(
                        "Database shutdown error:",
                        error.message
                    );

                }


                console.log(
                    "Canvas server stopped."
                );


                process.exit(0);

            }
        );


    }catch(error){

        console.error(
            "Shutdown error:",
            error.message
        );


        process.exit(1);

    }

}


process.on(
    "SIGTERM",
    ()=>shutdown("SIGTERM")
);

process.on(
    "SIGINT",
    ()=>shutdown("SIGINT")
);
