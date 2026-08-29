const express = require("express");
const { Pool } = require("pg");
const crypto = require("crypto");
const http = require("http");
const { Server } = require("socket.io");

const app = express();

const server = http.createServer(app);

const io = new Server(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
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
   JSON BODY
========================================= */

app.use(
    express.json({
        limit:"15mb"
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
   USERNAME CLEANER
========================================= */

function cleanUsername(username){

    return String(username || "")
        .trim()
        .replace(/^@/,"")
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


        if(
            result.rows.length === 0
        ){

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
            "Authentication failed:",
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

        /* USERS */

        await pool.query(`

            CREATE TABLE IF NOT EXISTS users (

                id SERIAL PRIMARY KEY,

                name VARCHAR(100) NOT NULL,

                username VARCHAR(100)
                    UNIQUE NOT NULL,

                email VARCHAR(255)
                    UNIQUE NOT NULL,

                password_hash TEXT
                    NOT NULL,

                created_at TIMESTAMP
                    DEFAULT CURRENT_TIMESTAMP

            );

        `);


        /* PROFILES */

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


        /* SESSIONS */

        await pool.query(`

            CREATE TABLE IF NOT EXISTS sessions (

                id SERIAL PRIMARY KEY,

                user_id INTEGER
                    NOT NULL
                    REFERENCES users(id)
                    ON DELETE CASCADE,

                token_hash TEXT
                    UNIQUE NOT NULL,

                created_at TIMESTAMP
                    DEFAULT CURRENT_TIMESTAMP,

                expires_at TIMESTAMP
                    NOT NULL

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

                category VARCHAR(100)
                    DEFAULT 'Other',

                description TEXT
                    DEFAULT '',

                thumbnail TEXT
                    DEFAULT '',

                status VARCHAR(30)
                    DEFAULT 'ended',

                created_at TIMESTAMP
                    DEFAULT CURRENT_TIMESTAMP,

                ended_at TIMESTAMP

            );

        `);


        /* =====================================
           UPGRADE OLD STREAM TABLE
        ===================================== */

        await pool.query(`

            ALTER TABLE streams

            ADD COLUMN IF NOT EXISTS
                user_id INTEGER
                REFERENCES users(id)
                ON DELETE CASCADE;

        `);


        await pool.query(`

            ALTER TABLE streams

            ADD COLUMN IF NOT EXISTS
                category VARCHAR(100)
                DEFAULT 'Other';

        `);


        await pool.query(`

            ALTER TABLE streams

            ADD COLUMN IF NOT EXISTS
                description TEXT
                DEFAULT '';

        `);


        await pool.query(`

            ALTER TABLE streams

            ADD COLUMN IF NOT EXISTS
                thumbnail TEXT
                DEFAULT '';

        `);


        await pool.query(`

            ALTER TABLE streams

            ADD COLUMN IF NOT EXISTS
                ended_at TIMESTAMP;

        `);


        console.log(
            "Canvas database initialized successfully."
        );


    }catch(error){

        console.error(
            "Database initialization failed:",
            error.message
        );

    }

}


/* =========================================
   BACKEND STATUS
========================================= */

app.get(
    "/",
    (req,res) => {

        res.json({

            status:"online",

            message:
                "Canvas backend is running."

        });

    }
);


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


            return res.json({

                success:true,

                database:
                    "connected",

                message:
                    "Canvas database connection is working.",

                server_time:
                    result.rows[0].now

            });


        }catch(error){

            console.error(
                "Database test failed:",
                error.message
            );


            return res.status(500).json({

                success:false,

                database:
                    "connection failed",

                message:
                    error.message

            });

        }

    }
);


/* =========================================
   SOCKET STATE
========================================= */

const streamRooms = new Map();


/* =========================================
   SOCKET CONNECTION
========================================= */

io.on(
    "connection",
    (socket) => {

        console.log(
            "Canvas Socket connected:",
            socket.id
        );


        socket.on(
            "disconnect",
            () => {

                console.log(
                    "Canvas Socket disconnected:",
                    socket.id
                );

            }
        );

    }
);
 
/* =========================================
   SIGNUP
========================================= */

const verificationCodes = new Map();


function generateVerificationCode(){

    return String(
        Math.floor(
            100000 +
            Math.random() * 900000
        )
    );

}


/* =========================================
   SEND SIGNUP CODE
========================================= */

app.post(
    "/api/signup/send-code",
    async (req,res) => {

        if(!pool){

            return res.status(500).json({

                success:false,

                message:
                    "Database is not configured."

            });

        }


        const name =
            String(
                req.body.name || ""
            ).trim();


        const username =
            cleanUsername(
                req.body.username
            );


        const email =
            String(
                req.body.email || ""
            )
            .trim()
            .toLowerCase();


        const password =
            String(
                req.body.password || ""
            );


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


        if(password.length < 6){

            return res.status(400).json({

                success:false,

                message:
                    "Password must be at least 6 characters."

            });

        }


        try{

            const existing =
                await pool.query(

                    `
                    SELECT id
                    FROM users
                    WHERE
                        username = $1
                    OR
                        email = $2
                    LIMIT 1
                    `,

                    [
                        username,
                        email
                    ]

                );


            if(existing.rows.length){

                return res.status(409).json({

                    success:false,

                    message:
                        "Username or email is already registered."

                });

            }


            const code =
                generateVerificationCode();


            verificationCodes.set(
                email,
                {

                    code:code,

                    name:name,

                    username:username,

                    email:email,

                    password:password,

                    expiresAt:
                        Date.now() +
                        10 * 60 * 1000

                }
            );


            console.log(
                "Canvas verification code:",
                email,
                code
            );


            /*
             * Email delivery can be connected
             * to your Resend setup here.
             *
             * The signup verification data
             * remains server-side.
             */


            return res.json({

                success:true,

                message:
                    "Verification code generated.",

                email:email

            });


        }catch(error){

            console.error(
                "Signup code error:",
                error.message
            );


            return res.status(500).json({

                success:false,

                message:
                    "Unable to send verification code."

            });

        }

    }
);


/* =========================================
   VERIFY SIGNUP CODE
========================================= */

app.post(
    "/api/signup/verify-code",
    async (req,res) => {

        if(!pool){

            return res.status(500).json({

                success:false,

                message:
                    "Database is not configured."

            });

        }


        const email =
            String(
                req.body.email || ""
            )
            .trim()
            .toLowerCase();


        const code =
            String(
                req.body.code || ""
            ).trim();


        if(!email || !code){

            return res.status(400).json({

                success:false,

                message:
                    "Email and verification code are required."

            });

        }


        const verification =
            verificationCodes.get(
                email
            );


        if(!verification){

            return res.status(400).json({

                success:false,

                message:
                    "Verification code not found or expired."

            });

        }


        if(
            Date.now() >
            verification.expiresAt
        ){

            verificationCodes.delete(
                email
            );


            return res.status(400).json({

                success:false,

                message:
                    "Verification code has expired."

            });

        }


        if(
            verification.code !==
            code
        ){

            return res.status(400).json({

                success:false,

                message:
                    "Invalid verification code."

            });

        }


        try{

            const existing =
                await pool.query(

                    `
                    SELECT id
                    FROM users

                    WHERE
                        username = $1

                    OR
                        email = $2

                    LIMIT 1
                    `,

                    [
                        verification.username,
                        verification.email
                    ]

                );


            if(existing.rows.length){

                verificationCodes.delete(
                    email
                );


                return res.status(409).json({

                    success:false,

                    message:
                        "Username or email is already registered."

                });

            }


            const passwordHash =
                hashPassword(
                    verification.password
                );


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

                    VALUES
                    (
                        $1,
                        $2,
                        $3,
                        $4
                    )

                    RETURNING
                        id,
                        name,
                        username,
                        email,
                        created_at
                    `,

                    [
                        verification.name,
                        verification.username,
                        verification.email,
                        passwordHash
                    ]

                );


            const user =
                userResult.rows[0];


            await pool.query(

                `
                INSERT INTO profiles
                (
                    user_id
                )

                VALUES
                ($1)

                ON CONFLICT
                    (user_id)
                DO NOTHING
                `,

                [
                    user.id
                ]

            );


            verificationCodes.delete(
                email
            );


            return res.status(201).json({

                success:true,

                message:
                    "Canvas account created successfully.",

                user:user

            });


        }catch(error){

            console.error(
                "Signup verification error:",
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
    async (req,res) => {

        if(!pool){

            return res.status(500).json({

                success:false,

                message:
                    "Database is not configured."

            });

        }


        const login =
            String(
                req.body.email ||
                req.body.username ||
                req.body.login ||
                ""
            )
            .trim()
            .toLowerCase();


        const password =
            String(
                req.body.password || ""
            );


        if(
            !login ||
            !password
        ){

            return res.status(400).json({

                success:false,

                message:
                    "Email/username and password are required."

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

                    WHERE
                        LOWER(email) = $1

                    OR
                        LOWER(username) = $1

                    LIMIT 1
                    `,

                    [
                        login
                    ]

                );


            if(
                result.rows.length === 0
            ){

                return res.status(401).json({

                    success:false,

                    message:
                        "Invalid email/username or password."

                });

            }


            const user =
                result.rows[0];


            const passwordHash =
                hashPassword(
                    password
                );


            if(
                passwordHash !==
                user.password_hash
            ){

                return res.status(401).json({

                    success:false,

                    message:
                        "Invalid email/username or password."

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

                VALUES
                (
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


            delete user.password_hash;


            return res.json({

                success:true,

                message:
                    "Login successful.",

                token:token,

                user:user

            });


        }catch(error){

            console.error(
                "Login error:",
                error.message
            );


            return res.status(500).json({

                success:false,

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
    async (req,res) => {

        try{

            const result =
                await pool.query(

                    `
                    SELECT

                        users.id,

                        users.name,

                        users.username,

                        users.email,

                        users.created_at,

                        COALESCE(
                            profiles.bio,
                            ''
                        ) AS bio,

                        COALESCE(
                            profiles.profile_picture,
                            ''
                        ) AS profile_picture

                    FROM users

                    LEFT JOIN profiles

                        ON profiles.user_id =
                           users.id

                    WHERE
                        users.id = $1

                    LIMIT 1
                    `,

                    [
                        req.user.id
                    ]

                );


            if(
                result.rows.length === 0
            ){

                return res.status(404).json({

                    success:false,

                    message:
                        "User not found."

                });

            }


            const user =
                result.rows[0];


            return res.json({

                success:true,

                user:user

            });


        }catch(error){

            console.error(
                "ME endpoint error:",
                error.message
            );


            return res.status(500).json({

                success:false,

                message:
                    "Unable to load your Canvas account."

            });

        }

    }
);


/* =========================================
   GET PROFILE
========================================= */

app.get(
    "/api/profile",
    authenticateUser,
    async (req,res) => {

        try{

            const result =
                await pool.query(

                    `
                    SELECT

                        users.id,

                        users.name,

                        users.username,

                        users.email,

                        COALESCE(
                            profiles.bio,
                            ''
                        ) AS bio,

                        COALESCE(
                            profiles.profile_picture,
                            ''
                        ) AS profile_picture

                    FROM users

                    LEFT JOIN profiles

                        ON profiles.user_id =
                           users.id

                    WHERE
                        users.id = $1

                    LIMIT 1
                    `,

                    [
                        req.user.id
                    ]

                );


            if(
                result.rows.length === 0
            ){

                return res.status(404).json({

                    success:false,

                    message:
                        "Profile not found."

                });

            }


            return res.json({

                success:true,

                profile:
                    result.rows[0]

            });


        }catch(error){

            console.error(
                "Profile load error:",
                error.message
            );


            return res.status(500).json({

                success:false,

                message:
                    "Unable to load profile."

            });

        }

    }
);


/* =========================================
   UPDATE PROFILE
========================================= */

app.put(
    "/api/profile",
    authenticateUser,
    async (req,res) => {

        const name =
            String(
                req.body.name ||
                ""
            ).trim();


        const username =
            cleanUsername(
                req.body.username
            );


        const bio =
            String(
                req.body.bio ||
                ""
            ).trim();


        const profilePicture =
            String(
                req.body.profile_picture ||
                req.body.profilePicture ||
                req.body.photo ||
                ""
            );


        if(!name || !username){

            return res.status(400).json({

                success:false,

                message:
                    "Name and username are required."

            });

        }


        if(name.length > 100){

            return res.status(400).json({

                success:false,

                message:
                    "Name is too long."

            });

        }


        if(username.length > 100){

            return res.status(400).json({

                success:false,

                message:
                    "Username is too long."

            });

        }


        if(bio.length > 1000){

            return res.status(400).json({

                success:false,

                message:
                    "Bio is too long."

            });

        }


        try{

            const duplicate =
                await pool.query(

                    `
                    SELECT id
                    FROM users

                    WHERE
                        username = $1

                    AND
                        id <> $2

                    LIMIT 1
                    `,

                    [
                        username,
                        req.user.id
                    ]

                );


            if(
                duplicate.rows.length
            ){

                return res.status(409).json({

                    success:false,

                    message:
                        "That username is already taken."

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
                    req.user.id
                ]

            );


            await pool.query(

                `
                INSERT INTO profiles
                (
                    user_id,
                    bio,
                    profile_picture
                )

                VALUES
                (
                    $1,
                    $2,
                    $3
                )

                ON CONFLICT
                    (user_id)

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


            return res.json({

                success:true,

                message:
                    "Profile updated successfully."

            });


        }catch(error){

            console.error(
                "Profile update error:",
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
   STREAMS
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
                req.body.title || ""
            ).trim();


        const category =
            String(
                req.body.category ||
                "Other"
            ).trim();


        const description =
            String(
                req.body.description ||
                ""
            ).trim();


        if(!title){

            return res.status(400).json({

                success:false,

                message:
                    "Stream title is required."

            });

        }


        if(title.length > 100){

            return res.status(400).json({

                success:false,

                message:
                    "Stream title is too long."

            });

        }


        if(description.length > 500){

            return res.status(400).json({

                success:false,

                message:
                    "Stream description is too long."

            });

        }


        const allowedCategories = [

            "Gaming",
            "Entertainment",
            "Music",
            "Education",
            "Sports",
            "Technology",
            "Other"

        ];


        const finalCategory =
            allowedCategories.includes(
                category
            )
                ? category
                : "Other";


        try{

            /*
             * Prevent one user from creating
             * multiple active streams.
             */

            const active =
                await pool.query(

                    `
                    SELECT id
                    FROM streams

                    WHERE
                        user_id = $1

                    AND
                        is_live = TRUE

                    LIMIT 1
                    `,

                    [
                        req.user.id
                    ]

                );


            if(active.rows.length){

                return res.status(409).json({

                    success:false,

                    message:
                        "You already have a live stream."

                });

            }


            const result =
                await pool.query(

                    `
                    INSERT INTO streams
                    (
                        user_id,
                        title,
                        category,
                        description,
                        is_live,
                        started_at
                    )

                    VALUES
                    (
                        $1,
                        $2,
                        $3,
                        $4,
                        TRUE,
                        CURRENT_TIMESTAMP
                    )

                    RETURNING
                        id,
                        user_id,
                        title,
                        category,
                        description,
                        is_live,
                        started_at
                    `,

                    [
                        req.user.id,
                        title,
                        finalCategory,
                        description
                    ]

                );


            const stream =
                result.rows[0];


            return res.status(201).json({

                success:true,

                message:
                    "Canvas stream created.",

                stream:stream

            });


        }catch(error){

            console.error(
                "Create stream error:",
                error.message
            );


            return res.status(500).json({

                success:false,

                message:
                    "Unable to create Canvas stream."

            });

        }

    }
);


/* =========================================
   LIVE STREAMS
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

                        streams.title,

                        streams.category,

                        streams.description,

                        streams.is_live,

                        streams.started_at,

                        users.id
                            AS user_id,

                        users.name,

                        users.username,

                        COALESCE(
                            profiles.profile_picture,
                            ''
                        )
                            AS profile_picture

                    FROM streams

                    INNER JOIN users

                        ON users.id =
                           streams.user_id

                    LEFT JOIN profiles

                        ON profiles.user_id =
                           users.id

                    WHERE
                        streams.is_live = TRUE

                    ORDER BY
                        streams.started_at DESC
                    `

                );


            return res.json({

                success:true,

                streams:
                    result.rows

            });


        }catch(error){

            console.error(
                "Live streams error:",
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
   SINGLE STREAM
========================================= */

app.get(
    "/api/streams/:id",
    async (req,res) => {

        const streamId =
            String(
                req.params.id ||
                ""
            ).trim();


        if(!streamId){

            return res.status(400).json({

                success:false,

                message:
                    "Stream ID is required."

            });

        }


        try{

            const result =
                await pool.query(

                    `
                    SELECT

                        streams.id,

                        streams.title,

                        streams.category,

                        streams.description,

                        streams.is_live,

                        streams.started_at,

                        streams.ended_at,

                        users.id
                            AS user_id,

                        users.name,

                        users.username,

                        COALESCE(
                            profiles.profile_picture,
                            ''
                        )
                            AS profile_picture

                    FROM streams

                    INNER JOIN users

                        ON users.id =
                           streams.user_id

                    LEFT JOIN profiles

                        ON profiles.user_id =
                           users.id

                    WHERE
                        streams.id = $1

                    LIMIT 1
                    `,

                    [
                        streamId
                    ]

                );


            if(
                result.rows.length === 0
            ){

                return res.status(404).json({

                    success:false,

                    message:
                        "Stream not found."

                });

            }


            return res.json({

                success:true,

                stream:
                    result.rows[0]

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
   END OWN STREAM
========================================= */

app.put(
    "/api/streams/:id/end",
    authenticateUser,
    async (req,res) => {

        const streamId =
            String(
                req.params.id ||
                ""
            ).trim();


        if(!streamId){

            return res.status(400).json({

                success:false,

                message:
                    "Stream ID is required."

            });

        }


        try{

            const result =
                await pool.query(

                    `
                    UPDATE streams

                    SET

                        is_live = FALSE,

                        ended_at =
                            CURRENT_TIMESTAMP

                    WHERE

                        id = $1

                    AND

                        user_id = $2

                    AND

                        is_live = TRUE

                    RETURNING

                        id,

                        title,

                        category,

                        description,

                        is_live,

                        started_at,

                        ended_at
                    `,

                    [
                        streamId,
                        req.user.id
                    ]

                );


            if(
                result.rows.length === 0
            ){

                return res.status(404).json({

                    success:false,

                    message:
                        "Live stream not found or you do not own it."

                });

            }


            /*
             * Notify connected viewers that
             * this stream has ended.
             */

            if(
                io &&
                typeof io.to === "function"
            ){

                io.to(
                    "stream:" +
                    streamId
                ).emit(
                    "stream-ended",
                    {

                        streamId:
                            streamId

                    }
                );

            }


            return res.json({

                success:true,

                message:
                    "Canvas stream ended.",

                stream:
                    result.rows[0]

            });


        }catch(error){

            console.error(
                "End stream error:",
                error.message
            );


            return res.status(500).json({

                success:false,

                message:
                    "Unable to end Canvas stream."

            });

        }

    }
);


/* =========================================
   STREAM SEARCH
========================================= */

app.get(
    "/api/streams/search",
    async (req,res) => {

        const query =
            String(
                req.query.q ||
                ""
            ).trim();


        if(!query){

            return res.json({

                success:true,

                streams:[]

            });

        }


        try{

            const search =
                "%" +
                query.toLowerCase() +
                "%";


            const result =
                await pool.query(

                    `
                    SELECT

                        streams.id,

                        streams.title,

                        streams.category,

                        streams.description,

                        streams.is_live,

                        streams.started_at,

                        users.name,

                        users.username,

                        COALESCE(
                            profiles.profile_picture,
                            ''
                        )
                            AS profile_picture

                    FROM streams

                    INNER JOIN users

                        ON users.id =
                           streams.user_id

                    LEFT JOIN profiles

                        ON profiles.user_id =
                           users.id

                    WHERE

                        streams.is_live = TRUE

                    AND
                    (
                        LOWER(streams.title)
                            LIKE $1

                        OR

                        LOWER(streams.category)
                            LIKE $1

                        OR

                        LOWER(streams.description)
                            LIKE $1

                        OR

                        LOWER(users.name)
                            LIKE $1

                        OR

                        LOWER(users.username)
                            LIKE $1
                    )

                    ORDER BY
                        streams.started_at DESC

                    LIMIT 50
                    `,

                    [
                        search
                    ]

                );


            return res.json({

                success:true,

                streams:
                    result.rows

            });


        }catch(error){

            console.error(
                "Stream search error:",
                error.message
            );


            return res.status(500).json({

                success:false,

                message:
                    "Unable to search Canvas streams."

            });

        }

    }
);


/* =========================================
   STREAM VIEW COUNT
========================================= */

app.post(
    "/api/streams/:id/view",
    async (req,res) => {

        const streamId =
            String(
                req.params.id ||
                ""
            ).trim();


        if(!streamId){

            return res.status(400).json({

                success:false,

                message:
                    "Stream ID is required."

            });

        }


        try{

            const result =
                await pool.query(

                    `
                    UPDATE streams

                    SET
                        viewer_count =
                            COALESCE(
                                viewer_count,
                                0
                            ) + 1

                    WHERE
                        id = $1

                    AND
                        is_live = TRUE

                    RETURNING
                        viewer_count
                    `,

                    [
                        streamId
                    ]

                );


            if(
                result.rows.length === 0
            ){

                return res.status(404).json({

                    success:false,

                    message:
                        "Live stream not found."

                });

            }


            return res.json({

                success:true,

                viewerCount:
                    result.rows[0]
                    .viewer_count

            });


        }catch(error){

            /*
             * If viewer_count does not exist
             * yet in an older database, don't
             * break the entire streaming API.
             */

            console.error(
                "Viewer count error:",
                error.message
            );


            return res.json({

                success:true,

                viewerCount:0

            });

        }

    }
);
/* =========================================
   SOCKET.IO STREAMING SIGNALING
========================================= */


/* =========================================
   SOCKET AUTH / CONNECTION
========================================= */

io.on(
    "connection",
    function(socket){

        console.log(
            "Canvas Socket connected:",
            socket.id
        );


        /* =====================================
           JOIN STREAM
        ===================================== */

        socket.on(
            "join-stream",
            function(data){

                if(
                    !data ||
                    !data.streamId
                ){

                    return;

                }


                const streamId =
                    String(
                        data.streamId
                    );


                const role =
                    data.role ===
                    "broadcaster"

                        ? "broadcaster"

                        : "viewer";


                const room =
                    "stream:" +
                    streamId;


                /*
                 * Save connection information.
                 */

                socket.canvasStreamId =
                    streamId;

                socket.canvasRole =
                    role;

                socket.canvasRoom =
                    room;


                /*
                 * Get users already inside
                 * the stream room BEFORE joining.
                 */

                const roomData =
                    io.sockets.adapter
                    .rooms.get(
                        room
                    );


                const existingPeers =
                    roomData
                        ? Array.from(
                            roomData
                        )
                        : [];


                /*
                 * Join room.
                 */

                socket.join(
                    room
                );


                console.log(
                    "Canvas stream joined:",
                    streamId,
                    role,
                    socket.id
                );


                /*
                 * Broadcaster gets existing
                 * viewers.
                 */

                if(
                    role ===
                    "broadcaster"
                ){

                    socket.emit(
                        "existing-peers",
                        existingPeers.filter(
                            function(peerId){

                                return (
                                    peerId !==
                                    socket.id
                                );

                            }
                        )
                    );

                }


                /*
                 * Tell everyone else that
                 * this peer joined.
                 */

                socket.to(
                    room
                ).emit(
                    "peer-joined",
                    {

                        socketId:
                            socket.id,

                        role:
                            role

                    }
                );

            }
        );


        /* =====================================
           LEAVE STREAM
        ===================================== */

        socket.on(
            "leave-stream",
            function(data){

                const streamId =
                    data &&
                    data.streamId

                        ? String(
                            data.streamId
                        )

                        : socket.canvasStreamId;


                if(!streamId){

                    return;

                }


                const room =
                    "stream:" +
                    streamId;


                socket.to(
                    room
                ).emit(
                    "peer-left",
                    {

                        socketId:
                            socket.id

                    }
                );


                socket.leave(
                    room
                );


                if(
                    socket.canvasRoom ===
                    room
                ){

                    socket.canvasRoom =
                        null;

                }


                if(
                    socket.canvasStreamId ===
                    streamId
                ){

                    socket.canvasStreamId =
                        null;

                }


                console.log(
                    "Canvas stream left:",
                    streamId,
                    socket.id
                );

            }
        );


        /* =====================================
           WEBRTC OFFER
        ===================================== */

        socket.on(
            "webrtc-offer",
            function(data){

                if(
                    !data ||
                    !data.target ||
                    !data.offer
                ){

                    return;

                }


                const target =
                    io.sockets.sockets.get(
                        data.target
                    );


                if(!target){

                    return;

                }


                target.emit(
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
            function(data){

                if(
                    !data ||
                    !data.target ||
                    !data.answer
                ){

                    return;

                }


                const target =
                    io.sockets.sockets.get(
                        data.target
                    );


                if(!target){

                    return;

                }


                target.emit(
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
           WEBRTC ICE CANDIDATE
        ===================================== */

        socket.on(
            "webrtc-ice",
            function(data){

                if(
                    !data ||
                    !data.target ||
                    !data.candidate
                ){

                    return;

                }


                const target =
                    io.sockets.sockets.get(
                        data.target
                    );


                if(!target){

                    return;

                }


                target.emit(
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
           VIEWER COUNT
        ===================================== */

        socket.on(
            "viewer-joined",
            async function(data){

                if(
                    !data ||
                    !data.streamId
                ){

                    return;

                }


                const streamId =
                    String(
                        data.streamId
                    );


                const room =
                    "stream:" +
                    streamId;


                socket.join(
                    room
                );


                try{

                    const result =
                        await pool.query(

                            `
                            UPDATE streams

                            SET
                                viewer_count =
                                    COALESCE(
                                        viewer_count,
                                        0
                                    ) + 1

                            WHERE
                                id = $1

                            AND
                                is_live = TRUE

                            RETURNING
                                viewer_count
                            `,

                            [
                                streamId
                            ]

                        );


                    if(
                        result.rows.length
                    ){

                        io.to(
                            room
                        ).emit(
                            "viewer-count",
                            {

                                streamId:
                                    streamId,

                                viewerCount:
                                    result.rows[0]
                                    .viewer_count

                            }
                        );

                    }

                }catch(error){

                    console.error(
                        "Viewer join count error:",
                        error.message
                    );

                }

            }
        );


        /* =====================================
           VIEWER LEFT
        ===================================== */

        socket.on(
            "viewer-left",
            async function(data){

                if(
                    !data ||
                    !data.streamId
                ){

                    return;

                }


                const streamId =
                    String(
                        data.streamId
                    );


                const room =
                    "stream:" +
                    streamId;


                try{

                    const result =
                        await pool.query(

                            `
                            UPDATE streams

                            SET
                                viewer_count =
                                    GREATEST(
                                        COALESCE(
                                            viewer_count,
                                            0
                                        ) - 1,
                                        0
                                    )

                            WHERE
                                id = $1

                            RETURNING
                                viewer_count
                            `,

                            [
                                streamId
                            ]

                        );


                    if(
                        result.rows.length
                    ){

                        io.to(
                            room
                        ).emit(
                            "viewer-count",
                            {

                                streamId:
                                    streamId,

                                viewerCount:
                                    result.rows[0]
                                    .viewer_count

                            }
                        );

                    }

                }catch(error){

                    console.error(
                        "Viewer leave count error:",
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
            async function(){

                console.log(
                    "Canvas Socket disconnected:",
                    socket.id
                );


                const streamId =
                    socket.canvasStreamId;


                const room =
                    socket.canvasRoom;


                /*
                 * Tell remaining peers that
                 * this connection disappeared.
                 */

                if(room){

                    socket.to(
                        room
                    ).emit(
                        "peer-left",
                        {

                            socketId:
                                socket.id

                        }
                    );

                }


                /*
                 * If broadcaster disconnects,
                 * notify viewers.
                 */

                if(
                    socket.canvasRole ===
                    "broadcaster" &&
                    streamId
                ){

                    io.to(
                        room
                    ).emit(
                        "broadcaster-disconnected",
                        {

                            streamId:
                                streamId

                        }
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
    "/api/health",
    async function(req,res){

        let database =
            false;


        try{

            if(pool){

                await pool.query(
                    "SELECT 1"
                );

                database =
                    true;

            }

        }catch(error){

            database =
                false;

        }


        return res.json({

            success:true,

            service:
                "Canvas Backend",

            status:
                "online",

            database:
                database
                    ? "connected"
                    : "disconnected",

            socket:
                io
                    ? "enabled"
                    : "disabled",

            time:
                new Date().toISOString()

        });

    }
);


/* =========================================
   404 API HANDLER
========================================= */

app.use(
    "/api",
    function(req,res){

        return res.status(404).json({

            success:false,

            message:
                "Canvas API endpoint not found."

        });

    }
);


/* =========================================
   GENERAL ERROR HANDLER
========================================= */

app.use(
    function(error,req,res,next){

        console.error(
            "Canvas server error:",
            error
        );


        if(res.headersSent){

            return next(
                error
            );

        }


        return res.status(500).json({

            success:false,

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
    3000;


server.listen(
    PORT,
    "0.0.0.0",
    function(){

        console.log(
            "================================="
        );

        console.log(
            "CANVAS BACKEND ONLINE"
        );

        console.log(
            "Port:",
            PORT
        );

        console.log(
            "Socket.IO: enabled"
        );

        console.log(
            "================================="
        );

    }
);
/* =========================================
   CANVAS DATABASE SETUP
========================================= */

async function setupDatabase(){

    if(!pool){

        console.error(
            "Canvas database is not configured."
        );

        return false;

    }


    try{

        /* =====================================
           USERS TABLE
        ===================================== */

        await pool.query(`

            CREATE TABLE IF NOT EXISTS users (

                id
                    SERIAL
                    PRIMARY KEY,

                name
                    VARCHAR(100)
                    NOT NULL,

                username
                    VARCHAR(100)
                    NOT NULL
                    UNIQUE,

                email
                    VARCHAR(255)
                    NOT NULL
                    UNIQUE,

                password_hash
                    TEXT
                    NOT NULL,

                created_at
                    TIMESTAMP
                    DEFAULT CURRENT_TIMESTAMP

            );

        `);


        /* =====================================
           PROFILES TABLE
        ===================================== */

        await pool.query(`

            CREATE TABLE IF NOT EXISTS profiles (

                id
                    SERIAL
                    PRIMARY KEY,

                user_id
                    INTEGER
                    NOT NULL
                    UNIQUE
                    REFERENCES users(id)
                    ON DELETE CASCADE,

                bio
                    TEXT
                    DEFAULT '',

                profile_picture
                    TEXT
                    DEFAULT '',

                updated_at
                    TIMESTAMP
                    DEFAULT CURRENT_TIMESTAMP

            );

        `);


        /* =====================================
           SESSIONS TABLE
        ===================================== */

        await pool.query(`

            CREATE TABLE IF NOT EXISTS sessions (

                id
                    SERIAL
                    PRIMARY KEY,

                user_id
                    INTEGER
                    NOT NULL
                    REFERENCES users(id)
                    ON DELETE CASCADE,

                token_hash
                    TEXT
                    NOT NULL
                    UNIQUE,

                expires_at
                    TIMESTAMP
                    NOT NULL,

                created_at
                    TIMESTAMP
                    DEFAULT CURRENT_TIMESTAMP

            );

        `);


        /* =====================================
           STREAMS TABLE
        ===================================== */

        await pool.query(`

            CREATE TABLE IF NOT EXISTS streams (

                id
                    SERIAL
                    PRIMARY KEY,

                user_id
                    INTEGER
                    NOT NULL
                    REFERENCES users(id)
                    ON DELETE CASCADE,

                title
                    VARCHAR(100)
                    NOT NULL,

                category
                    VARCHAR(50)
                    DEFAULT 'Other',

                description
                    VARCHAR(500)
                    DEFAULT '',

                thumbnail
                    TEXT
                    DEFAULT '',

                is_live
                    BOOLEAN
                    DEFAULT FALSE,

                viewer_count
                    INTEGER
                    DEFAULT 0,

                started_at
                    TIMESTAMP,

                ended_at
                    TIMESTAMP,

                created_at
                    TIMESTAMP
                    DEFAULT CURRENT_TIMESTAMP

            );

        `);


        /* =====================================
           STREAM INDEXES
        ===================================== */

        await pool.query(`

            CREATE INDEX IF NOT EXISTS
            streams_live_index

            ON streams(is_live);

        `);


        await pool.query(`

            CREATE INDEX IF NOT EXISTS
            streams_user_index

            ON streams(user_id);

        `);


        await pool.query(`

            CREATE INDEX IF NOT EXISTS
            streams_category_index

            ON streams(category);

        `);


        await pool.query(`

            CREATE INDEX IF NOT EXISTS
            sessions_user_index

            ON sessions(user_id);

        `);


        /* =====================================
           PROFILE INDEX
        ===================================== */

        await pool.query(`

            CREATE INDEX IF NOT EXISTS
            profiles_user_index

            ON profiles(user_id);

        `);


        console.log(
            "Canvas database tables are ready."
        );


        return true;


    }catch(error){

        console.error(
            "Canvas database setup failed:",
            error.message
        );


        return false;

    }

}


/* =========================================
   CLEAN EXPIRED SESSIONS
========================================= */

async function cleanExpiredSessions(){

    if(!pool){

        return;

    }


    try{

        await pool.query(`

            DELETE FROM sessions

            WHERE
                expires_at <
                CURRENT_TIMESTAMP

        `);


    }catch(error){

        console.error(
            "Session cleanup failed:",
            error.message
        );

    }

}


/* =========================================
   CLEAN OLD STREAMS
========================================= */

async function cleanOldStreams(){

    if(!pool){

        return;

    }


    try{

        /*
         * If a broadcaster disappears without
         * pressing End Streaming, an old stream
         * should not remain live forever.
         */

        await pool.query(`

            UPDATE streams

            SET

                is_live = FALSE,

                ended_at =
                    COALESCE(
                        ended_at,
                        CURRENT_TIMESTAMP
                    )

            WHERE

                is_live = TRUE

            AND

                started_at <
                CURRENT_TIMESTAMP
                - INTERVAL '24 hours'

        `);


    }catch(error){

        console.error(
            "Old stream cleanup failed:",
            error.message
        );

    }

}


/* =========================================
   DATABASE STARTUP
========================================= */

async function initializeCanvasDatabase(){

    const ready =
        await setupDatabase();


    if(!ready){

        console.error(
            "Canvas database initialization failed."
        );

        return;

    }


    await cleanExpiredSessions();

    await cleanOldStreams();


    /*
     * Repeat cleanup periodically.
     */

    setInterval(
        function(){

            cleanExpiredSessions();

            cleanOldStreams();

        },
        60 * 60 * 1000
    );


    console.log(
        "Canvas database initialization complete."
    );

}


/* =========================================
   RUN DATABASE INITIALIZATION
========================================= */

initializeCanvasDatabase()
    .catch(
        function(error){

            console.error(
                "Canvas startup database error:",
                error

            );

        }
    );
/* =========================================
   CANVAS SERVER STARTUP
========================================= */

const PORT =
    process.env.PORT || 10000;


/* =========================================
   BASIC SERVER STATUS
========================================= */

app.get(
    "/",
    function(req, res){

        res.json({

            success: true,

            message:
                "Canvas server is running.",

            status:
                "online",

            service:
                "Canvas Backend"

        });

    }
);


/* =========================================
   HEALTH CHECK
========================================= */

app.get(
    "/api/health",
    async function(req, res){

        try{

            if(!pool){

                return res.status(503).json({

                    success: false,

                    status:
                        "database_not_configured"

                });

            }


            await pool.query(
                "SELECT 1"
            );


            return res.json({

                success: true,

                status:
                    "healthy",

                database:
                    "connected"

            });


        }catch(error){

            console.error(
                "Health check failed:",
                error.message
            );


            return res.status(503).json({

                success: false,

                status:
                    "unhealthy",

                database:
                    "disconnected"

            });

        }

    }
);


/* =========================================
   404 HANDLER
========================================= */

app.use(
    function(req, res){

        res.status(404).json({

            success: false,

            message:
                "Canvas API route not found."

        });

    }
);


/* =========================================
   GLOBAL ERROR HANDLER
========================================= */

app.use(
    function(error, req, res, next){

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
   START CANVAS SERVER
========================================= */

server.listen(
    PORT,
    "0.0.0.0",
    function(){

        console.log(
            "================================="
        );

        console.log(
            "CANVAS SERVER IS ONLINE"
        );

        console.log(
            "Port:",
            PORT
        );

        console.log(
            "Environment:",
            process.env.NODE_ENV ||
            "production"
        );

        console.log(
            "================================="
        );

    }
);


/* =========================================
   GRACEFUL SHUTDOWN
========================================= */

async function shutdownCanvasServer(){

    console.log(
        "Canvas server shutting down..."
    );


    try{

        await new Promise(
            function(resolve){

                server.close(
                    function(){

                        resolve();

                    }
                );

            }
        );


        if(pool){

            await pool.end();

        }


        console.log(
            "Canvas server stopped."
        );


        process.exit(0);


    }catch(error){

        console.error(
            "Canvas shutdown error:",
            error.message
        );


        process.exit(1);

    }

}


process.on(
    "SIGTERM",
    shutdownCanvasServer
);


process.on(
    "SIGINT",
    shutdownCanvasServer
);
