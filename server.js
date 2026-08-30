const express = require("express");
const { Pool } = require("pg");
const crypto = require("crypto");
const http = require("http");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);

const io = new Server(server,{
    cors:{
        origin:"*",
        methods:["GET","POST","PUT","DELETE"]
    }
});

const PORT = process.env.PORT || 10000;

app.use((req,res,next)=>{
    res.header("Access-Control-Allow-Origin","*");
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

app.use(express.json({limit:"50mb"}));

/* DATABASE */

const databaseUrl = process.env.canvas_db_r13t;

const pool = databaseUrl
    ? new Pool({
        connectionString:databaseUrl,
        ssl:{rejectUnauthorized:false}
    })
    : null;

/* PASSWORD */

function hashPassword(password){
    return crypto
        .createHash("sha256")
        .update(String(password))
        .digest("hex");
}

/* USERNAME */

function cleanUsername(username){
    return String(username || "")
        .trim()
        .replace(/^@/,"")
        .toLowerCase();
}

/* TOKEN */

function createAuthToken(){
    return crypto.randomBytes(32).toString("hex");
}

function hashToken(token){
    return crypto
        .createHash("sha256")
        .update(String(token))
        .digest("hex");
}

/* AUTH */

async function authenticateUser(req,res,next){

    if(!pool){
        return res.status(500).json({
            success:false,
            message:"Database is not configured."
        });
    }

    const authorization =
        req.headers.authorization || "";

    if(!authorization.startsWith("Bearer ")){
        return res.status(401).json({
            success:false,
            message:"Authentication required."
        });
    }

    const token =
        authorization.substring(7).trim();

    if(!token){
        return res.status(401).json({
            success:false,
            message:"Authentication token is missing."
        });
    }

    try{

        const result = await pool.query(`
            SELECT
                users.id,
                users.name,
                users.username,
                users.email,
                users.created_at
            FROM sessions
            INNER JOIN users
                ON users.id=sessions.user_id
            WHERE sessions.token_hash=$1
            AND sessions.expires_at>CURRENT_TIMESTAMP
            LIMIT 1
        `,[hashToken(token)]);

        if(!result.rows.length){
            return res.status(401).json({
                success:false,
                message:"Invalid or expired authentication token."
            });
        }

        req.user=result.rows[0];
        next();

    }catch(error){

        console.error("Authentication error:",error);

        return res.status(500).json({
            success:false,
            message:"Unable to authenticate user."
        });
    }
}

/* DATABASE SETUP */

async function setupDatabase(){

    if(!pool){
        console.error(
            "Canvas database is not configured."
        );
        return false;
    }

    try{

        await pool.query(`
            CREATE TABLE IF NOT EXISTS users(
                id SERIAL PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                username VARCHAR(100) UNIQUE NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS profiles(
                id SERIAL PRIMARY KEY,
                user_id INTEGER UNIQUE NOT NULL
                    REFERENCES users(id)
                    ON DELETE CASCADE,
                bio TEXT DEFAULT '',
                profile_picture TEXT DEFAULT '',
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS sessions(
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL
                    REFERENCES users(id)
                    ON DELETE CASCADE,
                token_hash TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL
            );
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS streams(
                id SERIAL PRIMARY KEY,
                user_id INTEGER
                    REFERENCES users(id)
                    ON DELETE CASCADE,
                title VARCHAR(255)
                    DEFAULT 'Canvas Live Stream',
                category VARCHAR(100)
                    DEFAULT 'Other',
                description TEXT DEFAULT '',
                thumbnail TEXT DEFAULT '',
                is_live BOOLEAN DEFAULT FALSE,
                viewer_count INTEGER DEFAULT 0,
                started_at TIMESTAMP,
                ended_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        await pool.query(`
            ALTER TABLE streams
            ADD COLUMN IF NOT EXISTS thumbnail TEXT DEFAULT '';
        `);

        await pool.query(`
            ALTER TABLE streams
            ADD COLUMN IF NOT EXISTS viewer_count INTEGER DEFAULT 0;
        `);

        await pool.query(`
            ALTER TABLE streams
            ADD COLUMN IF NOT EXISTS is_live BOOLEAN DEFAULT FALSE;
        `);

        await pool.query(`
            ALTER TABLE streams
            ADD COLUMN IF NOT EXISTS started_at TIMESTAMP;
        `);

        await pool.query(`
            ALTER TABLE streams
            ADD COLUMN IF NOT EXISTS ended_at TIMESTAMP;
        `);

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

        console.log("Canvas database is ready.");
        return true;

    }catch(error){

        console.error(
            "Database setup error:",
            error
        );

        return false;
    }
}

/* STATUS */

app.get("/",(req,res)=>{
    res.json({
        success:true,
        service:"Canvas Backend",
        status:"online"
    });
});

app.get("/api/health",async(req,res)=>{

    let database=false;

    try{
        if(pool){
            await pool.query("SELECT 1");
            database=true;
        }
    }catch(error){
        database=false;
    }

    res.json({
        success:true,
        status:"online",
        database:database
            ?"connected"
            :"disconnected",
        socket:"enabled",
        time:new Date().toISOString()
    });
});

/* VERIFICATION */

const verificationCodes=new Map();

function generateVerificationCode(){
    return String(
        Math.floor(
            100000+
            Math.random()*900000
        )
    );
}

/* RESEND */

async function sendVerificationEmail(
    email,
    code
){

    const apiKey =
        process.env.RESEND_API_KEY;

    const from =
        process.env.RESEND_FROM_EMAIL;

    if(!apiKey || !from){

        console.log(
            "Resend is not configured."
        );

        console.log(
            "Canvas verification code:",
            code
        );

        return false;
    }

    try{

        const response =
            await fetch(
                "https://api.resend.com/emails",
                {
                    method:"POST",
                    headers:{
                        "Authorization":
                            "Bearer "+apiKey,
                        "Content-Type":
                            "application/json"
                    },
                    body:JSON.stringify({
                        from:from,
                        to:[email],
                        subject:
                            "Canvas verification code",
                        html:`
                            <div style="
                                font-family:Arial;
                                padding:20px;
                            ">
                                <h2>
                                    Canvas
                                </h2>
                                <p>
                                    Your verification code is:
                                </p>
                                <h1>
                                    ${code}
                                </h1>
                                <p>
                                    This code expires
                                    in 10 minutes.
                                </p>
                            </div>
                        `
                    })
                }
            );

        if(!response.ok){

            console.error(
                "Resend error:",
                await response.text()
            );

            return false;
        }

        return true;

    }catch(error){

        console.error(
            "Email error:",
            error
        );

        return false;
    }
}

/* SEND SIGNUP CODE */

app.post(
    "/api/signup/send-code",
    async(req,res)=>{

        if(!pool){
            return res.status(500).json({
                success:false,
                message:"Database is not configured."
            });
        }

        const name=
            String(req.body.name || "").trim();

        const username=
            cleanUsername(req.body.username);

        const email=
            String(req.body.email || "")
                .trim()
                .toLowerCase();

        const password=
            String(req.body.password || "");

        if(!name || !username || !email || !password){
            return res.status(400).json({
                success:false,
                message:"All fields are required."
            });
        }

        if(password.length<6){
            return res.status(400).json({
                success:false,
                message:
                    "Password must be at least 6 characters."
            });
        }

        try{

            const existing=
                await pool.query(`
                    SELECT id
                    FROM users
                    WHERE username=$1
                    OR email=$2
                    LIMIT 1
                `,[username,email]);

            if(existing.rows.length){
                return res.status(409).json({
                    success:false,
                    message:
                        "Username or email is already registered."
                });
            }

            const code=
                generateVerificationCode();

            verificationCodes.set(
                email,
                {
                    code,
                    name,
                    username,
                    email,
                    password,
                    expiresAt:
                        Date.now()+
                        10*60*1000
                }
            );

            const sent=
                await sendVerificationEmail(
                    email,
                    code
                );

            return res.json({
                success:true,
                message:sent
                    ?"Verification code sent."
                    :"Verification code generated.",
                email
            });

        }catch(error){

            console.error(
                "Signup code error:",
                error
            );

            return res.status(500).json({
                success:false,
                message:
                    "Unable to send verification code."
            });
        }
    }
);
/* VERIFY SIGNUP */

app.post(
    "/api/signup/verify-code",
    async(req,res)=>{

        if(!pool){
            return res.status(500).json({
                success:false,
                message:"Database is not configured."
            });
        }

        const email=
            String(req.body.email || "")
                .trim()
                .toLowerCase();

        const code=
            String(req.body.code || "").trim();

        if(!email || !code){
            return res.status(400).json({
                success:false,
                message:
                    "Email and verification code are required."
            });
        }

        const verification=
            verificationCodes.get(email);

        if(!verification){
            return res.status(400).json({
                success:false,
                message:
                    "Verification code not found or expired."
            });
        }

        if(Date.now()>verification.expiresAt){

            verificationCodes.delete(email);

            return res.status(400).json({
                success:false,
                message:
                    "Verification code has expired."
            });
        }

        if(verification.code!==code){
            return res.status(400).json({
                success:false,
                message:
                    "Invalid verification code."
            });
        }

        try{

            const existing=
                await pool.query(`
                    SELECT id
                    FROM users
                    WHERE username=$1
                    OR email=$2
                    LIMIT 1
                `,[
                    verification.username,
                    verification.email
                ]);

            if(existing.rows.length){

                verificationCodes.delete(email);

                return res.status(409).json({
                    success:false,
                    message:
                        "Username or email is already registered."
                });
            }

            const passwordHash=
                hashPassword(
                    verification.password
                );

            const result=
                await pool.query(`
                    INSERT INTO users(
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
                `,[
                    verification.name,
                    verification.username,
                    verification.email,
                    passwordHash
                ]);

            const user=result.rows[0];

            await pool.query(`
                INSERT INTO profiles(user_id)
                VALUES($1)
                ON CONFLICT(user_id)
                DO NOTHING
            `,[user.id]);

            verificationCodes.delete(email);

            return res.status(201).json({
                success:true,
                message:
                    "Canvas account created successfully.",
                user
            });

        }catch(error){

            console.error(
                "Signup verification error:",
                error
            );

            return res.status(500).json({
                success:false,
                message:
                    "Unable to create Canvas account."
            });
        }
    }
);

/* LOGIN */

app.post(
    "/api/login",
    async(req,res)=>{

        if(!pool){
            return res.status(500).json({
                success:false,
                message:"Database is not configured."
            });
        }

        const login=
            String(
                req.body.email ||
                req.body.username ||
                req.body.login ||
                ""
            )
            .trim()
            .toLowerCase();

        const password=
            String(req.body.password || "");

        if(!login || !password){
            return res.status(400).json({
                success:false,
                message:
                    "Email/username and password are required."
            });
        }

        try{

            const result=
                await pool.query(`
                    SELECT
                        id,
                        name,
                        username,
                        email,
                        password_hash,
                        created_at
                    FROM users
                    WHERE LOWER(email)=$1
                    OR LOWER(username)=$1
                    LIMIT 1
                `,[login]);

            if(!result.rows.length){
                return res.status(401).json({
                    success:false,
                    message:
                        "Invalid email/username or password."
                });
            }

            const user=result.rows[0];

            if(
                hashPassword(password)!==
                user.password_hash
            ){
                return res.status(401).json({
                    success:false,
                    message:
                        "Invalid email/username or password."
                });
            }

            const token=
                createAuthToken();

            await pool.query(`
                INSERT INTO sessions(
                    user_id,
                    token_hash,
                    expires_at
                )
                VALUES(
                    $1,
                    $2,
                    CURRENT_TIMESTAMP+
                    INTERVAL '30 days'
                )
            `,[
                user.id,
                hashToken(token)
            ]);

            delete user.password_hash;

            return res.json({
                success:true,
                message:"Login successful.",
                token,
                user
            });

        }catch(error){

            console.error(
                "Login error:",
                error
            );

            return res.status(500).json({
                success:false,
                message:
                    "Unable to log in to Canvas."
            });
        }
    }
);

/* CURRENT USER */

app.get(
    "/api/me",
    authenticateUser,
    async(req,res)=>{

        try{

            const result=
                await pool.query(`
                    SELECT
                        users.id,
                        users.name,
                        users.username,
                        users.email,
                        users.created_at,
                        COALESCE(
                            profiles.bio,''
                        ) AS bio,
                        COALESCE(
                            profiles.profile_picture,''
                        ) AS profile_picture
                    FROM users
                    LEFT JOIN profiles
                        ON profiles.user_id=users.id
                    WHERE users.id=$1
                    LIMIT 1
                `,[req.user.id]);

            if(!result.rows.length){
                return res.status(404).json({
                    success:false,
                    message:"User not found."
                });
            }

            res.json({
                success:true,
                user:result.rows[0]
            });

        }catch(error){

            console.error(
                "Current user error:",
                error
            );

            res.status(500).json({
                success:false,
                message:
                    "Unable to load current user."
            });
        }
    }
);

/* GET PROFILE */

app.get(
    "/api/profile",
    authenticateUser,
    async(req,res)=>{

        try{

            const result=
                await pool.query(`
                    SELECT
                        users.id,
                        users.name,
                        users.username,
                        users.email,
                        COALESCE(
                            profiles.bio,''
                        ) AS bio,
                        COALESCE(
                            profiles.profile_picture,''
                        ) AS profile_picture
                    FROM users
                    LEFT JOIN profiles
                        ON profiles.user_id=users.id
                    WHERE users.id=$1
                    LIMIT 1
                `,[req.user.id]);

            if(!result.rows.length){
                return res.status(404).json({
                    success:false,
                    message:"Profile not found."
                });
            }

            res.json({
                success:true,
                profile:result.rows[0]
            });

        }catch(error){

            console.error(
                "Profile error:",
                error
            );

            res.status(500).json({
                success:false,
                message:
                    "Unable to load profile."
            });
        }
    }
);

/* UPDATE PROFILE */

app.put(
    "/api/profile",
    authenticateUser,
    async(req,res)=>{

        const name=
            String(req.body.name || "").trim();

        const username=
            cleanUsername(req.body.username);

        const bio=
            String(req.body.bio || "").trim();

        const profilePicture=
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

        if(name.length>100){
            return res.status(400).json({
                success:false,
                message:"Name is too long."
            });
        }

        if(username.length>100){
            return res.status(400).json({
                success:false,
                message:"Username is too long."
            });
        }

        if(bio.length>1000){
            return res.status(400).json({
                success:false,
                message:"Bio is too long."
            });
        }

        if(profilePicture.length>10000000){
            return res.status(400).json({
                success:false,
                message:
                    "Profile picture is too large."
            });
        }

        try{

            const duplicate=
                await pool.query(`
                    SELECT id
                    FROM users
                    WHERE username=$1
                    AND id<>$2
                    LIMIT 1
                `,[
                    username,
                    req.user.id
                ]);

            if(duplicate.rows.length){
                return res.status(409).json({
                    success:false,
                    message:
                        "That username is already taken."
                });
            }

            await pool.query(`
                UPDATE users
                SET
                    name=$1,
                    username=$2
                WHERE id=$3
            `,[
                name,
                username,
                req.user.id
            ]);

            await pool.query(`
                INSERT INTO profiles(
                    user_id,
                    bio,
                    profile_picture
                )
                VALUES($1,$2,$3)
                ON CONFLICT(user_id)
                DO UPDATE SET
                    bio=EXCLUDED.bio,
                    profile_picture=
                        EXCLUDED.profile_picture,
                    updated_at=CURRENT_TIMESTAMP
            `,[
                req.user.id,
                bio,
                profilePicture
            ]);

            const updated=
                await pool.query(`
                    SELECT
                        users.id,
                        users.name,
                        users.username,
                        users.email,
                        COALESCE(
                            profiles.bio,''
                        ) AS bio,
                        COALESCE(
                            profiles.profile_picture,''
                        ) AS profile_picture
                    FROM users
                    LEFT JOIN profiles
                        ON profiles.user_id=users.id
                    WHERE users.id=$1
                `,[req.user.id]);

            res.json({
                success:true,
                message:
                    "Profile updated successfully.",
                profile:updated.rows[0]
            });

        }catch(error){

            console.error(
                "Profile update error:",
                error
            );

            res.status(500).json({
                success:false,
                message:
                    "Unable to update profile."
            });
        }
    }
);
/* CREATE STREAM */

app.post(
    "/api/streams",
    authenticateUser,
    async(req,res)=>{

        const title=
            String(
                req.body.title ||
                "Canvas Live Stream"
            ).trim();

        const category=
            String(
                req.body.category ||
                "Other"
            ).trim();

        const description=
            String(
                req.body.description ||
                ""
            ).trim();

        const thumbnail=
            String(
                req.body.thumbnail ||
                ""
            );

        const allowed=[
            "Gaming",
            "Entertainment",
            "Music",
            "Education",
            "Sports",
            "Technology",
            "Other"
        ];

        const finalCategory=
            allowed.includes(category)
                ?category
                :"Other";

        if(!title){
            return res.status(400).json({
                success:false,
                message:"Stream title is required."
            });
        }

        if(title.length>255){
            return res.status(400).json({
                success:false,
                message:"Stream title is too long."
            });
        }

        if(description.length>500){
            return res.status(400).json({
                success:false,
                message:
                    "Stream description is too long."
            });
        }

        if(thumbnail.length>10000000){
            return res.status(400).json({
                success:false,
                message:
                    "Thumbnail is too large."
            });
        }

        try{

            const active=
                await pool.query(`
                    SELECT id
                    FROM streams
                    WHERE user_id=$1
                    AND is_live=TRUE
                    LIMIT 1
                `,[req.user.id]);

            if(active.rows.length){
                return res.status(409).json({
                    success:false,
                    message:
                        "You already have a live stream."
                });
            }

            const result=
                await pool.query(`
                    INSERT INTO streams(
                        user_id,
                        title,
                        category,
                        description,
                        thumbnail,
                        is_live,
                        viewer_count,
                        started_at
                    )
                    VALUES(
                        $1,$2,$3,$4,$5,
                        TRUE,0,CURRENT_TIMESTAMP
                    )
                    RETURNING
                        id,
                        user_id,
                        title,
                        category,
                        description,
                        thumbnail,
                        is_live,
                        viewer_count,
                        started_at
                `,[
                    req.user.id,
                    title,
                    finalCategory,
                    description,
                    thumbnail
                ]);

            const stream=result.rows[0];

            io.emit(
                "stream-created",
                stream
            );

            res.status(201).json({
                success:true,
                message:
                    "Canvas stream created.",
                stream
            });

        }catch(error){

            console.error(
                "Create stream error:",
                error
            );

            res.status(500).json({
                success:false,
                message:
                    "Unable to create Canvas stream."
            });
        }
    }
);

/* UPDATE STREAM */

app.put(
    "/api/streams/:id",
    authenticateUser,
    async(req,res)=>{

        const streamId=
            String(req.params.id || "").trim();

        const title=
            String(req.body.title || "").trim();

        const category=
            String(
                req.body.category || "Other"
            ).trim();

        const description=
            String(
                req.body.description || ""
            ).trim();

        const thumbnail=
            String(req.body.thumbnail || "");

        if(!streamId){
            return res.status(400).json({
                success:false,
                message:"Stream ID is required."
            });
        }

        try{

            const result=
                await pool.query(`
                    UPDATE streams
                    SET
                        title=COALESCE(
                            NULLIF($1,''),
                            title
                        ),
                        category=COALESCE(
                            NULLIF($2,''),
                            category
                        ),
                        description=$3,
                        thumbnail=$4
                    WHERE id=$5
                    AND user_id=$6
                    AND is_live=TRUE
                    RETURNING
                        id,
                        title,
                        category,
                        description,
                        thumbnail,
                        is_live
                `,[
                    title,
                    category,
                    description,
                    thumbnail,
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

            res.json({
                success:true,
                stream:result.rows[0]
            });

        }catch(error){

            console.error(
                "Update stream error:",
                error
            );

            res.status(500).json({
                success:false,
                message:
                    "Unable to update stream."
            });
        }
    }
);

/* LIVE STREAMS */

app.get(
    "/api/streams/live",
    async(req,res)=>{

        if(!pool){
            return res.status(500).json({
                success:false,
                message:
                    "Database is not configured."
            });
        }

        try{

            const result=
                await pool.query(`
                    SELECT
                        streams.id,
                        streams.title,
                        streams.category,
                        streams.description,
                        streams.thumbnail,
                        streams.is_live,
                        streams.viewer_count,
                        streams.started_at,
                        users.id AS user_id,
                        users.name,
                        users.username,
                        COALESCE(
                            profiles.profile_picture,
                            ''
                        ) AS profile_picture
                    FROM streams
                    INNER JOIN users
                        ON users.id=streams.user_id
                    LEFT JOIN profiles
                        ON profiles.user_id=users.id
                    WHERE streams.is_live=TRUE
                    ORDER BY streams.started_at DESC
                `);

            res.json({
                success:true,
                streams:result.rows
            });

        }catch(error){

            console.error(
                "Live streams error:",
                error
            );

            res.status(500).json({
                success:false,
                message:
                    "Unable to load live streams."
            });
        }
    }
);

/* SINGLE STREAM */

app.get(
    "/api/streams/:id",
    async(req,res)=>{

        const streamId=
            String(req.params.id || "").trim();

        if(!streamId){
            return res.status(400).json({
                success:false,
                message:
                    "Stream ID is required."
            });
        }

        try{

            const result=
                await pool.query(`
                    SELECT
                        streams.id,
                        streams.title,
                        streams.category,
                        streams.description,
                        streams.thumbnail,
                        streams.is_live,
                        streams.viewer_count,
                        streams.started_at,
                        streams.ended_at,
                        users.id AS user_id,
                        users.name,
                        users.username,
                        COALESCE(
                            profiles.profile_picture,
                            ''
                        ) AS profile_picture
                    FROM streams
                    INNER JOIN users
                        ON users.id=streams.user_id
                    LEFT JOIN profiles
                        ON profiles.user_id=users.id
                    WHERE streams.id=$1
                    LIMIT 1
                `,[streamId]);

            if(!result.rows.length){
                return res.status(404).json({
                    success:false,
                    message:"Stream not found."
                });
            }

            res.json({
                success:true,
                stream:result.rows[0]
            });

        }catch(error){

            console.error(
                "Get stream error:",
                error
            );

            res.status(500).json({
                success:false,
                message:
                    "Unable to load stream."
            });
        }
    }
);

/* SEARCH */

app.get(
    "/api/streams/search",
    async(req,res)=>{

        const query=
            String(req.query.q || "").trim();

        if(!query){
            return res.json({
                success:true,
                streams:[]
            });
        }

        try{

            const search=
                "%"+query.toLowerCase()+"%";

            const result=
                await pool.query(`
                    SELECT
                        streams.id,
                        streams.title,
                        streams.category,
                        streams.description,
                        streams.thumbnail,
                        streams.is_live,
                        streams.viewer_count,
                        streams.started_at,
                        users.id AS user_id,
                        users.name,
                        users.username,
                        COALESCE(
                            profiles.profile_picture,
                            ''
                        ) AS profile_picture
                    FROM streams
                    INNER JOIN users
                        ON users.id=streams.user_id
                    LEFT JOIN profiles
                        ON profiles.user_id=users.id
                    WHERE streams.is_live=TRUE
                    AND(
                        LOWER(streams.title) LIKE $1
                        OR LOWER(streams.category) LIKE $1
                        OR LOWER(streams.description) LIKE $1
                        OR LOWER(users.name) LIKE $1
                        OR LOWER(users.username) LIKE $1
                    )
                    ORDER BY streams.started_at DESC
                    LIMIT 50
                `,[search]);

            res.json({
                success:true,
                streams:result.rows
            });

        }catch(error){

            console.error(
                "Search error:",
                error
            );

            res.status(500).json({
                success:false,
                message:
                    "Unable to search Canvas streams."
            });
        }
    }
);

/* END STREAM */

app.post(
    "/api/streams/:id/end",
    authenticateUser,
    async(req,res)=>{

        const streamId=
            String(req.params.id || "").trim();

        try{

            const result=
                await pool.query(`
                    UPDATE streams
                    SET
                        is_live=FALSE,
                        ended_at=CURRENT_TIMESTAMP
                    WHERE id=$1
                    AND user_id=$2
                    AND is_live=TRUE
                    RETURNING
                        id,
                        title,
                        category,
                        description,
                        thumbnail,
                        is_live,
                        viewer_count,
                        started_at,
                        ended_at
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

            io.to(
                "stream:"+streamId
            ).emit(
                "stream-ended",
                {
                    streamId:String(streamId)
                }
            );

            io.emit(
                "stream-ended",
                {
                    streamId:String(streamId)
                }
            );

            res.json({
                success:true,
                message:
                    "Canvas stream ended.",
                stream:result.rows[0]
            });

        }catch(error){

            console.error(
                "End stream error:",
                error
            );

            res.status(500).json({
                success:false,
                message:
                    "Unable to end Canvas stream."
            });
        }
    }
);

/*
 * VIEW COUNT
 *
 * REST view/unview endpoints are kept
 * for compatibility.
 *
 * Frontend should use ONLY ONE system
 * for each viewer.
 */

app.post(
    "/api/streams/:id/view",
    async(req,res)=>{

        const streamId=
            String(req.params.id || "").trim();

        try{

            const result=
                await pool.query(`
                    UPDATE streams
                    SET viewer_count=
                        COALESCE(viewer_count,0)+1
                    WHERE id=$1
                    AND is_live=TRUE
                    RETURNING viewer_count
                `,[streamId]);

            if(!result.rows.length){
                return res.status(404).json({
                    success:false,
                    message:
                        "Live stream not found."
                });
            }

            const count=
                result.rows[0].viewer_count;

            io.to("stream:"+streamId).emit(
                "viewer-count",
                {
                    streamId,
                    viewerCount:count
                }
            );

            res.json({
                success:true,
                viewerCount:count
            });

        }catch(error){

            console.error(
                "View count error:",
                error
            );

            res.status(500).json({
                success:false,
                message:
                    "Unable to update viewer count."
            });
        }
    }
);

app.post(
    "/api/streams/:id/unview",
    async(req,res)=>{

        const streamId=
            String(req.params.id || "").trim();

        try{

            const result=
                await pool.query(`
                    UPDATE streams
                    SET viewer_count=
                        GREATEST(
                            COALESCE(viewer_count,0)-1,
                            0
                        )
                    WHERE id=$1
                    RETURNING viewer_count
                `,[streamId]);

            const count=
                result.rows.length
                    ?result.rows[0].viewer_count
                    :0;

            io.to("stream:"+streamId).emit(
                "viewer-count",
                {
                    streamId,
                    viewerCount:count
                }
            );

            res.json({
                success:true,
                viewerCount:count
            });

        }catch(error){

            console.error(
                "Unview error:",
                error
            );

            res.status(500).json({
                success:false,
                message:
                    "Unable to update viewer count."
            });
        }
    }
);
/* SOCKET.IO */

io.on("connection",socket=>{

    console.log(
        "Canvas Socket connected:",
        socket.id
    );

    socket.on(
        "join-stream",
        data=>{

            if(!data || !data.streamId){
                return;
            }

            const streamId=
                String(data.streamId);

            const role=
                data.role==="broadcaster"
                    ?"broadcaster"
                    :"viewer";

            const room=
                "stream:"+streamId;

            const roomData=
                io.sockets.adapter.rooms.get(room);

            const peers=
                roomData
                    ?Array.from(roomData)
                    :[];

            socket.join(room);

            socket.canvasStreamId=streamId;
            socket.canvasRole=role;
            socket.canvasRoom=room;

            if(role==="broadcaster"){

                socket.emit(
                    "existing-peers",
                    peers.filter(
                        id=>id!==socket.id
                    )
                );
            }

            socket.to(room).emit(
                "peer-joined",
                {
                    socketId:socket.id,
                    role
                }
            );
        }
    );

    socket.on(
        "leave-stream",
        data=>{

            const streamId=
                data && data.streamId
                    ?String(data.streamId)
                    :socket.canvasStreamId;

            if(!streamId){
                return;
            }

            const room=
                "stream:"+streamId;

            socket.to(room).emit(
                "peer-left",
                {
                    socketId:socket.id
                }
            );

            socket.leave(room);

            socket.canvasStreamId=null;
            socket.canvasRoom=null;
        }
    );

    /* WEBRTC OFFER */

    socket.on(
        "webrtc-offer",
        data=>{

            if(
                !data ||
                !data.target ||
                !data.offer
            ){
                return;
            }

            const target=
                io.sockets.sockets.get(
                    data.target
                );

            if(!target){
                return;
            }

            target.emit(
                "webrtc-offer",
                {
                    sender:socket.id,
                    offer:data.offer
                }
            );
        }
    );

    /* WEBRTC ANSWER */

    socket.on(
        "webrtc-answer",
        data=>{

            if(
                !data ||
                !data.target ||
                !data.answer
            ){
                return;
            }

            const target=
                io.sockets.sockets.get(
                    data.target
                );

            if(!target){
                return;
            }

            target.emit(
                "webrtc-answer",
                {
                    sender:socket.id,
                    answer:data.answer
                }
            );
        }
    );

    /* ICE */

    socket.on(
        "webrtc-ice",
        data=>{

            if(
                !data ||
                !data.target ||
                !data.candidate
            ){
                return;
            }

            const target=
                io.sockets.sockets.get(
                    data.target
                );

            if(!target){
                return;
            }

            target.emit(
                "webrtc-ice",
                {
                    sender:socket.id,
                    candidate:data.candidate
                }
            );
        }
    );

    /* CHAT */

    socket.on(
        "chat-message",
        data=>{

            if(
                !data ||
                !data.streamId ||
                !data.message
            ){
                return;
            }

            const message=
                String(data.message).trim();

            if(!message || message.length>500){
                return;
            }

            const streamId=
                String(data.streamId);

            io.to(
                "stream:"+streamId
            ).emit(
                "chat-message",
                {
                    streamId,
                    message,
                    userId:data.userId || null,
                    name:
                        data.name ||
                        "Canvas User",
                    username:
                        data.username || "",
                    profilePicture:
                        data.profilePicture || "",
                    createdAt:
                        new Date().toISOString()
                }
            );
        }
    );

    /*
     * VIEWER JOIN
     *
     * This is the Socket.IO viewer system.
     */

    socket.on(
        "viewer-joined",
        async data=>{

            if(!data || !data.streamId){
                return;
            }

            const streamId=
                String(data.streamId);

            const room=
                "stream:"+streamId;

            socket.join(room);

            socket.canvasStreamId=streamId;
            socket.canvasRole="viewer";
            socket.canvasRoom=room;
            socket.canvasViewerCounted=true;

            try{

                const result=
                    await pool.query(`
                        UPDATE streams
                        SET viewer_count=
                            COALESCE(viewer_count,0)+1
                        WHERE id=$1
                        AND is_live=TRUE
                        RETURNING viewer_count
                    `,[streamId]);

                if(result.rows.length){

                    io.to(room).emit(
                        "viewer-count",
                        {
                            streamId,
                            viewerCount:
                                result.rows[0]
                                    .viewer_count
                        }
                    );
                }

            }catch(error){

                console.error(
                    "Viewer join error:",
                    error
                );
            }
        }
    );

    socket.on(
        "viewer-left",
        async data=>{

            if(!data || !data.streamId){
                return;
            }

            if(socket.canvasViewerCounted===false){
                return;
            }

            const streamId=
                String(data.streamId);

            socket.canvasViewerCounted=false;

            try{

                const result=
                    await pool.query(`
                        UPDATE streams
                        SET viewer_count=
                            GREATEST(
                                COALESCE(viewer_count,0)-1,
                                0
                            )
                        WHERE id=$1
                        RETURNING viewer_count
                    `,[streamId]);

                if(result.rows.length){

                    io.to(
                        "stream:"+streamId
                    ).emit(
                        "viewer-count",
                        {
                            streamId,
                            viewerCount:
                                result.rows[0]
                                    .viewer_count
                        }
                    );
                }

            }catch(error){

                console.error(
                    "Viewer leave error:",
                    error
                );
            }
        }
    );

    /* DISCONNECT */

    socket.on(
        "disconnect",
        async()=>{

            const room=
                socket.canvasRoom;

            const streamId=
                socket.canvasStreamId;

            const role=
                socket.canvasRole;

            console.log(
                "Canvas Socket disconnected:",
                socket.id
            );

            if(room){

                socket.to(room).emit(
                    "peer-left",
                    {
                        socketId:socket.id
                    }
                );
            }

            /*
             * Automatically remove a viewer
             * if the browser disappeared without
             * sending viewer-left.
             */

            if(
                role==="viewer" &&
                streamId &&
                socket.canvasViewerCounted
            ){

                socket.canvasViewerCounted=false;

                try{

                    const result=
                        await pool.query(`
                            UPDATE streams
                            SET viewer_count=
                                GREATEST(
                                    COALESCE(
                                        viewer_count,
                                        0
                                    )-1,
                                    0
                                )
                            WHERE id=$1
                            RETURNING viewer_count
                        `,[streamId]);

                    if(result.rows.length){

                        io.to(
                            "stream:"+streamId
                        ).emit(
                            "viewer-count",
                            {
                                streamId,
                                viewerCount:
                                    result.rows[0]
                                        .viewer_count
                            }
                        );
                    }

                }catch(error){

                    console.error(
                        "Disconnect viewer error:",
                        error
                    );
                }
            }

            if(
                role==="broadcaster" &&
                streamId
            ){

                io.to(
                    "stream:"+streamId
                ).emit(
                    "broadcaster-disconnected",
                    {
                        streamId
                    }
                );
            }
        }
    );
});

/* CLEAN SESSIONS */

async function cleanExpiredSessions(){

    if(!pool){
        return;
    }

    try{

        await pool.query(`
            DELETE FROM sessions
            WHERE expires_at<CURRENT_TIMESTAMP
        `);

    }catch(error){

        console.error(
            "Session cleanup error:",
            error
        );
    }
}

/* CLEAN OLD STREAMS */

async function cleanOldStreams(){

    if(!pool){
        return;
    }

    try{

        const result=
            await pool.query(`
                UPDATE streams
                SET
                    is_live=FALSE,
                    ended_at=
                        COALESCE(
                            ended_at,
                            CURRENT_TIMESTAMP
                        )
                WHERE is_live=TRUE
                AND started_at<
                    CURRENT_TIMESTAMP-
                    INTERVAL '24 hours'
                RETURNING id
            `);

        result.rows.forEach(stream=>{
            io.to(
                "stream:"+stream.id
            ).emit(
                "stream-ended",
                {
                    streamId:
                        String(stream.id)
                }
            );

            io.emit(
                "stream-ended",
                {
                    streamId:
                        String(stream.id)
                }
            );
        });

    }catch(error){

        console.error(
            "Old stream cleanup error:",
            error
        );
    }
}

/* DATABASE STARTUP */

async function startDatabase(){

    const ready=
        await setupDatabase();

    if(!ready){
        console.error(
            "Canvas database startup failed."
        );
        return;
    }

    await cleanExpiredSessions();
    await cleanOldStreams();

    setInterval(
        ()=>{
            cleanExpiredSessions();
            cleanOldStreams();
        },
        60*60*1000
    );

    console.log(
        "Canvas database initialization complete."
    );
}

/* API 404 */

app.use(
    "/api",
    (req,res)=>{
        res.status(404).json({
            success:false,
            message:
                "Canvas API endpoint not found."
        });
    }
);

/* GLOBAL ERROR */

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

/* START */

server.listen(
    PORT,
    "0.0.0.0",
    ()=>{
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
            "Socket.IO: ENABLED"
        );

        console.log(
            "Database:",
            pool
                ?"CONFIGURED"
                :"NOT CONFIGURED"
        );

        console.log(
            "================================="
        );
    }
);

startDatabase().catch(error=>{
    console.error(
        "Canvas database startup error:",
        error
    );
});

/* SHUTDOWN */

async function shutdown(){

    console.log(
        "Canvas server shutting down..."
    );

    try{

        await new Promise(resolve=>{
            server.close(resolve);
        });

        if(pool){
            await pool.end();
        }

        console.log(
            "Canvas server stopped."
        );

        process.exit(0);

    }catch(error){

        console.error(
            "Shutdown error:",
            error
        );

        process.exit(1);
    }
}

process.on("SIGTERM",shutdown);
process.on("SIGINT",shutdown);
