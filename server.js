const express = require("express");
const { Pool } = require("pg");
const crypto = require("crypto");

const app = express();
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
        .update(
            String(password)
        )
        .digest("hex");

}


/* =========================================
   USERNAME CLEANER
========================================= */

function cleanUsername(username){

    return String(
        username || ""
    )
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
        .update(
            String(token)
        )
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

        /* =====================================
           USERS
        ===================================== */

        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (

                id SERIAL PRIMARY KEY,

                name VARCHAR(100) NOT NULL,

                username VARCHAR(100)
                    UNIQUE NOT NULL,

                email VARCHAR(255)
                    UNIQUE NOT NULL,

                password_hash TEXT NOT NULL,

                created_at
                    TIMESTAMP
                    DEFAULT CURRENT_TIMESTAMP

            );
        `);


        /* =====================================
           PROFILES
        ===================================== */

        await pool.query(`
            CREATE TABLE IF NOT EXISTS profiles (

                id SERIAL PRIMARY KEY,

                user_id INTEGER
                    UNIQUE NOT NULL
                    REFERENCES users(id)
                    ON DELETE CASCADE,

                bio TEXT DEFAULT '',

                profile_picture TEXT DEFAULT '',

                updated_at
                    TIMESTAMP
                    DEFAULT CURRENT_TIMESTAMP

            );
        `);


        /* =====================================
           SESSIONS
        ===================================== */

        await pool.query(`
            CREATE TABLE IF NOT EXISTS sessions (

                id SERIAL PRIMARY KEY,

                user_id INTEGER NOT NULL
                    REFERENCES users(id)
                    ON DELETE CASCADE,

                token_hash TEXT
                    UNIQUE NOT NULL,

                created_at
                    TIMESTAMP
                    DEFAULT CURRENT_TIMESTAMP,

                expires_at
                    TIMESTAMP NOT NULL

            );
        `);


        /* =====================================
           STREAMS
        ===================================== */

        await pool.query(`
            CREATE TABLE IF NOT EXISTS streams (

                id SERIAL PRIMARY KEY,

                title VARCHAR(255)
                    DEFAULT 'Canvas Live Stream',

                status VARCHAR(30)
                    DEFAULT 'live',

                created_at
                    TIMESTAMP
                    DEFAULT CURRENT_TIMESTAMP,

                ended_at TIMESTAMP

            );
        `);


        await pool.query(`
            ALTER TABLE streams

            ADD COLUMN IF NOT EXISTS user_id

            INTEGER
            REFERENCES users(id)
            ON DELETE CASCADE;
        `);


        /* =====================================
           REAL FOLLOW SYSTEM
        ===================================== */

        await pool.query(`
            CREATE TABLE IF NOT EXISTS follows (

                id SERIAL PRIMARY KEY,

                follower_id INTEGER NOT NULL
                    REFERENCES users(id)
                    ON DELETE CASCADE,

                following_id INTEGER NOT NULL
                    REFERENCES users(id)
                    ON DELETE CASCADE,

                created_at
                    TIMESTAMP
                    DEFAULT CURRENT_TIMESTAMP,

                CONSTRAINT
                    follows_unique_relationship

                UNIQUE (
                    follower_id,
                    following_id
                ),

                CONSTRAINT
                    follows_no_self_follow

                CHECK (
                    follower_id <> following_id
                )

            );
        `);


        /* =====================================
           FOLLOW INDEXES
        ===================================== */

        await pool.query(`
            CREATE INDEX IF NOT EXISTS
            follows_follower_idx

            ON follows(follower_id);
        `);


        await pool.query(`
            CREATE INDEX IF NOT EXISTS
            follows_following_idx

            ON follows(following_id);
        `);


        console.log(
            "Canvas database initialized successfully."
        );


        console.log(
            "Canvas follow system initialized successfully."
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
   FOLLOW COUNT HELPER
========================================= */

async function getFollowCounts(
    userId
){

    const result =
        await pool.query(
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


    return {

        followers_count:
            Number(
                result.rows[0]
                    .followers_count
            ),

        following_count:
            Number(
                result.rows[0]
                    .following_count
            )

    };

}


/* =========================================
   PROFILE DATA HELPER
========================================= */

async function getProfileByUserId(
    userId
){

    const result =
        await pool.query(
            `
            SELECT

                users.id,

                users.name,

                users.username,

                users.email,

                users.created_at,

                profiles.bio,

                profiles.profile_picture,

                profiles.updated_at

            FROM users

            LEFT JOIN profiles

                ON profiles.user_id =
                   users.id

            WHERE users.id = $1

            LIMIT 1
            `,
            [userId]
        );


    if(
        result.rows.length === 0
    ){

        return null;

    }


    const profile =
        result.rows[0];


    const counts =
        await getFollowCounts(
            userId
        );


    return {

        id:
            profile.id,

        name:
            profile.name,

        username:
            profile.username,

        email:
            profile.email,

        bio:
            profile.bio || "",

        profile_picture:
            profile.profile_picture || "",

        created_at:
            profile.created_at,

        updated_at:
            profile.updated_at,

        followers_count:
            counts.followers_count,

        following_count:
            counts.following_count

    };

}


/* =========================================
   PUBLIC PROFILE HELPER
========================================= */

async function getPublicProfileByUsername(
    username
){

    const cleanUser =
        cleanUsername(username);


    if(!cleanUser){

        return null;

    }


    const result =
        await pool.query(
            `
            SELECT id
            FROM users
            WHERE LOWER(username) = $1
            LIMIT 1
            `,
            [cleanUser]
        );


    if(
        result.rows.length === 0
    ){

        return null;

    }


    return getProfileByUserId(
        result.rows[0].id
    );

}
 
/* =========================================
   CANVAS SERVER — PART 2
   SIGNUP + LOGIN + PROFILE
========================================= */


/* =========================================
   SIGNUP
========================================= */

app.post(
    "/api/signup",
    async (req,res) => {

        if(!pool){

            return res.status(500).json({

                success:false,

                message:
                    "Database is not configured."

            });

        }


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
                    "Name, username, email and password are required."

            });

        }


        const cleanName =
            String(name)
                .trim()
                .substring(0,100);


        const cleanUsernameValue =
            cleanUsername(username);


        const cleanEmail =
            String(email)
                .trim()
                .toLowerCase();


        if(
            cleanUsernameValue.length < 3
        ){

            return res.status(400).json({

                success:false,

                message:
                    "Username must be at least 3 characters."

            });

          }
       if(
            !/^[a-z0-9_.]+$/.test(
                cleanUsernameValue
            )
        ){

            return res.status(400).json({

                success:false,

                message:
                    "Username can only contain letters, numbers, underscores and dots."

            });

        }


        if(
            !/^[^\s@]+@[^\s@]+\.[^\s@]+$/
                .test(cleanEmail)
        ){

            return res.status(400).json({

                success:false,

                message:
                    "Please enter a valid email address."

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


        try{

            /* =================================
               CHECK EMAIL
            ================================= */

            const emailCheck =
                await pool.query(
                    `
                    SELECT id
                    FROM users
                    WHERE LOWER(email) = $1
                    LIMIT 1
                    `,
                    [cleanEmail]
                );


            if(
                emailCheck.rows.length > 0
            ){

                return res.status(409).json({

                    success:false,

                    message:
                        "An account with this email already exists."

                });

            }


            /* =================================
               CHECK USERNAME
            ================================= */

            const usernameCheck =
                await pool.query(
                    `
                    SELECT id
                    FROM users
                    WHERE LOWER(username) = $1
                    LIMIT 1
                    `,
                    [cleanUsernameValue]
                );


            if(
                usernameCheck.rows.length > 0
            ){

                return res.status(409).json({

                    success:false,

                    message:
                        "Username already exists."

                });

            }


            /* =================================
               CREATE USER
            ================================= */

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
                        cleanName,
                        cleanUsernameValue,
                        cleanEmail,
                        passwordHash
                    ]
                );


            const user =
                userResult.rows[0];


            /* =================================
               CREATE EMPTY PROFILE
            ================================= */

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
                    '',
                    ''
                )

                ON CONFLICT(user_id)
                DO NOTHING
                `,
                [user.id]
            );


            /* =================================
               CREATE SESSION
            ================================= */

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


            return res.status(201).json({

                success:true,

                message:
                    "Canvas account created successfully.",

                token,

                user:{

                    id:
                        user.id,

                    name:
                        user.name,

                    username:
                        user.username,

                    email:
                        user.email,

                    created_at:
                        user.created_at

                }

            });


        }catch(error){

            console.error(
                "Signup failed:",
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


        const {
            email,
            password
        } = req.body;


        if(
            !email ||
            !password
        ){

            return res.status(400).json({

                success:false,

                message:
                    "Email and password are required."

            });

        }


        try{

            const cleanEmail =
                String(email)
                    .trim()
                    .toLowerCase();


            const passwordHash =
                hashPassword(password);


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
                user.password_hash !==
                passwordHash
            ){

                return res.status(401).json({

                    success:false,

                    message:
                        "Email or password is incorrect."

                });

            }


            /* =================================
               NEW LOGIN SESSION
            ================================= */

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


            return res.json({

                success:true,

                message:
                    "Login successful.",

                token,

                user:{

                    id:
                        user.id,

                    name:
                        user.name,

                    username:
                        user.username,

                    email:
                        user.email,

                    created_at:
                        user.created_at

                }

            });


        }catch(error){

            console.error(
                "Login failed:",
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

            return res.json({

                success:true,

                user:{

                    id:
                        req.user.id,

                    name:
                        req.user.name,

                    username:
                        req.user.username,

                    email:
                        req.user.email,

                    created_at:
                        req.user.created_at

                }

            });


        }catch(error){

            console.error(
                "Get current user failed:",
                error.message
            );


            return res.status(500).json({

                success:false,

                message:
                    "Unable to get current user."

            });

        }

    }
);


/* =========================================
   GET MY PROFILE
   NOW INCLUDES REAL COUNTS
========================================= */

app.get(
    "/api/profile",
    authenticateUser,
    async (req,res) => {

        try{

            const profile =
                await getProfileByUserId(
                    req.user.id
                );


            if(!profile){

                return res.status(404).json({

                    success:false,

                    message:
                        "Canvas profile not found."

                });

            }


            return res.json({

                success:true,

                profile,

                /*
                   Also expose the fields directly
                   so older Canvas pages can read them.
                */

                id:
                    profile.id,

                name:
                    profile.name,

                username:
                    profile.username,

                email:
                    profile.email,

                bio:
                    profile.bio,

                profile_picture:
                    profile.profile_picture,

                followers_count:
                    profile.followers_count,

                following_count:
                    profile.following_count

            });


        }catch(error){

            console.error(
                "Get profile failed:",
                error.message
            );


            return res.status(500).json({

                success:false,

                message:
                    "Unable to load Canvas profile."

            });

        }

    }
);


/* =========================================
   GET PUBLIC PROFILE
========================================= */

app.get(
    "/api/profile/:username",
    async (req,res) => {

        try{

            const username =
                cleanUsername(
                    req.params.username
                );


            if(!username){

                return res.status(400).json({

                    success:false,

                    message:
                        "Username is required."

                });

            }


            const profile =
                await getPublicProfileByUsername(
                    username
                );


            if(!profile){

                return res.status(404).json({

                    success:false,

                    message:
                        "Canvas profile not found."

                });

            }


            /*
               Public profile deliberately does
               not expose password_hash or
               authentication information.
            */

            return res.json({

                success:true,

                profile

            });


        }catch(error){

            console.error(
                "Get public profile failed:",
                error.message
            );


            return res.status(500).json({

                success:false,

                message:
                    "Unable to load Canvas profile."

            });

        }

    }
);


/* =========================================
   UPDATE MY PROFILE
========================================= */

app.put(
    "/api/profile",
    authenticateUser,
    async (req,res) => {

        const {
            name,
            username,
            bio,
            profile_picture
        } = req.body;


        if(
            !name ||
            !username
        ){

            return res.status(400).json({

                success:false,

                message:
                    "Name and username are required."

            });

        }


        const cleanName =
            String(name)
                .trim()
                .substring(0,100);


        const cleanUsernameValue =
            cleanUsername(username);


        const cleanBio =
            String(
                bio || ""
            )
            .trim()
            .substring(0,1000);


        const cleanProfilePicture =
            String(
                profile_picture || ""
            );


        if(
            cleanUsernameValue.length < 3
        ){

            return res.status(400).json({

                success:false,

                message:
                    "Username must be at least 3 characters."

            });

        }


        if(
            !/^[a-z0-9_.]+$/.test(
                cleanUsernameValue
            )
        ){

            return res.status(400).json({

                success:false,

                message:
                    "Username can only contain letters, numbers, underscores and dots."

            });

              }
      try{

            /* =================================
               CHECK USERNAME OWNERSHIP
            ================================= */

            const usernameCheck =
                await pool.query(
                    `
                    SELECT id

                    FROM users

                    WHERE LOWER(username) = $1

                    AND id != $2

                    LIMIT 1
                    `,
                    [
                        cleanUsernameValue,
                        req.user.id
                    ]
                );


            if(
                usernameCheck.rows.length > 0
            ){

                return res.status(409).json({

                    success:false,

                    message:
                        "Username already exists."

                });

            }


            /* =================================
               UPDATE USER
            ================================= */

            await pool.query(
                `
                UPDATE users

                SET
                    name = $1,
                    username = $2

                WHERE id = $3
                `,
                [
                    cleanName,
                    cleanUsernameValue,
                    req.user.id
                ]
            );


            /* =================================
               UPDATE PROFILE
            ================================= */

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

                ON CONFLICT(user_id)

                DO UPDATE SET

                    bio =
                        EXCLUDED.bio,

                    profile_picture =
                        EXCLUDED.profile_picture,

                    updated_at =
                        CURRENT_TIMESTAMP
                `,
                [
                    req.user.id,
                    cleanBio,
                    cleanProfilePicture
                ]
            );


            const profile =
                await getProfileByUserId(
                    req.user.id
                );


            return res.json({

                success:true,

                message:
                    "Profile updated successfully.",

                profile

            });


        }catch(error){

            console.error(
                "Update profile failed:",
                error.message
            );


            return res.status(500).json({

                success:false,

                message:
                    "Unable to update Canvas profile."

            });

        }

    }
);


/* =========================================
   DELETE PROFILE PICTURE
========================================= */

app.delete(
    "/api/profile/picture",
    authenticateUser,
    async (req,res) => {
      try{

            await pool.query(
                `
                INSERT INTO profiles
                (
                    user_id,
                    profile_picture,
                    updated_at
                )

                VALUES
                (
                    $1,
                    '',
                    CURRENT_TIMESTAMP
                )

                ON CONFLICT(user_id)

                DO UPDATE SET

                    profile_picture = '',

                    updated_at =
                        CURRENT_TIMESTAMP
                `,
                [req.user.id]
            );


            return res.json({

                success:true,

                message:
                    "Profile picture deleted successfully."

            });


        }catch(error){

            console.error(
                "Delete profile picture failed:",
                error.message
            );


            return res.status(500).json({

                success:false,

                message:
                    "Unable to delete profile picture."

            });

        }

    }
);


/* =========================================
   LOGOUT
========================================= */

app.post(
    "/api/logout",
    authenticateUser,
    async (req,res) => {

        const authorization =
            req.headers.authorization || "";


        const token =
            authorization
                .substring(7)
                .trim();


        try{

            await pool.query(
                `
                DELETE FROM sessions

                WHERE token_hash = $1
                `,
                [
                    hashToken(token)
                ]
            );


            return res.json({

                success:true,

                message:
                    "Logged out successfully."

            });


        }catch(error){

            console.error(
                "Logout failed:",
                error.message
            );


            return res.status(500).json({

                success:false,

                message:
                    "Unable to log out."

            });

        }

    }
);
/* =========================================
   FOLLOW / UNFOLLOW SYSTEM
   ========================================= */

/*
   IMPORTANT:
   Follow relationships are stored in PostgreSQL.

   This means:
   - Follow works across different phones/devices.
   - Counts are real database counts.
   - Duplicate follows are prevented.
   - Self-follow is prevented.
   - Unfollow decreases the real count.
*/


/* =========================================
   GET FOLLOW STATUS
   GET /api/follow/:username/status
   ========================================= */

app.get(
    "/api/follow/:username/status",
    authenticateUser,
    async (req, res) => {

        const username =
            cleanUsername(req.params.username);

        try {

            const targetResult = await pool.query(
                `
                SELECT
                    id,
                    username,
                    name
                FROM users
                WHERE LOWER(username) = LOWER($1)
                LIMIT 1
                `,
                [username]
            );

            if (targetResult.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: "User not found."
                });
            }

            const targetUser =
                targetResult.rows[0];

            /* -----------------------------------------
               SELF PROFILE
            ----------------------------------------- */

            if (targetUser.id === req.user.id) {

                const counts =
                    await getFollowCounts(
                        targetUser.id
                    );

                return res.json({
                    success: true,
                    following: false,
                    isFollowing: false,
                    isSelf: true,
                    followers_count:
                        counts.followers_count,
                    following_count:
                        counts.following_count
                });
            }


            /* -----------------------------------------
               CHECK RELATIONSHIP
            ----------------------------------------- */

            const followResult =
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
                        targetUser.id
                    ]
                );


            /* -----------------------------------------
               GET REAL COUNTS
            ----------------------------------------- */

            const targetCounts =
                await getFollowCounts(
                    targetUser.id
                );

            const myCounts =
                await getFollowCounts(
                    req.user.id
                );


            return res.json({
                success: true,

                following:
                    followResult.rows.length > 0,

                isFollowing:
                    followResult.rows.length > 0,

                isSelf: false,

                followers_count:
                    targetCounts.followers_count,

                following_count:
                    targetCounts.following_count,

                viewer_followers_count:
                    myCounts.followers_count,

                viewer_following_count:
                    myCounts.following_count
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


/* =========================================
   FOLLOW USER
   POST /api/follow/:username
   ========================================= */

app.post(
    "/api/follow/:username",
    authenticateUser,
    async (req, res) => {

        const username =
            cleanUsername(req.params.username);

        try {

            /* -----------------------------------------
               FIND TARGET USER
            ----------------------------------------- */

            const targetResult =
                await pool.query(
                    `
                    SELECT
                        id,
                        username,
                        name
                    FROM users
                    WHERE LOWER(username) = LOWER($1)
                    LIMIT 1
                    `,
                    [username]
                );

            if (targetResult.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: "User not found."
                });
            }

            const targetUser =
                targetResult.rows[0];


            /* -----------------------------------------
               PREVENT SELF FOLLOW
            ----------------------------------------- */

            if (
                targetUser.id ===
                req.user.id
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        "You cannot follow yourself.",
                    following: false
                });
            }


            /* -----------------------------------------
               CREATE RELATIONSHIP
               
               ON CONFLICT guarantees that pressing
               Follow multiple times NEVER creates
               duplicate relationships.
            ----------------------------------------- */

            await pool.query(
                `
                INSERT INTO follows
                    (
                        follower_id,
                        following_id
                    )
                VALUES
                    ($1, $2)
                ON CONFLICT
                    (
                        follower_id,
                        following_id
                    )
                DO NOTHING
                `,
                [
                    req.user.id,
                    targetUser.id
                ]
            );


            /* -----------------------------------------
               GET TARGET COUNTS
            ----------------------------------------- */

            const targetCounts =
                await getFollowCounts(
                    targetUser.id
                );


            /* -----------------------------------------
               GET CURRENT USER COUNTS
            ----------------------------------------- */

            const myCounts =
                await getFollowCounts(
                    req.user.id
                );


            return res.json({

                success: true,

                following: true,

                isFollowing: true,

                username:
                    targetUser.username,

                followers_count:
                    targetCounts.followers_count,

                following_count:
                    targetCounts.following_count,

                viewer_followers_count:
                    myCounts.followers_count,

                viewer_following_count:
                    myCounts.following_count

            });

        } catch (error) {

            console.error(
                "Follow user failed:",
                error.message
            );

            return res.status(500).json({
                success: false,
                message:
                    "Unable to follow user."
            });
        }
    }
);


/* =========================================
   UNFOLLOW USER
   DELETE /api/follow/:username
   ========================================= */

app.delete(
    "/api/follow/:username",
    authenticateUser,
    async (req, res) => {

        const username =
            cleanUsername(req.params.username);

        try {

            /* -----------------------------------------
               FIND TARGET USER
            ----------------------------------------- */

            const targetResult =
                await pool.query(
                    `
                    SELECT
                        id,
                        username,
                        name
                    FROM users
                    WHERE LOWER(username) = LOWER($1)
                    LIMIT 1
                    `,
                    [username]
                );

            if (targetResult.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: "User not found."
                });
            }

            const targetUser =
                targetResult.rows[0];


            /* -----------------------------------------
               PREVENT SELF UNFOLLOW
            ----------------------------------------- */

            if (
                targetUser.id ===
                req.user.id
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        "You cannot unfollow yourself.",
                    following: false
                });
            }


            /* -----------------------------------------
               DELETE RELATIONSHIP
            ----------------------------------------- */

            await pool.query(
                `
                DELETE FROM follows
                WHERE follower_id = $1
                  AND following_id = $2
                `,
                [
                    req.user.id,
                    targetUser.id
                ]
            );


            /* -----------------------------------------
               GET TARGET COUNTS
            ----------------------------------------- */

            const targetCounts =
                await getFollowCounts(
                    targetUser.id
                );


            /* -----------------------------------------
               GET CURRENT USER COUNTS
            ----------------------------------------- */

            const myCounts =
                await getFollowCounts(
                    req.user.id
                );


            return res.json({

                success: true,

                following: false,

                isFollowing: false,

                username:
                    targetUser.username,

                followers_count:
                    targetCounts.followers_count,

                following_count:
                    targetCounts.following_count,

                viewer_followers_count:
                    myCounts.followers_count,

                viewer_following_count:
                    myCounts.following_count

            });

        } catch (error) {

            console.error(
                "Unfollow user failed:",
                error.message
            );

            return res.status(500).json({
                success: false,
                message:
                    "Unable to unfollow user."
            });
        }
    }
);
 /* =========================================
   GET FOLLOWERS
   GET /api/follow/:username/followers
   ========================================= */

app.get(
    "/api/follow/:username/followers",
    async (req, res) => {

        const username =
            cleanUsername(req.params.username);

        try {

            const result =
                await pool.query(
                    `
                    SELECT
                        users.id,
                        users.name,
                        users.username,
                        profiles.profile_picture
                    FROM follows

                    INNER JOIN users
                        ON users.id =
                           follows.follower_id

                    LEFT JOIN profiles
                        ON profiles.user_id =
                           users.id

                    WHERE follows.following_id = (
                        SELECT id
                        FROM users
                        WHERE LOWER(username) =
                              LOWER($1)
                        LIMIT 1
                    )

                    ORDER BY
                        follows.created_at DESC
                    `,
                    [username]
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


/* =========================================
   GET FOLLOWING
   GET /api/follow/:username/following
   ========================================= */

app.get(
    "/api/follow/:username/following",
    async (req, res) => {

        const username =
            cleanUsername(req.params.username);

        try {

            const result =
                await pool.query(
                    `
                    SELECT
                        users.id,
                        users.name,
                        users.username,
                        profiles.profile_picture
                    FROM follows

                    INNER JOIN users
                        ON users.id =
                           follows.following_id

                    LEFT JOIN profiles
                        ON profiles.user_id =
                           users.id

                    WHERE follows.follower_id = (
                        SELECT id
                        FROM users
                        WHERE LOWER(username) =
                              LOWER($1)
                        LIMIT 1
                    )

                    ORDER BY
                        follows.created_at DESC
                    `,
                    [username]
                );


            return res.json({

                success: true,

                following:
                    result.rows

            });

        } catch (error) {

            console.error(
                "Get following failed:",
                error.message
            );

            return res.status(500).json({
                success: false,
                message:
                    "Unable to load following."
            });
        }
    }
);


/* =========================================
   FOLLOW COUNTS
   GET /api/follow/:username/counts
   ========================================= */

app.get(
    "/api/follow/:username/counts",
    async (req, res) => {

        const username =
            cleanUsername(req.params.username);

        try {

            const userResult =
                await pool.query(
                    `
                    SELECT id
                    FROM users
                    WHERE LOWER(username) =
                          LOWER($1)
                    LIMIT 1
                    `,
                    [username]
                );


            if (userResult.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: "User not found."
                });
            }


            const counts =
                await getFollowCounts(
                    userResult.rows[0].id
                );


            return res.json({

                success: true,

                followers_count:
                    counts.followers_count,

                following_count:
                    counts.following_count

            });

        } catch (error) {

            console.error(
                "Get follow counts failed:",
                error.message
            );

            return res.status(500).json({
                success: false,
                message:
                    "Unable to load follow counts."
            });
        }
    }
);


/* =========================================
   STREAM ROUTES
   ========================================= */


/* =========================================
   CREATE STREAM
   POST /api/streams
   ========================================= */

app.post(
    "/api/streams",
    authenticateUser,
    async (req, res) => {

        const {
            title
        } = req.body;


        try {

            const cleanTitle =
                String(
                    title ||
                    "Canvas Live Stream"
                ).trim();


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
                        cleanTitle
                    ]
                );


            return res.status(201).json({

                success: true,

                message:
                    "Canvas stream started.",

                stream:
                    result.rows[0]

            });

        } catch (error) {

            console.error(
                "Create stream failed:",
                error.message
            );

            return res.status(500).json({
                success: false,
                message:
                    "Unable to start stream."
            });
        }
    }
);


/* =========================================
   GET MY STREAMS
   GET /api/streams/my
   ========================================= */

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
                    ORDER BY created_at DESC
                    `,
                    [req.user.id]
                );


            return res.json({

                success: true,

                streams:
                    result.rows

            });

        } catch (error) {

            console.error(
                "Get streams failed:",
                error.message
            );

            return res.status(500).json({
                success: false,
                message:
                    "Unable to load streams."
            });
        }
    }
);


/* =========================================
   GET LIVE STREAMS
   GET /api/streams/live
   ========================================= */

app.get(
    "/api/streams/live",
    async (req, res) => {

        if (!pool) {
            return res.status(500).json({
                success: false,
                message:
                    "Database is not configured."
            });
        }

try {

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
                        users.username

                    FROM streams

                    INNER JOIN users
                        ON users.id =
                           streams.user_id

                    WHERE streams.status = 'live'

                    ORDER BY
                        streams.created_at DESC
                    `
                );


            return res.json({

                success: true,

                streams:
                    result.rows

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


/* =========================================
   END STREAM
   PUT /api/streams/:id/end
   ========================================= */

app.put(
    "/api/streams/:id/end",
    authenticateUser,
    async (req, res) => {

        const streamId =
            req.params.id;

        try {

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
                        "Live stream not found."
                });
            }


            return res.json({

                success: true,

                message:
                    "Canvas stream ended.",

                stream:
                    result.rows[0]

            });

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
 /* =========================================
    DELETE STREAM
    DELETE /api/streams/:id
    ========================================= */

app.delete(
    "/api/streams/:id",
    authenticateUser,
    async (req, res) => {

        const streamId =
            req.params.id;

        try {

            const result =
                await pool.query(
                    `
                    DELETE FROM streams
                    WHERE id = $1
                      AND user_id = $2
                    RETURNING id
                    `,
                    [
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
                        "Stream not found."
                });
            }


            return res.json({

                success: true,

                message:
                    "Stream deleted successfully."

            });

        } catch (error) {

            console.error(
                "Delete stream failed:",
                error.message
            );

            return res.status(500).json({
                success: false,
                message:
                    "Unable to delete stream."
            });
        }
    }
);


/* =========================================
   PUBLIC STREAM INFORMATION
   GET /api/streams/:id
   ========================================= */

app.get(
    "/api/streams/:id",
    async (req, res) => {

        const streamId =
            req.params.id;

        try {

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

                        profiles.profile_picture,
                        profiles.bio

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
                    [streamId]
                );


            if (
                result.rows.length === 0
            ) {

                return res.status(404).json({
                    success: false,
                    message:
                        "Stream not found."
                });
            }


            const stream =
                result.rows[0];


            const counts =
                await getFollowCounts(
                    stream.user_id
                );


            return res.json({

                success: true,

                stream: {
                    ...stream,

                    followers_count:
                        counts.followers_count,

                    following_count:
                        counts.following_count
                }

            });

        } catch (error) {

            console.error(
                "Get stream information failed:",
                error.message
            );

            return res.status(500).json({
                success: false,
                message:
                    "Unable to load stream information."
            });
        }
    }
);


/* =========================================
   PUBLIC USER PROFILE
   GET /api/users/:username
   ========================================= */

app.get(
    "/api/users/:username",
    async (req, res) => {

        const username =
            cleanUsername(req.params.username);

        try {

            const profile =
                await getPublicProfileByUsername(
                    username
                );


            if (!profile) {

                return res.status(404).json({
                    success: false,
                    message:
                        "User not found."
                });
            }


            return res.json({

                success: true,

                profile

            });

        } catch (error) {

            console.error(
                "Get public user failed:",
                error.message
            );

            return res.status(500).json({
                success: false,
                message:
                    "Unable to load user."
            });
        }
    }
);


/* =========================================
   CURRENT USER PROFILE
   GET /api/account/profile
   ========================================= */

app.get(
    "/api/account/profile",
    authenticateUser,
    async (req, res) => {

        try {

            const profile =
                await getProfileByUserId(
                    req.user.id
                );


            if (!profile) {

                return res.status(404).json({
                    success: false,
                    message:
                        "Profile not found."
                });
            }


            return res.json({

                success: true,

                profile

            });

        } catch (error) {

            console.error(
                "Get account profile failed:",
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
/* =========================================
   ACCOUNT FOLLOW SUMMARY
   GET /api/account/follows
   ========================================= */

app.get(
    "/api/account/follows",
    authenticateUser,
    async (req, res) => {

        try {

            const counts =
                await getFollowCounts(
                    req.user.id
                );


            return res.json({

                success: true,

                followers_count:
                    counts.followers_count,

                following_count:
                    counts.following_count

            });

        } catch (error) {

            console.error(
                "Get account follows failed:",
                error.message
            );

            return res.status(500).json({
                success: false,
                message:
                    "Unable to load follow information."
            });
        }
    }
);


/* =========================================
   CHECK FOLLOW RELATIONSHIP BY USERNAME
   GET /api/account/follows/:username
   ========================================= */

app.get(
    "/api/account/follows/:username",
    authenticateUser,
    async (req, res) => {

        const username =
            cleanUsername(req.params.username);

        try {

            const targetResult =
                await pool.query(
                    `
                    SELECT id, username
                    FROM users
                    WHERE LOWER(username) =
                          LOWER($1)
                    LIMIT 1
                    `,
                    [username]
                );


            if (
                targetResult.rows.length === 0
            ) {

                return res.status(404).json({
                    success: false,
                    message:
                        "User not found."
                });
            }


            const target =
                targetResult.rows[0];


            if (
                target.id ===
                req.user.id
            ) {

                const counts =
                    await getFollowCounts(
                        req.user.id
                    );

                return res.json({

                    success: true,

                    following: false,

                    isFollowing: false,

                    isSelf: true,

                    followers_count:
                        counts.followers_count,

                    following_count:
                        counts.following_count

                });
            }


            const relationship =
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
                        target.id
                    ]
                );


            const counts =
                await getFollowCounts(
                    target.id
                );


            return res.json({

                success: true,

                following:
                    relationship.rows.length > 0,

                isFollowing:
                    relationship.rows.length > 0,

                isSelf: false,

                followers_count:
                    counts.followers_count,

                following_count:
                    counts.following_count

            });

        } catch (error) {

            console.error(
                "Account follow check failed:",
                error.message
            );

            return res.status(500).json({
                success: false,
                message:
                    "Unable to check follow relationship."
            });
        }
    }
);


/* =========================================
   PROFILE SEARCH
   GET /api/search/users?q=
   ========================================= */

app.get(
    "/api/search/users",
    async (req, res) => {

        const query =
            String(
                req.query.q || ""
            ).trim();


        if (!query) {

            return res.json({

                success: true,

                users: []

            });
        }


        try {

            const search =
                `%${query}%`;


            const result =
                await pool.query(
                    `
                    SELECT
                        users.id,
                        users.name,
                        users.username,
                        profiles.profile_picture,

                        (
                            SELECT COUNT(*)
                            FROM follows
                            WHERE following_id =
                                  users.id
                        )::INTEGER
                        AS followers_count

                    FROM users

                    LEFT JOIN profiles
                        ON profiles.user_id =
                           users.id

                    WHERE
                        users.username ILIKE $1
                        OR users.name ILIKE $1

                    ORDER BY
                        users.username ASC

                    LIMIT 50
                    `,
                    [search]
                );


            return res.json({

                success: true,

                users:
                    result.rows

            });

        } catch (error) {

            console.error(
                "User search failed:",
                error.message
            );

            return res.status(500).json({
                success: false,
                message:
                    "Unable to search users."
            });
        }
    }
);


/* =========================================
   LIVE STREAM SEARCH
   GET /api/search/streams?q=
   ========================================= */

app.get(
    "/api/search/streams",
    async (req, res) => {

        const query =
            String(
                req.query.q || ""
            ).trim();


        if (!query) {

            return res.json({

                success: true,

                streams: []

            });
        }


        try {

            const search =
                `%${query}%`;


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

                    WHERE
                        streams.status = 'live'
                    AND
                        (
                            streams.title ILIKE $1
                            OR users.username ILIKE $1
                            OR users.name ILIKE $1
                        )

                    ORDER BY
                        streams.created_at DESC

                    LIMIT 50
                    `,
                    [search]
                );


            return res.json({

                success: true,

                streams:
                    result.rows

            });

        } catch (error) {

            console.error(
                "Stream search failed:",
                error.message
            );

            return res.status(500).json({
                success: false,
                message:
                    "Unable to search streams."
            });
        }
    }
);


/* =========================================
   HEALTH CHECK
   GET /api/health
   ========================================= */

app.get(
    "/api/health",
    async (req, res) => {

        if (!pool) {

            return res.status(500).json({

                success: false,

                status:
                    "unhealthy",

                database:
                    "not configured"

            });
        }


        try {

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

        } catch (error) {

            console.error(
                "Health check failed:",
                error.message
            );


            return res.status(500).json({

                success: false,

                status:
                    "unhealthy",

                database:
                    "connection failed"

            });
        }
    }
);


/* =========================================
   DATABASE TEST
   GET /api/database-test
   ========================================= */

app.get(
    "/api/database-test",
    async (req, res) => {

        if (!pool) {

            return res.status(500).json({

                success: false,

                message:
                    "Database is not configured."

            });
        }


        try {

            const result =
                await pool.query(
                    "SELECT NOW() AS now"
                );


            return res.json({

                success: true,

                message:
                    "Canvas database is connected.",

                database:
                    "PostgreSQL",

                time:
                    result.rows[0].now

            });

        } catch (error) {

            console.error(
                "Database test failed:",
                error.message
            );


            return res.status(500).json({

                success: false,

                message:
                    "Database connection failed.",

                error:
                    error.message

            });
        }
    }
);
// =========================================
// 404 HANDLER
// =========================================

app.use((req, res) => {
    res.status(404).json({
        success: false,
        error: "API endpoint not found",
        path: req.originalUrl
    });
});


// =========================================
// GLOBAL ERROR HANDLER
// =========================================

app.use((err, req, res, next) => {

    console.error("SERVER ERROR:", err);

    if (res.headersSent) {
        return next(err);
    }

    res.status(500).json({
        success: false,
        error: "Internal server error"
    });
});


// =========================================
// START SERVER
// =========================================

const PORT = process.env.PORT || 3000;

async function startServer() {

    try {

        console.log("=================================");
        console.log("CANVAS SERVER STARTING");
        console.log("=================================");

        // Make sure database is ready
        await initializeDatabase();

        console.log("Database initialization complete");

        app.listen(PORT, "0.0.0.0", () => {

            console.log("=================================");
            console.log("CANVAS SERVER IS LIVE");
            console.log("PORT:", PORT);
            console.log("=================================");

        });

    } catch (error) {

        console.error(
            "DATABASE INITIALIZATION FAILED:",
            error
        );

        /*
         * Keep the process alive so Render can restart/retry
         * instead of silently disappearing.
         */

        process.exit(1);
    }
}


// =========================================
// DATABASE ERROR LISTENER
// =========================================

pool.on("error", (error) => {

    console.error(
        "POSTGRES POOL ERROR:",
        error
    );

});


// =========================================
// UNHANDLED PROMISE ERROR
// =========================================

process.on(
    "unhandledRejection",
    (reason) => {

        console.error(
            "UNHANDLED REJECTION:",
            reason
        );

    }
);


// =========================================
// UNCAUGHT EXCEPTION
// =========================================

process.on(
    "uncaughtException",
    (error) => {

        console.error(
            "UNCAUGHT EXCEPTION:",
            error
        );

    }
);


// =========================================
// START CANVAS
// =========================================

startServer();  
