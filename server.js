/*
=========================================================
                    CANVAS SERVER
                    PART 1 / 8
=========================================================

IMPORTANT:
- Signup and Login flow stays untouched.
- This file supports the existing Canvas frontend.
- Join Parts 1 through 8 in this exact order.

FEATURES:
- Existing authentication
- Profiles
- Profile pictures
- Followers / Following
- Live streams
- Completed streams
- Stream thumbnails
- Watch page
- Chat
- Gifts / support events
- Socket.IO
- Stream heartbeat
- WebRTC signaling
- PostgreSQL
=========================================================
*/


/* =====================================================
   DEPENDENCIES
===================================================== */

const express = require("express");

const http = require("http");

const cors = require("cors");

const crypto = require("crypto");

const bcrypt = require("bcryptjs");

const { Pool } = require("pg");

const {
    Server
} = require("socket.io");


/* =====================================================
   APP
===================================================== */

const app = express();

const server =
    http.createServer(app);


/* =====================================================
   SOCKET.IO
===================================================== */

const io =
    new Server(server, {

        cors: {
            origin: "*",

            methods: [
                "GET",
                "POST",
                "PUT",
                "DELETE",
                "OPTIONS"
            ]
        },

        transports: [
            "websocket",
            "polling"
        ]

    });


/* =====================================================
   BASIC CONFIG
===================================================== */

const PORT =
    process.env.PORT || 10000;

const API_BASE =
    "https://canvas-kh9p.onrender.com";


/* =====================================================
   CORS
===================================================== */

app.use(
    cors({

        origin: "*",

        methods: [
            "GET",
            "POST",
            "PUT",
            "DELETE",
            "OPTIONS"
        ],

        allowedHeaders: [
            "Content-Type",
            "Authorization"
        ]

    })
);


/* =====================================================
   BODY PARSING
===================================================== */

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


/* =====================================================
   BASIC ROUTES
===================================================== */

app.get(
    "/",
    (req, res) => {

        res.json({

            success: true,

            app: "Canvas",

            message:
                "Canvas server is running.",

            api:
                API_BASE

        });

    }
);


app.get(
    "/api/health",
    (req, res) => {

        res.json({

            success: true,

            status: "online",

            service: "Canvas API"

        });

    }
);


/* =====================================================
   DATABASE
===================================================== */

const DATABASE_URL =
    process.env.canvas_db_r13t ||
    process.env.DATABASE_URL;


const pool =
    new Pool({

        connectionString:
            DATABASE_URL,

        ssl:
            DATABASE_URL
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
            "Canvas PostgreSQL pool error:",
            error
        );

    }
);


/* =====================================================
   DATABASE TEST
===================================================== */

async function testDatabase(){

    if(!DATABASE_URL){

        console.warn(
            "Canvas database URL is not configured."
        );

        return false;

    }


    try{

        await pool.query(
            "SELECT NOW()"
        );


        console.log(
            "Canvas database connected."
        );


        return true;

    }catch(error){

        console.error(
            "Canvas database connection error:",
            error
        );


        return false;

    }

}


app.get(
    "/api/database-test",
    async (req, res) => {

        try{

            if(!DATABASE_URL){

                return res.status(500).json({

                    success: false,

                    message:
                        "Database URL is not configured."

                });

            }


            const result =
                await pool.query(
                    "SELECT NOW() AS now"
                );


            res.json({

                success: true,

                database: "connected",

                time:
                    result.rows[0].now

            });

        }catch(error){

            console.error(
                "Database test error:",
                error
            );


            res.status(500).json({

                success: false,

                message:
                    "Database connection failed."

            });

        }

    }
);


/* =====================================================
   GENERAL HELPERS
===================================================== */

function cleanUsername(
    username
){

    if(
        username === undefined ||
        username === null
    ){

        return "";

    }


    return String(username)
        .trim()
        .toLowerCase()
        .replace(/^@+/, "")
        .replace(/\s+/g, "")
        .replace(
            /[^a-z0-9_.]/g,
            ""
        );

}


function cleanText(
    value,
    maxLength = 1000
){

    if(
        value === undefined ||
        value === null
    ){

        return "";

    }


    return String(value)
        .trim()
        .slice(0, maxLength);

}


function makeId(){

    return crypto
        .randomBytes(18)
        .toString("hex");

}


function makeToken(){

    return crypto
        .randomBytes(48)
        .toString("hex");

}


function makeVerificationCode(){

    return String(
        Math.floor(
            100000 +
            Math.random() * 900000
        )
    );

}


/* =====================================================
   AUTH HELPERS
===================================================== */

function getBearerToken(req){

    const header =
        req.headers.authorization || "";


    if(
        !header.toLowerCase()
            .startsWith("bearer ")
    ){

        return "";

    }


    return header
        .slice(7)
        .trim();

}


async function getUserFromToken(
    token
){

    if(!token){

        return null;

    }


    try{

        const result =
            await pool.query(
                `
                SELECT *
                FROM users
                WHERE
                    auth_token = $1
                LIMIT 1
                `,
                [token]
            );


        if(
            !result.rows.length
        ){

            return null;

        }


        return result.rows[0];

    }catch(error){

        console.error(
            "Token lookup error:",
            error
        );


        return null;

    }

}


async function requireAuth(
    req,
    res,
    next
){

    try{

        const token =
            getBearerToken(req);


        if(!token){

            return res.status(401).json({

                success: false,

                message:
                    "Authentication required."

            });

        }


        const user =
            await getUserFromToken(
                token
            );


        if(!user){

            return res.status(401).json({

                success: false,

                message:
                    "Invalid or expired login."

            });

        }


        req.user = user;

        req.authToken = token;

        next();

    }catch(error){

        console.error(
            "Authentication error:",
            error
        );


        res.status(401).json({

            success: false,

            message:
                "Authentication failed."

        });

    }

}


async function optionalAuth(
    req,
    res,
    next
){

    try{

        const token =
            getBearerToken(req);


        if(token){

            req.user =
                await getUserFromToken(
                    token
                );

        }else{

            req.user = null;

        }


        next();

    }catch(error){

        req.user = null;

        next();

    }

}


/* =====================================================
   PUBLIC USER FORMAT
===================================================== */

function publicUser(
    user
){

    if(!user){

        return null;

    }


    return {

        id:
            user.id,

        user_id:
            user.id,

        username:
            user.username || "",

        name:
            user.name || "",

        email:
            user.email || "",

        profile_picture:
            user.profile_picture ||
            user.profilePicture ||
            user.photo ||
            user.avatar ||
            "",

        bio:
            user.bio || "",

        followers:
            Number(
                user.followers || 0
            ),

        following:
            Number(
                user.following || 0
            )

    };

}


/* =====================================================
   DATABASE INITIALIZATION
===================================================== */

async function initializeDatabase(){

    if(!DATABASE_URL){

        console.warn(
            "Skipping database initialization."
        );

        return;

    }


    try{

        await pool.query(`
            CREATE TABLE IF NOT EXISTS stream_recordings (
                id TEXT PRIMARY KEY,
                stream_id TEXT,
                user_id TEXT,
                title TEXT,
                category TEXT,
                description TEXT,
                thumbnail TEXT,
                profile_picture TEXT,
                status TEXT DEFAULT 'ended',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ended_at TIMESTAMP
            )
        `);


        console.log(
            "Canvas database initialization complete."
        );

    }catch(error){

        console.error(
            "Database initialization error:",
            error
        );

    }

}


/* =====================================================
   START DATABASE CHECK
===================================================== */

(async function(){

    await testDatabase();

    await initializeDatabase();

})();


/* =====================================================
   PART 1 ENDS HERE
===================================================== */
 /* =====================================================
    DATABASE TABLES
 ===================================================== */

async function ensureCanvasTables(){

    if(!DATABASE_URL){

        return;

    }

    try{

        /*
         * Profiles are kept separate from the existing
         * users/authentication system.
         */

        await pool.query(`
            CREATE TABLE IF NOT EXISTS profiles (
                user_id TEXT PRIMARY KEY,
                name TEXT DEFAULT '',
                username TEXT UNIQUE,
                bio TEXT DEFAULT '',
                profile_picture TEXT DEFAULT '',
                followers INTEGER DEFAULT 0,
                following INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);


        /*
         * Actual follow relationships.
         *
         * Follower/following numbers are calculated
         * from this table instead of blindly adding 1.
         */

        await pool.query(`
            CREATE TABLE IF NOT EXISTS user_follows (
                follower_id TEXT NOT NULL,
                following_id TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

                PRIMARY KEY (
                    follower_id,
                    following_id
                )
            )
        `);


        /*
         * Live / completed stream information.
         */

        await pool.query(`
            CREATE TABLE IF NOT EXISTS streams (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                title TEXT DEFAULT '',
                category TEXT DEFAULT 'Entertainment',
                description TEXT DEFAULT '',
                thumbnail TEXT DEFAULT '',
                profile_picture TEXT DEFAULT '',
                status TEXT DEFAULT 'live',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ended_at TIMESTAMP
            )
        `);


        /*
         * Older Canvas databases may already have the
         * streams table. Make sure newer fields exist.
         */

        const streamColumns = [

            [
                "category",
                "TEXT DEFAULT 'Entertainment'"
            ],

            [
                "description",
                "TEXT DEFAULT ''"
            ],

            [
                "thumbnail",
                "TEXT DEFAULT ''"
            ],

            [
                "profile_picture",
                "TEXT DEFAULT ''"
            ],

            [
                "status",
                "TEXT DEFAULT 'live'"
            ],

            [
                "created_at",
                "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
            ],

            [
                "ended_at",
                "TIMESTAMP"
            ]

        ];


        for(
            const [column,type]
            of streamColumns
        ){

            try{

                await pool.query(`
                    ALTER TABLE streams
                    ADD COLUMN IF NOT EXISTS
                    ${column}
                    ${type}
                `);

            }catch(error){

                console.warn(
                    `Could not add streams.${column}:`,
                    error.message
                );

            }

        }


        /*
         * Chat messages.
         */

        await pool.query(`
            CREATE TABLE IF NOT EXISTS stream_chat (
                id TEXT PRIMARY KEY,
                stream_id TEXT NOT NULL,
                user_id TEXT,
                username TEXT DEFAULT '',
                profile_picture TEXT DEFAULT '',
                message TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);


        /*
         * Stream gifts / support records.
         */

        await pool.query(`
            CREATE TABLE IF NOT EXISTS stream_gifts (
                id TEXT PRIMARY KEY,
                stream_id TEXT NOT NULL,
                sender_id TEXT,
                sender_username TEXT DEFAULT '',
                gift_type TEXT DEFAULT '',
                gift_name TEXT DEFAULT '',
                amount INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);


        console.log(
            "Canvas tables are ready."
        );

    }catch(error){

        console.error(
            "Canvas table setup error:",
            error
        );

    }

}


/* =====================================================
   START TABLE SETUP
 ===================================================== */

if(DATABASE_URL){

    ensureCanvasTables();

}


/* =====================================================
   CURRENT USER
 ===================================================== */

app.get(
    "/api/me",
    requireAuth,
    async (req,res) => {

        try{

            const user =
                req.user;


            let profile = null;


            try{

                const result =
                    await pool.query(
                        `
                        SELECT *
                        FROM profiles
                        WHERE
                            CAST(user_id AS TEXT)
                            =
                            CAST($1 AS TEXT)
                        LIMIT 1
                        `,
                        [user.id]
                    );


                if(
                    result.rows.length
                ){

                    profile =
                        result.rows[0];

                }

            }catch(profileError){

                console.warn(
                    "Profile lookup skipped:",
                    profileError.message
                );

            }
            res.json({

                success:true,

                user:{

                    id:
                        user.id,

                    name:
                        (
                            profile &&
                            profile.name
                        ) ||
                        user.name ||
                        "",

                    username:
                        (
                            profile &&
                            profile.username
                        ) ||
                        user.username ||
                        "",

                    email:
                        user.email || "",

                    bio:
                        (
                            profile &&
                            profile.bio
                        ) ||
                        user.bio ||
                        "",

                    profile_picture:
                        (
                            profile &&
                            profile.profile_picture
                        ) ||
                        user.profile_picture ||
                        user.profilePicture ||
                        user.photo ||
                        user.avatar ||
                        "",

                    followers:
                        Number(
                            (
                                profile &&
                                profile.followers
                            ) ||
                            user.followers ||
                            0
                        ),

                    following:
                        Number(
                            (
                                profile &&
                                profile.following
                            ) ||
                            user.following ||
                            0
                        )

                }

            });

        }catch(error){

            console.error(
                "GET /api/me error:",
                error
            );


            res.status(500).json({

                success:false,

                message:
                    "Could not load account."

            });

        }

    }
);


/* =====================================================
   PROFILE BY USER ID
 ===================================================== */

app.get(
    "/api/profile/:userId",
    optionalAuth,
    async (req,res) => {

        try{

            const userId =
                String(
                    req.params.userId || ""
                ).trim();


            if(!userId){

                return res.status(400).json({

                    success:false,

                    message:
                        "User ID is required."

                });

            }


            const result =
                await pool.query(
                    `
                    SELECT
                        p.*,
                        u.email
                    FROM profiles p
                    LEFT JOIN users u
                        ON CAST(u.id AS TEXT)
                        =
                        CAST(p.user_id AS TEXT)
                    WHERE
                        CAST(p.user_id AS TEXT)
                        =
                        CAST($1 AS TEXT)
                    LIMIT 1
                    `,
                    [userId]
                );


            if(
                !result.rows.length
            ){

                return res.status(404).json({

                    success:false,

                    message:
                        "Profile not found."

                });

            }


            const profile =
                result.rows[0];


            res.json({

                success:true,

                profile:{

                    id:
                        profile.user_id,

                    user_id:
                        profile.user_id,

                    name:
                        profile.name || "",

                    username:
                        profile.username || "",

                    bio:
                        profile.bio || "",

                    profile_picture:
                        profile.profile_picture || "",

                    followers:
                        Number(
                            profile.followers || 0
                        ),

                    following:
                        Number(
                            profile.following || 0
                        ),

                    email:
                        profile.email || ""

                }

            });

        }catch(error){

            console.error(
                "GET /api/profile/:userId error:",
                error
            );


            res.status(500).json({

                success:false,

                message:
                    "Could not load profile."

            });

        }

    }
);


/* =====================================================
   PROFILE LOOKUP BY USERNAME
 ===================================================== */

app.get(
    "/api/profile/username/:username",
    optionalAuth,
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


            const result =
                await pool.query(
                    `
                    SELECT
                        p.*,
                        u.email
                    FROM profiles p
                    LEFT JOIN users u
                        ON CAST(u.id AS TEXT)
                        =
                        CAST(p.user_id AS TEXT)
                    WHERE
                        LOWER(p.username)
                        =
                        LOWER($1)
                    LIMIT 1
                    `,
                    [username]
                );


            if(
                !result.rows.length
            ){

                return res.status(404).json({

                    success:false,

                    message:
                        "Profile not found."

                });

            }


            const profile =
                result.rows[0];


            res.json({

                success:true,

                profile:{

                    id:
                        profile.user_id,

                    user_id:
                        profile.user_id,

                    name:
                        profile.name || "",

                    username:
                        profile.username || "",

                    bio:
                        profile.bio || "",

                    profile_picture:
                        profile.profile_picture || "",

                    followers:
                        Number(
                            profile.followers || 0
                        ),

                    following:
                        Number(
                            profile.following || 0
                        ),

                    email:
                        profile.email || ""

                }

            });

        }catch(error){

            console.error(
                "Username profile error:",
                error
            );


            res.status(500).json({

                success:false,

                message:
                    "Could not find profile."

            });

        }

    }
);


/* =====================================================
   PART 2 ENDS HERE
 ===================================================== */
 /* =====================================================
   PROFILE CREATE / UPDATE
===================================================== */

app.put(
    "/api/profile",
    requireAuth,
    async (req,res) => {

        try{

            const userId =
                String(
                    req.user.id
                );


            const name =
                cleanText(
                    req.body.name,
                    100
                );


            const username =
                cleanUsername(
                    req.body.username
                );


            const bio =
                cleanText(
                    req.body.bio,
                    500
                );


            const profilePicture =
                cleanText(
                    req.body.profile_picture ||
                    req.body.profilePicture ||
                    req.body.photo ||
                    req.body.avatar ||
                    "",
                    50000000
                );


            if(!username){

                return res.status(400).json({

                    success:false,

                    message:
                        "Username is required."

                });

            }


            if(
                !/^[a-z0-9_.]{3,30}$/.test(
                    username
                )
            ){

                return res.status(400).json({

                    success:false,

                    message:
                        "Username must be 3-30 characters."

                });

            }


            /*
             * Check whether another account already
             * owns this username.
             */

            const usernameCheck =
                await pool.query(
                    `
                    SELECT user_id
                    FROM profiles
                    WHERE
                        LOWER(username)
                        =
                        LOWER($1)
                    AND
                        CAST(user_id AS TEXT)
                        !=
                        CAST($2 AS TEXT)
                    LIMIT 1
                    `,
                    [
                        username,
                        userId
                    ]
                );


            if(
                usernameCheck.rows.length
            ){

                return res.status(409).json({

                    success:false,

                    message:
                        "Username is already taken."

                });

            }


            /*
             * Preserve the real follower/following
             * counts instead of resetting them.
             */

            const existing =
                await pool.query(
                    `
                    SELECT
                        followers,
                        following
                    FROM profiles
                    WHERE
                        CAST(user_id AS TEXT)
                        =
                        CAST($1 AS TEXT)
                    LIMIT 1
                    `,
                    [userId]
                );


            let followers = 0;
            let following = 0;


            if(
                existing.rows.length
            ){

                followers =
                    Number(
                        existing.rows[0]
                            .followers || 0
                    );

                following =
                    Number(
                        existing.rows[0]
                            .following || 0
                    );

            }


            const result =
                await pool.query(
                    `
                    INSERT INTO profiles (
                        user_id,
                        name,
                        username,
                        bio,
                        profile_picture,
                        followers,
                        following,
                        updated_at
                    )
                    VALUES (
                        $1,
                        $2,
                        $3,
                        $4,
                        $5,
                        $6,
                        $7,
                        CURRENT_TIMESTAMP
                    )

                    ON CONFLICT (
                        user_id
                    )

                    DO UPDATE SET

                        name =
                            EXCLUDED.name,

                        username =
                            EXCLUDED.username,

                        bio =
                            EXCLUDED.bio,

                        profile_picture =
                            EXCLUDED.profile_picture,

                        updated_at =
                            CURRENT_TIMESTAMP

                    RETURNING *
                    `,
                    [
                        userId,
                        name,
                        username,
                        bio,
                        profilePicture,
                        followers,
                        following
                    ]
                );


            res.json({

                success:true,

                message:
                    "Profile saved successfully.",

                profile:
                    result.rows[0]

            });

        }catch(error){

            console.error(
                "PUT /api/profile error:",
                error
            );


            res.status(500).json({

                success:false,

                message:
                    "Could not save profile."

            });

        }

    }
);


/* =====================================================
   DELETE PROFILE PICTURE
===================================================== */

app.delete(
    "/api/profile/picture",
    requireAuth,
    async (req,res) => {

        try{

            const result =
                await pool.query(
                    `
                    UPDATE profiles
                    SET
                        profile_picture = '',
                        updated_at =
                            CURRENT_TIMESTAMP
                    WHERE
                        CAST(user_id AS TEXT)
                        =
                        CAST($1 AS TEXT)
                    RETURNING *
                    `,
                    [req.user.id]
                );


            if(
                !result.rows.length
            ){

                return res.status(404).json({

                    success:false,

                    message:
                        "Profile not found."

                });

            }


            res.json({

                success:true,

                message:
                    "Profile picture deleted.",

                profile:
                    result.rows[0]

            });

        }catch(error){

            console.error(
                "Delete profile picture error:",
                error
            );


            res.status(500).json({

                success:false,

                message:
                    "Could not delete profile picture."

            });

        }

    }
);


/* =====================================================
   SEARCH USERS
===================================================== */

app.get(
    "/api/users/search",
    optionalAuth,
    async (req,res) => {

        try{

            const query =
                cleanText(
                    req.query.q,
                    50
                );


            if(!query){

                return res.json({

                    success:true,

                    users:[]

                });

            }


            const search =
                `%${query.toLowerCase()}%`;


            const result =
                await pool.query(
                    `
                    SELECT
                        p.user_id,
                        p.name,
                        p.username,
                        p.bio,
                        p.profile_picture,
                        p.followers,
                        p.following
                    FROM profiles p
                    WHERE
                        LOWER(p.username)
                        LIKE $1
                    OR
                        LOWER(p.name)
                        LIKE $1
                    ORDER BY
                        CASE
                            WHEN
                                LOWER(p.username)
                                =
                                LOWER($2)
                            THEN 0
                            ELSE 1
                        END,
                        p.username ASC
                    LIMIT 30
                    `,
                    [
                        search,
                        query
                    ]
                );


            res.json({

                success:true,

                users:
                    result.rows.map(
                        user => ({

                            id:
                                user.user_id,

                            user_id:
                                user.user_id,

                            name:
                                user.name || "",

                            username:
                                user.username || "",

                            bio:
                                user.bio || "",

                            profile_picture:
                                user.profile_picture ||
                                "",

                            followers:
                                Number(
                                    user.followers || 0
                                ),

                            following:
                                Number(
                                    user.following || 0
                                )

                        })
                    )

            });

        }catch(error){

            console.error(
                "User search error:",
                error
            );


            res.status(500).json({

                success:false,

                message:
                    "Could not search users."

            });

        }

    }
);


/* =====================================================
   FOLLOW USER
===================================================== */

app.post(
    "/api/users/:userId/follow",
    requireAuth,
    async (req,res) => {

        try{

            const targetId =
                String(
                    req.params.userId || ""
                ).trim();


            if(!targetId){

                return res.status(400).json({

                    success:false,

                    message:
                        "User ID is required."

                });

            }


            if(
                String(req.user.id)
                ===
                targetId
            ){

                return res.status(400).json({

                    success:false,

                    message:
                        "You cannot follow yourself."

                });

            }


            const target =
                await pool.query(
                    `
                    SELECT user_id
                    FROM profiles
                    WHERE
                        CAST(user_id AS TEXT)
                        =
                        CAST($1 AS TEXT)
                    LIMIT 1
                    `,
                    [targetId]
                );


            if(
                !target.rows.length
            ){

                return res.status(404).json({

                    success:false,

                    message:
                        "User not found."

                });

            }


            await pool.query(
                `
                INSERT INTO user_follows (
                    follower_id,
                    following_id
                )
                VALUES ($1,$2)
                ON CONFLICT DO NOTHING
                `,
                [
                    req.user.id,
                    targetId
                ]
            );


            const targetCounts =
                await pool.query(
                    `
                    SELECT
                        COUNT(*) AS followers
                    FROM user_follows
                    WHERE
                        following_id
                        =
                        CAST($1 AS TEXT)
                    `,
                    [targetId]
                );


            const myCounts =
                await pool.query(
                    `
                    SELECT
                        COUNT(*) AS following
                    FROM user_follows
                    WHERE
                        follower_id
                        =
                        CAST($1 AS TEXT)
                    `,
                    [req.user.id]
                );


            const followers =
                Number(
                    targetCounts.rows[0]
                        .followers || 0
                );


            const following =
                Number(
                    myCounts.rows[0]
                        .following || 0
                );


            await pool.query(
                `
                UPDATE profiles
                SET
                    followers = $2,
                    updated_at =
                        CURRENT_TIMESTAMP
                WHERE
                    CAST(user_id AS TEXT)
                    =
                    CAST($1 AS TEXT)
                `,
                [
                    targetId,
                    followers
                ]
            );


            await pool.query(
                `
                UPDATE profiles
                SET
                    following = $2,
                    updated_at =
                        CURRENT_TIMESTAMP
                WHERE
                    CAST(user_id AS TEXT)
                    =
                    CAST($1 AS TEXT)
                `,
                [
                    req.user.id,
                    following
                ]
            );


            res.json({

                success:true,

                following:true,

                followers:

                    followers,

                followingCount:

                    following

            });

        }catch(error){

            console.error(
                "Follow user error:",
                error
            );


            res.status(500).json({

                success:false,

                message:
                    "Could not follow user."

            });

        }

    }
);


/* =====================================================
   UNFOLLOW USER
===================================================== */

app.delete(
    "/api/users/:userId/follow",
    requireAuth,
    async (req,res) => {

        try{

            const targetId =
                String(
                    req.params.userId || ""
                ).trim();


            if(!targetId){

                return res.status(400).json({

                    success:false,

                    message:
                        "User ID is required."

                });

            }


            await pool.query(
                `
                DELETE FROM user_follows
                WHERE
                    follower_id
                    =
                    CAST($1 AS TEXT)
                AND
                    following_id
                    =
                    CAST($2 AS TEXT)
                `,
                [
                    req.user.id,
                    targetId
                ]
            );


            const targetCounts =
                await pool.query(
                    `
                    SELECT
                        COUNT(*) AS followers
                    FROM user_follows
                    WHERE
                        following_id
                        =
                        CAST($1 AS TEXT)
                    `,
                    [targetId]
                );


            const myCounts =
                await pool.query(
                    `
                    SELECT
                        COUNT(*) AS following
                    FROM user_follows
                    WHERE
                        follower_id
                        =
                        CAST($1 AS TEXT)
                    `,
                    [req.user.id]
                );


            const followers =
                Number(
                    targetCounts.rows[0]
                        .followers || 0
                );


            const following =
                Number(
                    myCounts.rows[0]
                        .following || 0
                );


            await pool.query(
                `
                UPDATE profiles
                SET
                    followers = $2,
                    updated_at =
                        CURRENT_TIMESTAMP
                WHERE
                    CAST(user_id AS TEXT)
                    =
                    CAST($1 AS TEXT)
                `,
                [
                    targetId,
                    followers
                ]
            );


            await pool.query(
                `
                UPDATE profiles
                SET
                    following = $2,
                    updated_at =
                        CURRENT_TIMESTAMP
                WHERE
                    CAST(user_id AS TEXT)
                    =
                    CAST($1 AS TEXT)
                `,
                [
                    req.user.id,
                    following
                ]
            );


            res.json({

                success:true,

                following:false,

                followers:

                    followers,

                followingCount:

                    following

            });

        }catch(error){

            console.error(
                "Unfollow user error:",
                error
            );


            res.status(500).json({

                success:false,

                message:
                    "Could not unfollow user."

            });

        }

    }
);


/* =====================================================
   FOLLOW STATUS
===================================================== */

app.get(
    "/api/users/:userId/follow-status",
    requireAuth,
    async (req,res) => {

        try{

            const targetId =
                String(
                    req.params.userId || ""
                ).trim();


            const result =
                await pool.query(
                    `
                    SELECT 1
                    FROM user_follows
                    WHERE
                        follower_id
                        =
                        CAST($1 AS TEXT)
                    AND
                        following_id
                        =
                        CAST($2 AS TEXT)
                    LIMIT 1
                    `,
                    [
                        req.user.id,
                        targetId
                    ]
                );


            res.json({

                success:true,

                following:
                    result.rows.length > 0

            });

        }catch(error){

            console.error(
                "Follow status error:",
                error
            );


            res.status(500).json({

                success:false,

              message:
                    "Could not check follow status."

            });

        }

    }
);


/* =====================================================
   PROFILE COUNTS
===================================================== */

app.get(
    "/api/users/:userId/counts",
    async (req,res) => {

        try{

            const userId =
                String(
                    req.params.userId || ""
                ).trim();


            const result =
                await pool.query(
                    `
                    SELECT

                        (
                            SELECT COUNT(*)
                            FROM user_follows
                            WHERE
                                following_id
                                =
                                CAST($1 AS TEXT)
                        ) AS followers,

                        (
                            SELECT COUNT(*)
                            FROM user_follows
                            WHERE
                                follower_id
                                =
                                CAST($1 AS TEXT)
                        ) AS following
                    `,
                    [userId]
                );


            res.json({

                success:true,

                followers:
                    Number(
                        result.rows[0]
                            .followers || 0
                    ),

                following:
                    Number(
                        result.rows[0]
                            .following || 0
                    )

            });

        }catch(error){

            console.error(
                "Profile counts error:",
                error
            );


            res.status(500).json({

                success:false,

                message:
                    "Could not load profile counts."

            });

        }

    }
);


/* =====================================================
   PART 3 ENDS HERE
===================================================== 
/* =====================================================
   STREAM HELPERS
===================================================== */

function normalizeStreamStatus(
    status
){

    const value =
        String(
            status || ""
        )
        .trim()
        .toLowerCase();


    if(
        value === "ended" ||
        value === "completed" ||
        value === "finished"
    ){

        return "ended";

    }


    return "live";

}


function normalizeStream(
    row
){

    if(!row){

        return null;

    }


    return {

        id:
            row.id,

        streamId:
            row.id,

        user_id:
            row.user_id,

        userId:
            row.user_id,

        title:
            row.title || "",

        category:
            row.category ||
            "Entertainment",

        description:
            row.description || "",

        thumbnail:
            row.thumbnail || "",

        profilePicture:
            row.profile_picture || "",

        profile_picture:
            row.profile_picture || "",

        status:
            normalizeStreamStatus(
                row.status
            ),

        isLive:
            normalizeStreamStatus(
                row.status
            ) === "live",

        createdAt:
            row.created_at,

        endedAt:
            row.ended_at || null

    };

}


/* =====================================================
   GET LIVE STREAMS
===================================================== */

app.get(
    "/api/streams/live",
    optionalAuth,
    async (req,res) => {

        try{

            const result =
                await pool.query(
                    `
                    SELECT
                        s.*,
                        p.name,
                        p.username,
                        p.profile_picture AS
                            current_profile_picture
                    FROM streams s
                    LEFT JOIN profiles p
                        ON CAST(p.user_id AS TEXT)
                        =
                        CAST(s.user_id AS TEXT)
                    WHERE
                        LOWER(
                            COALESCE(
                                s.status,
                                'live'
                            )
                        )
                        =
                        'live'
                    ORDER BY
                        s.created_at DESC
                    `
                );


            const streams =
                result.rows.map(
                    row => {

                        const stream =
                            normalizeStream(
                                row
                            );


                        if(
                            !stream.profilePicture
                        ){

                            stream.profilePicture =
                                row.current_profile_picture ||
                                "";

                            stream.profile_picture =
                                stream.profilePicture;

                        }


                        stream.streamer = {

                            name:
                                row.name ||
                                "",

                            username:
                                row.username ||
                                "",

                            profilePicture:
                                stream.profilePicture

                        };


                        return stream;

                    }
                );


            res.json({

                success:true,

                streams:streams,

                count:
                    streams.length

            });

        }catch(error){

            console.error(
                "GET live streams error:",
                error
            );


            res.status(500).json({

                success:false,

                message:
                    "Could not load live streams.",

                streams:[]

            });

        }

    }
);


/* =====================================================
   GET ALL STREAMS
===================================================== */

app.get(
    "/api/streams",
    optionalAuth,
    async (req,res) => {

        try{

            const status =
                String(
                    req.query.status || ""
                )
                .trim()
                .toLowerCase();


            let result;


            if(
                status === "live"
            ){

                result =
                    await pool.query(
                        `
                        SELECT
                            s.*,
                            p.name,
                            p.username,
                            p.profile_picture
                                AS current_profile_picture
                        FROM streams s
                        LEFT JOIN profiles p
                            ON CAST(p.user_id AS TEXT)
                            =
                            CAST(s.user_id AS TEXT)
                        WHERE
                            LOWER(
                                COALESCE(
                                    s.status,
                                    'live'
                                )
                            )
                            =
                            'live'
                        ORDER BY
                            s.created_at DESC
                        `
                    );

            }else if(
                status === "ended" ||
                status === "completed"
            ){

                result =
                    await pool.query(
                        `
                        SELECT
                            s.*,
                            p.name,
                            p.username,
                            p.profile_picture
                                AS current_profile_picture
                        FROM streams s
                        LEFT JOIN profiles p
                            ON CAST(p.user_id AS TEXT)
                            =
                            CAST(s.user_id AS TEXT)
                        WHERE
                            LOWER(
                                COALESCE(
                                    s.status,
                                    'ended'
                                )
                            )
                            IN (
                                'ended',
                                'completed'
                            )
                        ORDER BY
                            s.ended_at DESC NULLS LAST,
                            s.created_at DESC
                        `
                    );

            }else{

                result =
                    await pool.query(
                        `
                        SELECT
                            s.*,
                            p.name,
                            p.username,
                            p.profile_picture
                                AS current_profile_picture
                        FROM streams s
                        LEFT JOIN profiles p
                            ON CAST(p.user_id AS TEXT)
                            =
                            CAST(s.user_id AS TEXT)
                        ORDER BY
                            s.created_at DESC
                        `
                    );

            }


            const streams =
                result.rows.map(
                    row => {

                        const stream =
                            normalizeStream(
                                row
                            );


                        if(
                            !stream.profilePicture
                        ){

                            stream.profilePicture =
                                row.current_profile_picture ||
                                "";

                            stream.profile_picture =
                                stream.profilePicture;

                        }


                        stream.streamer = {

                            name:
                                row.name ||
                                "",

                            username:
                                row.username ||
                                "",

                            profilePicture:
                                stream.profilePicture

                        };


                        return stream;

                    }
                );


            res.json({

                success:true,

                streams:streams,

                count:
                    streams.length

            });

        }catch(error){

            console.error(
                "GET /api/streams error:",
                error
            );


            res.status(500).json({

                success:false,

                message:
                    "Could not load streams.",

                streams:[]

            });

        }

    }
);


/* =====================================================
   GET MY STREAMS
===================================================== */

app.get(
    "/api/streams/my",
    requireAuth,
    async (req,res) => {

        try{

            const result =
                await pool.query(
                    `
                    SELECT
                        s.*,
                        p.name,
                        p.username,
                        p.profile_picture
                            AS current_profile_picture
                    FROM streams s
                    LEFT JOIN profiles p
                        ON CAST(p.user_id AS TEXT)
                        =
                        CAST(s.user_id AS TEXT)
                WHERE
                        CAST(s.user_id AS TEXT)
                        =
                        CAST($1 AS TEXT)
                    ORDER BY
                        s.created_at DESC
                    `,
                    [req.user.id]
                );


            const streams =
                result.rows.map(
                    row => {

                        const stream =
                            normalizeStream(
                                row
                            );


                        if(
                            !stream.profilePicture
                        ){

                            stream.profilePicture =
                                row.current_profile_picture ||
                                "";

                            stream.profile_picture =
                                stream.profilePicture;

                        }


                        stream.streamer = {

                            name:
                                row.name ||
                                "",

                            username:
                                row.username ||
                                "",

                            profilePicture:
                                stream.profilePicture

                        };


                        return stream;

                    }
                );


            res.json({

                success:true,

                streams:streams

            });

        }catch(error){

            console.error(
                "GET my streams error:",
                error
            );


            res.status(500).json({

                success:false,

                message:
                    "Could not load your streams.",

                streams:[]

            });

        }

    }
);


/* =====================================================
   GET SINGLE STREAM
===================================================== */

app.get(
    "/api/streams/:id",
    optionalAuth,
    async (req,res) => {

        try{

            const streamId =
                String(
                    req.params.id || ""
                ).trim();


            if(!streamId){

                return res.status(400).json({

                    success:false,

                    message:
                        "Stream ID is required."

                });

            }


            const result =
                await pool.query(
                    `
                    SELECT
                        s.*,
                        p.name,
                        p.username,
                        p.profile_picture
                            AS current_profile_picture
                    FROM streams s
                    LEFT JOIN profiles p
                        ON CAST(p.user_id AS TEXT)
                        =
                        CAST(s.user_id AS TEXT)
                    WHERE
                        s.id = $1
                    LIMIT 1
                    `,
                    [streamId]
                );


            if(
                !result.rows.length
            ){

                return res.status(404).json({

                    success:false,

                    message:
                        "Stream not found."

                });

            }


            const row =
                result.rows[0];


            const stream =
                normalizeStream(
                    row
                );


            if(
                !stream.profilePicture
            ){

                stream.profilePicture =
                    row.current_profile_picture ||
                    "";

                stream.profile_picture =
                    stream.profilePicture;

            }


            stream.streamer = {

                name:
                    row.name || "",

                username:
                    row.username || "",

                profilePicture:
                    stream.profilePicture

            };


            res.json({

                success:true,

                stream:stream

            });

        }catch(error){

            console.error(
                "GET single stream error:",
                error
            );


            res.status(500).json({

                success:false,

                message:
                    "Could not load stream."

            });

        }

    }
);


/* =====================================================
   CREATE STREAM
===================================================== */

app.post(
    "/api/streams",
    requireAuth,
    async (req,res) => {

        try{

            const streamId =
                cleanText(
                    req.body.streamId ||
                    req.body.id ||
                    makeId(),
                    200
                );


            const title =
                cleanText(
                    req.body.title,
                    200
                );


            const category =
                cleanText(
                    req.body.category ||
                    "Entertainment",
                    100
                );


            const description =
                cleanText(
                    req.body.description,
                    1000
                );


            const thumbnail =
                cleanText(
                    req.body.thumbnail ||
                    "",
                    50000000
                );


            let profilePicture =
                cleanText(
                    req.body.profilePicture ||
                    req.body.profile_picture ||
                    "",
                    50000000
                );


            const requestedStreamer =
                cleanText(
                    req.body.streamer,
                    200
                );


            /*
             * The authenticated profile remains the
             * source of truth for profile information.
             */

            try{

                const profile =
                    await pool.query(
                        `
                        SELECT
                            name,
                            username,
                            profile_picture
                        FROM profiles
                        WHERE
                            CAST(user_id AS TEXT)
                            =
                            CAST($1 AS TEXT)
                        LIMIT 1
                        `,
                        [req.user.id]
                    );


                if(
                    profile.rows.length
                ){

                    if(
                        !profilePicture
                    ){

                        profilePicture =
                            profile.rows[0]
                                .profile_picture ||
                            "";

                    }

                }

            }catch(profileError){

                console.warn(
                    "Could not load stream profile:",
                    profileError.message
                );

            }


            const existing =
                await pool.query(
                    `
                    SELECT id
                    FROM streams
                    WHERE
                        id = $1
                    LIMIT 1
                    `,
                    [streamId]
                );


            if(
                existing.rows.length
            ){

                return res.status(409).json({

                    success:false,

                    message:
                        "Stream ID already exists."

                });

            }


            const result =
                await pool.query(
                    `
                    INSERT INTO streams (
                        id,
                        user_id,
                        title,
                        category,
                        description,
                        thumbnail,
                        profile_picture,
                        status,
                        created_at,
                        ended_at
                    )
                    VALUES (
                        $1,
                        $2,
                        $3,
                        $4,
                        $5,
                        $6,
                        $7,
                        'live',
                        CURRENT_TIMESTAMP,
                        NULL
                    )
                    RETURNING *
                    `,
                    [
                        streamId,
                        req.user.id,
                        title,
                        category,
                        description,
                        thumbnail,
                        profilePicture
                    ]
                );


            const stream =
                normalizeStream(
                    result.rows[0]
                );


            stream.streamer =
                requestedStreamer ||
                req.user.username ||
                "";


            io.emit(
                "stream-started",
                stream
            );


            res.status(201).json({

                success:true,

                message:
                    "Stream started.",

                stream:stream

            });

        }catch(error){

            console.error(
                "POST /api/streams error:",
                error
            );


            res.status(500).json({

                success:false,

                message:
                    "Could not start stream."

            });

        }

    }
);


/* =====================================================
   PART 4 ENDS HERE
===================================================== */
/* =====================================================
   END STREAM
===================================================== */

app.put(
    "/api/streams/:id/end",
    requireAuth,
    async (req,res) => {

        try{

            const streamId =
                String(
                    req.params.id || ""
                ).trim();


            if(!streamId){

                return res.status(400).json({

                    success:false,

                    message:
                        "Stream ID is required."

                });

            }


            const existing =
                await pool.query(
                    `
                    SELECT *
                    FROM streams
                    WHERE
                        id = $1
                    AND
                        CAST(user_id AS TEXT)
                        =
                        CAST($2 AS TEXT)
                    LIMIT 1
                    `,
                    [
                        streamId,
                        req.user.id
                    ]
                );


            if(
                !existing.rows.length
            ){

                return res.status(404).json({

                    success:false,

                    message:
                        "Stream not found."

                });

            }


            /*
             * IMPORTANT:
             * Ending a stream does NOT delete it.
             *
             * This keeps completed streams available
             * for Canvas history / recorded content.
             */

            const result =
                await pool.query(
                    `
                    UPDATE streams
                    SET
                        status = 'ended',
                        ended_at =
                            CURRENT_TIMESTAMP
                    WHERE
                        id = $1
                    AND
                        CAST(user_id AS TEXT)
                        =
                        CAST($2 AS TEXT)
                    RETURNING *
                    `,
                    [
                        streamId,
                        req.user.id
                    ]
                );


            const stream =
                normalizeStream(
                    result.rows[0]
                );


            /*
             * Save a completed-stream record as well.
             * The actual stream row remains available.
             */

            try{

                await pool.query(
                    `
                    INSERT INTO stream_recordings (
                        id,
                        stream_id,
                        user_id,
                        title,
                        category,
                        description,
                        thumbnail,
                        profile_picture,
                        status,
                        created_at,
                        ended_at
                    )
                    VALUES (
                        $1,
                        $2,
                        $3,
                        $4,
                        $5,
                        $6,
                        $7,
                        $8,
                        'ended',
                        $9,
                        $10
                    )
                    ON CONFLICT (id)
                    DO UPDATE SET
                        status = 'ended',
                        ended_at = EXCLUDED.ended_at,
                        thumbnail = EXCLUDED.thumbnail,
                        profile_picture =
                            EXCLUDED.profile_picture
                    `,
                    [
                        makeId(),
                        stream.id,
                        stream.user_id,
                        stream.title,
                        stream.category,
                        stream.description,
                        stream.thumbnail,
                        stream.profilePicture,
                        stream.createdAt,
                        stream.endedAt
                    ]
                );

            }catch(recordingError){

                console.warn(
                    "Recording archive warning:",
                    recordingError.message
                );

            }


            io.to(streamId).emit(
                "stream-ended",
                {
                    streamId:streamId,
                    stream:stream
                }
            );


            io.emit(
                "stream-ended",
                {
                    streamId:streamId,
                    stream:stream
                }
            );


            res.json({

                success:true,

                message:
                    "Stream ended.",

                stream:stream

            });

        }catch(error){

            console.error(
                "PUT /api/streams/:id/end error:",
                error
            );


            res.status(500).json({

                success:false,

                message:
                    "Could not end stream."

            });

        }

    }
);


/* =====================================================
   DELETE STREAM
===================================================== */

app.delete(
    "/api/streams/:id",
    requireAuth,
    async (req,res) => {

        try{

            const streamId =
                String(
                    req.params.id || ""
                ).trim();


            const result =
                await pool.query(
                    `
                    DELETE FROM streams
                    WHERE
                        id = $1
                    AND
                        CAST(user_id AS TEXT)
                        =
                        CAST($2 AS TEXT)
                    RETURNING *
                    `,
                    [
                        streamId,
                        req.user.id
                    ]
                );


            if(
                !result.rows.length
            ){

                return res.status(404).json({

                    success:false,

                    message:
                        "Stream not found."

                });

            }


            io.emit(
                "stream-deleted",
                {
                    streamId:streamId
                }
            );


            res.json({

                success:true,

                message:
                    "Stream deleted."

            });

        }catch(error){

            console.error(
                "DELETE stream error:",
                error
            );


            res.status(500).json({

                success:false,

                message:
                    "Could not delete stream."

            });

        }

    }
);


/* =====================================================
   STREAM HEARTBEAT
===================================================== */

app.post(
    "/api/streams/:id/heartbeat",
    requireAuth,
    async (req,res) => {

        try{

            const streamId =
                String(
                    req.params.id || ""
                ).trim();


            const result =
                await pool.query(
                    `
                    SELECT id
                    FROM streams
                    WHERE
                        id = $1
                    AND
                        CAST(user_id AS TEXT)
                        =
                        CAST($2 AS TEXT)
                    AND
                        LOWER(
                            COALESCE(
                                status,
                                'live'
                            )
                        )
                        =
                        'live'
                    LIMIT 1
                    `,
                    [
                        streamId,
                        req.user.id
                    ]
                );


            if(
                !result.rows.length
            ){

                return res.status(404).json({

                    success:false,

                    message:
                        "Live stream not found."

                });

            }


            /*
             * We intentionally do not end the stream
             * when a heartbeat is missed.
             *
             * The frontend controls the real End
             * Streaming action.
             */

            res.json({

                success:true,

                streamId:streamId,

                status:"live",

                timestamp:
                    new Date().toISOString()

            });

        }catch(error){

            console.error(
                "Heartbeat error:",
                error
            );


            res.status(500).json({

                success:false,

                message:
                    "Heartbeat failed."

            });

        }

    }
);


/* =====================================================
   RECORDING / COMPLETED STREAMS
===================================================== */

app.get(
    "/api/streams/recordings",
    optionalAuth,
    async (req,res) => {

        try{

            const result =
                await pool.query(
                    `
                    SELECT
                        s.*,
                        p.name,
                        p.username,
                        p.profile_picture
                            AS current_profile_picture
                    FROM streams s
                    LEFT JOIN profiles p
                        ON CAST(p.user_id AS TEXT)
                        =
                        CAST(s.user_id AS TEXT)
                    WHERE
                        LOWER(
                            COALESCE(
                            .status,
                                ''
                            )
                        )
                        IN (
                            'ended',
                            'completed'
                        )
                    ORDER BY
                        s.ended_at DESC NULLS LAST,
                        s.created_at DESC
                    `
                );


            const streams =
                result.rows.map(
                    row => {

                        const stream =
                            normalizeStream(
                                row
                            );


                        if(
                            !stream.profilePicture
                        ){

                            stream.profilePicture =
                                row.current_profile_picture ||
                                "";

                            stream.profile_picture =
                                stream.profilePicture;

                        }


                        stream.streamer = {

                            name:
                                row.name || "",

                            username:
                                row.username || "",

                            profilePicture:
                                stream.profilePicture

                        };


                        return stream;

                    }
                );


            res.json({

                success:true,

                streams:streams,

                count:
                    streams.length

            });

        }catch(error){

            console.error(
                "Recording list error:",
                error
            );


            res.status(500).json({

                success:false,

                message:
                    "Could not load recordings.",

                streams:[]

            });

        }

    }
);


/* =====================================================
   GET STREAM CHAT HISTORY
===================================================== */

app.get(
    "/api/streams/:id/chat",
    async (req,res) => {

        try{

            const streamId =
                String(
                    req.params.id || ""
                ).trim();


            const result =
                await pool.query(
                    `
                    SELECT
                        id,
                        stream_id,
                        user_id,
                        username,
                        profile_picture,
                        message,
                        created_at
                    FROM stream_chat
                    WHERE
                        stream_id = $1
                    ORDER BY
                        created_at ASC
                    LIMIT 200
                    `,
                    [streamId]
                );


            res.json({

                success:true,

                messages:
                    result.rows.map(
                        row => ({

                            id:
                                row.id,

                            streamId:
                                row.stream_id,

                            userId:
                                row.user_id,

                            username:
                                row.username || "",

                            profilePicture:
                                row.profile_picture || "",

                            message:
                                row.message || "",

                            createdAt:
                                row.created_at

                        })
                    )

            });

        }catch(error){

            console.error(
                "Chat history error:",
                error
            );


            res.status(500).json({

                success:false,

                message:
                    "Could not load chat.",

                messages:[]

            });

        }

    }
);


/* =====================================================
   SEND CHAT MESSAGE THROUGH API
===================================================== */

app.post(
    "/api/streams/:id/chat",
    requireAuth,
    async (req,res) => {

        try{

            const streamId =
                String(
                    req.params.id || ""
                ).trim();


            const message =
                cleanText(
                    req.body.message,
                    500
                );


            if(!message){

                return res.status(400).json({

                    success:false,

                    message:
                        "Message cannot be empty."

                });

            }


            const stream =
                await pool.query(
                    `
                    SELECT id
                    FROM streams
                    WHERE
                        id = $1
                    LIMIT 1
                    `,
                    [streamId]
                );


            if(
                !stream.rows.length
            ){

                return res.status(404).json({

                    success:false,

                    message:
                        "Stream not found."

                });

            }


            let profilePicture = "";


            try{

                const profile =
                    await pool.query(
                        `
                        SELECT
                            username,
                            profile_picture
                        FROM profiles
                        WHERE
                            CAST(user_id AS TEXT)
                            =
                            CAST($1 AS TEXT)
                        LIMIT 1
                        `,
                        [req.user.id]
                    );


                if(
                    profile.rows.length
                ){

                    profilePicture =
                        profile.rows[0]
                            .profile_picture ||
                        "";

                }

            }catch(profileError){

                console.warn(
                    "Chat profile lookup warning:",
                    profileError.message
                );

            }


            const username =
                req.user.username ||
                "";


            const chatId =
                makeId();


            const result =
                await pool.query(
                    `
                    INSERT INTO stream_chat (
                        id,
                        stream_id,
                        user_id,
                        username,
                        profile_picture,
                        message
                    )
                    VALUES (
                        $1,
                        $2,
                        $3,
                        $4,
                        $5,
                        $6
                    )
                    RETURNING *
                    `,
                    [
                        chatId,
                        streamId,
                        req.user.id,
                        username,
                        profilePicture,
                        message
                    ]
                );


            const chatMessage = {

                id:
                    result.rows[0].id,

                streamId:
                    streamId,

                userId:
                    req.user.id,

                username:
                    result.rows[0].username ||
                    "",

                profilePicture:
                    result.rows[0].profile_picture ||
                    "",

                message:
                    result.rows[0].message,

                createdAt:
                    result.rows[0].created_at

            };


            io.to(streamId).emit(
                "chat-message",
                chatMessage
            );


            res.status(201).json({

                success:true,

                message:
                    chatMessage

            });

        }catch(error){

            console.error(
                "Send chat error:",
                error
            );


            res.status(500).json({

                success:false,

                message:
                    "Could not send chat message."

            });

        }

    }
);


/* =====================================================
   PART 5 ENDS HERE
===================================================== */
/* =====================================================
   STREAM GIFTS / SUPPORT
===================================================== */

app.get(
    "/api/streams/:id/gifts",
    async (req,res) => {

        try{

            const streamId =
                String(
                    req.params.id || ""
                ).trim();


            const result =
                await pool.query(
                    `
                    SELECT
                        id,
                        stream_id,
                        sender_id,
                        sender_username,
                        gift_type,
                        gift_name,
                        amount,
                        created_at
                    FROM stream_gifts
                    WHERE
                        stream_id = $1
                    ORDER BY
                        created_at DESC
                    LIMIT 100
                    `,
                    [streamId]
                );


            res.json({

                success:true,

                gifts:
                    result.rows.map(
                        row => ({

                            id:
                                row.id,

                            streamId:
                                row.stream_id,

                            senderId:
                                row.sender_id,

                            senderUsername:
                                row.sender_username || "",

                            giftType:
                                row.gift_type || "",

                            giftName:
                                row.gift_name || "",

                            amount:
                                Number(
                                    row.amount || 1
                                ),

                            createdAt:
                                row.created_at

                        })
                    )

            });

        }catch(error){

            console.error(
                "Get gifts error:",
                error
            );


            res.status(500).json({

                success:false,

                message:
                    "Could not load gifts.",

                gifts:[]

            });

        }

    }
);


/* =====================================================
   SEND GIFT / SUPPORT
===================================================== */

app.post(
    "/api/streams/:id/gifts",
    requireAuth,
    async (req,res) => {

        try{

            const streamId =
                String(
                    req.params.id || ""
                ).trim();


            const giftType =
                cleanText(
                    req.body.giftType ||
                    req.body.type ||
                    "",
                    50
                );


            const giftName =
                cleanText(
                    req.body.giftName ||
                    req.body.name ||
                    giftType ||
                    "Gift",
                    100
                );


            let amount =
                Number(
                    req.body.amount || 1
                );


            if(
                !Number.isFinite(amount) ||
                amount < 1
            ){

                amount = 1;

            }


            amount =
                Math.floor(amount);


            const stream =
                await pool.query(
                    `
                    SELECT
                        id,
                        status
                    FROM streams
                    WHERE
                        id = $1
                    LIMIT 1
                    `,
                    [streamId]
                );


            if(
                !stream.rows.length
            ){

                return res.status(404).json({

                    success:false,

                    message:
                        "Stream not found."

                });

            }


            const giftId =
                makeId();


            const username =
                req.user.username ||
                "";


            const result =
                await pool.query(
                    `
                    INSERT INTO stream_gifts (
                        id,
                        stream_id,
                        sender_id,
                        sender_username,
                        gift_type,
                        gift_name,
                        amount
                    )
                    VALUES (
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
                        giftId,
                        streamId,
                        req.user.id,
                        username,
                        giftType,
                        giftName,
                        amount
                    ]
                );


            const gift = {

                id:
                    result.rows[0].id,

                streamId:
                    streamId,

                senderId:
                    req.user.id,

                senderUsername:
                    result.rows[0]
                        .sender_username || "",

                giftType:
                    result.rows[0]
                        .gift_type || "",

                giftName:
                    result.rows[0]
                        .gift_name || "",

                amount:
                    Number(
                        result.rows[0]
                            .amount || 1
                    ),

                createdAt:
                    result.rows[0].created_at

            };


            io.to(streamId).emit(
                "gift-received",
                gift
            );


            res.status(201).json({

                success:true,

                gift:gift

            });

        }catch(error){

            console.error(
                "Send gift error:",
                error
            );


            res.status(500).json({

                success:false,

                message:
                    "Could not send gift."

            });

        }

    }
);


/* =====================================================
   SOCKET.IO CONNECTION
===================================================== */

io.on(
    "connection",
    (socket) => {

        console.log(
            "Canvas socket connected:",
            socket.id
        );


        /* =============================================
           JOIN STREAM ROOM
        ============================================= */

        socket.on(
            "join-stream",
            async (data) => {

                try{

                    const streamId =
                        typeof data === "string"
                            ? data
                            : data &&
                              data.streamId;


                    if(!streamId){

                        return;

                    }


                    socket.join(
                        String(streamId)
                    );


                    socket.data.streamId =
                        String(streamId);


                    socket.emit(
                        "stream-room-joined",
                        {
                            streamId:
                                String(streamId)
                        }
                    );


                    socket.to(
                        String(streamId)
                    ).emit(
                        "viewer-joined",
                        {
                            socketId:
                                socket.id,

                            streamId:
                                String(streamId)
                        }
                    );
                    }catch(error){

                    console.error(
                        "join-stream socket error:",
                        error
                    );

                }

            }
        );


        /* =============================================
           LEAVE STREAM ROOM
        ============================================= */

        socket.on(
            "leave-stream",
            (data) => {

                try{

                    const streamId =
                        typeof data === "string"
                            ? data
                            : data &&
                              data.streamId;


                    if(!streamId){

                        return;

                    }


                    socket.leave(
                        String(streamId)
                    );


                    socket.to(
                        String(streamId)
                    ).emit(
                        "viewer-left",
                        {
                            socketId:
                                socket.id,

                            streamId:
                                String(streamId)
                        }
                    );


                    if(
                        socket.data.streamId
                        ===
                        String(streamId)
                    ){

                        socket.data.streamId =
                            null;

                    }

                }catch(error){

                    console.error(
                        "leave-stream error:",
                        error
                    );

                }

            }
        );


        /* =============================================
           STREAM STARTED
        ============================================= */

        socket.on(
            "stream-started",
            (data) => {

                try{

                    if(!data){

                        return;

                    }


                    const streamId =
                        String(
                            data.streamId ||
                            data.id ||
                            ""
                        );


                    if(!streamId){

                        return;

                    }


                    socket.data.streamId =
                        streamId;


                    socket.join(
                        streamId
                    );


                    socket.broadcast.emit(
                        "stream-started",
                        data
                    );

                }catch(error){

                    console.error(
                        "stream-started error:",
                        error
                    );

                }

            }
        );


        /* =============================================
           STREAM ENDED
        ============================================= */

        socket.on(
            "stream-ended",
            (data) => {

                try{

                    if(!data){

                        return;

                    }


                    const streamId =
                        String(
                            data.streamId ||
                            data.id ||
                            ""
                        );


                    if(!streamId){

                        return;

                    }


                    io.to(
                        streamId
                    ).emit(
                        "stream-ended",
                        {
                            streamId:
                                streamId,

                            stream:
                                data.stream ||
                                null
                        }
                    );


                    socket.broadcast.emit(
                        "stream-ended",
                        {
                            streamId:
                                streamId,

                            stream:
                                data.stream ||
                                null
                        }
                    );

                }catch(error){

                    console.error(
                        "stream-ended error:",
                        error
                    );

                }

            }
        );


        /* =============================================
           STREAM HEARTBEAT
        ============================================= */

        socket.on(
            "stream-heartbeat",
            async (data) => {

                try{

                    if(!data){

                        return;

                    }


                    const streamId =
                        String(
                            data.streamId ||
                            data.id ||
                            ""
                        );


                    if(!streamId){

                        return;

                    }


                    socket.data.streamId =
                        streamId;


                    /*
                     * Heartbeat only confirms that the
                     * client is still active.
                     *
                     * It NEVER ends a stream.
                     */

                    socket.emit(
                        "stream-heartbeat-ack",
                        {
                            streamId:
                                streamId,

                            timestamp:
                                new Date()
                                    .toISOString()
                        }
                    );

                }catch(error){

                    console.error(
                        "Socket heartbeat error:",
                        error
                    );

                }

            }
        );


        /* =============================================
           CHAT THROUGH SOCKET
        ============================================= */

        socket.on(
            "chat-message",
            async (data) => {

                try{

                    if(!data){

                        return;

                    }


                    const streamId =
                        String(
                            data.streamId ||
                            ""
                        ).trim();


                    const message =
                        cleanText(
                            data.message,
                            500
                        );


                    if(
                        !streamId ||
                        !message
                    ){

                        return;

                    }


                    let userId =
                        data.userId ||
                        null;


                    let username =
                        cleanText(
                            data.username,
                            100
                        );


                    let profilePicture =
                        cleanText(
                            data.profilePicture ||
                            data.profile_picture ||
                            "",
                            50000000
                        );


                    /*
                     * Socket connections do not automatically
                     * carry the HTTP Authorization header.
                     *
                     * If the client sends a token, verify it.
                     */

                    const token =
                        cleanText(
                            data.token ||
                            data.authToken ||
                            "",
                            500
                        );


                    if(token){

                        const user =
                            await getUserFromToken(
                                token
                            );


                        if(user){

                            userId =
                                user.id;

                            username =
                                user.username ||
                                username;

                        }

                    }


                    const chatId =
                        makeId();


                    const result =
                        await pool.query(
                            `
                            INSERT INTO stream_chat (
                                id,
                                stream_id,
                                user_id,
                                username,
                                profile_picture,
                                message
                            )
                            VALUES (
                                $1,
                                $2,
                                $3,
                                $4,
                                $5,
                                $6
                            )
                            RETURNING *
                            `,
                            [
                                chatId,
                                streamId,
                                userId,
                                username,
                                profilePicture,
                                message
                            ]
                        );


                    const chatMessage = {

                        id:
                            result.rows[0].id,

                        streamId:
                            streamId,

                        userId:
                            result.rows[0].user_id,

                        username:
                            result.rows[0]
                                .username || "",

                        profilePicture:
                            result.rows[0]
                                .profile_picture || "",

                        message:
                            result.rows[0]
                                .message,

                        createdAt:
                            result.rows[0]
                                .created_at

                    };


                    io.to(
                        streamId
                    ).emit(
                        "chat-message",
                        chatMessage
                    );

                }catch(error){

                    console.error(
                        "Socket chat error:",
                        error
                    );

                }

            }
        );


        /* =============================================
           DISCONNECT
        ============================================= */

        socket.on(
            "disconnect",
            (reason) => {

                try{

                    const streamId =
                        socket.data.streamId;


                    if(streamId){

                        socket.to(
                            streamId
                        ).emit(
                            "viewer-left",
                            {
                                socketId:
                                    socket.id,

                                streamId:
                                    streamId,

                                reason:
                                    reason
                            }
                        );

                    }
                    console.log(
                        "Canvas socket disconnected:",
                        socket.id,
                        reason
                    );

                }catch(error){

                    console.error(
                        "Socket disconnect error:",
                        error
                    );

                }

            }
        );

    }
);


/* =====================================================
   PART 6 ENDS HERE
===================================================
/* =====================================================
   WEBRTC SIGNALING
===================================================== */


/*
 * The server does not process the actual video.
 *
 * It only relays WebRTC signaling messages between
 * the broadcaster and viewers.
 */


/* =====================================================
   JOIN BROADCAST
===================================================== */

io.on(
    "connection",
    (socket) => {

        socket.on(
            "join-broadcast",
            (data) => {

                try{

                    const streamId =
                        String(
                            data &&
                            (
                                data.streamId ||
                                data.id
                            ) ||
                            ""
                        ).trim();


                    if(!streamId){

                        return;

                    }


                    socket.join(
                        streamId
                    );


                    socket.data.broadcastStreamId =
                        streamId;


                    socket.to(
                        streamId
                    ).emit(
                        "broadcast-available",
                        {
                            streamId:
                                streamId,

                            broadcasterSocketId:
                                socket.id
                        }
                    );

                }catch(error){

                    console.error(
                        "join-broadcast error:",
                        error
                    );

                }

            }
        );


        /* =============================================
           VIEWER REQUESTS BROADCAST
        ============================================= */

        socket.on(
            "request-broadcast",
            (data) => {

                try{

                    const streamId =
                        String(
                            data &&
                            (
                                data.streamId ||
                                data.id
                            ) ||
                            ""
                        ).trim();


                    if(!streamId){

                        return;

                    }


                    socket.join(
                        streamId
                    );


                    socket.data.broadcastStreamId =
                        streamId;


                    socket.to(
                        streamId
                    ).emit(
                        "viewer-request",
                        {
                            streamId:
                                streamId,

                            viewerSocketId:
                                socket.id
                        }
                    );

                }catch(error){

                    console.error(
                        "request-broadcast error:",
                        error
                    );

                }

            }
        );


        /* =============================================
           WEBRTC OFFER
        ============================================= */

        socket.on(
            "webrtc-offer",
            (data) => {

                try{

                    if(!data){

                        return;

                    }


                    const streamId =
                        String(
                            data.streamId ||
                            ""
                        ).trim();


                    const targetSocketId =
                        String(
                            data.targetSocketId ||
                            data.viewerSocketId ||
                            data.socketId ||
                            ""
                        ).trim();


                    if(!streamId){

                        return;

                    }


                    const payload = {

                        streamId:
                            streamId,

                        offer:
                            data.offer || null,

                        broadcasterSocketId:
                            socket.id

                    };


                    if(targetSocketId){

                        io.to(
                            targetSocketId
                        ).emit(
                            "webrtc-offer",
                            payload
                        );

                    }else{

                        socket.to(
                            streamId
                        ).emit(
                            "webrtc-offer",
                            payload
                        );

                    }

                }catch(error){

                    console.error(
                        "WebRTC offer error:",
                        error
                    );

                }

            }
        );


        /* =============================================
           WEBRTC ANSWER
        ============================================= */

        socket.on(
            "webrtc-answer",
            (data) => {

                try{

                    if(!data){

                        return;

                    }


                    const streamId =
                        String(
                            data.streamId ||
                            ""
                        ).trim();


                    const targetSocketId =
                        String(
                            data.targetSocketId ||
                            data.broadcasterSocketId ||
                            data.socketId ||
                            ""
                        ).trim();


                    if(!streamId){

                        return;

                    }


                    const payload = {

                        streamId:
                            streamId,

                        answer:
                            data.answer || null,

                        viewerSocketId:
                            socket.id

                    };


                    if(targetSocketId){

                        io.to(
                            targetSocketId
                        ).emit(
                            "webrtc-answer",
                            payload
                        );

                    }else{

                        socket.to(
                            streamId
                        ).emit(
                            "webrtc-answer",
                            payload
                        );

                    }

                }catch(error){

                    console.error(
                        "WebRTC answer error:",
                        error
                    );

                }

            }
        );


        /* =============================================
           ICE CANDIDATE
        ============================================= */

        socket.on(
            "webrtc-ice-candidate",
            (data) => {

                try{

                    if(!data){

                        return;

                    }
                  const streamId =
                        String(
                            data.streamId ||
                            ""
                        ).trim();


                    const targetSocketId =
                        String(
                            data.targetSocketId ||
                            data.viewerSocketId ||
                            data.broadcasterSocketId ||
                            data.socketId ||
                            ""
                        ).trim();


                    if(!streamId){

                        return;

                    }


                    const payload = {

                        streamId:
                            streamId,

                        candidate:
                            data.candidate || null,

                        socketId:
                            socket.id

                    };


                    if(targetSocketId){

                        io.to(
                            targetSocketId
                        ).emit(
                            "webrtc-ice-candidate",
                            payload
                        );

                    }else{

                        socket.to(
                            streamId
                        ).emit(
                            "webrtc-ice-candidate",
                            payload
                        );

                    }

                }catch(error){

                    console.error(
                        "WebRTC ICE error:",
                        error
                    );

                }

            }
        );


        /* =============================================
           STOP BROADCAST
        ============================================= */

        socket.on(
            "stop-broadcast",
            (data) => {

                try{

                    const streamId =
                        String(
                            data &&
                            (
                                data.streamId ||
                                data.id
                            ) ||
                            socket.data.broadcastStreamId ||
                            ""
                        ).trim();


                    if(!streamId){

                        return;

                    }


                    socket.to(
                        streamId
                    ).emit(
                        "broadcast-stopped",
                        {
                            streamId:
                                streamId
                        }
                    );


                    socket.data.broadcastStreamId =
                        null;

                }catch(error){

                    console.error(
                        "stop-broadcast error:",
                        error
                    );

                }

            }
        );

    }
);


/* =====================================================
   STREAM SEARCH
===================================================== */

app.get(
    "/api/streams/search",
    optionalAuth,
    async (req,res) => {

        try{

            const query =
                cleanText(
                    req.query.q,
                    100
                );


            if(!query){

                return res.json({

                    success:true,

                    streams:[]

                });

            }


            const search =
                `%${query.toLowerCase()}%`;


            const result =
                await pool.query(
                    `
                    SELECT
                        s.*,
                        p.name,
                        p.username,
                        p.profile_picture
                            AS current_profile_picture
                    FROM streams s
                    LEFT JOIN profiles p
                        ON CAST(p.user_id AS TEXT)
                        =
                        CAST(s.user_id AS TEXT)
                    WHERE
                        LOWER(
                            COALESCE(
                                s.title,
                                ''
                            )
                        )
                        LIKE $1

                    OR

                        LOWER(
                            COALESCE(
                                s.category,
                                ''
                            )
                        )
                        LIKE $1

                    OR

                        LOWER(
                            COALESCE(
                                s.description,
                                ''
                            )
                        )
                        LIKE $1

                    OR

                        LOWER(
                            COALESCE(
                                p.username,
                                ''
                            )
                        )
                        LIKE $1

                    OR

                        LOWER(
                            COALESCE(
                                p.name,
                                ''
                            )
                        )
                        LIKE $1

                    ORDER BY
                        CASE
                            WHEN
                                LOWER(
                                    COALESCE(
                                        s.status,
                                        'ended'
                                    )
                                )
                                =
                                'live'
                            THEN 0
                            ELSE 1
                        END,

                        s.created_at DESC

                    LIMIT 50
                    `,
                    [search]
                );


            const streams =
                result.rows.map(
                    row => {

                        const stream =
                            normalizeStream(
                                row
                            );


                        if(
                            !stream.profilePicture
                        ){

                            stream.profilePicture =
                                row.current_profile_picture ||
                                "";

                            stream.profile_picture =
                                stream.profilePicture;

                        }


                        stream.streamer = {

                            name:
                                row.name || "",

                            username:
                                row.username || "",

                            profilePicture:
                                stream.profilePicture

                        };


                        return stream;

                    }
                );


            res.json({

                success:true,

                streams:
                    streams,

                count:
                    streams.length

            });

        }catch(error){

            console.error(
                "Stream search error:",
                error
            );


            res.status(500).json({

                success:false,

                message:
                    "Could not search streams.",

                streams:[]

            });

        }

    }
);


/* =====================================================
   STREAM CATEGORY FILTER
===================================================== */

app.get(
    "/api/streams/category/:category",
    optionalAuth,
    async (req,res) => {

        try{

            const category =
                cleanText(
                    req.params.category,
                    100
                );


            const result =
                await pool.query(
                    `
                    SELECT
                        s.*,
                        p.name,
                        p.username,
                        p.profile_picture
                            AS current_profile_picture
                    FROM streams s
                    LEFT JOIN profiles p
                        ON CAST(p.user_id AS TEXT)
                        =
                        CAST(s.user_id AS TEXT)
                    WHERE
                        LOWER(
                            COALESCE(
                                s.category,
                                ''
                            )
                        )
                        =
                        LOWER($1)
                    ORDER BY

                        CASE
                            WHEN
                                LOWER(
                                    COALESCE(
                                        s.status,
                                        'ended'
                                    )
                                )
                                =
                                'live'
                            THEN 0
                            ELSE 1
                        END,

                        s.created_at DESC

                    LIMIT 100
                    `,
                    [category]
                );


            const streams =
                result.rows.map(
                    row => {

                        const stream =
                            normalizeStream(
                                row
                            );


                        if(
                            !stream.profilePicture
                        ){

                            stream.profilePicture =
                                row.current_profile_picture ||
                                "";

                            stream.profile_picture =
                                stream.profilePicture;

                        }


                        stream.streamer = {

                            name:
                                row.name || "",

                            username:
                                row.username || "",

                            profilePicture:
                                stream.profilePicture

                        };


                        return stream;

                    }
                );


            res.json({

                success:true,

                category:

                    category,

                streams:

                    streams

            });

        }catch(error){

            console.error(
                "Category stream error:",
                error
            );


            res.status(500).json({

                success:false,

                message:
                    "Could not load category.",

                streams:[]

            });

        }

    }
);


/* =====================================================
   STREAM VIEW COUNT
===================================================== */

app.post(
    "/api/streams/:id/view",
    async (req,res) => {

        try{

            const streamId =
                String(
                    req.params.id || ""
                ).trim();


            /*
             * Keep this lightweight and compatible
             * with existing databases.
             *
             * A dedicated view counter is optional,
             * so the endpoint succeeds even when the
             * existing streams table has no view column.
             */

            try{

                await pool.query(
                    `
                    ALTER TABLE streams
                    ADD COLUMN IF NOT EXISTS
                    viewer_count INTEGER DEFAULT 0
                    `
                );

            }catch(columnError){

                console.warn(
                    "Viewer count column warning:",
                    columnError.message
                );

            }


            try{

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
                    `,
                    [streamId]
                );

            }catch(updateError){

                console.warn(
                    "Viewer count update warning:",
                    updateError.message
                );

            }


            res.json({

                success:true,

                streamId:
                    streamId

            });

        }catch(error){

            console.error(
                "Stream view error:",
                error
            );


            res.status(500).json({

                success:false,

                message:
                    "Could not record view."

            });

        }

    }
);


/* =====================================================
   STREAM VIEWER COUNT
===================================================== */

app.get(
    "/api/streams/:id/viewers",
    async (req,res) => {

        try{

            const streamId =
                String(
                    req.params.id || ""
                ).trim();


            let count = 0;


            try{

                const result =
                    await pool.query(
                        `
                        SELECT
                            COALESCE(
                                viewer_count,
                                0
                            ) AS viewer_count
                        FROM streams
                        WHERE
                            id = $1
                        LIMIT 1
                        `,
                        [streamId]
                    );


                if(
                    result.rows.length
                ){

                    count =
                        Number(
                            result.rows[0]
                                .viewer_count || 0
                        );

                }

            }catch(error){

                count = 0;

            }


            /*
             * Socket room size is more useful for the
             * current live viewer count.
             */

            const room =
                io.sockets.adapter
                    .rooms
                    .get(streamId);


            const socketCount =
                room
                    ? room.size
                    : 0;


            res.json({

                success:true,

                streamId:
                    streamId,

                viewers:
                    socketCount ||
                    count

            });

        }catch(error){

            console.error(
                "Viewer count error:",
                error
            );


            res.status(500).json({

                success:false,

                message:
                    "Could not load viewer count.",

                viewers:0

            });

        }

    }
);


/* =====================================================
   PART 7 ENDS HERE
===================================================== */
/* =====================================================
   EXISTING SIGNUP / LOGIN
===================================================== */

/*
 * IMPORTANT:
 *
 * Signup and Login are intentionally kept separate from
 * the Profile / Watch / Go Live modifications above.
 *
 * The existing Canvas authentication flow uses:
 *
 * - email
 * - password
 * - verification code
 * - auth token
 *
 * Profile, stream and Socket.IO changes do not alter the
 * authentication endpoints.
 */


/* =====================================================
   RESEND CONFIG
===================================================== */

let resend = null;

try{

    const {
        Resend
    } = require("resend");


    if(
        process.env.RESEND_API_KEY
    ){

        resend =
            new Resend(
                process.env.RESEND_API_KEY
            );

    }

}catch(error){

    console.warn(
        "Resend package is not available."
    );

}


/* =====================================================
   VERIFICATION CODES
===================================================== */

const verificationCodes =
    new Map();


/* =====================================================
   SEND SIGNUP VERIFICATION CODE
===================================================== */

app.post(
    "/api/signup/send-code",
    async (req,res) => {

        try{

            const email =
                String(
                    req.body.email || ""
                )
                .trim()
                .toLowerCase();


            if(!email){

                return res.status(400).json({

                    success:false,

                    message:
                        "Email is required."

                });

            }


            const existing =
                await pool.query(
                    `
                    SELECT id
                    FROM users
                    WHERE
                        LOWER(email)
                        =
                        LOWER($1)
                    LIMIT 1
                    `,
                    [email]
                );


            if(
                existing.rows.length
            ){

                return res.status(409).json({

                    success:false,

                    message:
                        "An account with this email already exists."

                });

            }


            const code =
                makeVerificationCode();


            verificationCodes.set(
                email,
                {
                    code:code,

                    expiresAt:
                        Date.now() +
                        10 * 60 * 1000
                }
            );


            /*
             * If Resend is configured, send the real
             * verification email.
             */

            if(
                resend &&
                process.env.RESEND_FROM_EMAIL
            ){

                await resend.emails.send({

                    from:
                        process.env.RESEND_FROM_EMAIL,

                    to:
                        email,

                    subject:
                        "Canvas verification code",

                    text:
                        `Your Canvas verification code is ${code}. This code expires in 10 minutes.`

                });

            }else{

                /*
                 * Development fallback.
                 *
                 * The code is logged so local testing
                 * still works without email configuration.
                 */

                console.log(
                    `Canvas verification code for ${email}: ${code}`
                );

            }


            res.json({

                success:true,

                message:
                    "Verification code sent."

            });
              }catch(error){

            console.error(
                "Send signup code error:",
                error
            );


            res.status(500).json({

                success:false,

                message:
                    "Could not send verification code."

            });

        }

    }
);


/* =====================================================
   VERIFY SIGNUP CODE / CREATE ACCOUNT
===================================================== */

app.post(
    "/api/signup/verify-code",
    async (req,res) => {

        try{

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


            const password =
                String(
                    req.body.password || ""
                );


            const name =
                cleanText(
                    req.body.name,
                    100
                );


            const username =
                cleanUsername(
                    req.body.username
                );


            if(
                !email ||
                !code ||
                !password
            ){

                return res.status(400).json({

                    success:false,

                    message:
                        "Email, code and password are required."

                });

            }


            if(
                password.length < 6
            ){

                return res.status(400).json({

                    success:false,

                    message:
                        "Password must be at least 6 characters."

                });

            }


            const savedCode =
                verificationCodes.get(
                    email
                );


            if(!savedCode){

                return res.status(400).json({

                    success:false,

                    message:
                        "Verification code not found or expired."

                });

            }


            if(
                Date.now() >
                savedCode.expiresAt
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
                savedCode.code !== code
            ){

                return res.status(400).json({

                    success:false,

                    message:
                        "Invalid verification code."

                });

            }


            const existing =
                await pool.query(
                    `
                    SELECT id
                    FROM users
                    WHERE
                        LOWER(email)
                        =
                        LOWER($1)
                    LIMIT 1
                    `,
                    [email]
                );


            if(
                existing.rows.length
            ){

                verificationCodes.delete(
                    email
                );


                return res.status(409).json({

                    success:false,

                    message:
                        "An account with this email already exists."

                });

            }


            const passwordHash =
                await bcrypt.hash(
                    password,
                    12
                );


            const userId =
                makeId();


            const authToken =
                makeToken();


            /*
             * Keep the users table compatible with the
             * existing Canvas authentication system.
             */

            const result =
                await pool.query(
                    `
                    INSERT INTO users (
                        id,
                        name,
                        username,
                        email,
                        password,
                        auth_token
                    )
                    VALUES (
                        $1,
                        $2,
                        $3,
                        $4,
                        $5,
                        $6
                    )
                    RETURNING
                        id,
                        name,
                        username,
                        email
                    `,
                    [
                        userId,
                        name,
                        username || null,
                        email,
                        passwordHash,
                        authToken
                    ]
                );


            verificationCodes.delete(
                email
            );


            /*
             * Create an empty Canvas profile so the
             * profile page can immediately load it.
             */

            try{

                await pool.query(
                    `
                    INSERT INTO profiles (
                        user_id,
                        name,
                        username,
                        bio,
                        profile_picture,
                        followers,
                        following
                    )
                    VALUES (
                        $1,
                        $2,
                        $3,
                        '',
                        '',
                        0,
                        0
                    )
                    ON CONFLICT (
                        user_id
                    )
                    DO NOTHING
                    `,
                    [
                        userId,
                        name,
                        username || null
                    ]
                );

            }catch(profileError){

                console.warn(
                    "Initial profile creation warning:",
                    profileError.message
                );

            }


            res.status(201).json({

                success:true,

                message:
                    "Account created successfully.",

                token:
                    authToken,

                authToken:
                    authToken,

                user:
                    result.rows[0]

            });

        }catch(error){

            console.error(
                "Verify signup error:",
                error
            );


            res.status(500).json({

                success:false,

                message:
                    "Could not create account."

            });

        }

    }
);


/* =====================================================
   LOGIN
===================================================== */

app.post(
    "/api/login",
    async (req,res) => {

        try{

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
                !email ||
                !password
            ){

                return res.status(400).json({

                    success:false,

                    message:
                        "Email and password are required."

                });

            }


            const result =
                await pool.query(
                    `
                    SELECT *
                    FROM users
                    WHERE
                        LOWER(email)
                        =
                        LOWER($1)
                    LIMIT 1
                    `,
                    [email]
                );


            if(
                !result.rows.length
            ){

                return res.status(401).json({

                    success:false,

                    message:
                        "Invalid email or password."

                });

            }


            const user =
                result.rows[0];


            const storedPassword =
                user.password ||
                user.password_hash ||
                "";


            let passwordCorrect =
                false;


            if(
                storedPassword
            ){

                try{

                    passwordCorrect =
                        await bcrypt.compare(
                            password,
                            storedPassword
                        );

                }catch(error){

                    passwordCorrect =
                        false;

                }

            }


            if(!passwordCorrect){

                return res.status(401).json({

                    success:false,

                    message:
                        "Invalid email or password."

                });

            }


            const authToken =
                makeToken();


            /*
             * Replace the current token with the new
             * login token.
             *
             * This keeps the existing Canvas token-based
             * authentication model.
             */

            await pool.query(
                `
                UPDATE users
                SET
                    auth_token = $1
                WHERE
                    id = $2
                `,
                [
                    authToken,
                    user.id
                ]
            );


            let profile = null;


            try{

                const profileResult =
                    await pool.query(
                        `
                        SELECT *
                        FROM profiles
                        WHERE
                            CAST(user_id AS TEXT)
                            =
                            CAST($1 AS TEXT)
                        LIMIT 1
                        `,
                        [user.id]
                    );


                if(
                    profileResult.rows.length
                ){

                    profile =
                        profileResult.rows[0];

                }

            }catch(profileError){

                console.warn(
                    "Login profile lookup warning:",
                    profileError.message
                );

            }


            res.json({

                success:true,

                message:
                    "Login successful.",

                token:
                    authToken,

                authToken:
                    authToken,

                user:{

                    id:
                        user.id,

                    name:
                        (
                            profile &&
                            profile.name
                        ) ||
                        user.name ||
                        "",

                    username:
                        (
                            profile &&
                            profile.username
                        ) ||
                        user.username ||
                        "",

                    email:
                        user.email || "",

                    bio:
                        (
                            profile &&
                            profile.bio
                        ) ||
                        "",

                    profile_picture:
                        (
                            profile &&
                            profile.profile_picture
                        ) ||
                        user.profile_picture ||
                        user.profilePicture ||
                        "",

                    followers:
                        Number(
                            (
                                profile &&
                                profile.followers
                            ) ||
                            0
                        ),

                    following:
                        Number(
                            (
                                profile &&
                                profile.following
                            ) ||
                            0
                        )

                }

            });

        }catch(error){

            console.error(
                "Login error:",
                error
            );


            res.status(500).json({

                success:false,

                message:
                    "Could not log in."

            });

        }

    }
);


/* =====================================================
   LOGOUT
===================================================== */

app.post(
    "/api/logout",
    requireAuth,
    async (req,res) => {

        try{

            await pool.query(
                `
                UPDATE users
                SET
                    auth_token = NULL
                WHERE
                    id = $1
                `,
                [req.user.id]
            );


            res.json({

                success:true,

                message:
                    "Logged out successfully."

            });

        }catch(error){

            console.error(
                "Logout error:",
                error
            );


            res.status(500).json({

                success:false,

                message:
                    "Could not log out."

            });

        }

    }
);


/* =====================================================
   GLOBAL ERROR HANDLER
===================================================== */

app.use(
    (error,req,res,next) => {

        console.error(
            "Canvas server error:",
            error
        );


        if(
            res.headersSent
        ){

            return next(
                error
            );

        }


        res.status(500).json({

            success:false,

            message:
                "Canvas server error."

        });

    }
);


/* =====================================================
   404 HANDLER
===================================================== */

app.use(
    (req,res) => {

        res.status(404).json({

            success:false,

            message:
                "Canvas API endpoint not found.",

            path:
                req.path

        });

    }
);


/* =====================================================
   SERVER START
===================================================== */

async function startCanvasServer(){

    try{

        /*
         * Make sure the database tables are ready before
         * accepting requests.
         */

        await ensureCanvasTables();


        server.listen(
            PORT,
            () => {

                console.log(
                    "========================================"
                );

                console.log(
                    "       CANVAS SERVER IS ONLINE"
                );

                console.log(
                    "========================================"
                );

                console.log(
                    `Port: ${PORT}`
                );

                console.log(
                    `API: ${API_BASE}`
                );

                console.log(
                    "Socket.IO: enabled"
                );

                console.log(
                    "WebRTC signaling: enabled"
                );

                console.log(
                    "Live streams: enabled"
                );

                console.log(
                    "Completed streams: enabled"
                );

                
                console.log(
                    "Profile system: enabled"
                );

                console.log(
                    "Chat: enabled"
                );

                console.log(
                    "Gifts / Support: enabled"
                );

                console.log(
                    "========================================"
                );

            }
        );

    }catch(error){

        console.error(
            "Canvas startup error:",
            error
        );


        /*
         * Start the server even if database startup
         * encounters a recoverable problem.
         */

        server.listen(
            PORT,
            () => {

                console.log(
                    `Canvas server started on port ${PORT} with database warnings.`
                );

            }
        );

    }

}


startCanvasServer();


/* =====================================================
   GRACEFUL SHUTDOWN
===================================================== */

async function shutdownCanvasServer(
    signal
){

    console.log(
        `Canvas received ${signal}. Shutting down...`
    );


    try{

        await pool.end();

    }catch(error){

        console.error(
            "Database shutdown error:",
            error
        );

    }


    try{

        io.close();

    }catch(error){

        console.error(
            "Socket shutdown error:",
            error
        );

    }


    process.exit(0);

}


process.on(
    "SIGTERM",
    () => {

        shutdownCanvasServer(
            "SIGTERM"
        );

    }
);


process.on(
    "SIGINT",
    () => {

        shutdownCanvasServer(
            "SIGINT"
        );

    }
);


/* =====================================================
                    END OF SERVER.JS
===================================================== */    
                          
