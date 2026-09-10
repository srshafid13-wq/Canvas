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

        methods: [
            "GET",
            "POST"
        ]

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
   JSON BODY
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
        .update(
            String(password)
        )
        .digest("hex");

}


/* =========================================
   USERNAME CLEANER
========================================= */

function cleanUsername(username) {

    return String(
        username || ""
    )
        .trim()
        .replace(/^@/, "")
        .toLowerCase();

}


/* =========================================
   AUTH TOKEN
========================================= */

function createAuthToken() {

    return crypto
        .randomBytes(32)
        .toString("hex");

}


function hashToken(token) {

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


        /* =====================================
           STREAM OWNER
        ===================================== */

        await pool.query(`
            ALTER TABLE streams

            ADD COLUMN IF NOT EXISTS user_id

            INTEGER
            REFERENCES users(id)
            ON DELETE CASCADE;
        `);


        /* =====================================
           FOLLOW SYSTEM
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


    } catch (error) {

        console.error(
            "Database initialization failed:",
            error.message
        );

    }

}
/* =========================================
   CANVAS SERVER — PART 2
   BASIC ROUTES + FOLLOW HELPERS
========================================= */


/* =========================================
   BACKEND STATUS
========================================= */

app.get(
    "/",
    (req, res) => {

        res.json({

            status: "online",

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
                    "SELECT NOW() AS now"
                );


            return res.json({

                success: true,

                database:
                    "connected",

                message:
                    "Canvas database connection is working.",

                server_time:
                    result.rows[0].now

            });


        } catch (error) {

            console.error(
                "Database test failed:",
                error.message
            );


            return res.status(500).json({

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
   FOLLOW COUNT HELPER
========================================= */

async function getFollowCounts(userId) {

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

async function getProfileByUserId(userId) {

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


    if (
        result.rows.length === 0
    ) {

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
) {

    const cleanUser =
        cleanUsername(username);


    if (!cleanUser) {

        return null;

    }


    const result =
        await pool.query(
            `
            SELECT
                id

            FROM users

            WHERE LOWER(username) = $1

            LIMIT 1
            `,
            [cleanUser]
        );


    if (
        result.rows.length === 0
    ) {

        return null;

    }


    return getProfileByUserId(
        result.rows[0].id
    );

}


/* =========================================
   FIND USER BY USERNAME
========================================= */

async function getUserByUsername(
    username
) {

    const cleanUser =
        cleanUsername(username);


    if (!cleanUser) {

        return null;

    }


    const result =
        await pool.query(
            `
            SELECT
                id,
                name,
                username,
                email,
                created_at

            FROM users

            WHERE LOWER(username) = $1

            LIMIT 1
            `,
            [cleanUser]
        );


    if (
        result.rows.length === 0
    ) {

        return null;

    }


    return result.rows[0];

}


/* =========================================
   SIGNUP
========================================= */

app.post(
    "/api/signup",
    async (req, res) => {

        if (!pool) {

            return res.status(500).json({

                success: false,

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


        const cleanName =
            String(name)
                .trim()
                .substring(0, 100);


        const cleanUsernameValue =
            cleanUsername(username);


        const cleanEmail =
            String(email)
                .trim()
                .toLowerCase();


        if (
            cleanUsernameValue.length < 3
        ) {

            return res.status(400).json({

                success: false,

                message:
                    "Username must be at least 3 characters."

            });

        }


        if (
            !/^[a-z0-9_.]+$/.test(
                cleanUsernameValue
            )
        ) {

            return res.status(400).json({

                success: false,

                message:
                    "Username can only contain letters, numbers, underscores and dots."

            });

        }


        if (
            !/^[^\s@]+@[^\s@]+\.[^\s@]+$/
                .test(cleanEmail)
        ) {

            return res.status(400).json({

                success: false,

                message:
                    "Please enter a valid email address."

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

  try {

            /* ================================
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


            if (
                emailCheck.rows.length > 0
            ) {

                return res.status(409).json({

                    success: false,

                    message:
                        "An account with this email already exists."

                });

            }


            /* ================================
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


            if (
                usernameCheck.rows.length > 0
            ) {

                return res.status(409).json({

                    success: false,

                    message:
                        "Username already exists."

                });

            }


            /* ================================
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


            /* ================================
               CREATE PROFILE
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


            /* ================================
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

                success: true,

                message:
                    "Canvas account created successfully.",

                token,

                user: {

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


        } catch (error) {

            console.error(
                "Signup failed:",
                error.message
            );


            return res.status(500).json({

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

        if (!pool) {

            return res.status(500).json({

                success: false,

                message:
                    "Database is not configured."

            });

        }


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


        try {

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


            if (
                result.rows.length === 0
            ) {

                return res.status(401).json({

                    success: false,

                    message:
                        "Email or password is incorrect."

                });

            }


            const user =
                result.rows[0];


            if (
                user.password_hash !==
                passwordHash
            ) {

                return res.status(401).json({

                    success: false,

                    message:
                        "Email or password is incorrect."

                });

            }


            /* ================================
               CREATE LOGIN SESSION
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

                success: true,

                message:
                    "Login successful.",

                token,

                user: {

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


        } catch (error) {

            console.error(
                "Login failed:",
                error.message
            );


            return res.status(500).json({

                success: false,

                message:
                    "Unable to log in to Canvas."

            });

        }

    }
);
/* =========================================
   CANVAS SERVER — PART 3
   PROFILE + FOLLOW SYSTEM
========================================= */


/* =========================================
   CURRENT USER
   GET /api/me
========================================= */

app.get(
    "/api/me",
    authenticateUser,
    async (req, res) => {

        try {

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

                    created_at:
                        req.user.created_at

                }

            });


        } catch (error) {

            console.error(
                "Get current user failed:",
                error.message
            );


            return res.status(500).json({

                success: false,

                message:
                    "Unable to get current user."

            });

        }

    }
);


/* =========================================
   GET MY PROFILE
   GET /api/profile
========================================= */

app.get(
    "/api/profile",
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
                        "Canvas profile not found."

                });

            }


            return res.json({

                success: true,

                profile,

                /*
                 * Direct fields are also returned
                 * for older Canvas pages.
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


        } catch (error) {

            console.error(
                "Get profile failed:",
                error.message
            );


            return res.status(500).json({

                success: false,

                message:
                    "Unable to load Canvas profile."

            });

        }

    }
);


/* =========================================
   GET PUBLIC PROFILE
   GET /api/profile/:username
========================================= */

app.get(
    "/api/profile/:username",
    async (req, res) => {

        if (!pool) {

            return res.status(500).json({

                success: false,

                message:
                    "Database is not configured."

            });

        }


        try {

            const username =
                cleanUsername(
                    req.params.username
                );


            if (!username) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Username is required."

                });

            }


            const profile =
                await getPublicProfileByUsername(
                    username
                );


            if (!profile) {

                return res.status(404).json({

                    success: false,

                    message:
                        "Canvas profile not found."

                });

            }


            /*
             * Never expose password_hash
             * or session information.
             */

            return res.json({

                success: true,

                profile

            });


        } catch (error) {

            console.error(
                "Get public profile failed:",
                error.message
            );


            return res.status(500).json({

                success: false,

                message:
                    "Unable to load Canvas profile."

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

        if (!pool) {

            return res.status(500).json({

                success: false,

                message:
                    "Database is not configured."

            });

        }


        try {

            const username =
                cleanUsername(
                    req.params.username
                );


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
   UPDATE MY PROFILE
   PUT /api/profile
========================================= */

app.put(
    "/api/profile",
    authenticateUser,
    async (req, res) => {

        if (!pool) {

            return res.status(500).json({

                success: false,

                message:
                    "Database is not configured."

            });

        }


        const {
            name,
            username,
            bio,
            profile_picture
        } = req.body;


        if (
            !name ||
            !username
        ) {

            return res.status(400).json({

                success: false,

                message:
                    "Name and username are required."

            });

        }


        const cleanName =
            String(name)
                .trim()
                .substring(0, 100);


        const cleanUsernameValue =
            cleanUsername(username);


        const cleanBio =
            String(
                bio || ""
            )
                .trim()
                .substring(0, 1000);


        const cleanProfilePicture =
            String(
                profile_picture || ""
            );


        if (
            cleanUsernameValue.length < 3
        ) {

            return res.status(400).json({

                success: false,

                message:
                    "Username must be at least 3 characters."

            });

        }


        if (
            !/^[a-z0-9_.]+$/.test(
                cleanUsernameValue
            )
        ) {

            return res.status(400).json({

                success: false,

                message:
                    "Username can only contain letters, numbers, underscores and dots."

            });

        }


        try {

            /* =================================
               CHECK USERNAME
            ================================= */

            const usernameCheck =
                await pool.query(
                    `
                    SELECT id

                    FROM users

                    WHERE LOWER(username) = $1

                      AND id <> $2

                    LIMIT 1
                    `,
                    [
                        cleanUsernameValue,
                        req.user.id
                    ]
                );


            if (
                usernameCheck.rows.length > 0
            ) {

                return res.status(409).json({

                    success: false,

                    message:
                        "Username already exists."

                });

            }


            /* =================================
               UPDATE USER
            ================================= */

            const userResult =
                await pool.query(
                    `
                    UPDATE users

                    SET
                        name = $1,
                        username = $2

                    WHERE id = $3

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
                        req.user.id
                    ]
                );


            if (
                userResult.rows.length === 0
            ) {

                return res.status(404).json({

                    success: false,

                    message:
                        "User account not found."

                });

            }


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

                success: true,

                message:
                    "Canvas profile updated successfully.",

                profile

            });


        } catch (error) {

            console.error(
                "Update profile failed:",
                error.message
            );


            return res.status(500).json({

                success: false,

                message:
                    "Unable to update Canvas profile."

            });

        }

    }
);


/* =========================================
   ACCOUNT PROFILE
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
   CHECK FOLLOW BY USERNAME
   GET /api/account/follows/:username
========================================= */

app.get(
    "/api/account/follows/:username",
    authenticateUser,
    async (req, res) => {

        if (!pool) {

            return res.status(500).json({

                success: false,

                message:
                    "Database is not configured."

            });

        }


        const username =
            cleanUsername(
                req.params.username
            );


        try {

            const target =
                await getUserByUsername(
                    username
                );


            if (!target) {

                return res.status(404).json({

                    success: false,

                    message:
                        "User not found."

                });

            }


            /* =================================
               SELF
            ================================= */

            if (
                Number(target.id) ===
                Number(req.user.id)
            ) {

                const counts =
                    await getFollowCounts(
                        target.id
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


            const following =
                relationship.rows.length > 0;


            return res.json({

                success: true,

                following,

                isFollowing:
                    following,

                isSelf: false,

                followers_count:
                    counts.followers_count,

                following_count:
                    counts.following_count

            });


        } catch (error) {

            console.error(
                "Follow check failed:",
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
   FOLLOW USER
   POST /api/follow/:username
========================================= */

app.post(
    "/api/follow/:username",
    authenticateUser,
    async (req, res) => {

        if (!pool) {

            return res.status(500).json({

                success: false,

                message:
                    "Database is not configured."

            });

        }


        const username =
            cleanUsername(
                req.params.username
            );


        try {

            const target =
                await getUserByUsername(
                    username
                );


            if (!target) {

                return res.status(404).json({

                    success: false,

                    message:
                        "User not found."

                });

            }


            if (
                Number(target.id) ===
                Number(req.user.id)
            ) {

                return res.status(400).json({

                    success: false,

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
                    target.id
                ]
            );


            const counts =
                await getFollowCounts(
                    target.id
                );


            /*
             * Notify everyone watching this
             * creator's stream that the
             * follower count changed.
             */

            io.emit(
                "follow-count-update",
                {

                    username:
                        target.username,

                    userId:
                        target.id,

                    followers_count:
                        counts.followers_count

                }
            );


            return res.json({

                success: true,

                following: true,

                isFollowing: true,

                followers_count:
                    counts.followers_count,

                following_count:
                    counts.following_count

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

        if (!pool) {

            return res.status(500).json({

                success: false,

                message:
                    "Database is not configured."

            });

        }


        const username =
            cleanUsername(
                req.params.username
            );


        try {

            const target =
                await getUserByUsername(
                    username
                );


            if (!target) {
              return res.status(404).json({

                    success: false,

                    message:
                        "User not found."

                });

            }


            const result =
                await pool.query(
                    `
                    DELETE FROM follows

                    WHERE follower_id = $1

                      AND following_id = $2

                    RETURNING id
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


            io.emit(
                "follow-count-update",
                {

                    username:
                        target.username,

                    userId:
                        target.id,

                    followers_count:
                        counts.followers_count

                }
            );


            return res.json({

                success: true,

                following: false,

                isFollowing: false,

                removed:
                    result.rows.length > 0,

                followers_count:
                    counts.followers_count,

                following_count:
                    counts.following_count

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
/* =========================================================
   CANVAS SERVER — PART 4 / 6
   STREAMS + SOCKET.IO + REAL-TIME WATCHING + CHAT
========================================================= */

/* =========================================================
   STREAM HELPERS
========================================================= */

async function getStreamById(streamId) {

    if (!pool) return null;

    const result = await pool.query(
        `
        SELECT
            s.id,
            s.title,
            s.status,
            s.created_at,
            s.ended_at,
            s.user_id,

            u.name AS creator_name,
            u.username AS creator_username,

            p.profile_picture AS creator_photo,

            (
                SELECT COUNT(*)
                FROM follows f
                WHERE f.following_id = s.user_id
            )::int AS followers_count,

            (
                SELECT COUNT(*)
                FROM follows f
                WHERE f.follower_id = s.user_id
            )::int AS following_count

        FROM streams s

        LEFT JOIN users u
            ON u.id = s.user_id

        LEFT JOIN profiles p
            ON p.user_id = s.user_id

        WHERE s.id = $1

        LIMIT 1
        `,
        [streamId]
    );

    if (!result.rows.length) {
        return null;
    }

    const stream = result.rows[0];

    const viewers =
        viewerRooms.get(String(stream.id))?.size || 0;

    return {
        id: stream.id,
        title: stream.title || "Live Stream",
        status: stream.status || "live",
        created_at: stream.created_at,
        ended_at: stream.ended_at,

        user_id: stream.user_id,

        creator: {
            id: stream.user_id,
            name: stream.creator_name || "Creator",
            username: stream.creator_username || "",
            profile_picture: stream.creator_photo || "",
            followers_count: Number(stream.followers_count || 0),
            following_count: Number(stream.following_count || 0)
        },

        creatorName: stream.creator_name || "Creator",
        creatorUsername: stream.creator_username || "",
        creatorPhoto: stream.creator_photo || "",

        viewerCount: viewers,
        viewers: viewers,
        watching: viewers,
        watchingCount: viewers
    };
}


/* =========================================================
   GET ALL CURRENT STREAMS
========================================================= */

app.get("/api/streams", async (req, res) => {

    try {

        if (!pool) {
            return res.status(503).json({
                success: false,
                message: "Database is not configured"
            });
        }

        const result = await pool.query(
            `
            SELECT
                s.id,
                s.title,
                s.status,
                s.created_at,
                s.ended_at,
                s.user_id,

                u.name AS creator_name,
                u.username AS creator_username,

                p.profile_picture AS creator_photo

            FROM streams s

            LEFT JOIN users u
                ON u.id = s.user_id

            LEFT JOIN profiles p
                ON p.user_id = s.user_id

            WHERE
                LOWER(COALESCE(s.status, 'live')) IN
                ('live', 'active', 'streaming')

            ORDER BY s.created_at DESC
            `
        );

        const streams = result.rows.map(stream => {

            const viewers =
                viewerRooms.get(String(stream.id))?.size || 0;

            return {
                id: stream.id,
                title: stream.title || "Live Stream",
                status: stream.status || "live",

                created_at: stream.created_at,
                ended_at: stream.ended_at,

                user_id: stream.user_id,

                creator: {
                    id: stream.user_id,
                    name: stream.creator_name || "Creator",
                    username: stream.creator_username || "",
                    profile_picture: stream.creator_photo || ""
                },

                creatorName: stream.creator_name || "Creator",
                creatorUsername: stream.creator_username || "",
                creatorPhoto: stream.creator_photo || "",

                viewerCount: viewers,
                viewers: viewers,
                watching: viewers,
                watchingCount: viewers
            };

        });

        res.json({
            success: true,
            streams
        });

    } catch (error) {

        console.error("GET /api/streams error:", error);

        res.status(500).json({
            success: false,
            message: "Failed to load streams"
        });
    }
});


/* =========================================================
   GET ONE STREAM
========================================================= */

app.get("/api/streams/:id", async (req, res) => {

    try {

        const stream = await getStreamById(req.params.id);

        if (!stream) {

            return res.status(404).json({
                success: false,
                message: "Stream not found"
            });

        }

        const status = String(stream.status || "").toLowerCase();

        const ended =
            status === "ended" ||
            status === "offline" ||
            status === "completed";

        if (ended) {

            return res.json({
                success: true,
                stream: {
                    ...stream,
                    isEnded: true,
                    isLive: false,
                    is_live: false
                }
            });

        }

        res.json({
            success: true,
            stream: {
                ...stream,
                isEnded: false,
                isLive: true,
                is_live: true
            }
        });

    } catch (error) {

        console.error("GET /api/streams/:id error:", error);

        res.status(500).json({
            success: false,
            message: "Failed to load stream"
        });
    }
});


/* =========================================================
   OLD /api/stream/:id COMPATIBILITY ROUTE
========================================================= */

app.get("/api/stream/:id", async (req, res) => {

    try {

        const stream = await getStreamById(req.params.id);

        if (!stream) {

            return res.status(404).json({
                success: false,
                message: "Stream not found"
            });

        }

        res.json({
            success: true,
            stream
        });

    } catch (error) {

        console.error("GET /api/stream/:id error:", error);

        res.status(500).json({
            success: false,
            message: "Failed to load stream"
        });
    }
});


/* =========================================================
   VIEWER ROOM STORAGE
========================================================= */

const viewerRooms = new Map();

/*
   viewerRooms:

   streamId -> Set of socket IDs

   Example:

   "15" -> Set {
       "socket123",
       "socket456"
   }
*/


function getViewerCount(streamId) {

    const room = viewerRooms.get(String(streamId));

    if (!room) {
        return 0;
    }

    return room.size;
}


function broadcastViewerCount(streamId) {

    const id = String(streamId);

    const count = getViewerCount(id);

    io.to("stream:" + id).emit(
        "viewer-count",
        {
            streamId: id,
            viewerCount: count,
            viewers: count,
            watching: count,
            watchingCount: count
        }
    );

    io.to("stream:" + id).emit(
        "watching-count",
        {
            streamId: id,
            viewerCount: count,
            viewers: count,
            watching: count,
            watchingCount: count
        }
    );
}


/* =========================================================
   CHAT STORAGE
========================================================= */

const chatRooms = new Map();

const MAX_CHAT_MESSAGES = 100;


function getChatMessages(streamId) {

    const id = String(streamId);

    if (!chatRooms.has(id)) {
        chatRooms.set(id, []);
    }

    return chatRooms.get(id);
      }
  function addChatMessage(streamId, message) {

    const id = String(streamId);

    const messages = getChatMessages(id);

    messages.push(message);

    if (messages.length > MAX_CHAT_MESSAGES) {

        messages.splice(
            0,
            messages.length - MAX_CHAT_MESSAGES
        );

    }

    return message;
}


/* =========================================================
   SOCKET.IO AUTH HELPER
========================================================= */

async function authenticateSocket(socket) {

    try {

        const token =
            socket.handshake.auth?.token ||
            socket.handshake.query?.token ||
            "";

        if (!token || !pool) {
            return null;
        }

        const tokenHash = hashToken(token);

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
            WHERE
                s.token_hash = $1
                AND s.expires_at > CURRENT_TIMESTAMP
            LIMIT 1
            `,
            [tokenHash]
        );

        if (!result.rows.length) {
            return null;
        }

        return result.rows[0];

    } catch (error) {

        console.error(
            "Socket authentication error:",
            error
        );

        return null;
    }
}


/* =========================================================
   SOCKET.IO CONNECTION
========================================================= */

io.on("connection", async (socket) => {

    console.log(
        "Canvas Socket connected:",
        socket.id
    );

    socket.user = await authenticateSocket(socket);


    /* =====================================================
       JOIN STREAM
    ===================================================== */

    socket.on("join-stream", async (data = {}) => {

        try {

            const streamId = String(
                data.streamId ||
                data.stream_id ||
                data.id ||
                ""
            );

            if (!streamId) {

                socket.emit("stream-error", {
                    message: "Stream ID is required"
                });

                return;
            }

            const stream = await getStreamById(streamId);

            if (!stream) {

                socket.emit("stream-error", {
                    message: "Stream not found",
                    streamId
                });

                return;
            }

            if (socket.currentStreamId) {

                const oldId =
                    String(socket.currentStreamId);

                socket.leave(
                    "stream:" + oldId
                );

                const oldRoom =
                    viewerRooms.get(oldId);

                if (oldRoom) {

                    oldRoom.delete(socket.id);

                    if (oldRoom.size === 0) {
                        viewerRooms.delete(oldId);
                    }

                }

                broadcastViewerCount(oldId);
            }


            socket.currentStreamId = streamId;

            socket.join(
                "stream:" + streamId
            );


            if (!viewerRooms.has(streamId)) {
                viewerRooms.set(
                    streamId,
                    new Set()
                );
            }

            viewerRooms
                .get(streamId)
                .add(socket.id);


            const count =
                getViewerCount(streamId);


            socket.emit(
                "stream-joined",
                {
                    streamId,
                    viewerCount: count,
                    viewers: count,
                    watching: count,
                    watchingCount: count
                }
            );


            broadcastViewerCount(streamId);


            const messages =
                getChatMessages(streamId);

            socket.emit(
                "chat-history",
                {
                    streamId,
                    messages
                }
            );


            console.log(
                `Viewer joined stream ${streamId}: ${count}`
            );

        } catch (error) {

            console.error(
                "join-stream error:",
                error
            );

            socket.emit(
                "stream-error",
                {
                    message: "Unable to join stream"
                }
            );
        }

    });


    /* =====================================================
       LEAVE STREAM
    ===================================================== */

    socket.on("leave-stream", (data = {}) => {

        try {

            const streamId = String(
                data.streamId ||
                data.stream_id ||
                socket.currentStreamId ||
                ""
            );

            if (!streamId) {
                return;
            }

            socket.leave(
                "stream:" + streamId
            );


            const room =
                viewerRooms.get(streamId);

            if (room) {

                room.delete(socket.id);

                if (room.size === 0) {
                    viewerRooms.delete(streamId);
                }

            }


            if (
                String(socket.currentStreamId) ===
                streamId
            ) {
                socket.currentStreamId = null;
            }


            broadcastViewerCount(streamId);


            console.log(
                `Viewer left stream ${streamId}: ${getViewerCount(streamId)}`
            );

        } catch (error) {

            console.error(
                "leave-stream error:",
                error
            );
        }

    });


    /* =====================================================
       GET CHAT HISTORY
    ===================================================== */

    socket.on("get-chat-history", (data = {}) => {

        const streamId = String(
            data.streamId ||
            data.stream_id ||
            socket.currentStreamId ||
            ""
        );

        if (!streamId) {
            return;
        }

        socket.emit(
            "chat-history",
            {
                streamId,
                messages: getChatMessages(streamId)
            }
        );

    });


    /* =====================================================
       SEND CHAT
    ===================================================== */

    socket.on("send-chat", async (data = {}) => {

        try {

            const streamId = String(
                data.streamId ||
                data.stream_id ||
                socket.currentStreamId ||
                ""
            );

            let messageText =
                data.message ??
                data.text ??
                data.content ??
                "";

            messageText =
                String(messageText)
                .trim()
                .slice(0, 500);


            if (!streamId || !messageText) {
                return;
            }


            if (
                socket.currentStreamId &&
                String(socket.currentStreamId) !== streamId
            ) {
                return;
            }


            const user =
                socket.user || null;


            let username =
                user?.username ||
                data.username ||
                data.userName ||
                "Viewer";


            username =
                String(username)
                .trim()
                .slice(0, 50);


            let displayName =
                user?.name ||
                data.name ||
                data.displayName ||
                username;


            displayName =
                String(displayName)
                .trim()
                .slice(0, 80);


            const message = {

                id:
                    crypto.randomUUID
                    ? crypto.randomUUID()
                    : crypto.randomBytes(16).toString("hex"),

                streamId,

                userId:
                    user?.id ||
                    data.userId ||
                    data.user_id ||
                    null,

                username,

                name: displayName,

                message: messageText,

                text: messageText,

                createdAt:
                    new Date().toISOString()

            };


            addChatMessage(
                streamId,
                message
            );


            io.to(
                "stream:" + streamId
            ).emit(
                "chat-message",
                message
            );


            /*
               Compatibility event for older Watch versions.
            */

            io.to(
                "stream:" + streamId
            ).emit(
                "new-chat-message",
                message
            );


        } catch (error) {

            console.error(
                "send-chat error:",
                error
            );

            socket.emit(
                "chat-error",
                {
                    message: "Unable to send message"
                }
            );
        }

    });


    /* =====================================================
       CHAT MESSAGE ALIAS
    ===================================================== */

    socket.on("chat-message", async (data = {}) => {

        socket.emit(
            "chat-message-received",
            data
        );

    });


    /* =====================================================
       STREAM STATUS
    ===================================================== */

    socket.on("stream-status", (data = {}) => {

        const streamId = String(
            data.streamId ||
            data.stream_id ||
            socket.currentStreamId ||
            ""
        );

        if (!streamId) {
            return;
        }

        io.to(
            "stream:" + streamId
        ).emit(
            "stream-status",
            {
                streamId,
                status: data.status || "live"
            }
        );

    });


    /* =====================================================
       DISCONNECT
    ===================================================== */

    socket.on("disconnect", (reason) => {

        try {

            const streamId =
                socket.currentStreamId
                    ? String(socket.currentStreamId)
                    : "";


            if (streamId) {

                const room =
                    viewerRooms.get(streamId);

                if (room) {

                    room.delete(socket.id);

                    if (room.size === 0) {
                        viewerRooms.delete(streamId);
                    }

                }

                broadcastViewerCount(
                    streamId
                );

            }


            console.log(
                "Canvas Socket disconnected:",
                socket.id,
                reason
            );

        } catch (error) {

            console.error(
                "Socket disconnect cleanup error:",
                error
            );
        }

    });

});


/* =========================================================
   SOCKET ERROR PROTECTION
========================================================= */

io.engine.on(
    "connection_error",
    (error) => {
console.error(
            "Socket.IO connection error:",
            error.message
        );

    }
);


/* =========================================================
   STREAM VIEWER COUNT REST ENDPOINT
========================================================= */

app.get(
    "/api/streams/:id/viewers",
    (req, res) => {

        const streamId =
            String(req.params.id);

        const count =
            getViewerCount(streamId);

        res.json({
            success: true,
            streamId,
            viewerCount: count,
            viewers: count,
            watching: count,
            watchingCount: count
        });

    }
);


/* =========================================================
   STREAM CHAT REST ENDPOINT
========================================================= */

app.get(
    "/api/streams/:id/chat",
    (req, res) => {

        const streamId =
            String(req.params.id);

        res.json({
            success: true,
            streamId,
            messages:
                getChatMessages(streamId)
        });

    }
);


/* =========================================================
   LEGACY CHAT ENDPOINT
========================================================= */

app.get(
    "/api/chat/:streamId",
    (req, res) => {

        const streamId =
            String(req.params.streamId);

        res.json({
            success: true,
            streamId,
            messages:
                getChatMessages(streamId)
        });

    }
);
 /* =========================================================
    CANVAS SERVER — PART 5 / 6
    STREAM CONTROL + SEARCH + RECORDINGS + FOLLOW HELPERS
 ========================================================= */


/* =========================================================
   CREATE STREAM
   ========================================================= */

app.post("/api/streams", authenticateUser, async (req, res) => {

    try {

        if (!pool) {
            return res.status(503).json({
                success: false,
                message: "Database is not configured"
            });
        }

        const title = String(
            req.body?.title ||
            req.body?.streamTitle ||
            "Live Stream"
        ).trim().slice(0, 200);

        const result = await pool.query(
            `
            INSERT INTO streams
                (title, status, user_id, created_at)
            VALUES
                ($1, 'live', $2, CURRENT_TIMESTAMP)
            RETURNING
                id,
                title,
                status,
                created_at,
                ended_at,
                user_id
            `,
            [
                title || "Live Stream",
                req.user.id
            ]
        );

        const stream = result.rows[0];

        res.status(201).json({
            success: true,
            stream: {
                ...stream,
                viewerCount: 0,
                viewers: 0,
                watching: 0,
                watchingCount: 0
            }
        });

    } catch (error) {

        console.error(
            "POST /api/streams error:",
            error
        );

        res.status(500).json({
            success: false,
            message: "Failed to create stream"
        });
    }
});


/* =========================================================
   START STREAM
   ========================================================= */

app.post(
    "/api/streams/:id/start",
    authenticateUser,
    async (req, res) => {

        try {

            if (!pool) {
                return res.status(503).json({
                    success: false,
                    message: "Database is not configured"
                });
            }

            const streamId =
                String(req.params.id);

            const result = await pool.query(
                `
                UPDATE streams
                SET
                    status = 'live',
                    ended_at = NULL
                WHERE
                    id = $1
                    AND user_id = $2
                RETURNING
                    id,
                    title,
                    status,
                    created_at,
                    ended_at,
                    user_id
                `,
                [
                    streamId,
                    req.user.id
                ]
            );

            if (!result.rows.length) {

                return res.status(404).json({
                    success: false,
                    message: "Stream not found"
                });

            }

            const stream =
                result.rows[0];

            io.emit(
                "stream-started",
                {
                    streamId: String(stream.id),
                    stream
                }
            );

            res.json({
                success: true,
                stream
            });

        } catch (error) {

            console.error(
                "Start stream error:",
                error
            );

            res.status(500).json({
                success: false,
                message: "Failed to start stream"
            });
        }
    }
);


/* =========================================================
   END STREAM
   ========================================================= */

app.post(
    "/api/streams/:id/end",
    authenticateUser,
    async (req, res) => {

        try {

            if (!pool) {
                return res.status(503).json({
                    success: false,
                    message: "Database is not configured"
                });
            }

            const streamId =
                String(req.params.id);

            const result = await pool.query(
                `
                UPDATE streams
                SET
                    status = 'ended',
                    ended_at = CURRENT_TIMESTAMP
                WHERE
                    id = $1
                    AND user_id = $2
                RETURNING
                    id,
                    title,
                    status,
                    created_at,
                    ended_at,
                    user_id
                `,
                [
                    streamId,
                    req.user.id
                ]
            );

            if (!result.rows.length) {

                return res.status(404).json({
                    success: false,
                    message: "Stream not found"
                });

            }

            const stream =
                result.rows[0];

            const room =
                viewerRooms.get(streamId);

            if (room) {

                io.to(
                    "stream:" + streamId
                ).emit(
                    "stream-ended",
                    {
                        streamId,
                        status: "ended"
                    }
                );

                viewerRooms.delete(
                    streamId
                );

            }

            io.emit(
                "stream-ended-global",
                {
                    streamId,
                    status: "ended"
                }
            );

            res.json({
                success: true,
                stream: {
                    ...stream,
                    isEnded: true,
                    isLive: false,
                    is_live: false
                }
            });

        } catch (error) {

            console.error(
                "End stream error:",
                error
            );

            res.status(500).json({
                success: false,
                message: "Failed to end stream"
            });
        }
    }
);


/* =========================================================
   LEGACY END STREAM ROUTE
   ========================================================= */

app.post(
    "/api/stream/:id/end",
    authenticateUser,
    async (req, res) => {

        try {

            if (!pool) {
                return res.status(503).json({
                    success: false,
                    message: "Database is not configured"
                });
            }

            const streamId =
                String(req.params.id)
          );
const result = await pool.query(
                `
                UPDATE streams
                SET
                    status = 'ended',
                    ended_at = CURRENT_TIMESTAMP
                WHERE
                    id = $1
                    AND user_id = $2
                RETURNING
                    id,
                    title,
                    status,
                    created_at,
                    ended_at,
                    user_id
                `,
                [
                    streamId,
                    req.user.id
                ]
            );

            if (!result.rows.length) {

                return res.status(404).json({
                    success: false,
                    message: "Stream not found"
                });

            }

            io.to(
                "stream:" + streamId
            ).emit(
                "stream-ended",
                {
                    streamId,
                    status: "ended"
                }
            );

            viewerRooms.delete(
                streamId
            );

            res.json({
                success: true,
                stream: result.rows[0]
            });

        } catch (error) {

            console.error(
                "Legacy end stream error:",
                error
            );

            res.status(500).json({
                success: false,
                message: "Failed to end stream"
            });
        }
    }
);


/* =========================================================
   DELETE / REMOVE STREAM
   ========================================================= */

app.delete(
    "/api/streams/:id",
    authenticateUser,
    async (req, res) => {

        try {

            if (!pool) {
                return res.status(503).json({
                    success: false,
                    message: "Database is not configured"
                });
            }

            const streamId =
                String(req.params.id);

            const result = await pool.query(
                `
                DELETE FROM streams
                WHERE
                    id = $1
                    AND user_id = $2
                RETURNING id
                `,
                [
                    streamId,
                    req.user.id
                ]
            );

            if (!result.rows.length) {

                return res.status(404).json({
                    success: false,
                    message: "Stream not found"
                });

            }

            viewerRooms.delete(
                streamId
            );

            chatRooms.delete(
                streamId
            );

            io.to(
                "stream:" + streamId
            ).emit(
                "stream-deleted",
                {
                    streamId
                }
            );

            res.json({
                success: true,
                message: "Stream deleted"
            });

        } catch (error) {

            console.error(
                "DELETE /api/streams/:id error:",
                error
            );

            res.status(500).json({
                success: false,
                message: "Failed to delete stream"
            });
        }
    }
);


/* =========================================================
   FOLLOW STATE
   GET /api/follow/:username
   ========================================================= */

app.get(
    "/api/follow/:username",
    authenticateUser,
    async (req, res) => {

        try {

            if (!pool) {
                return res.status(503).json({
                    success: false,
                    message: "Database is not configured"
                });
            }

            const username =
                String(req.params.username)
                .trim()
                .replace(/^@+/, "");

            const target =
                await getUserByUsername(
                    username
                );

            if (!target) {

                return res.status(404).json({
                    success: false,
                    message: "User not found"
                });

            }

            const result = await pool.query(
                `
                SELECT id
                FROM follows
                WHERE
                    follower_id = $1
                    AND following_id = $2
                LIMIT 1
                `,
                [
                    req.user.id,
                    target.id
                ]
            );

            const following =
                result.rows.length > 0;

            res.json({
                success: true,
                following,
                isFollowing: following,
                is_following: following
            });

        } catch (error) {

            console.error(
                "GET follow state error:",
                error
            );

            res.status(500).json({
                success: false,
                message: "Failed to check follow state"
            });
        }
    }
);


/* =========================================================
   SEARCH USERS + STREAMS
   ========================================================= */

app.get(
    "/api/search",
    async (req, res) => {

        try {

            if (!pool) {
                return res.status(503).json({
                    success: false,
                    message: "Database is not configured"
                });
            }

            const query =
                String(
                    req.query.q ||
                    req.query.query ||
                    req.query.search ||
                    ""
                )
                .trim()
                .slice(0, 100);

            if (!query) {

                return res.json({
                    success: true,
                    users: [],
                    streams: []
                });

            }

            const pattern =
                "%" + query + "%";


            const usersResult =
                await pool.query(
                    `
                    SELECT
                        u.id,
                        u.name,
                        u.username,
                        p.profile_picture
                    FROM users u

                    LEFT JOIN profiles p
                        ON p.user_id = u.id

                    WHERE
                        LOWER(u.username)
                            LIKE LOWER($1)
                        OR
                        LOWER(u.name)
                            LIKE LOWER($1)

                    ORDER BY
                        CASE
                            WHEN LOWER(u.username)
                                = LOWER($2)
                            THEN 0
                            ELSE 1
                        END,
                        u.username ASC

                    LIMIT 30
                    `,
                    [
                        pattern,
                        query
                    ]
                );


            const streamsResult =
                await pool.query(
                    `
                    SELECT
                        s.id,
                        s.title,
                        s.status,
                        s.created_at,
                        s.user_id,

                        u.name AS creator_name,
                        u.username AS creator_username,

                        p.profile_picture AS creator_photo

                    FROM streams s

                    LEFT JOIN users u
                        ON u.id = s.user_id

                    LEFT JOIN profiles p
                        ON p.user_id = s.user_id

                    WHERE
                        LOWER(COALESCE(s.status, 'live'))
                            IN ('live', 'active', 'streaming')
                        AND
                        LOWER(COALESCE(s.title, ''))
                            LIKE LOWER($1)

                    ORDER BY
                        s.created_at DESC

                    LIMIT 30
                    `,
                    [pattern]
                );


            const users =
                usersResult.rows.map(
                    user => ({
                        id: user.id,
                        name: user.name || "User",
                        username: user.username,
                        profile_picture:
                            user.profile_picture || ""
                    })
                );


            const streams =
                streamsResult.rows.map(
                    stream => {

                        const count =
                            getViewerCount(
                                String(stream.id)
                            );

                        return {
                            id: stream.id,
                            title:
                                stream.title ||
                                "Live Stream",

                            status:
                                stream.status ||
                                "live",

                            created_at:
                                stream.created_at,

                            user_id:
                                stream.user_id,

                            creator: {
                                id:
                                    stream.user_id,

                                name:
                                    stream.creator_name ||
                                    "Creator",

                                username:
                                    stream.creator_username ||
                                    "",

                                profile_picture:
                                    stream.creator_photo ||
                                    ""
                            },

                            creatorName:
                                stream.creator_name ||
                                "Creator",

                            creatorUsername:
                                stream.creator_username ||
                                "",

                            creatorPhoto:
                                stream.creator_photo ||
                                "",

                            viewerCount: count,
                            viewers: count,
                            watching: count,
                            watchingCount: count
                        };

                    }
                );


            res.json({
                success: true,
                users,
                streams,
                results: [
                    ...users.map(
                        user => ({
                            type: "user",
                            ...user
                        })
                    ),
                    ...streams.map(
                        stream => ({
                            type: "stream",
                            ...stream
                        })
                    )
                ]
            });

        } catch (error) {

            console.error(
                "GET /api/search error:",
                error
            );

            res.status(500).json({
                success: false,
                message: "Search failed"
            });
        }
    }
);


/* =========================================================
   SEARCH USERS COMPATIBILITY ROUTE
   ========================================================= */

app.get(
    "/api/users/search",
    async (req, res) => {

        try {

            const query =
                String(
                    req.query.q ||
                    req.query.query ||
                    ""
                )
                .trim();

            if (!pool || !query) {

                return res.json({
                    success: true,
                    users: []
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
                    FROM users u

                    LEFT JOIN profiles p
                        ON p.user_id = u.id

                    WHERE
                        LOWER(u.username)
                            LIKE LOWER($1)
                        OR
                        LOWER(u.name)
                            LIKE LOWER($1)

                    ORDER BY u.username ASC
                    LIMIT 30
                    `,
                    ["%" + query + "%"]
                );

            res.json({
                success: true,
                users:
                result.rows.map(
                        user => ({
                            id: user.id,
                            name:
                                user.name ||
                                "User",

                            username:
                                user.username,

                            profile_picture:
                                user.profile_picture ||
                                ""
                        })
                    )
            });

        } catch (error) {

            console.error(
                "User search error:",
                error
            );

            res.status(500).json({
                success: false,
                message: "User search failed"
            });
        }
    }
);


/* =========================================================
   RECORDINGS TABLE
   ========================================================= */

async function ensureRecordingsTable() {

    if (!pool) {
        return;
    }

    try {

        await pool.query(
            `
            CREATE TABLE IF NOT EXISTS stream_recordings (
                id SERIAL PRIMARY KEY,

                stream_id INTEGER,

                user_id INTEGER,

                title TEXT,

                recording_url TEXT,

                thumbnail_url TEXT,

                duration INTEGER,

                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            `
        );

        await pool.query(
            `
            CREATE INDEX IF NOT EXISTS
            idx_stream_recordings_stream
            ON stream_recordings(stream_id)
            `
        );

        await pool.query(
            `
            CREATE INDEX IF NOT EXISTS
            idx_stream_recordings_user
            ON stream_recordings(user_id)
            `
        );

    } catch (error) {

        console.error(
            "Recording table setup error:",
            error
        );
    }
}


/* =========================================================
   GET RECORDINGS
   ========================================================= */

app.get(
    "/api/recordings",
    async (req, res) => {

        try {

            if (!pool) {
                return res.status(503).json({
                    success: false,
                    message: "Database is not configured"
                });
            }

            const result =
                await pool.query(
                    `
                    SELECT
                        r.id,
                        r.stream_id,
                        r.user_id,
                        r.title,
                        r.recording_url,
                        r.thumbnail_url,
                        r.duration,
                        r.created_at,

                        u.name AS creator_name,
                        u.username AS creator_username,

                        p.profile_picture AS creator_photo

                    FROM stream_recordings r

                    LEFT JOIN users u
                        ON u.id = r.user_id

                    LEFT JOIN profiles p
                        ON p.user_id = r.user_id

                    ORDER BY
                        r.created_at DESC

                    LIMIT 100
                    `
                );

            res.json({
                success: true,
                recordings:
                    result.rows.map(
                        recording => ({
                            ...recording,

                            creator: {
                                id:
                                    recording.user_id,

                                name:
                                    recording.creator_name ||
                                    "Creator",

                                username:
                                    recording.creator_username ||
                                    "",

                                profile_picture:
                                    recording.creator_photo ||
                                    ""
                            }
                        })
                    )
            });

        } catch (error) {

            console.error(
                "GET /api/recordings error:",
                error
            );

            res.status(500).json({
                success: false,
                message: "Failed to load recordings"
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
                    message: "Database is not configured"
                });
            }

            const streamId =
                req.body?.streamId ||
                req.body?.stream_id ||
                null;

            const title =
                String(
                    req.body?.title ||
                    "Recorded Stream"
                )
                .trim()
                .slice(0, 200);

            const recordingUrl =
                String(
                    req.body?.recordingUrl ||
                    req.body?.recording_url ||
                    req.body?.url ||
                    ""
                )
                .trim();

            const thumbnailUrl =
                String(
                    req.body?.thumbnailUrl ||
                    req.body?.thumbnail_url ||
                    ""
                )
                .trim();

            const duration =
                Number(
                    req.body?.duration || 0
                );


            const result =
                await pool.query(
                    `
                    INSERT INTO stream_recordings
                        (
                            stream_id,
                            user_id,
                            title,
                            recording_url,
                            thumbnail_url,
                            duration
                        )
                    VALUES
                        ($1,$2,$3,$4,$5,$6)
                    RETURNING *
                    `,
                    [
                        streamId || null,
                        req.user.id,
                        title,
                        recordingUrl,
                        thumbnailUrl,
                        Number.isFinite(duration)
                            ? Math.max(
                                0,
                                Math.floor(duration)
                            )
                            : 0
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
                message: "Failed to save recording"
            });
        }
    }
);


/* =========================================================
   INITIALIZE RECORDINGS
   ========================================================= */

ensureRecordingsTable();
 /* =========================================================
    CANVAS SERVER — PART 6 / 6
    SIGNUP VERIFICATION + HEALTH + ERROR HANDLING + STARTUP
 ========================================================= */


/* =========================================================
   TEMPORARY SIGNUP VERIFICATION STORAGE
   ========================================================= */

/*
   Verification codes are kept in memory.

   This means:
   - A server restart clears pending codes.
   - Verified accounts remain safely stored in PostgreSQL.
   - No password is stored here.
*/

const signupVerificationCodes = new Map();


function generateVerificationCode() {

    return String(
        crypto.randomInt(
            100000,
            1000000
        )
    );

}


function normalizeEmail(email) {

    return String(
        email || ""
    )
    .trim()
    .toLowerCase();

}


/* =========================================================
   RESEND CONFIGURATION
   ========================================================= */

const resendApiKey =
    process.env.RESEND_API_KEY ||
    process.env.RESEND_API_KEY_CANVAS ||
    "";

const resendFromEmail =
    process.env.RESEND_FROM_EMAIL ||
    process.env.RESEND_FROM ||
    "Canvas <onboarding@resend.dev>";


/* =========================================================
   SEND EMAIL USING RESEND
   ========================================================= */

async function sendVerificationEmail(
    email,
    code
) {

    if (!resendApiKey) {

        console.warn(
            "RESEND_API_KEY is not configured."
        );

        return false;
    }


    try {

        const response =
            await fetch(
                "https://api.resend.com/emails",
                {
                    method: "POST",

                    headers: {
                        "Authorization":
                            "Bearer " +
                            resendApiKey,

                        "Content-Type":
                            "application/json"
                    },

                    body: JSON.stringify({

                        from:
                            resendFromEmail,

                        to: [email],

                        subject:
                            "Canvas verification code",

                        html: `
                            <div style="
                                font-family:Arial,Helvetica,sans-serif;
                                max-width:600px;
                                margin:auto;
                                padding:30px;
                                color:#4b3326;
                            ">

                                <h1 style="
                                    margin:0 0 20px;
                                    font-size:32px;
                                    font-weight:800;
                                ">
                                    Canvas
                                </h1>

                                <p>
                                    Your Canvas verification code is:
                                </p>

                                <div style="
                                    font-size:32px;
                                    font-weight:800;
                                    letter-spacing:8px;
                                    padding:20px 0;
                                ">
                                    ${code}
                                </div>

                                <p>
                                    This code expires in 10 minutes.
                                </p>

                            </div>
                        `
                    })
                }
            );


        if (!response.ok) {

            const text =
                await response.text();

            console.error(
                "Resend error:",
                text
            );

            return false;
        }


        return true;

    } catch (error) {

        console.error(
            "Verification email error:",
            error
        );

        return false;
    }

}


/* =========================================================
   SEND SIGNUP CODE
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
                    SELECT id
                    FROM users
                    WHERE LOWER(email) = LOWER($1)
                    LIMIT 1
                    `,
                    [email]
                );


            if (existing.rows.length) {

                return res.status(409).json({
                    success: false,
                    message:
                        "An account with this email already exists"
                });

            }


            const code =
                generateVerificationCode();


            signupVerificationCodes.set(
                email,
                {
                    code,
                    expiresAt:
                        Date.now() +
                        (10 * 60 * 1000)
                }
            );


            const sent =
                await sendVerificationEmail(
                    email,
                    code
                );


            /*
               Development fallback:

               If Resend isn't configured,
               the API still confirms that the
               code was generated.

               The code is NOT returned when
               email sending works.
            */

            if (!sent) {

                console.warn(
                    "Email service unavailable. Verification code generated for:",
                    email
                );

                return res.json({
                    success: true,
                    message:
                        "Verification code created. Email service is not configured."
                });

            }


            res.json({
                success: true,
                message:
                    "Verification code sent"
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
   VERIFY SIGNUP CODE
   ========================================================= */

app.post(
    "/api/signup/verify-code",
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

            const code =
                String(
                    req.body?.code ||
                    req.body?.verificationCode ||
                    req.body?.verification_code ||
                    ""
                )
                .trim();


            if (!email || !code) {

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
   VERIFIED SIGNUP COMPATIBILITY ROUTE
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
                .slice(0, 100);

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


            if (password.length < 6) {

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


            if (existing.rows.length) {

                const row =
                    existing.rows[0];

                if (
                    String(row.username)
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
                hashPassword(password);


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
                    [user.id]
                );


                await client.query(
                    "COMMIT"
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
   LOGIN COMPATIBILITY ALIASES
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
                    [identifier]
                );


            if (!result.rows.length) {

                return res.status(401).json({
                    success: false,
                    message:
                        "Invalid email/username or password"
                });

            }


            const user =
                result.rows[0];


            const valid =
                hashPassword(password) ===
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
                hashToken(token);


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
   LOGOUT
   ========================================================= */

app.post(
    "/api/logout",
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


            const auth =
                String(
                    req.headers.authorization ||
                    ""
                );


            const token =
                auth.startsWith("Bearer ")
                    ? auth.slice(7).trim()
                    : "";


            if (token) {

                await pool.query(
                    `
                    DELETE FROM sessions
                    WHERE token_hash = $1
                    `,
                    [
                        hashToken(token)
                    ]
                );

            }


            res.json({
                success: true,
                message:
                    "Logged out successfully"
            });


        } catch (error) {

            console.error(
                "Logout error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Logout failed"
            });

        }

    }
);


/* =========================================================
   HEALTH CHECK
   ========================================================= */

app.get(
    "/health",
    async (req, res) => {

        let database =
            "not-configured";


        if (pool) {

            try {

                await pool.query(
                    "SELECT 1"
                );

                database = "connected";

            } catch (error) {

                database = "error";

            }

        }


        res.json({
            success: true,
            service: "Canvas",
            status: "online",
            database,
            socketio: true,
            timestamp:
                new Date().toISOString()
        });

    }
);


/* =========================================================
   API HEALTH ALIAS
   ========================================================= */

app.get(
    "/api/health",
    async (req, res) => {

        let database =
            "not-configured";


        if (pool) {

            try {

                await pool.query(
                    "SELECT 1"
                );

                database = "connected";

            } catch (error) {

                database = "error";

            }

        }


        res.json({
            success: true,
            status: "online",
            database,
            socketio: true
        });

    }
);


/* =========================================================
   404 API HANDLER
   ========================================================= */

app.use(
    "/api",
    (req, res) => {

        res.status(404).json({
            success: false,
            message:
                "API endpoint not found",
            path:
                req.originalUrl
        });

    }
);


/* =========================================================
   GLOBAL ERROR HANDLER
   ========================================================= */

app.use(
    (error, req, res, next) => {

        console.error(
            "Canvas server error:",
            error
        );


        if (res.headersSent) {
            return next(error);
        }


        res.status(
            error.status || 500
        ).json({
            success: false,
            message:
                error.message ||
                "Internal server error"
        });

    }
);


/* =========================================================
   PERIODIC SESSION CLEANUP
   ========================================================= */

if (pool) {

    setInterval(
        async () => {

            try {

                await pool.query(
                    `
                    DELETE FROM sessions
                    WHERE expires_at <= CURRENT_TIMESTAMP
                    `
                );

            } catch (error) {

                console.error(
                    "Session cleanup error:",
                    error
                );

            }

        },
        60 * 60 * 1000
    );

}


/* =========================================================
   PERIODIC VERIFICATION CODE CLEANUP
   ========================================================= */

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
                now > data.expiresAt
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
    "unhandledRejection",
    (error) => {

        console.error(
            "Unhandled promise rejection:",
            error
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


/* =========================================================
   START SERVER
   ========================================================= */

async function startServer() {

    try {

        await initializeDatabase();

        await ensureRecordingsTable();


        httpServer.listen(
            PORT,
            "0.0.0.0",
            () => {

                console.log(
                    "======================================"
                );

                console.log(
                    "Canvas server is ONLINE"
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
                        ? "CONFIGURED"
                        : "NOT CONFIGURED"
                );

                console.log(
                    "Signup/Login: ENABLED"
                );

                console.log(
                    "======================================"
                );

            }
        );


    } catch (error) {

        console.error(
            "Canvas server startup error:",
            error
        );


        /*
           Still start HTTP server if database
           initialization has a temporary problem.
           The API will return proper database errors
           instead of completely crashing.
        */

        httpServer.listen(
            PORT,
            "0.0.0.0",
            () => {

                console.log(
                    "Canvas server started with database warning."
                );

            }
        );

    }

}


startServer();
                        
                    
            
          
