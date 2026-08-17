const express = require("express");
const { Pool } = require("pg");
const crypto = require("crypto");

const app = express();

const PORT = process.env.PORT || 3000;


/* =========================================
   JSON BODY LIMIT
========================================= */

app.use(express.json({
    limit: "10mb"
}));


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
   DATABASE
========================================= */

const databaseUrl =
    process.env.canvas_db_r13t;

const pool = databaseUrl
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
        .update(password)
        .digest("hex");

}


/* =========================================
   NORMALIZE USERNAME
========================================= */

function cleanUsername(username) {

    return String(username || "")
        .trim()
        .replace(/^@/, "")
        .toLowerCase();

}


/* =========================================
   INITIALIZE DATABASE
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
           USERS TABLE
        ===================================== */

        await pool.query(`

            CREATE TABLE IF NOT EXISTS users (

                id SERIAL PRIMARY KEY,

                name VARCHAR(100) NOT NULL,

                username VARCHAR(100) UNIQUE NOT NULL,

                email VARCHAR(255) UNIQUE NOT NULL,

                password_hash TEXT NOT NULL,

                created_at TIMESTAMP
                    DEFAULT CURRENT_TIMESTAMP

            );

        `);


        /* =====================================
           PROFILES TABLE
        ===================================== */

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
   BACKEND STATUS
========================================= */

app.get("/", (req, res) => {

    res.json({

        status: "online",

        message:
            "Canvas backend is running."

    });

});


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

            console.error(
                "Database test failed:",
                error.message
            );


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


        /* =====================================
           VALIDATION
        ===================================== */

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


            if (!cleanUser) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Username is required."

                });

            }


            /* =================================
               CHECK EXISTING USER
            ================================= */

            const existingUser =
                await pool.query(

                    `
                    SELECT
                        id,
                        username,
                        email

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
                existingUser.rows.length > 0
            ) {

                const existing =
                    existingUser.rows[0];


                if (
                    String(existing.username)
                        .toLowerCase() ===
                    cleanUser
                ) {

                    return res.status(409).json({

                        success: false,

                        message:
                            "Username already exists."

                    });

                }


                return res.status(409).json({

                    success: false,

                    message:
                        "Email already exists."

                });

            }


            /* =================================
               HASH PASSWORD
            ================================= */

            const passwordHash =
                hashPassword(password);


            /* =================================
               CREATE USER
            ================================= */

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

                    VALUES
                    ($1, $2, $3, $4)

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

                ON CONFLICT (user_id)
                DO NOTHING
                `,

                [
                    user.id
                ]

            );


            /* =================================
               RESPONSE
            ================================= */

            return res.status(201).json({

                success: true,

                message:
                    "Canvas account created successfully.",

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
                    "Unable to create account."

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


        /* =====================================
           VALIDATION
        ===================================== */

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


            /* =================================
               FIND USER
            ================================= */

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

                    [
                        cleanEmail
                    ]

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


            /* =================================
               CHECK PASSWORD
            ================================= */

            const passwordHash =
                hashPassword(password);


            if (
                passwordHash !==
                user.password_hash
            ) {

                return res.status(401).json({

                    success: false,

                    message:
                        "Email or password is incorrect."

                });

            }


            /* =================================
               LOGIN SUCCESS
            ================================= */

            return res.json({

                success: true,

                message:
                    "Login successful.",

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
                    "Unable to log in."

            });

        }

    }
);
/* =========================================
   GET PROFILE
========================================= */

app.get(
    "/api/profile/:username",
    async (req, res) => {

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
                        ) AS profile_picture,

                        profiles.updated_at

                    FROM users

                    LEFT JOIN profiles
                        ON profiles.user_id =
                           users.id

                    WHERE LOWER(users.username) = $1

                    LIMIT 1
                    `,

                    [
                        username
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


            return res.json({

                success: true,

                profile:
                    result.rows[0]

            });


        } catch (error) {

            console.error(
                "Profile fetch failed:",
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
   UPDATE PROFILE
========================================= */

app.put(
    "/api/profile/:username",
    async (req, res) => {

        const username =
            cleanUsername(
                req.params.username
            );


        const {
            name,
            bio,
            profile_picture
        } = req.body;


        if (!username) {

            return res.status(400).json({

                success: false,

                message:
                    "Username is required."

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

            /* =================================
               FIND USER
            ================================= */

            const userResult =
                await pool.query(

                    `
                    SELECT
                        id,
                        name,
                        username,
                        email

                    FROM users

                    WHERE LOWER(username) = $1

                    LIMIT 1
                    `,

                    [
                        username
                    ]

                );


            if (
                userResult.rows.length === 0
            ) {

                return res.status(404).json({

                    success: false,

                    message:
                        "User not found."

                });

            }


            const user =
                userResult.rows[0];


            const userId =
                user.id;


            /* =================================
               UPDATE NAME ONLY IF SENT
            ================================= */

            if (
                name !== undefined &&
                name !== null
            ) {

                const cleanName =
                    String(name).trim();


                if (cleanName.length > 0) {

                    await pool.query(

                        `
                        UPDATE users

                        SET name = $1

                        WHERE id = $2
                        `,

                        [
                            cleanName,
                            userId
                        ]

                    );

                }

            }


            /* =================================
               GET CURRENT PROFILE
            ================================= */

            const currentProfileResult =
                await pool.query(

                    `
                    SELECT
                        bio,
                        profile_picture

                    FROM profiles

                    WHERE user_id = $1

                    LIMIT 1
                    `,

                    [
                        userId
                    ]

                );


            let currentBio = "";

            let currentPicture = "";


            if (
                currentProfileResult.rows.length > 0
            ) {

                currentBio =
                    currentProfileResult.rows[0].bio || "";

                currentPicture =
                    currentProfileResult.rows[0].profile_picture || "";

            }


            /* =================================
               KEEP OLD DATA WHEN NOT SENT
            ================================= */

            const finalBio =
                bio !== undefined &&
                bio !== null
                    ? String(bio)
                    : currentBio;


            const finalPicture =
                profile_picture !== undefined &&
                profile_picture !== null
                    ? String(profile_picture)
                    : currentPicture;


            /* =================================
               CREATE / UPDATE PROFILE
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

                ON CONFLICT (user_id)

                DO UPDATE SET

                    bio =
                        EXCLUDED.bio,

                    profile_picture =
                        EXCLUDED.profile_picture,

                    updated_at =
                        CURRENT_TIMESTAMP
                `,

                [
                    userId,
                    finalBio,
                    finalPicture
                ]

            );


            /* =================================
               GET COMPLETE UPDATED PROFILE
            ================================= */

            const updatedResult =
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
                        ) AS profile_picture,

                        profiles.updated_at

                    FROM users

                    LEFT JOIN profiles
                        ON profiles.user_id =
                           users.id

                    WHERE users.id = $1

                    LIMIT 1
                    `,

                    [
                        userId
                    ]

                );


            const updatedProfile =
                updatedResult.rows[0];


            /* =================================
               RESPONSE
            ================================= */

            return res.json({

                success: true,

                message:
                    "Profile saved successfully.",

                profile:
                    updatedProfile

            });


        } catch (error) {

            console.error(
                "Profile update failed:",
                error.message
            );


            return res.status(500).json({

                success: false,

                message:
                    "Unable to save profile.",

                error:
                    error.message

            });

        }

    }
);


/* =========================================
   START STREAM
========================================= */

app.post(
    "/api/streams/start",
    async (req, res) => {

        const {
            title
        } = req.body;


        if (!pool) {

            return res.status(500).json({

                success: false,

                message:
                    "Database is not configured."

            });

        }


        try {

            const streamTitle =
                title &&
                String(title).trim()
                    ? String(title).trim()
                    : "Canvas Live Stream";


            const result =
                await pool.query(

                    `
                    INSERT INTO streams
                    (
                        title,
                        status,
                        started_at
                    )

                    VALUES
                    (
                        $1,
                        'live',
                        CURRENT_TIMESTAMP
                    )

                    RETURNING
                        id,
                        title,
                        status,
                        started_at
                    `,

                    [
                        streamTitle
                    ]

                );


            const stream =
                result.rows[0];


            return res.status(201).json({

                success: true,

                message:
                    "Canvas stream started.",

                streamId:
                    stream.id,

                stream:
                    stream

            });


        } catch (error) {

            console.error(
                "Start stream failed:",
                error.message
            );


            return res.status(500).json({

                success: false,

                message:
                    "Unable to start stream.",

                error:
                    error.message

            });

        }

    }
);


/* =========================================
   STOP STREAM
========================================= */

app.post(
    "/api/streams/stop",
    async (req, res) => {

        const {
            streamId
        } = req.body;


        if (!streamId) {

            return res.status(400).json({

                success: false,

                message:
                    "Stream ID is required."

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

            const result =
                await pool.query(

                    `
                    UPDATE streams

                    SET
                        status = 'ended',

                        ended_at =
                            CURRENT_TIMESTAMP

                    WHERE id = $1

                      AND status = 'live'

                    RETURNING
                        id,
                        title,
                        status,
                        started_at,
                        ended_at
                    `,

                    [
                        streamId
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
                    "Canvas stream stopped.",

                stream:
                    result.rows[0]

            });


        } catch (error) {

            console.error(
                "Stop stream failed:",
                error.message
            );


            return res.status(500).json({

                success: false,

                message:
                    "Unable to stop stream.",

                error:
                    error.message

            });

        }

    }
);


/* =========================================
   SERVER START
========================================= */

app.listen(
    PORT,
    async () => {

        console.log(
            `Canvas backend running on port ${PORT}`
        );


        await initializeDatabase();

    }
);
