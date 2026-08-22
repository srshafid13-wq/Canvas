const express = require("express");
const { Pool } = require("pg");
const crypto = require("crypto");

const app = express();

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

    if (req.method === "OPTIONS") {

        return res.sendStatus(204);

    }

    next();

});


/* =========================================
   JSON BODY LIMIT
========================================= */

app.use(
    express.json({
        limit: "10mb"
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
   RESEND CONFIGURATION
========================================= */

const resendApiKey =
    process.env.RESEND_API_KEY;


const resendFromEmail =
    process.env.RESEND_FROM_EMAIL ||
    "Canvas <onboarding@resend.dev>";


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
   NORMALIZE USERNAME
========================================= */

function cleanUsername(username) {

    return String(username || "")
        .trim()
        .replace(/^@/, "")
        .toLowerCase();

}


/* =========================================
   AUTHENTICATION TOKEN
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
   VERIFICATION CODE
========================================= */

function createVerificationCode() {

    return String(
        crypto.randomInt(
            100000,
            1000000
        )
    );

}


function hashVerificationCode(code) {

    return crypto
        .createHash("sha256")
        .update(String(code))
        .digest("hex");

}


/* =========================================
   SEND VERIFICATION EMAIL
========================================= */

async function sendVerificationEmail(
    email,
    code
) {

    if (!resendApiKey) {

        throw new Error(
            "RESEND_API_KEY is not configured."
        );

    }


    const response =
        await fetch(
            "https://api.resend.com/emails",
            {

                method: "POST",

                headers: {

                    "Authorization":
                        `Bearer ${resendApiKey}`,

                    "Content-Type":
                        "application/json"

                },

                body:
                    JSON.stringify({

                        from:
                            resendFromEmail,

                        to: [
                            email
                        ],

                        subject:
                            "Your Canvas verification code",

                        html: `

<div style="
    font-family:Arial,sans-serif;
    max-width:500px;
    margin:auto;
    padding:30px;
    color:#4b3024;
">

    <div style="
        text-align:center;
        margin-bottom:25px;
    ">

        <h1 style="
            margin:0;
            color:#6F4E37;
            font-size:38px;
        ">
            Canvas
        </h1>

    </div>


    <h2 style="
        color:#4b3024;
    ">
        Verify your email
    </h2>


    <p>
        Use the verification code below
        to finish creating your Canvas account.
    </p>


    <div style="
        margin:25px 0;
        padding:22px;
        background:#f7f3ef;
        border-radius:12px;
        text-align:center;
    ">

        <div style="
            font-size:32px;
            font-weight:bold;
            letter-spacing:8px;
            color:#6F4E37;
        ">
            ${code}
        </div>

    </div>


    <p>
        This code expires in
        <strong>10 minutes</strong>.
    </p>


    <p style="
        color:#777;
        font-size:14px;
    ">
        If you did not request this code,
        you can safely ignore this email.
    </p>

</div>

                        `

                    })

            }
        );


    if (!response.ok) {

        const errorText =
            await response.text();


        throw new Error(
            `Resend email failed: ${errorText}`
        );

    }


    return true;

}


/* =========================================
   AUTHENTICATION MIDDLEWARE
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

                [
                    tokenHash
                ]

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


        await pool.query(`

            CREATE TABLE IF NOT EXISTS signup_verifications (

                id SERIAL PRIMARY KEY,

                name VARCHAR(100) NOT NULL,

                username VARCHAR(100) NOT NULL,

                email VARCHAR(255) NOT NULL,

                password_hash TEXT NOT NULL,

                code_hash TEXT NOT NULL,

                expires_at TIMESTAMP NOT NULL,

                attempts INTEGER
                    DEFAULT 0,

                created_at TIMESTAMP
                    DEFAULT CURRENT_TIMESTAMP

            );

        `);


        await pool.query(`

            CREATE TABLE IF NOT EXISTS streams (

                id SERIAL PRIMARY KEY,

                title VARCHAR(255)
                    DEFAULT 'Canvas Live Stream',

                status VARCHAR(30)
                    DEFAULT 'live',

                created_at TIMESTAMP
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

app.get(
    "/",
    (req, res) => {

        res.json({

            status:
                "online",

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
                    "SELECT NOW()"
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
   PART 1 ENDS HERE
========================================= */
/* =========================================
   SEND SIGNUP VERIFICATION CODE
========================================= */

app.post(
    "/api/signup/send-code",
    async (req, res) => {

        const {
            name,
            username,
            email,
            password
        } = req.body;


        /* =====================================
           REQUIRED FIELDS
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


        /* =====================================
           PASSWORD VALIDATION
        ===================================== */

        if (
            String(password).length < 8
        ) {

            return res.status(400).json({

                success: false,

                message:
                    "Password must be at least 8 characters."

            });

        }


        /* =====================================
           DATABASE CHECK
        ===================================== */

        if (!pool) {

            return res.status(500).json({

                success: false,

                message:
                    "Database is not configured."

            });

        }


        /* =====================================
           EMAIL SERVICE CHECK
        ===================================== */

        if (!resendApiKey) {

            return res.status(500).json({

                success: false,

                message:
                    "Email service is not configured."

            });

        }


        try {

            const cleanName =
                String(name)
                    .trim();


            const cleanUser =
                cleanUsername(username);


            const cleanEmail =
                String(email)
                    .trim()
                    .toLowerCase();


            /* =================================
               USERNAME REQUIRED
            ================================= */

            if (!cleanUser) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Username is required."

                });

            }


            /* =================================
               USERNAME VALIDATION
            ================================= */

            if (
                !/^[a-zA-Z0-9_.]+$/
                    .test(cleanUser)
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Invalid username."

                });

            }


            /* =================================
               CHECK EXISTING ACCOUNT
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
               REMOVE OLD VERIFICATION
            ================================= */

            await pool.query(

                `
                DELETE FROM signup_verifications

                WHERE LOWER(email) = $1
                `,

                [
                    cleanEmail
                ]

            );


            /* =================================
               CREATE VERIFICATION CODE
            ================================= */

            const code =
                createVerificationCode();


            const codeHash =
                hashVerificationCode(
                    code
                );


            /* =================================
               HASH PASSWORD
            ================================= */

            const passwordHash =
                hashPassword(
                    password
                );


            /* =================================
               SAVE PENDING SIGNUP
            ================================= */

            await pool.query(

                `
                INSERT INTO signup_verifications
                (
                    name,
                    username,
                    email,
                    password_hash,
                    code_hash,
                    expires_at
                )

                VALUES
                (
                    $1,
                    $2,
                    $3,
                    $4,
                    $5,
                    CURRENT_TIMESTAMP
                    + INTERVAL '10 minutes'
                )
                `,

                [
                    cleanName,
                    cleanUser,
                    cleanEmail,
                    passwordHash,
                    codeHash
                ]

            );


            /* =================================
               SEND VERIFICATION EMAIL
            ================================= */

            await sendVerificationEmail(
                cleanEmail,
                code
            );


            /* =================================
               SUCCESS
            ================================= */

            return res.json({

                success: true,

                message:
                    "Verification code sent to your email.",

                email:
                    cleanEmail

            });


        } catch (error) {

            console.error(
                "Verification code sending failed:",
                error.message
            );


            return res.status(500).json({

                success: false,

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
    async (req, res) => {

        const {
            email,
            code
        } = req.body;


        /* =====================================
           REQUIRED FIELDS
        ===================================== */

        if (
            !email ||
            !code
        ) {

            return res.status(400).json({

                success: false,

                message:
                    "Email and verification code are required."

            });

        }


        /* =====================================
           DATABASE CHECK
        ===================================== */

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


            const cleanCode =
                String(code)
                    .trim();


            /* =================================
               CODE FORMAT
            ================================= */

            if (
                !/^\d{6}$/.test(cleanCode)
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Verification code must be 6 digits."

                });

            }


            /* =================================
               FIND VERIFICATION
            ================================= */

            const verificationResult =
                await pool.query(

                    `
                    SELECT

                        id,
                        name,
                        username,
                        email,
                        password_hash,
                        code_hash,
                        expires_at,
                        attempts

                    FROM signup_verifications

                    WHERE LOWER(email) = $1

                    ORDER BY created_at DESC

                    LIMIT 1
                    `,

                    [
                        cleanEmail
                    ]

                );


            if (
                verificationResult.rows.length === 0
            ) {

                return res.status(404).json({

                    success: false,

                    message:
                        "No verification request was found for this email."

                });

            }


            const verification =
                verificationResult.rows[0];


            /* =================================
               CHECK EXPIRATION
            ================================= */

            if (
                new Date(
                    verification.expires_at
                ) <= new Date()
            ) {

                await pool.query(

                    `
                    DELETE FROM signup_verifications

                    WHERE id = $1
                    `,

                    [
                        verification.id
                    ]

                );


                return res.status(410).json({

                    success: false,

                    message:
                        "Verification code has expired. Please request a new code."

                });

            }


            /* =================================
               LIMIT ATTEMPTS
            ================================= */

            if (
                Number(verification.attempts) >= 5
            ) {

                await pool.query(

                    `
                    DELETE FROM signup_verifications

                    WHERE id = $1
                    `,

                    [
                        verification.id
                    ]

                );


                return res.status(429).json({

                    success: false,

                    message:
                        "Too many incorrect attempts. Please request a new code."

                });

            }


            /* =================================
               CHECK CODE
            ================================= */

            const submittedCodeHash =
                hashVerificationCode(
                    cleanCode
                );


            if (
                submittedCodeHash !==
                verification.code_hash
            ) {

                await pool.query(

                    `
                    UPDATE signup_verifications

                    SET attempts =
                        attempts + 1

                    WHERE id = $1
                    `,

                    [
                        verification.id
                    ]

                );


                return res.status(401).json({

                    success: false,

                    message:
                        "Incorrect verification code."

                });

            }


            /* =================================
               FINAL USER CHECK
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
                        cleanUsername(
                            verification.username
                        ),

                        cleanEmail
                    ]

                );


            if (
                existingUser.rows.length > 0
            ) {

                const existing =
                    existingUser.rows[0];


                await pool.query(

                    `
                    DELETE FROM signup_verifications

                    WHERE id = $1
                    `,

                    [
                        verification.id
                    ]

                );


                if (
                    String(existing.username)
                        .toLowerCase() ===
                    cleanUsername(
                        verification.username
                    )
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
               CREATE VERIFIED USER
            ================================= */

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

                        cleanUsername(
                            verification.username
                        ),

                        cleanEmail,

                        verification.password_hash

                    ]

                );


            const user =
                userResult.rows[0];


            /* =================================
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

                ON CONFLICT (user_id)
                DO NOTHING
                `,

                [
                    user.id
                ]

            );


            /* =================================
               REMOVE USED VERIFICATION
            ================================= */

            await pool.query(

                `
                DELETE FROM signup_verifications

                WHERE id = $1
                `,

                [
                    verification.id
                ]

            );


            /* =================================
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


            /* =================================
               SUCCESS
            ================================= */

            return res.status(201).json({

                success: true,

                message:
                    "Email verified and Canvas account created successfully.",

                token:
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
                "Signup verification failed:",
                error.message
            );


            return res.status(500).json({

                success: false,

                message:
                    "Unable to verify email."

            });

        }

    }
);


/* =========================================
   PART 2 ENDS HERE
========================================= */
/* =========================================
   RESEND SIGNUP VERIFICATION CODE
========================================= */

app.post(
    "/api/signup/resend-code",
    async (req, res) => {

        const {
            email
        } = req.body;


        /* =====================================
           EMAIL REQUIRED
        ===================================== */

        if (!email) {

            return res.status(400).json({

                success: false,

                message:
                    "Email is required."

            });

        }


        /* =====================================
           DATABASE CHECK
        ===================================== */

        if (!pool) {

            return res.status(500).json({

                success: false,

                message:
                    "Database is not configured."

            });

        }


        /* =====================================
           EMAIL SERVICE CHECK
        ===================================== */

        if (!resendApiKey) {

            return res.status(500).json({

                success: false,

                message:
                    "Email service is not configured."

            });

        }


        try {

            const cleanEmail =
                String(email)
                    .trim()
                    .toLowerCase();


            /* =================================
               FIND PENDING SIGNUP
            ================================= */

            const result =
                await pool.query(

                    `
                    SELECT

                        id,
                        name,
                        username,
                        email,
                        password_hash

                    FROM signup_verifications

                    WHERE LOWER(email) = $1

                    ORDER BY created_at DESC

                    LIMIT 1
                    `,

                    [
                        cleanEmail
                    ]

                );


            if (
                result.rows.length === 0
            ) {

                return res.status(404).json({

                    success: false,

                    message:
                        "No pending signup was found for this email."

                });

            }


            const signup =
                result.rows[0];


            /* =================================
               CREATE NEW CODE
            ================================= */

            const code =
                createVerificationCode();


            const codeHash =
                hashVerificationCode(
                    code
                );


            /* =================================
               UPDATE VERIFICATION
            ================================= */

            await pool.query(

                `
                UPDATE signup_verifications

                SET

                    code_hash = $1,

                    expires_at =
                        CURRENT_TIMESTAMP
                        + INTERVAL '10 minutes',

                    attempts = 0

                WHERE id = $2
                `,

                [
                    codeHash,
                    signup.id
                ]

            );


            /* =================================
               SEND NEW CODE
            ================================= */

            await sendVerificationEmail(
                cleanEmail,
                code
            );


            /* =================================
               SUCCESS
            ================================= */

            return res.json({

                success: true,

                message:
                    "A new verification code has been sent."

            });


        } catch (error) {

            console.error(
                "Resend verification failed:",
                error.message
            );


            return res.status(500).json({

                success: false,

                message:
                    "Unable to resend verification code."

            });

        }

    }
);


/* =========================================
   CLEAN EXPIRED VERIFICATION REQUESTS
========================================= */

async function cleanExpiredVerifications() {

    if (!pool) {

        return;
    }


    try {

        await pool.query(

            `
            DELETE FROM signup_verifications

            WHERE expires_at <=
                  CURRENT_TIMESTAMP
            `

        );


    } catch (error) {

        console.error(
            "Verification cleanup failed:",
            error.message
        );

    }

}


/* =========================================
   CLEAN EXPIRED SESSIONS
========================================= */

async function cleanExpiredSessions() {

    if (!pool) {

        return;
    }


    try {

        await pool.query(

            `
            DELETE FROM sessions

            WHERE expires_at <=
                  CURRENT_TIMESTAMP
            `

        );


    } catch (error) {

        console.error(
            "Session cleanup failed:",
            error.message
        );

    }

}


/* =========================================
   SERVER START
========================================= */

app.listen(
    PORT,
    async () => {

        console.log(
            `Canvas backend running on port ${PORT}`
        );


        /* =====================================
           INITIALIZE DATABASE
        ===================================== */

        await initializeDatabase();


        /* =====================================
           INITIAL CLEANUP
        ===================================== */

        await cleanExpiredSessions();

        await cleanExpiredVerifications();


        /* =====================================
           HOURLY CLEANUP
        ===================================== */

        setInterval(
            cleanExpiredSessions,
            60 * 60 * 1000
        );


        setInterval(
            cleanExpiredVerifications,
            60 * 60 * 1000
        );

    }
);
