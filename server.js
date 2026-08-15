const express = require("express");
const { Pool } = require("pg");

const app = express();

const PORT = process.env.PORT || 3000;

app.use(express.json());


// =========================================
// DATABASE CONNECTION
// =========================================

const DATABASE_URL =
    process.env.DATABASE_URL ||
    process.env.CANVAS_DATABASE_URL;

const pool = DATABASE_URL
    ? new Pool({
        connectionString: DATABASE_URL,
        ssl: {
            rejectUnauthorized: false
        }
    })
    : null;


// =========================================
// CANVAS BACKEND STATUS
// =========================================

app.get("/", (req, res) => {

    res.json({
        status: "online",
        message: "Canvas backend is running."
    });

});


// =========================================
// DATABASE TEST
// =========================================

app.get("/api/database-test", async (req, res) => {

    if (!pool) {

        return res.status(500).json({
            success: false,
            message: "DATABASE_URL environment variable is missing."
        });

    }

    try {

        const result = await pool.query(
            "SELECT NOW() AS current_time"
        );

        res.json({
            success: true,
            message: "Canvas database connection is working.",
            databaseTime: result.rows[0].current_time
        });

    } catch (error) {

        console.error(
            "Database connection error:",
            error
        );

        res.status(500).json({
            success: false,
            message: "Database connection failed.",
            error: error.message
        });

    }

});


// =========================================
// CREATE STREAM TABLE
// =========================================

app.get("/api/database-setup", async (req, res) => {

    if (!pool) {

        return res.status(500).json({
            success: false,
            message: "DATABASE_URL environment variable is missing."
        });

    }

    try {

        await pool.query(`
            CREATE TABLE IF NOT EXISTS streams (

                id SERIAL PRIMARY KEY,

                title TEXT NOT NULL,

                category TEXT,

                description TEXT,

                creator TEXT,

                username TEXT,

                thumbnail TEXT,

                status TEXT DEFAULT 'live',

                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

                ended_at TIMESTAMP

            );
        `);

        res.json({
            success: true,
            message: "Canvas streams table is ready."
        });

    } catch (error) {

        console.error(
            "Database setup error:",
            error
        );

        res.status(500).json({
            success: false,
            message: "Could not create streams table.",
            error: error.message
        });

    }

});


// =========================================
// SIGNUP
// =========================================

app.post("/api/signup", async (req, res) => {

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
            message: "All fields are required."

        });

    }


    /*
     * Account database storage will be
     * added after the stream database
     * is confirmed working.
     */

    res.json({

        success: true,

        message: "Signup request received.",

        user: {
            name: name,
            username: username,
            email: email
        }

    });

});


// =========================================
// START STREAM
// =========================================

app.post("/api/streams/start", async (req, res) => {

    if (!pool) {

        return res.status(500).json({
            success: false,
            message: "Database connection is not configured."
        });

    }

    const {
        title,
        category,
        description,
        creator,
        username,
        thumbnail
    } = req.body;


    if (!title) {

        return res.status(400).json({
            success: false,
            message: "Stream title is required."
        });

    }


    try {

        const result = await pool.query(
            `
            INSERT INTO streams
            (
                title,
                category,
                description,
                creator,
                username,
                thumbnail,
                status
            )
            VALUES
            ($1, $2, $3, $4, $5, $6, 'live')
            RETURNING *
            `,
            [
                title,
                category || "",
                description || "",
                creator || "Canvas Creator",
                username || "",
                thumbnail || ""
            ]
        );


        const stream = result.rows[0];


        res.json({

            success: true,

            message: "Canvas stream started.",

            streamId: stream.id,

            stream: stream

        });

    } catch (error) {

        console.error(
            "Start stream error:",
            error
        );

        res.status(500).json({

            success: false,

            message: "Could not start stream.",

            error: error.message

        });

    }

});


// =========================================
// STOP STREAM
// =========================================

app.post("/api/streams/stop", async (req, res) => {

    if (!pool) {

        return res.status(500).json({
            success: false,
            message: "Database connection is not configured."
        });

    }

    const {
        streamId
    } = req.body;


    if (!streamId) {

        return res.status(400).json({

            success: false,

            message: "Stream ID is required."

        });

    }


    try {

        const result = await pool.query(
            `
            UPDATE streams

            SET
                status = 'ended',
                ended_at = CURRENT_TIMESTAMP

            WHERE id = $1
            AND status = 'live'

            RETURNING *
            `,
            [streamId]
        );


        if (result.rows.length === 0) {

            return res.status(404).json({

                success: false,

                message: "Live stream not found."

            });

        }


        res.json({

            success: true,

            message: "Canvas stream stopped.",

            stream: result.rows[0]

        });

    } catch (error) {

        console.error(
            "Stop stream error:",
            error
        );

        res.status(500).json({

            success: false,

            message: "Could not stop stream.",

            error: error.message

        });

    }

});


// =========================================
// GET LIVE STREAMS
// =========================================

app.get("/api/streams", async (req, res) => {

    if (!pool) {

        return res.status(500).json({

            success: false,

            message: "Database connection is not configured."

        });

    }


    try {

        const result = await pool.query(
            `
            SELECT *

            FROM streams

            WHERE status = 'live'

            ORDER BY created_at DESC
            `
        );


        res.json({

            success: true,

            streams: result.rows

        });

    } catch (error) {

        console.error(
            "Get streams error:",
            error
        );

        res.status(500).json({

            success: false,

            message: "Could not load live streams."

        });

    }

});


// =========================================
// SEARCH STREAMS
// =========================================

app.get("/api/streams/search", async (req, res) => {

    if (!pool) {

        return res.status(500).json({

            success: false,

            message: "Database connection is not configured."

        });

    }


    const search =
        String(req.query.q || "")
            .trim();


    if (!search) {

        return res.json({

            success: true,

            streams: []

        });

    }


    try {

        const searchValue =
            `%${search}%`;


        const result = await pool.query(
            `
            SELECT *

            FROM streams

            WHERE status = 'live'

            AND (

                title ILIKE $1

                OR category ILIKE $1

                OR description ILIKE $1

                OR creator ILIKE $1

                OR username ILIKE $1

            )

            ORDER BY created_at DESC
            `,
            [searchValue]
        );


        res.json({

            success: true,

            streams: result.rows

        });

    } catch (error) {

        console.error(
            "Search streams error:",
            error
        );

        res.status(500).json({

            success: false,

            message: "Could not search streams."

        });

    }

});


// =========================================
// START SERVER
// =========================================

app.listen(PORT, () => {

    console.log(
        `Canvas backend running on port ${PORT}`
    );

});
