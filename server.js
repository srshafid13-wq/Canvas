const express = require("express");

const app = express();

const PORT = process.env.PORT || 3000;

app.use(express.json());


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
// DATABASE CONNECTION TEST
// =========================================

app.get("/api/database-test", (req, res) => {

    const databaseUrl =
        process.env.canvas_db_r13t;


    if (!databaseUrl) {

        return res.status(500).json({

            success: false,
            database: "not connected",
            message:
                "Database environment variable was not found."

        });

    }


    res.json({

        success: true,
        database: "environment variable detected",
        message:
            "Canvas database environment variable is available."

    });

});


// =========================================
// SIGNUP
// =========================================

app.post("/api/signup", (req, res) => {

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
// START SERVER
// =========================================

app.listen(PORT, () => {

    console.log(
        `Canvas backend running on port ${PORT}`
    );

});
