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
// SIGNUP
// =========================================

app.post("/api/signup", (req, res) => {

    const {
        name,
        username,
        email,
        password
    } = req.body;


    // Check required fields

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


    // Temporary response
    // Database will be connected next.

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
