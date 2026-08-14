const express = require("express");

const app = express();

const PORT = process.env.PORT || 3000;

app.use(express.json());

app.get("/", (req, res) => {
    res.json({
        status: "online",
        message: "Canvas backend is running."
    });
});

app.listen(PORT, () => {
    console.log(`Canvas backend running on port ${PORT}`);
});
