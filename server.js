require("dotenv").config();

const express = require("express");
const db = require("./database");
const authRoutes = require("./routes/auth");

const app = express();
app.use(express.json());
app.use("/auth", authRoutes);

app.get("/", (req, res) => {
    res.json({
        mensagem: "API de Autenticação funcionando!"
    });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});