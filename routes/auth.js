const express = require("express");
const bcrypt = require("bcrypt");
const db = require("../database");
const router = express.Router();
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");
const speakeasy = require("speakeasy");
const QRCode = require("qrcode");

router.post("/register", async (req, res) => {

    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({
            message: "Preencha todos os campos."
        });
    }

    try {

        const hash = await bcrypt.hash(password, 10);

        db.run(
            "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
            [name, email, hash],
            function(err) {

                if (err) {
                    return res.status(400).json({
                        message: "E-mail já cadastrado."
                    });
                }

                res.status(201).json({
                    message: "Usuário cadastrado com sucesso!"
                });

            }
        );

    } catch (error) {

        res.status(500).json({
            message: "Erro interno do servidor."
        });

    }

});
// Login
router.post("/login", (req, res) => {

    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({
            message: "Preencha todos os campos."
        });
    }

    db.get(
        "SELECT * FROM users WHERE email = ?",
        [email],
        async (err, user) => {

            if (err) {
                return res.status(500).json({
                    message: "Erro interno."
                });
            }

            if (!user) {
                return res.status(404).json({
                    message: "Usuário não encontrado."
                });
            }

            const senhaCorreta = await bcrypt.compare(password, user.password);

            if (!senhaCorreta) {
                return res.status(401).json({
                    message: "Senha incorreta."
                });
            }

            const token = jwt.sign(
                {
                    id: user.id,
                    email: user.email
                },
                process.env.JWT_SECRET,
                {
                    expiresIn: "15m"
                }
            );

            const refreshToken = uuidv4();

            db.run(
                "UPDATE users SET refreshToken = ? WHERE id = ?",
                [refreshToken, user.id]
            );

            res.json({
                message: "Login realizado com sucesso!",
                token,
                refreshToken
            });

        }
    );

});

router.get("/setup-2fa", (req, res) => {

    const email = req.query.email;

    if (!email) {
        return res.send("<h2>Informe o e-mail na URL.</h2>");
    }

    db.get(
        "SELECT * FROM users WHERE email = ?",
        [email],
        async (err, user) => {

            if (err) {
                return res.status(500).send("Erro interno.");
            }

            if (!user) {
                return res.send("<h2>Usuário não encontrado.</h2>");
            }

            const secret = speakeasy.generateSecret({
                name: `Central de Autenticação (${email})`
            });

            db.run(
                "UPDATE users SET secret = ? WHERE id = ?",
                [secret.base32, user.id]
            );

            const qrCode = await QRCode.toDataURL(secret.otpauth_url);

            res.send(`
<!DOCTYPE html>

<html lang="pt-br">

<head>

<meta charset="UTF-8">

<title>Configurar 2FA</title>

<style>

body{

    font-family:Arial;
    background:#f4f4f4;
    text-align:center;
    margin-top:40px;

}

.card{

    width:500px;
    margin:auto;
    background:white;
    padding:30px;
    border-radius:10px;
    box-shadow:0 0 15px rgba(0,0,0,.2);

}

img{

    width:280px;

}

</style>

</head>

<body>

<div class="card">

<h1>Central de Autenticação Segura</h1>

<h3>Google Authenticator (2FA)</h3>

<p><b>Usuário:</b> ${email}</p>

<p>Escaneie o QR Code abaixo.</p>

<img src="${qrCode}">

<p>Depois abra o aplicativo Google Authenticator e utilize o código de 6 dígitos.</p>

</div>

</body>

</html>
`);

        }

    );

});
router.post("/verify-2fa", (req, res) => {

    const { email, token } = req.body;

    if (!email || !token) {
        return res.status(400).json({
            message: "Informe o e-mail e o código."
        });
    }

    db.get(
        "SELECT * FROM users WHERE email = ?",
        [email],
        (err, user) => {

            if (err) {
                return res.status(500).json({
                    message: "Erro interno."
                });
            }

            if (!user) {
                return res.status(404).json({
                    message: "Usuário não encontrado."
                });
            }

            const verified = speakeasy.totp.verify({
                secret: user.secret,
                encoding: "base32",
                token: token,
                window: 1
            });

            if (!verified) {
                return res.status(401).json({
                    message: "Código inválido."
                });
            }

            const jwtToken = jwt.sign(
                {
                    id: user.id,
                    email: user.email
                },
                process.env.JWT_SECRET,
                {
                    expiresIn: "15m"
                }
            );

            res.json({
                message: "2FA validado com sucesso!",
                token: jwtToken
            });

        }
    );

});
module.exports = router;