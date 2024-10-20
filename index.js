const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const axios = require("axios");

const app = express();

const PORT = process.env.AUTH_PORT || 5000;

app.use(express.json());

require("dotenv").config();

// Activar CORS
app.use(
  cors({
    origin: "*",
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true,
  })
);

// Configuración de la base de datos
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE,
  charset: "utf8mb4",
});

db.connect((err) => {
  if (err) {
    console.error("Error al conectar a la base de datos:", err);
  } else {
    console.log("Conexión exitosa a la base de datos!");
  }
});

app.get("/datos", (req, res) => {
  const query = `
      SELECT * FROM prueba;
    `;
  db.query(query, (err, result) => {
    if (err) {
      res.status(500).json({ error: "Consulta no procesada" });
    } else {
      res.status(200).json(result);
    }
  });
});

// Levantar el servidor
app.listen(PORT, () => {
  console.log(`Auth service running on port ${PORT}`);
});
