const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const axios = require("axios");
const crypto = require("crypto");

require("dotenv").config();

const jwt = require("jsonwebtoken");
const app = express();
const PORT = process.env.AUTH_PORT || 5000;

app.use(express.json());

// Activar CORS
app.use(
  cors({
    origin: "*",
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true,
  })
);

app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header(
    "Access-Control-Allow-Headers",
    "Origin, X-Requested-With, Content-Type, Accept, Authorization"
  );
  res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  next();
});

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

app.get("/", (req, res) => {
  res.send("Auth service running!");
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

//----------------LOGIN PAGE-------------------//

//Normal Login

const generateToken = (user, expiresIn) => {
  const payload = {
    userId: user.id,
    email: user.email,
  };

  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn });
};

const saveToken = (userId, token, expiresAt) => {
  const query =
    "INSERT INTO session_token (user_id, token, expires_date) VALUES (?, ?, ?)";

  db.query(query, [userId, token, expiresAt], (err, results) => {
    if (err) {
      console.error("Error saving token to the database", err);
    }
  });
};

app.post("/api/login", (req, res) => {
  const { email, password, rememberMe } = req.body;

  // Hash the password using MD5
  const hashedPassword = crypto
    .createHash("md5")
    .update(password)
    .digest("hex");

  const query = "SELECT * FROM users WHERE email = ? AND password = ?";
  db.query(query, [email, hashedPassword], (err, results) => {
    if (err) {
      console.error("Database query error:", err);
      return res.status(500).json({ error: "Internal server error" });
    }
    if (results.length == 0) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const user = results[0];
    const expiresIn = rememberMe ? "30d" : "1d";
    const token = generateToken(user, expiresIn);

    const expiresAt = new Date(
      Date.now() + (rememberMe ? 30 : 1) * 24 * 60 * 60 * 1000
    );
    saveToken(user.id, token, expiresAt);

    res.json({
      name: user.name,
      type: user.type,
      email: user.email,
      token: token,
    });
  });
});

app.post("/api/logout", (req, res) => {
  const { session_token } = req.body;
  const token = session_token;
  const query = `DELETE FROM session_token WHERE token = ?`;

  db.query(query, token, (err, results) => {
    if (err) {
      console.error("Database query error:", err);
      return res.status(500).json({ error: "Internal server error" });
    } else {
      return res
        .status(200)
        .json({ message: "Token eliminado exitosamente!." });
    }
  });
});

//Gogle Auth
app.post("/api/auth/google", async (req, res) => {
  const { idToken } = req.body;

  try {
    const ticket = await verifyGoogleToken(idToken);
    const { sub, name, email, picture, given_name } = ticket;

    const queryCheckUser = `
        SELECT * 
        FROM users 
        WHERE google_id = ?
      `;

    // Verifica si el usuario ya existe
    db.query(queryCheckUser, [sub], async (err, results) => {
      if (err) {
        console.error("Database query error:", err);
        return res.status(500).json({ error: "Database error" });
      }

      if (results.length > 0) {
        const user = results[0];

        const sessionToken = generateToken30Days(user);
        saveTokenFor30Days(user.id, sessionToken, (err) => {
          if (err) {
            return res
              .status(500)
              .json({ message: "Error al guardar el token de sesión." });
          }
        });
        return res.status(200).json({
          name: user.name,
          type: user.type,
          email: user.email,
          token: sessionToken,
        });
      } else {
        // Si no existe un usuario con el google_id, verificar si hay un usuario con el correo
        const queryCheckUserByEmail = `
        SELECT * 
        FROM users 
        WHERE email = ?
    `;

        db.query(queryCheckUserByEmail, [email], (err, emailResults) => {
          if (err) {
            console.error("Database query error:", err);
            return res.status(500).json({ error: "Database error" });
          }

          if (emailResults.length > 0) {
            // Si existe un usuario con el correo, actualizar su google_id
            const user = emailResults[0];
            const updateGoogleIdQuery = `
                UPDATE users 
                SET google_id = ?, profile_picture_url = ?
                WHERE id = ?
            `;

            db.query(updateGoogleIdQuery, [sub, picture, user.id], (err) => {
              if (err) {
                console.error("Error updating google_id:", err);
                return res.status(500).json({ error: "Error updating user" });
              }

              // Generar token y devolver datos
              const sessionToken = generateToken30Days({
                id: user.id,
                email: user.email,
              });

              saveTokenFor30Days(user.id, sessionToken, (err) => {
                if (err) {
                  return res
                    .status(500)
                    .json({ message: "Error al guardar el token de sesión." });
                }
              });

              return res.status(200).json({
                name: user.name,
                type: user.type,
                email: user.email,
                token: sessionToken,
              });
            });
          } else {
            // Si no existe, insertar nuevo usuario
            const newUserQuery = `
                INSERT INTO users (google_id, name, email, email_verified, profile_picture_url, given_name, suscription_plan, status) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            `;

            const newUser = {
              google_id: sub,
              name: name,
              email: email,
              email_verified: true,
              profile_picture_url: picture,
              given_name: given_name,
              suscription_plan: 1,
              status: 1,
            };

            db.query(
              newUserQuery,
              [
                newUser.google_id,
                newUser.name,
                newUser.email,
                newUser.email_verified,
                newUser.profile_picture_url,
                newUser.given_name,
                newUser.suscription_plan,
                newUser.status,
              ],
              (err, insertResult) => {
                if (err) {
                  console.error("Error inserting new user:", err);
                  return res
                    .status(500)
                    .json({ error: "Error creating new user" });
                }

                const sessionToken = generateToken30Days({
                  id: insertResult.insertId,
                  email: newUser.email,
                });

                saveTokenFor30Days(
                  insertResult.insertId,
                  sessionToken,
                  (err) => {
                    if (err) {
                      return res.status(500).json({
                        message: "Error al guardar el token de sesión.",
                      });
                    }
                  }
                );

                return res.status(201).json({
                  name: newUser.name,
                  type: "1",
                  email: newUser.email,
                  token: sessionToken,
                });
              }
            );
          }
        });
      }
    });
  } catch (error) {
    console.error("Token verification failed:", error);
    return res.status(401).json({ error: "Invalid token" });
  }
});

// Función para generar el token JWT con duración de 1 mes
const generateToken30Days = (user) => {
  const payload = {
    userId: user.id,
    email: user.email,
  };

  // Generar el token con una duración de 30 días
  const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: "30d" });
  return token;
};

const saveTokenFor30Days = (userId, token) => {
  // Consulta para guardar el token en la base de datos
  const query =
    "INSERT INTO session_token (user_id, token, expires_date) VALUES (?, ?, ?)";
  const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // Fecha de expiración a 30 días

  db.query(query, [userId, token, expiresAt], (err, results) => {
    if (err) {
      console.error("Error al guardar el token en la base de datos", err);
    }
  });
};

// Función para verificar el token de Google
const verifyGoogleToken = async (token) => {
  const response = await axios.get(
    `https://www.googleapis.com/oauth2/v3/tokeninfo?id_token=${token}`
  );
  return response.data;
};

// Levantar el servidor
app.listen(PORT, () => {
  console.log(`Auth service running on port ${PORT}`);
});
