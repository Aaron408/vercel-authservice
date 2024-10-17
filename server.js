// services/auth/server.js
const express = require("express");
const mysql = require("mysql2");
const jwt = require("jsonwebtoken");
const axios = require("axios");
const app = express();
const PORT = process.env.PORT || 5000;
const cors = require("cors"); // Importar cors
const nodemailer = require("nodemailer");
const crypto = require("crypto");

require("dotenv").config(); // Cargar desde la raíz del proyecto

// Activar CORS
app.use(cors({
  origin: 'http://localhost:3000', // Cambia el puerto según donde esté corriendo tu app local
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  credentials: true // Si necesitas enviar cookies o autenticación
}));

app.use(express.json());


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

//-------------TOKEN VERIFICATION----------------//

// Middleware para verificar el token
const verifyToken = async (req, res, next) => {
  const token = req.headers["authorization"]?.split(" ")[1];

  if (!token) {
    return res
      .status(401)
      .json({ message: "Acceso denegado. Token no proporcionado." });
  }

  try {
    // Busca el token en la base de datos
    const session = await db.query(
      "SELECT * FROM session_token WHERE token = ?",
      [token]
    );

    if (session.length === 0) {
      return res
        .status(401)
        .json({ message: "Token inválido o no encontrado." });
    }

    // Verifica si el token ha expirado
    const sessionData = session[0];
    const now = new Date();
    if (new Date(sessionData.expires_date) < now) {
      return res.status(401).json({ message: "Token ha expirado." });
    }

    // Si todo está bien, pasa al siguiente middleware
    req.user = { id: sessionData.user_id };
    next();
  } catch (error) {
    return res.status(401).json({ message: "Error al verificar el token." });
  }
};

module.exports = verifyToken;

//-------------LOGIN PAGE-------------//

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

    if (results.length === 0) {
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

// Función para verificar el token de Google
const verifyGoogleToken = async (token) => {
  const response = await axios.get(
    `https://www.googleapis.com/oauth2/v3/tokeninfo?id_token=${token}`
  );
  return response.data;
};

//---------------Register Page----------------//

app.post("/api/checkEmail", (req, res) => {
  const { email } = req.body;

  db.query(
    "SELECT COUNT(*) as count FROM users WHERE email = ?",
    [email],
    (err, results) => {
      if (err) {
        return res
          .status(500)
          .json({ message: "Error al verificar el correo" });
      }

      if (results[0].count > 0) {
        return res.status(200).json({ exists: true });
      } else {
        return res.status(200).json({ exists: false });
      }
    }
  );
});

const generateVerificationCode = () => {
  return Math.floor(100000 + Math.random() * 900000);
};

app.post("/api/sendVerificationCode", (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ message: "Correo electrónico requerido" });
  }

  const verificationCode = generateVerificationCode();

  db.query(
    "INSERT INTO verification_codes (email, code) VALUES (?, ?)",
    [email, verificationCode],
    (err, result) => {
      if (err) {
        console.error("Error al insertar el código de verificación:", err);
        return res
          .status(500)
          .json({ message: "Hubo un error al generar el código." });
      }

      const transporter = nodemailer.createTransport({
        host: "smtp.titan.email",
        port: 465,
        secure: true,
        auth: {
          user: process.env.NODE_EMAIL,
          pass: process.env.NODE_PASSWORD,
        },
      });

      const enviarCorreo = (email, verificationCode, res) => {
        const mailOptions = {
          from: `"CRONIS" <${process.env.NODE_EMAIL}>`,
          to: email,
          subject: "Código de verificación",
          text: `Tu código de verificación para CRONIS es: ${verificationCode}. Este código expira en 3 minutos.`, // Cuerpo del correo en texto plano
        };

        transporter.sendMail(mailOptions, (error, info) => {
          if (error) {
            console.error("Error al enviar el correo de verificación:", error);
            console.error("Detalles del error:", error.message, error.stack);

            return res.status(500).json({
              message: "Hubo un error al enviar el correo de verificación.",
            });
          }

          res.status(200).json({
            message: "Código de verificación enviado correctamente",
          });
        });
      };

      enviarCorreo(email, verificationCode, res);
    }
  );
});

app.post("/api/verify-code", (req, res) => {
  const { email, code } = req.body;

  db.query(
    "SELECT * FROM verification_codes WHERE email = ? AND code = ? AND expires_at > NOW()",
    [email, code],
    (err, results) => {
      if (err) {
        console.error("Error al verificar el código:", err);
        return res.status(500).json({ error: "Error interno del servidor" });
      }

      if (results.length > 0) {
        res.json({ isValid: true });
      } else {
        res.json({ isValid: false });
      }
    }
  );
});

app.post("/api/register", async (req, res) => {
  const { nombre, email, password } = req.body;

  if (!nombre || !email || !password) {
    return res.status(400).json({ error: "Todos los campos son requeridos" });
  }

  try {
    db.query(
      "SELECT * FROM users WHERE email = ?",
      [email],
      async (err, results) => {
        if (err) {
          console.error("Error al verificar el usuario existente:", err);
          return res.status(500).json({ error: "Error interno del servidor" });
        }

        if (results.length > 0) {
          return res.status(400).json({ error: "El usuario ya existe" });
        }

        const hashedPassword = crypto
          .createHash("md5")
          .update(password)
          .digest("hex");

        db.query(
          "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
          [nombre, email, hashedPassword],
          (err, result) => {
            if (err) {
              console.error("Error al insertar nuevo usuario:", err);
              return res
                .status(500)
                .json({ error: "Error al crear nuevo usuario" });
            }

            db.query("DELETE FROM verification_codes WHERE email = ?", [email]);

            res.status(201).json({ success: true, userId: result.insertId });
          }
        );
      }
    );
  } catch (error) {
    console.error("Error al registrar el usuario:", error);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

//--------------HOME PAGE---------------//

// Levantar el servidor
app.listen(PORT, () => {
  console.log(`Auth service running on port ${PORT}`);
});
