const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const multer = require("multer");
const xlsx = require("xlsx");
const session = require("express-session");
const path = require("path");
require("dotenv").config();

const app = express();

// =======================
// MIDDLEWARES
// =======================
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Servir archivos estáticos
app.use(express.static(path.join(__dirname, "public")));

// Sesiones
app.use(
  session({
    secret: "mini-hackaton-secret",
    resave: false,
    saveUninitialized: false,
  })
);

// =======================
// CONEXIÓN MYSQL
// =======================
const db = mysql.createConnection({
  host: process.env.DB_HOST || "localhost",
  user: process.env.DB_USER || "lab_user",
  password: process.env.DB_PASS || "lab_pass",
  database: process.env.DB_NAME || "laboratorio",
});

db.connect((err) => {
  if (err) {
    console.error("❌ Error conectando a MySQL:", err);
  } else {
    console.log("✅ MySQL conectado correctamente");
  }
});

// =======================
// MIDDLEWARES DE AUTORIZACIÓN
// =======================
function verificarSesion(req, res, next) {
  if (!req.session.usuario) {
    return res.status(401).json({ ok: false, msg: "No has iniciado sesión" });
  }
  next();
}

// Permite varios roles: solo("ADMIN", "ASISTENTE")
function solo(...rolesPermitidos) {
  return (req, res, next) => {
    if (!req.session.usuario) {
      return res.status(401).json({ ok: false, msg: "No has iniciado sesión" });
    }
    if (!rolesPermitidos.includes(req.session.usuario.rol)) {
      return res.status(403).json({ ok: false, msg: "No autorizado" });
    }
    next();
  };
}

// =======================
// RUTA RAÍZ
// =======================
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// =======================
// AUTH
// =======================

// LOGIN
app.post("/api/auth/login", (req, res) => {
  const { correo, password } = req.body;

  db.query("SELECT * FROM usuarios WHERE correo = ?", [correo], (err, rows) => {
    if (err) {
      console.error(err);
      return res.json({ ok: false, msg: "Error en servidor" });
    }

    if (rows.length === 0) {
      return res.json({ ok: false, msg: "Correo no encontrado" });
    }

    const user = rows[0];

    bcrypt.compare(password, user.password_hash, (err, valid) => {
      if (err) {
        console.error(err);
        return res.json({ ok: false, msg: "Error al validar contraseña" });
      }

      if (!valid) {
        return res.json({ ok: false, msg: "Contraseña incorrecta" });
      }

      req.session.usuario = {
        id: user.id,
        correo: user.correo,
        rol: user.rol,
      };

      res.json({ ok: true, rol: user.rol });
    });
  });
});

// LOGOUT
app.post("/api/auth/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({ ok: true });
  });
});

// REGISTER (solo ADMIN)
app.post("/api/auth/register", verificarSesion, solo("ADMIN"), (req, res) => {
  const { nombre, correo, password, rol } = req.body;

  if (!nombre || !correo || !password) {
    return res.status(400).json({ ok: false, msg: "Faltan datos" });
  }

  const rolValido = ["ADMIN", "ASISTENTE", "AUDITOR"].includes(rol)
    ? rol
    : "ASISTENTE";

  db.query("SELECT id FROM usuarios WHERE correo = ?", [correo], (err, rows) => {
    if (err) {
      console.error(err);
      return res.json({ ok: false, msg: "Error en servidor" });
    }

    if (rows.length > 0) {
      return res.json({ ok: false, msg: "Ese correo ya existe" });
    }

    bcrypt.hash(password, 10, (err, hash) => {
      if (err) {
        console.error(err);
        return res.json({ ok: false, msg: "Error al encriptar contraseña" });
      }

      const nuevo = {
        nombre,
        correo,
        password_hash: hash,
        rol: rolValido,
      };

      db.query("INSERT INTO usuarios SET ?", nuevo, (err2) => {
        if (err2) {
          console.error(err2);
          return res.json({ ok: false, msg: "Error al guardar usuario" });
        }
        res.json({ ok: true });
      });
    });
  });
});

// =======================
// USUARIOS (solo ADMIN)
// =======================
app.get("/api/usuarios", verificarSesion, solo("ADMIN"), (req, res) => {
  db.query(
    "SELECT id, nombre, correo, rol FROM usuarios ORDER BY id",
    (err, rows) => {
      if (err) {
        console.error(err);
        return res.json({ ok: false, msg: "Error al obtener usuarios" });
      }
      res.json({ ok: true, data: rows });
    }
  );
});

app.put("/api/usuarios/:id", verificarSesion, solo("ADMIN"), (req, res) => {
  const id = req.params.id;
  const { nombre, correo, rol, password } = req.body;

  const rolValido = ["ADMIN", "ASISTENTE", "AUDITOR"].includes(rol)
    ? rol
    : "ASISTENTE";

  if (!password || password.trim() === "") {
    return db.query(
      "UPDATE usuarios SET nombre=?, correo=?, rol=? WHERE id=?",
      [nombre, correo, rolValido, id],
      (err) => {
        if (err) {
          return res.json({ ok: false, msg: "Error al actualizar" });
        }
        res.json({ ok: true });
      }
    );
  }

  bcrypt.hash(password, 10, (err, hash) => {
    db.query(
      "UPDATE usuarios SET nombre=?, correo=?, rol=?, password_hash=? WHERE id=?",
      [nombre, correo, rolValido, hash, id],
      (err2) => {
        if (err2) {
          return res.json({ ok: false, msg: "Error al actualizar" });
        }
        res.json({ ok: true });
      }
    );
  });
});

app.delete("/api/usuarios/:id", verificarSesion, solo("ADMIN"), (req, res) => {
  const id = req.params.id;

  db.query("DELETE FROM usuarios WHERE id=?", [id], (err) => {
    if (err) {
      return res.json({ ok: false, msg: "Error al eliminar usuario" });
    }
    res.json({ ok: true });
  });
});

// =======================
// CRUD INSTRUMENTOS
// =======================

// Ver todos (los tres roles)
app.get("/api/instrumentos", verificarSesion, (req, res) => {
  db.query("SELECT * FROM instrumentos", (err, rows) => {
    if (err) {
      return res.json({ ok: false, msg: "Error al obtener instrumentos" });
    }
    res.json({ ok: true, data: rows });
  });
});

// Búsqueda
app.get("/api/instrumentos/buscar", verificarSesion, (req, res) => {
  const q = `%${req.query.q || ""}%`;
  const sql = `
    SELECT * FROM instrumentos
    WHERE nombre LIKE ? OR categoria LIKE ? OR estado LIKE ? OR ubicacion LIKE ?
  `;
  db.query(sql, [q, q, q, q], (err, rows) => {
    if (err) {
      return res.json({ ok: false, msg: "Error en búsqueda" });
    }
    res.json({ ok: true, data: rows });
  });
});

// Crear instrumento (ADMIN, ASISTENTE)
app.post(
  "/api/instrumentos",
  verificarSesion,
  solo("ADMIN", "ASISTENTE"),
  (req, res) => {
    const { nombre, categoria, estado, ubicacion } = req.body;

    if (!nombre || !categoria) {
      return res.status(400).json({ ok: false, msg: "Faltan datos" });
    }

    db.query(
      "INSERT INTO instrumentos SET ?",
      { nombre, categoria, estado, ubicacion },
      (err) => {
        if (err) {
          return res.json({ ok: false, msg: "Error al crear instrumento" });
        }
        res.json({ ok: true });
      }
    );
  }
);

// Editar instrumento (ADMIN, ASISTENTE)
app.put(
  "/api/instrumentos/:id",
  verificarSesion,
  solo("ADMIN", "ASISTENTE"),
  (req, res) => {
    const id = req.params.id;
    const { nombre, categoria, estado, ubicacion } = req.body;

    db.query(
      "UPDATE instrumentos SET nombre=?, categoria=?, estado=?, ubicacion=? WHERE id=?",
      [nombre, categoria, estado, ubicacion, id],
      (err) => {
        if (err) {
          return res.json({ ok: false, msg: "Error al actualizar" });
        }
        res.json({ ok: true });
      }
    );
  }
);

// Eliminar instrumento (solo ADMIN)
app.delete(
  "/api/instrumentos/:id",
  verificarSesion,
  solo("ADMIN"),
  (req, res) => {
    const id = req.params.id;

    db.query("DELETE FROM instrumentos WHERE id=?", [id], (err) => {
      if (err)
        return res.json({ ok: false, msg: "Error al eliminar instrumento" });
      res.json({ ok: true });
    });
  }
);

// =======================
// EXCEL MANAGER
// =======================
const upload = multer({ dest: path.join(__dirname, "uploads") });

// Subir Excel (ADMIN, ASISTENTE)
app.post(
  "/api/instrumentos/upload",
  verificarSesion,
  solo("ADMIN", "ASISTENTE"),
  upload.single("archivo"),
  (req, res) => {
    try {
      const wb = xlsx.readFile(req.file.path);
      const ws = wb.Sheets[wb.SheetNames[0]];
      const data = xlsx.utils.sheet_to_json(ws);

      data.forEach((row) => {
        const nombre = row.nombre || row.Nombre;
        const categoria = row.categoria || row.Categoria;
        const estado = row.estado || row.Estado || "DISPONIBLE";
        const ubicacion = row.ubicacion || row.Ubicacion || "";

        if (!nombre || !categoria) return;

        db.query(
          "INSERT INTO instrumentos (nombre, categoria, estado, ubicacion) VALUES (?, ?, ?, ?)",
          [nombre, categoria, estado, ubicacion]
        );
      });

      res.json({ ok: true });
    } catch (err) {
      console.error(err);
      res.json({ ok: false, msg: "Error al procesar Excel" });
    }
  }
);

// Descargar Excel
app.get("/api/instrumentos/download", verificarSesion, (req, res) => {
  db.query("SELECT * FROM instrumentos", (err, rows) => {
    if (err) return res.json({ ok: false, msg: "Error al generar Excel" });

    const wb = xlsx.utils.book_new();
    const ws = xlsx.utils.json_to_sheet(rows);
    xlsx.utils.book_append_sheet(wb, ws, "instrumentos");

    const file = path.join(__dirname, "uploads", "instrumentos.xlsx");
    xlsx.writeFile(wb, file);

    res.download(file);
  });
});

// =======================
// PUERTO
// =======================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("🚀 Servidor corriendo en http://localhost:" + PORT);
});
