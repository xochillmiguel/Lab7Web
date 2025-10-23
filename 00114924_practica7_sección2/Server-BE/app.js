import express from "express";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import bodyParser from "body-parser";
import cors from "cors";

const app = express();
const PORT = 5000;
const JWT_SECRET = "your_jwt_secret"; //En producción usa una clave más fuerte y guárdala en una variable de entorno (.env)

app.use(bodyParser.json());
app.use(cors());

// Agregando un usuario de prueba con contraseña encriptada
const hashedPassword = bcrypt.hashSync("12345", 10);
const users = [
  {
    id: 1,
    email: "test@uca.edu.sv",
    password: hashedPassword,
  },
];

//Middleware: Verificar el token JWT
const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ message: "Unauthorized" });

  const token = authHeader.split(" ")[1];
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid token" });
    req.user = user;
    next();
  });
};

//Ruta para iniciar sesión
app.post("/signin", async (req, res) => {
  const { email, password } = req.body;
  const user = users.find((u) => u.email === email);
  if (!user) return res.status(404).json({ message: "User not found" });

  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid)
    return res.status(400).json({ message: "Invalid credentials" });

  // Generar token JWT con una duración de 1 hora
  const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: "1h" });
  res.status(200).json({ token });
});

app.get("/protected", verifyToken, (req, res) => {
  res.status(200).json({ message: "Protected data accessed", user: req.user });
});

app.listen(PORT, () =>
  console.log(`Server running at http://localhost:${PORT}`)
);
