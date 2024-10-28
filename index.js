import express from "express";
import cookieParser from "cookie-parser";
import cors from "cors";
import dotenv from "dotenv";

import { login } from "./controllers/userRoutes.js";
import { signup } from "./controllers/userRoutes.js";
import { logout } from "./controllers/userRoutes.js";
import { usrDelete } from "./controllers/userRoutes.js";
import { usrGet } from "./controllers/userRoutes.js";
import { usrProfile } from "./controllers/userRoutes.js";
import { usrUpdate } from "./controllers/userRoutes.js";

dotenv.config();

const app = express();

app.use(cors({
  origin: process.env.CLIENT_URL,
  methods: "GET, POST, PUT, DELETE",
  allowedHeaders: "Content-Type, Authorization",
  credentials: true
}));

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

app.get("/", (req, res) => {
  res.send("Hello from Lynktree");
});

app.post("/api/user/signup", signup);
app.post("/api/user/login", login);
app.get("/api/user/logout", logout);
app.delete("/api/user/delete", usrDelete);
app.get("/api/user/get", usrGet);
app.get("/api/user/profile/:username", usrProfile);
app.put("/api/user/update/:userID", usrUpdate);

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});