import express from "express";
import cookieParser from "cookie-parser";
import cors from "cors";
import dotenv from "dotenv";

import {
  login,
  signup,
  usrDelete,
  usrGet,
  usrProfile,
  usrUpdate,
} from "./controllers/userRoutes.js";

dotenv.config();

const app = express();

app.use(
  cors({
    origin: "https://lynktree.vercel.app",
  })
);

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

app.get("/", (req, res) => {
  res.send("Hello from Lynktree");
});

app.post("/api/user/signup", signup);
app.post("/api/user/login", login);
app.delete("/api/user/delete", usrDelete);
app.get("/api/user/get", usrGet);
app.get("/api/user/profile/:username", usrProfile);
app.put("/api/user/update/:userID", usrUpdate);

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
