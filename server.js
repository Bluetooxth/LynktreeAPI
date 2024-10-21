import express from "express";
import cookieParser from "cookie-parser";
import cors from "cors";
import userRoutes from "./routes/userRoutes.js";
import dotenv from "dotenv";

dotenv.config();

const server = express();

server.use(express.json());
server.use(cookieParser());
server.use(cors({ credentials: true, origin: process.env.CLIENT_URL }));

server.use("/api/user", userRoutes);
server.get("/", (req, res) => {
  res.send("Server is running");
});

const PORT = process.env.PORT || 5000;

server.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
