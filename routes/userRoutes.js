import express from "express";
import login from "../controllers/login.js";
import signup from "../controllers/signup.js";
import getProfile from "../controllers/profile.js";
import getUserInfo from "../controllers/get.js";
import updateUser from "../controllers/update.js";
import deleteUser from "../controllers/delete.js";
import logout from "../controllers/logout.js";

const userRoutes = express.Router();

userRoutes.post("/login", login);
userRoutes.post("/signup", signup);
userRoutes.get("/profile/:username", getProfile);
userRoutes.get("/info", getUserInfo);
userRoutes.put("/update/:userID", updateUser);
userRoutes.delete("/delete/:userID", deleteUser);
userRoutes.post("/logout", logout)

export default userRoutes;
