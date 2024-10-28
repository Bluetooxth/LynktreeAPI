import prisma from "../prisma/prismaClient.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();

export const signup = async (req, res) => {
  const { name, username, email, password } = req.body;

  if (!name || !username || !email || !password) {
    return res.status(400).json({ message: "All fields are required" });
  }

  try {
    const user = await prisma.user.findUnique({
      where: {
        email,
      },
    });

    if (user) {
      return res.status(400).json({ message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    const newUser = await prisma.user.create({
      data: {
        name,
        username,
        email,
        password: hashedPassword,
      },
    });

    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    res.status(500).json({ message: "Internal server error" });
  }
};

export const login = async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "All fields are required" });
  }

  try {
    const user = await prisma.user.findUnique({
      where: {
        email,
      },
    });

    if (!user) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const isPasswordCorrect = await bcrypt.compare(password, user.password);

    if (!isPasswordCorrect) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign({ userID: user.id }, process.env.JWT_SECRET, {
      expiresIn: "24h",
    });

    res.cookie("token", token, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      maxAge: 24 * 60 * 60 * 1000,
      partitioned: true
    });

    res.status(200).json({ message: "User logged in successfully" });
  } catch (error) {
    res.status(500).json({ message: "Internal server error" });
  }
};

export const logout = (req, res) => {
  res.clearCookie("token", { path: "/" });
  res.status(200).json({ message: "User logged out successfully" });
};

export const usrDelete = async (req, res) => {
  const token = req.cookies.token;

  if (!token) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  try {
    const { userID } = jwt.verify(token, process.env.JWT_SECRET);

    await prisma.user.delete({
      where: {
        id: userID,
      },
    });

    res.clearCookie("token", { path: "/" });

    res.status(200).json({ message: "User deleted successfully" });
  } catch (error) {
    res.status(500).json({ message: "Internal server error" });
  }
};

export const usrGet = async (req, res) => {
  const token = req.cookies.token;

  if (!token) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  try {
    const { userID } = jwt.verify(token, process.env.JWT_SECRET);

    const user = await prisma.user.findUnique({
      where: {
        id: userID,
      },
      select: {
        id: true,
        name: true,
        username: true,
        email: true,
        tagline: true,
        profile_url: true,
        links: {
          select: {
            id: true,
            name: true,
            url: true,
            icon: true,
          },
        },
      },
    });

    res.status(200).json(user);
  } catch (error) {
    res.status(500).json({ message: "Internal server error" });
  }
};

export const usrProfile = async (req, res) => {
  const { username } = req.params;

  if (!username) {
    return res.status(400).json({ message: "Username is required" });
  }

  try {
    const user = await prisma.user.findUnique({
      where: {
        username,
      },
      select: {
        id: true,
        name: true,
        username: true,
        tagline: true,
        profile_url: true,
        links: {
          select: {
            id: true,
            name: true,
            url: true,
            icon: true,
          },
        },
      },
    });

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.status(200).json(user);
  } catch (error) {
    res.status(500).json({ message: "Internal server error" });
  }
};

export const usrUpdate = async (req, res) => {
  const { userID } = req.params;
  const { name, username, email, password, tagline, profile_url, links } =
    req.body;

  if (!userID) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  try {
    const user = await prisma.user.findUnique({
      where: {
        id: userID,
      },
    });

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const updatedData = {
      name: name,
      username: username,
      email: email,
      tagline: tagline,
      profile_url: profile_url,
    };

    if (password) {
      updatedData.password = await bcrypt.hash(password, 12);
    }

    await prisma.links.deleteMany({
      where: {
        userID: userID,
      },
    });

    await prisma.user.update({
      where: {
        id: userID,
      },
      data: {
        ...updatedData,
        links: {
          create: links.map((link) => ({
            name: link.name,
            url: link.url,
            icon: link.icon,
          })),
        },
      },
    });

    res.status(200).json({ message: "User updated successfully" });
  } catch (error) {
    res.status(500).json({ message: "Internal server error" });
  }
};
