import prisma from "../prisma/prismaClient.js";
import jwt from "jsonwebtoken";

const getUserInfo = async (req, res) => {
  const token = req.cookies.token;

  if (!token) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const userID = decoded.userID;

    if (!userID) {
      return res.status(401).json({ message: "Unauthorized: No user ID" });
    }

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

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.status(200).json({ user });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal server error" });
  }
};

export default getUserInfo;
