import prisma from "../prisma/prismaClient.js";
import bcrypt from "bcrypt";

const updateUser = async (req, res) => {
  const { userID } = req.params;
  const { name, username, email, password, tagline, profile_url, links } = req.body;

  if (!userID) {
    return res.status(400).json({ message: "Please provide a user ID" });
  }

  try {
    const user = await prisma.user.findUnique({
      where: { id: userID },
    });

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const updatedData = {
      username,
      name,
      email,
      profile_url,
      tagline,
    };

    if (password) {
      const hashedPassword = await bcrypt.hash(password, 10);
      updatedData.password = hashedPassword;
    }

    await prisma.links.deleteMany({
      where: { userID: userID },
    });

    const newLinks = links ? 
      links.map(link => ({
        name: link.name,
        url: link.url,
        icon: link.icon,
      })) : [];

    const updatedUser = await prisma.user.update({
      where: { id: userID },
      data: {
        ...updatedData,
        links: {
          create: newLinks.map(link => ({
            name: link.name,
            url: link.url,
            icon: link.icon,
          })),
        },
      },
    });

    res.status(200).json({ message: "User updated successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal server error" });
  }
};

export default updateUser;