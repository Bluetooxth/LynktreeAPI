import prisma from "../prisma/prismaClient.js";

const deleteUser = async (req, res) => {
  const { userID } = req.params;

  if (!userID) {
    return res.status(400).json({ message: "Please provide a user ID" });
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

    await prisma.user.delete({
      where: {
        id: userID,
      },
    });

    res.status(200).json({ message: "User deleted successfully" });
  } catch (error) {
    res.status(500).json({ message: "Internal server error" });
  }
};

export default deleteUser;
