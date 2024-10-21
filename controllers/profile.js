import prisma from "../prisma/prismaClient.js";

const getProfile = async (req, res) => {
  const { username } = req.params;

  if (!username) {
    return res.status(400).json({ message: "Please provide a username" });
  }

  try {
    const profile = await prisma.user.findUnique({
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

    if (!profile) {
      return res.status(404).json({ message: "Profile not found" });
    }

    res.status(200).json({ profile });
  } catch (error) {
    res.status(500).json({ message: "Internal server error" });
  }
};

export default getProfile;
