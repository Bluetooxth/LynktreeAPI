const logout = async (req, res) => {
    res.clearCookie("token",{
        httpOnly: true,
        sameSite: "None",
        secure: true,
    })
    res.status(200).json({ message: "Logout successful" });
}

export default logout;