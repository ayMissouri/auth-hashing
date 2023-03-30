const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient();
const router = express.Router();
const secret = process.env.JWT_SECRET;

router.post("/register", async (req, res) => {
  const { password } = req.body;

  const hash = await bcrypt.hash(password, 10);
  try {
    const user = await prisma.user.create({
      data: { ...req.body, password: hash },
    });
    res.json({ user: { id: user.id, username: user.username } });
  } catch (e) {
    res.status(500).json({ error: e });
  }
});

router.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const doesUserExist = await prisma.user.findUnique({
    where: { username: username },
  });
  const doesPasswordMatch = await bcrypt.compare(
    password,
    doesUserExist.password
  );

  if (!doesUserExist) {
    res.status(401).json({ error: "Invalid Username." });
  } else if (!doesPasswordMatch) {
    res.status(401).json({ error: "Invalid Password." });
  } else {
    res.json(jwt.sign(doesUserExist.username, secret));
  }
});

module.exports = router;
