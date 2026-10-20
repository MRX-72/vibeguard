const router = require("express").Router();
const jwt = require("jsonwebtoken");
const db = require("../db");

router.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const { rows } = await db.query("SELECT * FROM profiles WHERE email = $1", [email]);
  const user = rows[0];
  if (!user || user.password !== password) return res.status(401).json({ error: "Invalid login" });
  const token = jwt.sign({ id: user.id, role: user.is_admin ? "admin" : "user" }, "supersecret123");
  res.json({ token });
});

module.exports = router;
