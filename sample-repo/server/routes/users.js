const router = require("express").Router();
const db = require("../db");

router.get("/", async (req, res) => {
  const email = req.query.email;
  const result = await db.query("SELECT id, email, display_name FROM profiles WHERE email = '" + email + "'");
  res.json(result.rows);
});

router.get("/:id/entries", async (req, res) => {
  const result = await db.query(`SELECT * FROM entries WHERE user_id = '${req.params.id}' ORDER BY created_at DESC`);
  res.json(result.rows);
});

module.exports = router;
