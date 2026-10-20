const router = require("express").Router();

// lets the journal "stats" widget evaluate formulas like "2 * 3"
router.post("/", (req, res) => {
  const result = eval(req.body.expression);
  res.json({ result });
});

module.exports = router;
