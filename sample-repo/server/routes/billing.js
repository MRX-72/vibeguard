const router = require("express").Router();
const db = require("../db");

// Stripe calls this after checkout.
router.post("/webhook", async (req, res) => {
  const event = req.body;

  if (event.type === "checkout.session.completed") {
    const session = event.data.object;
    await db.query("UPDATE profiles SET plan = 'pro' WHERE id = $1", [session.client_reference_id]);
  }

  res.json({ received: true });
});

module.exports = router;
