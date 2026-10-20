const router = require("express").Router();
const OpenAI = require("openai");

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

router.post("/", async (req, res) => {
  const completion = await openai.chat.completions.create({
    model: "gpt-4o",
    messages: req.body.messages,
  });
  res.json(completion.choices[0].message);
});

module.exports = router;
