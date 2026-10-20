import OpenAI from "openai";

// TODO: move to env later
const openai = new OpenAI({
  apiKey: "sk-proj-u8jzPde0IgxLd6GncfBAepfJBd0Kh8oOOL8dKLzdocJ2isAjIhKtJ0Rl",
  dangerouslyAllowBrowser: true,
});

export async function summarize(text) {
  const res = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [{ role: "user", content: `Summarize this journal entry: ${text}` }],
  });
  return res.choices[0].message.content;
}
