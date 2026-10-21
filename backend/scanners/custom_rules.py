"""VibeGuard's own rules (§7): the mistakes AI app builders make that generic scanners don't know about.

Three engines, one catalog:
- semgrep taint rules (rules/vibe-coded.yml) prove request/URL data reaches a sink -> "Confirmed reachable".
  They ride along in the main semgrep run (a second run would cost 26-50 s on Render) and come back through from_semgrep().
- ast-grep rules (rules/ast-grep/rules/*.yml) for structural patterns, run by VibeRules below.
- Python checks for files that aren't JS/TS: env files, Supabase migrations, Firebase rules, plus cross-file checks.

Every finding gets its words from CATALOG, so a rule's title, severity, fix and re-prompt are written once.
"""

import json
import re
from datetime import date
from pathlib import Path

from models import Finding

from . import supabase_sql
from .base import EXCLUDE, PLACEHOLDER, TEST_PATH, Scanner, classify_secret, read_json, rel, snippet

RULES = Path(__file__).resolve().parent.parent / "rules"
AST_GREP = RULES / "ast-grep" / "sgconfig.yml"
JS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts")
SKIP_DIRS = {"node_modules", ".git", "dist", "build", ".next", "out", "coverage", ".vercel", ".netlify", ".turbo"}

# rule -> base text; VARIANTS override per variant. {name} placeholders are filled from the hit.
CATALOG = {
    "frontend-secret": dict(
        severity="Critical", kind="secret", cwe=["CWE-200", "CWE-798"],
        title="{noun} exposed in the browser",
        impact="Anyone who opens your site can copy this key out of its JavaScript and use it. They don't need your code.",
        reason="Code that runs in the browser is public: every visitor downloads it, so a key in it is published.",
        fix="- {var}=…\n+ {server_var}=…   # no {prefix} prefix, so only server code can read it\n# and stop committing env files: add them to .gitignore",
        reprompt="Move every call that uses the {noun} into server code (an API route or a Supabase Edge Function) and read the key "
                 "there from an environment variable without a public prefix ({server_var}). The browser should call your route, never "
                 "the provider directly. Then rotate the key: the old value has already been published.",
        refs=["{doc}"],
    ),
    "supabase-rls-off": dict(
        severity="Critical", kind="config", cwe=["CWE-862"],
        title="Row-Level Security is off for {table}",
        impact="Anyone on the internet can read, change or delete every row in {table}.",
        reason="No login and no special key needed: the public anon key in your site's JavaScript is enough.",
        explanation="Supabase serves every table in the public schema through its API, and the key needed to call it ships in your "
                    "site's JavaScript. {table} has no Row-Level Security{disabled}, so anyone can read, change or delete every row "
                    "with a few lines of code.",
        fix="+ alter table {table} enable row level security;\n{policy_fix}",
        reprompt="Write a new Supabase migration that enables Row-Level Security on {table} and adds policies so signed-in users "
                 "can only read and change their own rows{owner_hint}. Put any admin-only access in policies that check an admin "
                 "role stored in the database, never in React code.",
        refs=["https://supabase.com/docs/guides/database/postgres/row-level-security"],
    ),
    "firebase-open-rules": dict(
        severity="Critical", kind="config", cwe=["CWE-284"],
        title="Firebase rules let anyone {ops} {scope}",
        impact="Anyone on the internet can {ops_verb} {scope_data}.",
        reason="Your Firebase config is in your site's JavaScript, so anyone can talk to the database directly, skipping your app.",
        explanation="{file} allows {ops} on {path} {cond}. Firebase serves this {service} straight to browsers, and the config "
                    "needed to reach it is public by design, so these rules are the only thing standing between strangers and your data.",
        fix="- allow {raw_ops}: {raw_cond};\n+ allow {raw_ops}: if request.auth != null && request.auth.uid == userId;",
        reprompt="Rewrite {file} so every rule checks who is asking: signed-in users may only read and write their own documents "
                 "(request.auth.uid matches the document's owner), and nothing is open to everyone unless it's truly public content. "
                 "Test the rules in the Firebase emulator before deploying.",
        refs=["https://firebase.google.com/docs/rules/insecure-rules"],
    ),
    "client-only-auth": dict(
        severity="High", kind="code", cwe=["CWE-602"],
        title="Admin access decided in the browser",
        impact="Any visitor can give themselves admin powers over whatever this check protects.",
        reason="Checks in browser code can be skipped or edited by anyone with developer tools.",
        reprompt="In {file}, stop relying on browser-side checks for admin access. Store roles in a Supabase table users can't "
                 "edit, enforce them in Row-Level Security policies (or a server function), and keep the React check only to hide buttons.",
        refs=["https://supabase.com/docs/guides/database/postgres/custom-claims-and-role-based-access-control-rbac"],
    ),
    "cors-wildcard": dict(
        severity="High", kind="code", cwe=["CWE-346", "CWE-942"],
        title="API trusts every website with your users' logins",
        impact="Any website your users visit can make requests to your API as them and read the answers.",
        reason="Allowing credentials for every origin turns any website into a client of your API, logged in as the visitor.",
        explanation="{file}:{line} accepts any Origin and also allows credentials (cookies). So any website a signed-in user visits "
                    "can call your API with their cookies and read the responses.",
        fix="- origin: true,\n+ origin: [\"https://your-app.com\"],   // only your own site(s)",
        reprompt="In {file}, replace the CORS setup with an explicit list of the origins that may call this API (your production "
                 "and preview domains). Never echo the request's Origin while allowing credentials.",
        refs=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS#requests_with_credentials"],
    ),
    "xss-sink": dict(
        severity="High", kind="code", cwe=["CWE-79"],
        title="Text from the page URL is rendered as HTML",
        impact="Anyone can send your users a link that runs their own code on your site, stealing sessions or acting as them.",
        reason="It runs in your users' browsers with their session, and all it takes is a crafted link.",
        explanation="{file}:{line} puts data from the URL or request into HTML without escaping it. Anyone can craft a link that "
                    "makes your page run their JavaScript for whoever opens it.",
        fix="{line_fix}",
        reprompt="In {file}, render user-controlled text as plain JSX text (React escapes it) instead of with "
                 "dangerouslySetInnerHTML or innerHTML. Where HTML is really needed, pass it through DOMPurify.sanitize() first.",
        refs=["https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html",
              "https://github.com/cure53/DOMPurify"],
    ),
    "sql-string-concat": dict(
        severity="Critical", kind="code", cwe=["CWE-89"],
        title="SQL query built from request data",
        impact="Anyone can read, change or delete anything in your database, including other users' data and password hashes.",
        reason="It's exploitable with one crafted request and exposes the whole database.",
        explanation="{file}:{line} builds a SQL query by pasting request data into the query text. Anyone can send input that "
                    "closes the string and adds their own SQL.",
        fix="{line_fix}",
        reprompt="In {file}, make every SQL query parameterized: keep the query text constant and pass values separately "
                 "(db.query(\"... WHERE id = $1\", [id])). Never build SQL with + or template strings.",
        refs=["https://node-postgres.com/features/queries#parameterized-query", "https://owasp.org/www-community/attacks/SQL_Injection"],
    ),
    "no-rate-limit": dict(
        severity="Medium", kind="config", cwe=["CWE-770"],
        title="No rate limit on login and sign-up endpoints",
        impact="Attackers can try passwords and one-time codes as fast as your server answers.",
        reason="Brute force needs no skill, only time, and nothing here slows it down.",
        explanation="{method} {path} has no rate limit, and nothing else in the project limits requests.",
        fix="{fix_text}",
        reprompt="Add rate limiting to every login, sign-up, password-reset and one-time-code endpoint (for Express, "
                 "express-rate-limit with about 10 attempts per 15 minutes per IP), and return 429 when it's exceeded.",
        refs=["https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#protect-against-automated-attacks"],
    ),
    "debug-in-prod": dict(
        severity="Medium", kind="config", cwe=["CWE-489"],
        title="Debug settings turned on in production config",
        impact="Anyone who triggers an error sees stack traces and internal details that help them plan an attack.",
        reason="It doesn't give access by itself, but it hands attackers a map of your app.",
        explanation="{file} sets {setting_line}, which turns on debug output in production.",
        fix="- {setting_line}\n+ {setting_off}",
        reprompt="Turn off debug output in production: set debug flags to false in {file}, log errors on the server, and return "
                 "only a generic message to users.",
        refs=["https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html"],
    ),
    "eval-user-input": dict(
        severity="Critical", kind="code", cwe=["CWE-95"],
        title="Request data is run as code",
        impact="Anyone can run their own code on your server: read your keys and database, or take the server over.",
        reason="One request is enough, and it gives full control of the server.",
        explanation="{file}:{line} passes request data to {sink}, which runs it as JavaScript on your server. Anyone can send "
                    "code instead of the input you expect.",
        fix="{line_fix}",
        reprompt="In {file}, never run request data as code. Parse the input into the exact shape you expect (for formulas, "
                 "use a math parser like mathjs's evaluate(), which can't run code) and reject anything else.",
        refs=["https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval#never_use_direct_eval!"],
    ),
    "unrestricted-upload": dict(
        severity="Medium", kind="code", cwe=["CWE-434"],
        title="File uploads accept any type and size",
        impact="Anyone can fill your disk with huge files or upload files of any type.",
        reason="Uploads with no limits are an easy way to take a server down or store anything on it.",
        explanation="{file}:{line} accepts uploads with no fileFilter and no size limits.",
        fix="- {line_text}\n+ const upload = multer({\n+   dest: \"uploads/\",   // outside public/\n"
            "+   limits: { fileSize: 5 * 1024 * 1024 },\n+   fileFilter: (req, file, cb) => cb(null, [\"image/png\", \"image/jpeg\"].includes(file.mimetype)),\n+ })",
        reprompt="In {file}, limit uploads: set a maximum file size, allow only the file types the feature needs (check the "
                 "MIME type and extension), store them outside any publicly served folder, and give them random names.",
        refs=["https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html"],
    ),
    "supabase-edge-service-role-no-auth": dict(
        severity="High", kind="code", cwe=["CWE-306"],
        title="Edge Function uses the service-role key without checking who's calling",
        impact="Any visitor can trigger this function and make it read, change or delete data in your database with full admin rights.",
        reason="Anyone who finds the function's URL gets admin access to your database.",
        explanation="Supabase Edge Functions can be called by anyone with your project's anon key, and that key ships in your "
                    "site's JavaScript. This function builds a client with the service-role key, which ignores Row-Level Security, "
                    "and nothing in the file checks who the caller is: no auth.getUser(), no Authorization header check.",
        fix="+ const auth = req.headers.get(\"Authorization\") ?? \"\"\n+ const { data: { user } } = await createClient(Deno.env.get(\"SUPABASE_URL\")!, "
            "Deno.env.get(\"SUPABASE_ANON_KEY\")!, {\n+   global: { headers: { Authorization: auth } },\n+ }).auth.getUser()\n"
            "+ if (!user) return new Response(\"Unauthorized\", { status: 401 })",
        reprompt="In {file}, check the caller before using the service-role client: read the Authorization header, call "
                 "supabase.auth.getUser() with it, return 401 if there's no user, and only read or change rows that belong to that user.",
        refs=["https://supabase.com/docs/guides/functions/auth"],
    ),
    "supabase-getsession-on-server": dict(
        severity="Medium", kind="code", cwe=["CWE-287"],
        title="Server code trusts supabase.auth.getSession()",
        impact="Someone can send a forged session and your server code treats them as a signed-in user.",
        reason="An attacker needs a crafted request, and it only matters where the session decides access.",
        explanation="On the server, getSession() reads the session from the request's cookies or storage without checking it with "
                    "Supabase, so a tampered or expired token passes. Supabase's docs say never to trust it in server code; getUser() "
                    "(or getClaims()) verifies the token.",
        fix="- const { data: { session } } = await supabase.auth.getSession()\n+ const { data: { user } } = await supabase.auth.getUser()",
        reprompt="In {file}, replace supabase.auth.getSession() with supabase.auth.getUser() for every server-side auth decision, "
                 "and use the returned user (not session.user) to decide what the caller may do.",
        refs=["https://supabase.com/docs/reference/javascript/auth-getsession"],
    ),
    "supabase-privilege-escalation": dict(
        severity="Critical", kind="config", cwe=["CWE-269"],
        title="Anyone can sign up as an admin",
        impact="Anyone can create an account with admin rights and use everything an admin can.",
        reason="It takes one sign-up call with an extra field, and it unlocks everything admins can do.",
        explanation="{fn} copies {key} from the new user's sign-up metadata into {target}. The person signing up chooses that "
                    "metadata (supabase.auth.signUp({ options: { data: { {key}: ... } } })), so they can pick their own role.",
        fix="- {line_text}\n+ -- never take roles from sign-up data: give everyone the lowest role, and promote admins by hand\n"
            "+ insert into public.profiles (id, email) values (new.id, new.email);",
        reprompt="In the {fn} function, stop reading {key} from raw_user_meta_data: new users should always get the default "
                 "(lowest) role. Grant admin rights only from the database (an admin-only policy or the Supabase dashboard).",
        refs=["https://supabase.com/docs/guides/database/postgres/custom-claims-and-role-based-access-control-rbac",
              "https://supabase.com/docs/guides/auth/managing-user-data#accessing-user-metadata"],
    ),
    "supabase-rpc-exposed": dict(
        severity="High", kind="config", cwe=["CWE-306"],
        title="{audience_cap} can run {fn} through your API",
        impact="{audience_cap} can call {fn} with any arguments, and it runs with full database rights.",
        reason="SECURITY DEFINER skips Row-Level Security, and Supabase serves every public function at /rest/v1/rpc.",
        explanation="{fn} runs as SECURITY DEFINER, so it ignores Row-Level Security, and Supabase exposes every function in the "
                    "public schema at /rest/v1/rpc/{short}. Nothing in it checks who's calling, so {audience} can call it with "
                    "supabase.rpc(\"{short}\", …). {revoke_note}",
        fix="+ -- only your server or a cron job should run it:\n+ revoke execute on function {fn} from public, anon, authenticated;\n"
            "+ -- or, if users call it, check them first inside the function:\n+ if (select auth.uid()) is null then raise exception 'not allowed'; end if;",
        reprompt="For the Postgres function {fn}: if only the server or a scheduled job runs it, revoke EXECUTE from public, "
                 "anon and authenticated in a new migration. If app users call it, add a check at the top that the caller "
                 "(auth.uid()) is allowed to act on the rows it touches, or make it SECURITY INVOKER so Row-Level Security applies.",
        refs=["https://supabase.com/docs/guides/database/functions#security-definer-vs-invoker",
              "https://supabase.com/docs/guides/database/database-linter?lint=0028_anon_security_definer_function_executable"],
    ),
    "supabase-storage-open": dict(
        severity="Critical", kind="config", cwe=["CWE-732"],
        title="{audience_cap} can overwrite or delete files in {bucket}",
        impact="{audience_cap} can replace or delete files that belong to other users.",
        reason="Storage policies are the only thing between the internet and your files.",
        explanation="Storage policy \"{policy}\" ({file}:{line}) lets {audience} {cmd_text} in {bucket} and only checks the bucket "
                    "name, not who owns the file.",
        fix="- {using_text}\n+ bucket_id = '{bucket_id}' and (select auth.uid())::text = (storage.foldername(name))[1]",
        reprompt="Rewrite the storage policies for {bucket} so users can only touch files in their own folder: check "
                 "(storage.foldername(name))[1] = auth.uid()::text, and upload each user's files under their user id.",
        refs=["https://supabase.com/docs/guides/storage/security/access-control"],
    ),
    "plaintext-password": dict(
        severity="High", kind="code", cwe=["CWE-256"],
        title="Passwords are stored in plain text",
        impact="Anyone who gets a copy of your database (a leak, a backup, an open table) can log in as every user, and try "
               "the same passwords on their email and bank accounts.",
        reason="One database leak exposes every user's password, everywhere they reused it.",
        explanation="{file}:{line} compares the password someone typed with the stored one directly, which only works if "
                    "passwords are saved as-is. They should be stored as slow, salted hashes (bcrypt or argon2) and checked "
                    "with the library's compare function.",
        fix="- {line_text}\n+ {line_fix}",
        reprompt="In {file}, store passwords only as bcrypt (or argon2) hashes: hash on sign-up and password change with "
                 "bcrypt.hash(password, 12), and check logins with bcrypt.compare(). Migrate existing users by asking them to reset "
                 "their password. Or let Supabase Auth handle passwords entirely.",
        refs=["https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html"],
    ),
    "jwt-no-expiry": dict(
        severity="Medium", kind="code", cwe=["CWE-613"],
        title="Login tokens never expire",
        impact="A token that leaks once (a shared screenshot, a log, a stolen laptop) works forever, and you can't log anyone out.",
        reason="It doesn't open anything by itself, but it turns every token leak into permanent access.",
        explanation="{file}:{line} signs a login token with no expiry (no expiresIn and no exp claim), so it stays valid until "
                    "you change the signing secret for everyone.",
        fix="- {line_text}\n+ {line_fix}",
        reprompt="In {file}, give every login token a short lifetime (jwt.sign(payload, secret, { expiresIn: \"1h\" })) and add "
                 "refresh tokens if users need to stay logged in longer.",
        refs=["https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html#token-explicit-revocation-by-the-user"],
    ),
    "mass-assignment": dict(
        severity="High", kind="code", cwe=["CWE-915"],
        title="The whole request body is saved to the database",
        impact="Users can set any column they like on the row, such as is_admin, plan or another user's id.",
        reason="It needs only one extra field in a request the app already sends.",
        explanation="{file}:{line} passes the request body straight into a database write, so every field the caller sends is "
                    "saved, including ones your form never shows.",
        fix="- {line_text}\n+ const { display_name, bio } = req.body   // only the fields users may change\n"
            "+ … .update({ display_name, bio })",
        reprompt="In {file}, never pass req.body (or the parsed request) directly to insert/update/create. Pick the allowed "
                 "fields explicitly, validate them (for example with zod), and set ownership fields like user_id from the session.",
        refs=["https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html"],
    ),
    "ai-open-proxy": dict(
        severity="Medium", kind="code", cwe=["CWE-284"], money_risk=True,
        title="Anyone can use your AI endpoint as a free chatbot",
        impact="Anyone can use your AI key for whatever they want (their own apps, spam, jailbreaks) and you get the bill.",
        reason="It's direct cost exposure, and abuse of AI endpoints is common and automated.",
        explanation="{file}:{line} sends the conversation exactly as the caller wrote it, with no system prompt of your own, so "
                    "the endpoint answers anything, not just what your feature is for.",
        fix="- messages: req.body.messages,\n+ messages: [\n+   { role: \"system\", content: \"You help with <your feature> only. Refuse anything else.\" },\n"
            "+   { role: \"user\", content: String(req.body.text).slice(0, 4000) },\n+ ],",
        reprompt="In {file}, build the AI request on the server: your own system prompt, only the user's text (with a length "
                 "limit), a fixed model and max_tokens. Don't accept whole message arrays or model names from the browser, and "
                 "require sign-in plus a per-user rate limit.",
        refs=["https://genai.owasp.org/llmrisk/llm102025-unbounded-consumption/"],
    ),
    "webhook-unsigned": dict(
        severity="High", kind="code", cwe=["CWE-345"], money_risk=True,
        title="{provider} webhook handled without checking its signature",
        impact="Anyone can send a fake \"{event}\" event and your app will act on it.",
        reason="Webhook URLs are easy to guess, and the app trusts whatever arrives.",
        explanation="This code handles {provider}'s \"{event}\" event, but nothing in the file verifies the request's signature "
                    "with your webhook secret. Anyone can POST that event to the endpoint.",
        fix="+ // verify before trusting: {verify_hint}\n+ if (!valid) return res.status(400).send(\"bad signature\")",
        reprompt="In {file}, verify every {provider} webhook signature with your webhook secret (from the environment) before "
                 "handling the event, using {provider}'s official SDK or HMAC check on the raw request body, and reject anything "
                 "that doesn't match.",
        refs=["{doc}"],
    ),
    "missing-auth": dict(
        severity="High", kind="code", cwe=["CWE-306"],
        title="Your API hands out login tokens but never checks them",
        impact="Every endpoint answers anyone. Logging in changes nothing: the data and actions are open without it.",
        reason="It's the same as having no login at all, for every route at once.",
        explanation="{file}:{line} creates login tokens, but nothing in your server code ever verifies one (no jwt.verify(), "
                    "no auth middleware), so none of your routes know who's calling.",
        fix="+ function requireUser(req, res, next) {\n+   try {\n+     req.user = jwt.verify(req.headers.authorization?.replace(\"Bearer \", \"\"), process.env.JWT_SECRET)\n"
            "+     next()\n+   } catch {\n+     res.status(401).json({ error: \"Sign in first\" })\n+   }\n+ }\n"
            "+ app.use(\"/api/users\", requireUser, require(\"./routes/users\"))   // and every other private route",
        reprompt="Add an auth middleware that verifies the login token (jwt.verify with the secret from the environment) and "
                 "puts the user on req.user, apply it to every route except login and sign-up, and use req.user.id (never an id "
                 "from the URL or body) to decide whose data a request can touch.",
        refs=["https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"],
    ),
    "stripe-webhook-unsigned": dict(
        severity="High", kind="code", cwe=["CWE-345"], money_risk=True,
        title="Stripe webhook handled without checking Stripe's signature",
        impact="Anyone can fake a successful payment and get paid features, credits or orders for free.",
        reason="It's direct money loss, and webhook URLs are easy to guess.",
        explanation="This code reacts to Stripe payment events, but nothing in the file verifies the Stripe-Signature header with "
                    "stripe.webhooks.constructEvent(). Anyone can POST a fake \"payment succeeded\" event to it.",
        fix="- const event = req.body\n+ const event = stripe.webhooks.constructEvent(\n+   rawBody, // the unparsed request body, e.g. from express.raw()\n"
            "+   req.headers[\"stripe-signature\"],\n+   process.env.STRIPE_WEBHOOK_SECRET,\n+ )",
        reprompt="In {file}, verify every Stripe webhook before trusting it: read the raw request body, call "
                 "stripe.webhooks.constructEvent(rawBody, the stripe-signature header, STRIPE_WEBHOOK_SECRET from the environment), "
                 "return 400 if it throws, and only then handle the event.",
        refs=["https://docs.stripe.com/webhooks#verify-official-libraries"],
    ),
}

POLICY_REPROMPT = ("In a new Supabase migration, drop policy \"{policy}\" on {table} and replace it with one that only matches the "
                  "caller's own rows{owner_hint}, unless every row of this table is really meant to be open to {audience}.")

VARIANTS = {
    ("frontend-secret", "env-file"): dict(
        explanation="{var} starts with {prefix}, so {framework} copies its value into the JavaScript every visitor downloads. "
                    "{what_cap} is meant to stay on a server."),
    ("frontend-secret", "code-env"): dict(
        kind="code", title="{noun} read in browser code",
        explanation="{file} reads {var}. Because of the {prefix} prefix, the build replaces it with the actual value, so the key "
                    "ends up in the JavaScript every visitor downloads.",
        fix="- {line_text}\n+ // call your own API route or Edge Function here; it reads {server_var} on the server"),
    ("frontend-secret", "browser-sdk"): dict(
        kind="code", title="AI SDK set to run in the browser", money_risk=True,
        impact="Anyone can copy the key from your site and run up your AI bill or drain its quota.",
        explanation="dangerouslyAllowBrowser: true makes the SDK run in visitors' browsers, so whatever API key it uses is sent to "
                    "every visitor. The option's name is the SDK's own warning.",
        fix="- const openai = new OpenAI({ apiKey, dangerouslyAllowBrowser: true })\n+ // in a server route or Edge Function:\n"
            "+ const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY })",
        evidence=["Line {flag_line}: dangerouslyAllowBrowser: true makes the SDK run in the browser"]),
    ("frontend-secret", "literal"): dict(
        title="{noun} hardcoded in browser code",
        explanation="{file} runs in visitors' browsers, so this key is part of the JavaScript every visitor downloads, not just "
                    "your repository. Rotate it{rotate_at}, then move the call to the server.",
        fix="- {line_text}\n+ // the browser calls your API route; the route reads {server_var} from the environment"),
    ("supabase-rls-off", "open-write"): dict(
        title="Anyone can {verbs} every row in {table}",
        impact="Anyone on the internet can {verbs} any row in {table}.",
        explanation="Policy \"{policy}\" ({file}:{line}) lets {audience} {cmd_text} with a condition of true, so it doesn't limit "
                    "anything. Policies add up, so one open policy opens the table.",
        fix="- create policy \"{policy}\" on {table} for {cmd} using (true);\n{policy_fix}", reprompt=POLICY_REPROMPT),
    ("supabase-rls-off", "signed-in-write"): dict(
        severity="High", title="Any signed-in user can {verbs} every row in {table}",
        impact="If anyone can sign up for your app, anyone can {verbs} every row in {table}.",
        reason="Signing up is usually open, so \"signed in\" means \"anyone with an email address\".",
        explanation="Policy \"{policy}\" ({file}:{line}) only checks that the caller is signed in. If only invited staff can sign "
                    "in to this project, that may be intended; otherwise every user can {verbs} everyone's rows.",
        fix="- create policy \"{policy}\" on {table} for {cmd} to authenticated using (true);\n{policy_fix}", reprompt=POLICY_REPROMPT),
    ("supabase-rls-off", "open-read"): dict(
        severity="High", title="Anyone can read every row in {table}",
        impact="Anyone on the internet can read every row in {table}.",
        reason="If this table holds personal data, it's a data leak; the table's name suggests it might.",
        explanation="Policy \"{policy}\" ({file}:{line}) lets anyone, without signing in, read every row in {table}. That's right for "
                    "public content like published posts, and wrong for personal data.",
        fix="- create policy \"{policy}\" on {table} for select using (true);\n{policy_fix}", reprompt=POLICY_REPROMPT),
    ("supabase-rls-off", "signed-in-read"): dict(
        severity="Medium", title="Any signed-in user can read every row in {table}",
        impact="If anyone can sign up for your app, anyone can read every row in {table}.",
        reason="Signing up is usually open, and the table's name suggests personal data.",
        explanation="Policy \"{policy}\" ({file}:{line}) lets every signed-in user read every row in {table}, not just their own.",
        fix="- create policy \"{policy}\" on {table} for select to authenticated using (true);\n{policy_fix}", reprompt=POLICY_REPROMPT),
    ("supabase-rls-off", "open-insert"): dict(
        severity="Medium", title="Anyone can add rows to {table}",
        impact="Anyone can add rows to {table}, including rows that claim to belong to someone else.",
        reason="Fine for public forms like a waitlist; risky when rows carry an owner.",
        explanation="Policy \"{policy}\" ({file}:{line}) lets {audience} insert any row into {table}. If rows belong to users, "
                    "check the new row's owner is the caller.",
        fix="- with check (true)\n+ with check ((select auth.uid()) = {owner_or_user_id})", reprompt=POLICY_REPROMPT),
    ("supabase-rls-off", "view"): dict(
        severity="High", title="View {table} skips Row-Level Security",
        impact="Anyone can read, through {table}, rows that Row-Level Security hides on the underlying tables.",
        reason="Supabase's own security advisor treats this as an error.",
        explanation="Postgres views run with their creator's rights unless they're created with security_invoker, so {table} "
                    "returns rows from the tables it reads even where Row-Level Security would hide them. Supabase serves it to "
                    "browsers like any table.",
        fix="- create view {table} as\n+ create view {table} with (security_invoker = true) as",
        reprompt="In a new Supabase migration, recreate the view {table} with (security_invoker = true) so it respects the "
                 "Row-Level Security of the tables it reads.",
        refs=["https://supabase.com/docs/guides/database/database-linter?lint=0010_security_definer_view"]),
    ("firebase-open-rules", "test-mode"): dict(
        title="Firebase test-mode rules: open to everyone until {until}",
        explanation="{file} uses Firebase's test-mode rule, which allows {ops} on {path} for anyone until {until}. Firebase serves "
                    "this {service} straight to browsers, and the config needed to reach it is public by design."),
    ("firebase-open-rules", "signed-in-all"): dict(
        severity="High", title="Any signed-in user can {ops} all your Firebase data",
        impact="Anyone who signs up can {ops_verb} every user's data.",
        reason="Signing up is open, so \"signed in\" means \"anyone with an email address\".",
        explanation="{file} allows {ops} on {path} for any signed-in user. It doesn't check that the data belongs to them."),
    ("firebase-open-rules", "signed-in-other"): dict(
        severity="High", title="Any signed-in user can {ops} other users' {collection}",
        impact="Any signed-in user can {ops_verb} other users' {collection}.",
        reason="Signing up is open, and the rule never checks the owner.",
        explanation="{file} allows {ops} on {path} for any signed-in user, but never compares {{{var}}} with request.auth.uid, "
                    "so one user can reach everyone else's documents.",
        fix="- allow {raw_ops}: {raw_cond};\n+ allow {raw_ops}: if request.auth != null && request.auth.uid == {var};"),
    ("firebase-open-rules", "open-read"): dict(
        severity="High", title="Anyone can read {collection} in Firebase",
        impact="Anyone on the internet can read every document in {collection}.",
        reason="Fine for public content; the collection's name suggests personal data."),
    ("client-only-auth", "storage-flag"): dict(
        explanation="{file} reads {key} from {storage} to decide access. Anyone can open their browser's developer tools and "
                    "set it to whatever they like.",
        fix="- {line_text}\n+ const { data: isAdmin } = await supabase.rpc(\"is_admin\")   // decided by the database, not the browser"),
    ("client-only-auth", "guarded-mutation"): dict(
        title="Admin-only {cmd} on {table} is checked only in the browser",
        impact="Anyone can {cmd} rows in {table} by sending the request themselves, skipping your admin check.",
        explanation="{file} only runs this {cmd} when the user looks like an admin, but that check happens in the browser. The "
                    "request goes straight to Supabase, so anyone can send it without the check. {server_note}",
        fix="+ create policy \"Only admins can {cmd}\" on public.{table} for {cmd} to authenticated\n"
            "+   using (exists (select 1 from public.profiles p where p.id = (select auth.uid()) and p.is_admin));"),
    ("cors-wildcard", "wildcard"): dict(
        severity="Low", kind="config", title="API allows requests from any website",
        impact="Today, little: any site can read what this API returns to anyone. It matters once you add cookie-based logins.",
        reason="Without cookie logins, a wildcard only exposes what's already public.",
        explanation="{file}:{line} sets Access-Control-Allow-Origin to *. That's fine for public data. If you add cookie-based "
                    "login later, browsers block it, and the usual \"fix\" (echoing the caller's origin with credentials) lets "
                    "any website act as your users.",
        fix="- app.use(cors())\n+ app.use(cors({ origin: [\"https://your-app.com\"] }))"),
    ("xss-sink", "pattern"): dict(
        title="HTML rendered from data without sanitizing",
        impact="If this value can contain anything a user wrote, they can run their code in everyone else's browser.",
        reason="Stored scripts run for every viewer, with their session.",
        explanation="{file}:{line} renders {value} as raw HTML. If it can contain anything a user wrote (a comment, a profile "
                    "field, a message), they can put a script in it that runs for everyone who views it."),
    ("sql-string-concat", "pattern"): dict(
        title="SQL query built by pasting values into the string",
        explanation="{file}:{line} builds SQL by pasting values into the query text. If any of them can come from a user, they "
                    "can rewrite the query. Even when they can't today, parameters are the safe default."),
    ("sql-string-concat", "postgrest"): dict(
        title="Supabase filter built from request data", cwe=["CWE-943"],
        impact="Anyone can add their own conditions to this query and read rows they shouldn't see.",
        explanation="{file}:{line} builds a PostgREST filter string with request data. The caller can add their own filters "
                    "(commas and dots are filter syntax) and read rows the query was meant to hide.",
        fix="- .or(`email.eq.${q},name.eq.${q}`)\n+ .or(`email.eq.${JSON.stringify(q)},name.eq.${JSON.stringify(q)}`)   // or use .eq()/.ilike() per column"),
    ("eval-user-input", "command"): dict(
        title="Request data is run as a shell command", cwe=["CWE-78"],
        explanation="{file}:{line} passes request data to {sink}, which runs it through a shell. Anyone can add their own commands "
                    "with ; or &&.",
        fix="- exec(`convert ${input} out.png`)\n+ execFile(\"convert\", [input, \"out.png\"])   // no shell, arguments stay arguments",
        reprompt="In {file}, never pass request data to a shell. Use execFile/spawn with an argument array (no shell: true) and "
                 "validate each argument against an allow-list."),
    ("no-rate-limit", "ai"): dict(
        title="No rate limit on endpoints that call paid AI APIs", money_risk=True,
        impact="Anyone can call these endpoints in a loop and run up your AI bill or burn your credits.",
        reason="Each call costs you money, and nothing stops a script from calling them thousands of times.",
        explanation="{method} {path} calls a paid AI API, and nothing limits how often it can be called.",
        reprompt="Add a per-user rate limit (for example a few requests per minute, using @upstash/ratelimit or a counter "
                 "table) to every endpoint that calls a paid AI API, and return 429 when it's exceeded. Require sign-in for them too."),
    ("debug-in-prod", "stack"): dict(
        kind="code", title="Error responses include stack traces", cwe=["CWE-209"],
        explanation="{file}:{line} sends the error's stack trace to whoever made the request. It reveals file paths, library "
                    "versions and code structure.",
        fix="- {line_text}\n+ console.error(err)\n+ res.status(500).json({ error: \"Something went wrong\" })",
        reprompt="In {file}, log errors on the server and send users only a generic message. Never put err.stack (or raw error "
                 "details) in a response."),
    ("unrestricted-upload", "public"): dict(
        severity="High", title="Uploads of any type are saved into a public folder",
        impact="Anyone can upload an .html or .svg file that then runs as a page on your own domain, with your users' sessions.",
        reason="An uploaded page on your own domain is stored XSS that every visitor trusts.",
        explanation="{file}:{line} accepts any file type and size, and saves uploads in {dest}, which your site serves as-is."),
}

VARIANTS.update({
    ("supabase-privilege-escalation", "metadata-policy"): dict(
        severity="High", title="Policy trusts user_metadata, which users can edit",
        impact="Any user can give themselves whatever {key_text} this policy checks, and pass it.",
        reason="supabase.auth.updateUser() lets every signed-in user change their own user_metadata.",
        explanation="Policy \"{policy}\" on {table} ({file}:{line}) decides access from auth.jwt() -> 'user_metadata'. Every "
                    "user can change their own user_metadata with supabase.auth.updateUser({ data: … }), so this check doesn't "
                    "hold. app_metadata is the server-only place for roles.",
        fix="- … auth.jwt() -> 'user_metadata' ->> '{key}' …\n+ … auth.jwt() -> 'app_metadata' ->> '{key}' …   -- only the server can set app_metadata",
        reprompt="Replace every use of user_metadata in Row-Level Security policies with app_metadata (set it from the server "
                 "with the service-role key) or with a lookup in a roles table users can't write to."),
    ("supabase-privilege-escalation", "self-update"): dict(
        severity="High", title="{title_text}",
        impact="Any user can change {col} on their own row in {table}, and so give themselves {col_label} rights.",
        reason="The policy lets users edit their own row, and nothing stops them editing the column that grants privileges.",
        explanation="Policy \"{policy}\" ({file}:{line}) lets users update their own row in {table}, and {table} has a {col} "
                    "column. Nothing limits which columns they change (no column grant, no check on {col}, no trigger), so "
                    "supabase.from(\"{short}\").update({ {col}: … }) works for their own row.{used_note}",
        fix="+ revoke update on {table} from authenticated;\n+ grant update ({safe_cols}) on {table} to authenticated;   "
            "-- every column except {col}",
        reprompt="Stop users from changing {col} in {table}: in a new migration, revoke UPDATE on the table from authenticated "
                 "and grant UPDATE only on the columns users may edit, or add `and {col} = (select {col} from {table} where "
                 "id = auth.uid())` to the policy's WITH CHECK."),
    ("supabase-privilege-escalation", "role-self-grant"): dict(
        title="Users can give themselves any role",
        impact="Any signed-in user can add an admin role for themselves in {table}.",
        reason="The roles table accepts rows from the very users it's meant to rank.",
        explanation="Policy \"{policy}\" ({file}:{line}) lets users {cmd} their own rows in {table}, the table your app reads "
                    "roles from. So a user can add a row giving themselves any role.",
        fix="- create policy \"{policy}\" on {table} for {cmd} …\n+ -- only admins (or the server) may write roles:\n"
            "+ create policy \"Admins manage roles\" on {table} for all to authenticated using (public.has_role((select auth.uid()), 'admin'));",
        reprompt="Make {table} read-only for normal users: drop the policy that lets users {cmd} their own rows, and allow "
                 "writes only to admins (checked with a SECURITY DEFINER has_role() function) or the service role."),
    ("plaintext-password", "store"): dict(
        explanation="{file}:{line} saves the password exactly as typed. It should be stored as a slow, salted hash (bcrypt or "
                    "argon2), never as-is.",
        fix="- {line_text}\n+ password_hash: await bcrypt.hash(password, 12),"),
    ("ai-open-proxy", "model"): dict(
        title="Callers choose which AI model you pay for",
        impact="Anyone can switch your endpoint to the most expensive model and run up your bill.",
        explanation="{file}:{line} takes the model name from the request, so callers can pick a model many times pricier than "
                    "the one your feature needs.",
        fix="- {line_text}\n+ model: \"gpt-4o-mini\",   // fixed on the server"),
    ("missing-auth", "admin-server-fn"): dict(
        title="Server function uses the service-role key without checking who's calling",
        impact="Anyone can call this server function directly and it acts with full database rights.",
        reason="Server functions are public HTTP endpoints, and the service-role key skips Row-Level Security.",
        explanation="{file}:{line} is a server function (anyone can call it over HTTP, not just your UI) that changes data "
                    "with the service-role client, and nothing in it checks who's calling: no auth middleware, no getUser(), no "
                    "require…() guard.",
        fix="+ const user = await requireUser()   // throws 401 when there's no valid session\n"
            "+ // …then only touch rows that belong to user.id",
        reprompt="In {file}, check the caller at the top of every server function that uses the service-role client (an auth "
                 "middleware or a requireUser() helper that verifies the session), and scope every query to that user's rows."),
    ("cors-wildcard", "python-credentials"): dict(
        explanation="{file}:{line} allows every origin with credentials. With a wildcard and credentials, Starlette/FastAPI and "
                    "flask-cors answer with the caller's own origin when the request carries cookies, so any website a signed-in "
                    "user visits can call your API as them and read the responses.",
        fix="- allow_origins=[\"*\"],\n+ allow_origins=[\"https://your-app.com\"],   # only your own site(s)",
        reprompt="In {file}, replace the wildcard CORS origin with the exact list of your app's domains, and keep "
                 "allow_credentials only if you really use cookie-based login."),
    ("supabase-privilege-escalation", "metadata-code"): dict(
        kind="code", severity="High", title="Role read from user_metadata, which users can edit",
        impact="Any user can call supabase.auth.updateUser() to give themselves this role and pass the check.",
        reason="user_metadata is written by the user; checks built on it hold only until someone tries.",
        explanation="{file}:{line} decides access from user_metadata. Every signed-in user can change their own user_metadata "
                    "with supabase.auth.updateUser({ data: … }), so this check doesn't hold. app_metadata (set only by the server) "
                    "or a roles table is the place for roles.",
        fix="- {line_text}\n+ // read the role from app_metadata (server-set) or check it in the database (RLS / an is_admin() function)",
        reprompt="In {file}, stop reading roles from user_metadata. Store roles in app_metadata (set with the service-role key "
                 "from the server) or in a roles table, and enforce them in Row-Level Security, not only in the UI."),
    ("supabase-rpc-exposed", "reads"): dict(
        severity="Medium", title="{audience_cap} can read data through {fn}",
        impact="{audience_cap} can call {fn} with any arguments and read what it returns, past Row-Level Security.",
        reason="It only reads, and it may be meant to be public (like a share link); check what it returns."),
    ("supabase-rpc-exposed", "job"): dict(
        severity="Medium", title="{audience_cap} can trigger {fn} whenever they like",
        impact="{audience_cap} can run this job at will, as often as they like, with full database rights.",
        reason="It takes no arguments, so callers can't aim it, but they decide when (and how often) it runs.",
        explanation="{fn} runs as SECURITY DEFINER (ignoring Row-Level Security) and changes data, and Supabase exposes it at "
                    "/rest/v1/rpc/{short}. Nothing in it checks who's calling, so {audience} can trigger it with "
                    "supabase.rpc(\"{short}\"). {revoke_note}"),
    ("supabase-storage-open", "upload"): dict(
        severity="Medium", title="{audience_cap} can upload files to {bucket}",
        impact="Anyone can fill {bucket} with files of any size and type, on your storage bill.",
        reason="Fine for anonymous uploads (like a public report form); otherwise it's free storage for strangers."),
    ("supabase-storage-open", "read"): dict(
        severity="High", title="{audience_cap} can download every file in {bucket}",
        impact="Anyone can list and download every file in {bucket}.",
        reason="Fine for public assets; a leak for private uploads."),
})

# what an env var name is, for titles ("OpenAI API key exposed in the browser")
NOUNS = [(r"SERVICE_ROLE", "Supabase service_role key"), (r"SUPABASE_SECRET", "Supabase secret key"), (r"OPENAI", "OpenAI API key"),
         (r"ANTHROPIC|CLAUDE", "Anthropic API key"), (r"GROQ", "Groq API key"), (r"GEMINI", "Gemini API key"),
         (r"OPENROUTER", "OpenRouter API key"), (r"MISTRAL", "Mistral API key"), (r"STRIPE", "Stripe secret key"),
         (r"RESEND", "Resend API key"), (r"SENDGRID", "SendGrid API key"), (r"TWILIO", "Twilio credentials"),
         (r"ELEVENLABS", "ElevenLabs API key"), (r"REPLICATE", "Replicate API token"), (r"DATABASE_URL|DB_URL", "Database password")]
PUBLIC_PREFIX = re.compile(r"^(VITE_|NEXT_PUBLIC_|REACT_APP_|EXPO_PUBLIC_|NUXT_PUBLIC_|GATSBY_|VUE_APP_|PUBLIC_)")
SECRETS_DOC = "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"
ENV_DOCS = {"VITE_": "https://vite.dev/guide/env-and-mode", "NEXT_PUBLIC_": "https://nextjs.org/docs/app/guides/environment-variables",
            "REACT_APP_": "https://create-react-app.dev/docs/adding-custom-environment-variables/",
            "EXPO_PUBLIC_": "https://docs.expo.dev/guides/environment-variables/"}
FRAMEWORK = {"VITE_": "Vite", "NEXT_PUBLIC_": "Next.js", "REACT_APP_": "Create React App", "EXPO_PUBLIC_": "Expo",
             "NUXT_PUBLIC_": "Nuxt", "GATSBY_": "Gatsby", "VUE_APP_": "Vue CLI", "PUBLIC_": "SvelteKit and Astro"}
SECRET_NAME = re.compile(r"SECRET|SERVICE_ROLE|PRIVATE|PASSWORD|OPENAI|ANTHROPIC|CLAUDE|GROQ|GEMINI|MISTRAL|COHERE|REPLICATE|"
                         r"ELEVENLABS|DEEPSEEK|PERPLEXITY|OPENROUTER|TOGETHER|HUGGING|HF_TOKEN|RESEND|SENDGRID|TWILIO|DATABASE_URL|DB_URL|ADMIN_(KEY|TOKEN)")
PUBLIC_NAME = re.compile(r"PUBLISHABLE|ANON|PUBLIC_KEY|SITE_KEY|_ID$")
SENSITIVE = re.compile(r"(?i)user|profile|account|member|customer|client|patient|employee|payment|invoice|order|subscription|"
                       r"billing|transaction|message|chat|conversation|comment|note|journal|entr(y|ies)|diary|document|upload|"
                       r"address|contact|phone|email|secret|token|credential|session|health|medical|private|personal")
OWNER = re.compile(r"\b(user_id|owner_id|profile_id|author_id|created_by|account_id)\b")


def _fill(text, v):
    for k, val in v.items():
        text = text.replace("{" + k + "}", str(val))
    return text


def build(rule, variant, root, file, line, end=None, confidence=None, secret=None, group="", **v):
    """A Finding for `rule`/`variant` at file:line, with every text field taken from the catalog and filled in from `v`.
    `group` splits findings the report would otherwise merge (one card per table, not one per migration file)."""
    spec = CATALOG[rule] | VARIANTS.get((rule, variant), {})
    quiet = spec["kind"] == "secret" or ENV_FILE.search(file)  # neighbouring env lines are often secrets
    code, start = snippet(root, file, line, end or line, context=0 if quiet else 2)
    lines = code.splitlines()
    v = {"file": file, "line": line, "line_text": lines[line - start].strip() if 0 <= line - start < len(lines) else ""} | v
    text = {k: _fill(spec.get(k, ""), v) for k in ("title", "impact", "reason", "explanation", "fix", "reprompt")}
    f = Finding(
        source="vibeguard", raw_rule_id=f"vibe.{rule}" + (f":{variant}" if variant else "") + (f"@{group}" if group else ""), kind=spec["kind"],
        severity=spec["severity"], confidence=confidence or "Likely", title=text["title"], impact=text["impact"],
        severity_reason=text["reason"], explanation=text["explanation"], fix_diff=text["fix"], reprompt=text["reprompt"],
        file=file, line=line, end_line=end or line, code_snippet=code, snippet_start=start, cwe=spec["cwe"],
        money_risk=bool(spec.get("money_risk") or v.get("money_risk")),
        refs=[_fill(r, v) for r in spec.get("refs", []) if _fill(r, v) != r or "{" not in r] + ([v["rotate"]] if v.get("rotate") else []),
        evidence=[_fill(e, v) for e in spec.get("evidence", [])] + list(v.get("extra_evidence", [])),
    )
    f._secret = secret
    return f


class VibeRules(Scanner):
    """Step 4 of the pipeline (§3): our own rules. Python checks always run; ast-grep rules run when it's installed."""

    name = "vibeguard"
    label = "VibeGuard rules"
    binary = "ast-grep"
    timeout = 90

    def available(self):
        return True  # the Python checks need nothing installed

    def run(self, root, work):
        files = _files(root)
        texts = _Texts(root)
        schema = _migrations(root, files, texts)
        tables = schema.tables
        findings = (_env_files(root, files, texts) + _client_literals(root, files, texts) + _rls(root, tables) + _supabase_deep(root, schema, texts)
                    + _firebase(root, files, texts) + _rate_limits(root, files, texts) + _template_html(root, files, texts))
        findings += _auth_checks(root, files, texts)
        structural = super().available()
        if structural and any(f.endswith(JS) for f in files):
            findings += self._ast_grep(root, work, tables)
        _connect(root, findings, files, texts)
        self.passed = _passed(findings, files, texts, schema)
        self.checked = f"{len(files):,} file{'s' * (len(files) != 1)}" + ("" if structural else " (structural rules skipped: ast-grep isn't installed)")
        return findings

    def _ast_grep(self, root, work, tables):
        args = [self.binary, "scan", "--config", str(AST_GREP), "--json=compact", "--include-metadata"]
        for pattern in EXCLUDE:  # the same "doesn't ship" exclusions as semgrep
            args += ["--globs", f"!**/{pattern}"]
        r = self.exec(args + [str(root)], ok=(0, 1))  # exit 1 = a rule with severity "error" matched
        out = work / "ast-grep.json"
        out.write_text(r.stdout)
        found = []
        for m in read_json(out, []):
            meta = m.get("metadata") or {}
            if "vibe" not in meta:
                continue
            file = rel(root, m["file"])
            line, end = m["range"]["start"]["line"] + 1, m["range"]["end"]["line"] + 1
            mv = {k: x["text"] for k, x in (m.get("metaVariables") or {}).get("single", {}).items()}
            f = _from_ast(root, meta, file, line, end, mv, tables)
            if f:
                found.append(f)
        return found


def _from_ast(root, meta, file, line, end, mv, tables):
    rule, variant, conf = meta["vibe"], meta.get("variant", ""), meta.get("confidence", "Likely")
    v = {}
    if rule == "frontend-secret" and variant == "code-env":
        var = mv.get("VAR", "")
        prefix = PUBLIC_PREFIX.match(var)[0] if PUBLIC_PREFIX.match(var) else ""
        v = {"var": var, "prefix": prefix, "noun": _noun(var), "server_var": var[len(prefix):], "doc": ENV_DOCS.get(prefix, SECRETS_DOC)}
    elif rule == "frontend-secret" and variant == "browser-sdk":
        text = _read(root, file).splitlines()
        flag = next((i for i in range(line, end + 1) if "dangerouslyAllowBrowser" in text[i - 1]), line)
        v = {"flag_line": flag, "noun": "AI API key", "server_var": "OPENAI_API_KEY", "doc": SECRETS_DOC}
    elif rule == "client-only-auth" and variant == "storage-flag":
        v = {"key": mv.get("KEY", ""), "storage": mv.get("STORE", "localStorage").replace("window.", "")}
    elif rule == "client-only-auth" and variant == "guarded-mutation":
        table = mv.get("TABLE", "").strip("'\"`")
        v = {"table": table, "cmd": mv.get("WRITE", "change")}
        verdict = _server_guard(tables, table, v["cmd"])
        if verdict is False:
            return None  # RLS on, with no policy that opens this command: the server enforces it, the React check is just UI
        conf, v["server_note"] = verdict or (conf, f"Whether the server stops it depends on {table}'s Row-Level Security policies, which aren't in this code.")
        if verdict:
            v["extra_evidence"] = [v["server_note"]]
    elif rule == "xss-sink":
        v = {"value": _value(root, file, line), "line_fix": _xss_fix(root, file, line)}
    elif rule == "sql-string-concat":
        v = {"line_fix": _sql_fix(root, file, line)}
    elif rule == "plaintext-password" and variant == "compare":
        v = {"line_fix": _password_fix(_read(root, file).splitlines()[line - 1].strip())}
    elif rule == "jwt-no-expiry":
        v = {"line_fix": _jwt_fix(_read(root, file).splitlines()[line - 1].strip())}
    elif rule == "webhook-unsigned":
        event = _read(root, file).splitlines()[line - 1]
        event = re.search(r"""["'`]((?:order|subscription|transaction|payment|checkout|user|organizationMembership|PAYMENT|CHECKOUT|BILLING)[\w.]*)["'`]""", event)
        v = _webhook_provider(event[1] if event else "", _read(root, file))
    elif rule == "unrestricted-upload":
        dest = re.search(r"""(?:dest|destination)\s*:\s*["'`]([^"'`]+)""", "\n".join(_read(root, file).splitlines()[line - 1 : end]))
        v = {"dest": dest[1] if dest else "a public folder"}
    return build(rule, variant, root, file, line, end if rule not in ("xss-sink", "sql-string-concat", "debug-in-prod") else line,
                 conf, **v)


def from_semgrep(root, r):
    """A finding from one of our taint rules (rules/vibe-coded.yml), which ran inside the main semgrep scan."""
    meta = r["extra"].get("metadata") or {}
    rule, variant = meta["vibe"], meta.get("variant", "")
    file, line = rel(root, r["path"]), r["start"]["line"]
    text = _read(root, file).splitlines()
    sink = text[line - 1] if 0 < line <= len(text) else ""
    v = {}
    if rule == "sql-string-concat":
        variant = "postgrest" if ".or(" in sink else variant
        v = {"line_fix": _sql_fix(root, file, line)}
    elif rule == "xss-sink":
        v = {"line_fix": _xss_fix(root, file, line)}
    elif rule == "eval-user-input":
        called = re.search(r"\b(eval|Function|setTimeout|setInterval|runIn\w+Context|Script|execSync|exec|spawn)\s*\(", sink)
        v = {"sink": f"{called[1]}()" if called else "a function that runs code", "line_fix": _eval_fix(sink)}
    f = build(rule, variant, root, file, line, None, "Confirmed reachable", **v)
    f.evidence = ["Request or URL data flows into this line in the same function (taint analysis)."] + f.evidence
    return f


# --- helpers ------------------------------------------------------------------

class _Texts(dict):
    """File contents, read once per scan."""

    def __init__(self, root):
        super().__init__()
        self.root = root

    def __missing__(self, file):
        self[file] = _read(self.root, file)
        return self[file]


def _read(root, file):
    try:
        return (root / file).read_text(errors="replace")
    except OSError:
        return ""


def _files(root):
    out = []
    for p in sorted(root.rglob("*")):
        if p.is_file() and not SKIP_DIRS.intersection(p.relative_to(root).parts[:-1]) and p.stat().st_size < 1_000_000:
            out.append(p.relative_to(root).as_posix())
    return out


def _noun(var):
    return next((noun for pattern, noun in NOUNS if re.search(pattern, var)), var)


def _html_value(src):
    """(start, end) of the expression after `__html:` in a line, honouring strings, template literals and nesting."""
    m = re.search(r"__html\s*:\s*", src)
    if not m:
        return None
    i, stack = m.end(), []  # open brackets, quotes, "`" for a template literal and "${" inside one
    while i < len(src):
        c, top = src[i], stack[-1] if stack else None
        if top in ("'", '"', "`"):
            if c == "\\":
                i += 2
                continue
            if c == top:
                stack.pop()
            elif top == "`" and src.startswith("${", i):
                stack.append("${")
                i += 2
                continue
        elif c in "'\"`([{":
            stack.append(c)
        elif c in ")]}":
            if not stack:
                break
            stack.pop()
        elif c == "," and not stack:
            break
        i += 1
    return m.end(), len(src[:i].rstrip())


def _value(root, file, line):
    src = _read(root, file).splitlines()[line - 1] if line else ""
    span = _html_value(src)
    return src[span[0] : span[1]].strip() if span else "this value"


def _xss_fix(root, file, line):
    text = _read(root, file).splitlines()
    src = text[line - 1].strip() if 0 < line <= len(text) else ""
    span = _html_value(src)
    if not span:
        return "- el.innerHTML = value\n+ el.textContent = value   // or DOMPurify.sanitize(value) if it must be HTML"
    value = src[span[0] : span[1]].strip()
    element = re.match(r"(.*?)<(\w+)\s+dangerouslySetInnerHTML=\{\{\s*__html\s*:\s*`([^`]*)`\s*\}\}\s*/>(.*)$", src)
    if element:  # a template on a self-closing element: plain JSX children, which React escapes
        before, tag, template, after = element.groups()
        children = re.sub(r"\$\{([^}]*)\}", r"{\1}", template)
        return f"- {src}\n+ {before}<{tag}>{children}</{tag}>{after}   // React escapes {{…}} in JSX"
    return f"- {src}\n+ {src[: span[0]]}DOMPurify.sanitize({value}){src[span[1]:]}"


STORED = re.compile(r"(?i)^(user|row|account|record|member|admin|existing|found|result|data|u|dbuser|rows\[\d+\])\??\.(password|passwd|pwd)$")


def _password_fix(src):
    """user.password !== password -> !(await bcrypt.compare(password, user.password_hash))."""
    for m in re.finditer(r"([\w.\[\]?]+)\s*(===|!==|==|!=)\s*([\w.\[\]?]+)", src):
        left, op, right = m[1], m[2], m[3]
        stored, typed = (left, right) if STORED.match(left) else (right, left) if STORED.match(right) else (None, None)
        if stored:
            check = f"await bcrypt.compare({typed}, {stored.rsplit('.', 1)[0].rstrip('?')}.password_hash)"
            return src[: m.start()] + (f"!({check})" if op.startswith("!") else check) + src[m.end() :]
    return "const ok = await bcrypt.compare(password, user.password_hash)"


def _jwt_fix(src):
    """jwt.sign(payload, secret) -> jwt.sign(payload, secret, { expiresIn: "1h" })."""
    m = re.search(r"jwt\.sign\(", src)
    if not m:
        return 'jwt.sign(payload, secret, { expiresIn: "1h" })'
    i, depth, quote = m.end(), 0, None
    while i < len(src):
        c = src[i]
        if quote:
            quote = None if c == quote and src[i - 1] != "\\" else quote
        elif c in "\"'`":
            quote = c
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                return src[:i] + ', { expiresIn: "1h" }' + src[i:]
            depth -= 1
        i += 1
    return src


WEBHOOKS = [  # (file mentions, event pattern, provider, how to verify, docs, money)
    (r"lemon", r"^(order|subscription)_", "Lemon Squeezy", "compare the X-Signature header with an HMAC-SHA256 of the raw body (your signing secret)",
     "https://docs.lemonsqueezy.com/help/webhooks/signing-requests", True),
    (r"paddle", r"^(transaction|subscription)\.", "Paddle", "paddle.webhooks.unmarshal(rawBody, secret, signature)",
     "https://developer.paddle.com/webhooks/signature-verification", True),
    (r"razorpay", r"^(payment|order|subscription)\.", "Razorpay", "Razorpay.validateWebhookSignature(rawBody, signature, secret)",
     "https://razorpay.com/docs/webhooks/validate-test/", True),
    (r"paypal", r"^(PAYMENT|CHECKOUT|BILLING)\.", "PayPal", "PayPal's verify-webhook-signature API with the transmission headers",
     "https://developer.paypal.com/api/rest/webhooks/rest/", True),
    (r"clerk|svix", r"^(user|organizationMembership)\.", "Clerk", "new Webhook(secret).verify(rawBody, svixHeaders) from the svix package",
     "https://clerk.com/docs/webhooks/sync-data", False),
    (r"polar", r"^(order|checkout|subscription)\.", "Polar", "validateEvent(rawBody, headers, secret) from @polar-sh/sdk/webhooks",
     "https://docs.polar.sh/integrate/webhooks/delivery", True),
]


def _webhook_provider(event, text):
    low = text.lower()
    hit = next((w for w in WEBHOOKS if re.search(w[0], low) and re.match(w[1], event)), None) or next(
        (w for w in WEBHOOKS if re.match(w[1], event)), None)
    if not hit:
        return {"provider": "Payment provider", "event": event, "verify_hint": "check the signature header with your webhook secret",
                "doc": "https://cheatsheetseries.owasp.org/cheatsheets/Web_Service_Security_Cheat_Sheet.html", "money_risk": True}
    return {"provider": hit[2], "event": event, "verify_hint": hit[3], "doc": hit[4], "money_risk": hit[5]}


RATE_FIXES = {
    ("auth", "express"): "+ import rateLimit from \"express-rate-limit\"\n+ const authLimit = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10 })\n"
                         "- {line_text}\n+ {line_limited}",
    ("ai", "express"): "+ import rateLimit from \"express-rate-limit\"\n+ const aiLimit = rateLimit({ windowMs: 60 * 1000, limit: 5 })\n"
                       "- {line_text}\n+ {line_limited}",
    ("auth", "next"): "+ import { Ratelimit } from \"@upstash/ratelimit\"\n+ import { Redis } from \"@upstash/redis\"\n"
                      "+ const limit = new Ratelimit({ redis: Redis.fromEnv(), limiter: Ratelimit.slidingWindow(10, \"15 m\") })\n"
                      "+ const { success } = await limit.limit(req.headers.get(\"x-forwarded-for\") ?? \"anon\")\n"
                      "+ if (!success) return new Response(\"Too many attempts\", { status: 429 })",
    ("ai", "next"): "+ import { Ratelimit } from \"@upstash/ratelimit\"\n+ import { Redis } from \"@upstash/redis\"\n"
                    "+ const limit = new Ratelimit({ redis: Redis.fromEnv(), limiter: Ratelimit.slidingWindow(5, \"1 m\") })\n"
                    "+ const { success } = await limit.limit(userId)   // the signed-in user's id\n"
                    "+ if (!success) return new Response(\"Too many requests\", { status: 429 })",
    ("ai", "edge"): "+ // count this user's calls in the last minute (a small table, or Upstash) and refuse above a limit\n"
                    "+ const { count } = await admin.from(\"ai_calls\").select(\"*\", { count: \"exact\", head: true })\n"
                    "+   .eq(\"user_id\", user.id).gte(\"created_at\", new Date(Date.now() - 60_000).toISOString())\n"
                    "+ if ((count ?? 0) >= 5) return new Response(\"Too many requests\", { status: 429 })\n"
                    "+ await admin.from(\"ai_calls\").insert({ user_id: user.id })",
}


def _eval_fix(sink):
    sink = sink.strip()
    if "eval(" in sink:
        return f"- {sink}\n+ {sink.replace('eval(', 'evaluate(')}   // mathjs evaluate(): math only, it can't run code"
    return f"- {sink}\n+ // parse the input into the shape you expect; never run it"


def _sql_fix(root, file, line):
    text = _read(root, file).splitlines()
    src = text[line - 1].strip() if 0 < line <= len(text) else ""
    fixed = parameterize(src, "?" if re.search(r"\bmysql2?\b", "\n".join(text)) else "$")
    return f"- {src}\n+ {fixed}" if fixed else f"- {src}\n+ // keep the SQL text constant and pass values separately: db.query(\"... WHERE id = $1\", [id])"


def parameterize(line, style="$"):
    """`db.query("... = '" + email + "'")` -> `db.query("... = $1", [email])`. None when the call isn't a simple one-liner."""
    m = re.search(r"\.(query|execute|raw|unsafe|exec|prepare|\$queryRawUnsafe|\$executeRawUnsafe)\(", line)
    if not m:
        return None
    start = i = m.end()
    depth, quote = 0, None
    while i < len(line):
        c = line[i]
        if quote:
            quote = None if c == quote and line[i - 1] != "\\" else quote
        elif c in "\"'`":
            quote = c
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                break
            depth -= 1
        elif c == "," and depth == 0:
            break
        i += 1
    arg, rest = line[start:i].strip(), line[i:]
    if arg.startswith("`") and arg.endswith("`"):
        pieces = re.split(r"\$\{([^}]*)\}", arg[1:-1])  # text, expr, text, expr, …, text
    else:
        tokens = _split_plus(arg)
        if not tokens:
            return None
        pieces = [""]  # same alternation; odd length means the last piece is text
        for tok in tokens:
            literal = len(tok) >= 2 and tok[0] in "\"'" and tok[-1] == tok[0]
            if literal and len(pieces) % 2:
                pieces[-1] += tok[1:-1]
            elif literal:
                pieces.append(tok[1:-1])
            else:
                if len(pieces) % 2 == 0:
                    pieces.append("")
                pieces.append(tok)
    texts, exprs = pieces[0::2], [e.strip() for e in pieces[1::2]]
    if not exprs or not all(exprs):
        return None
    sql = texts[0]
    for n in range(1, len(exprs) + 1):
        text = texts[n] if n < len(texts) else ""
        if sql.endswith("'") and text.startswith("'"):  # '${x}' -> $1: the driver handles quoting
            sql, text = sql[:-1], text[1:]
        sql += (f"${n}" if style == "$" else "?") + text
    if '"' in sql:
        return None
    return f'{line[: m.end()]}"{sql}", [{", ".join(exprs)}]{rest}'


def _split_plus(expr):
    """Split `"a" + b + "c"` on top-level +; None if there's something we don't parse."""
    out, buf, depth, quote = [], "", 0, None
    for i, c in enumerate(expr):
        if quote:
            buf += c
            if c == quote and expr[i - 1] != "\\":
                quote = None
        elif c in "\"'`":
            quote = c
            buf += c
        elif c in "([{":
            depth += 1
            buf += c
        elif c in ")]}":
            depth -= 1
            buf += c
        elif c == "+" and depth == 0:
            out.append(buf.strip())
            buf = ""
        else:
            buf += c
    out.append(buf.strip())
    return out if len(out) > 1 and all(out) and not any(t.startswith("`") for t in out) else None


# --- env files: secrets with a public prefix, debug flags in production ----------------------------------

ENV_FILE = re.compile(r"(^|/)\.env(\.[\w.-]+)?$")
ENV_EXAMPLE = re.compile(r"(?i)example|sample|template|dist|defaults?$")
PROD_ENV = re.compile(r"(^|/)\.env\.(production|prod|live)(\.local)?$")
DEBUG_ON = re.compile(r"^\s*(DEBUG|APP_DEBUG|FLASK_DEBUG|DJANGO_DEBUG|\w*_DEBUG|\w*STACK_?TRACES?\w*|VERBOSE_ERRORS|DISPLAY_ERRORS)\s*=\s*"
                      r"[\"']?(true|1|yes|on|\*)[\"']?\s*$|^\s*NODE_ENV\s*=\s*[\"']?development[\"']?\s*$", re.I)


def _env_files(root, files, texts):
    out = []
    for file in files:
        if not ENV_FILE.search(file) or ENV_EXAMPLE.search(file):
            continue
        prod = bool(PROD_ENV.search(file))
        for n, raw in enumerate(texts[file].splitlines(), 1):
            m = re.match(r"^\s*(?:export\s+)?([A-Z][A-Z0-9_]*)\s*=\s*(.*?)\s*$", raw)
            if not m:
                continue
            name, value = m[1], m[2].strip("'\"")
            if prod and DEBUG_ON.match(raw):
                off = re.sub(r"=.*", "=" + ("production" if name == "NODE_ENV" else "false"), raw.strip())
                out.append(build("debug-in-prod", "env", root, file, n, setting=name, setting_line=raw.strip(), setting_off=off))
            prefix = PUBLIC_PREFIX.match(name)
            if not prefix or PUBLIC_NAME.search(name) or len(value) < 8 or PLACEHOLDER.match(value):
                continue
            info = classify_secret(value, file, "")
            known = not info["false_positive"] and info["severity"] in ("Critical", "High") and (info["rotate"] or info["env_var"] != "API_KEY")
            if known or (SECRET_NAME.search(name) and not info["false_positive"]):
                noun = _noun(name) if _noun(name) != name else re.sub(r"^(Exposed |Hardcoded )|( exposed)$", "", info["title"])
                what = info["what"] if info["what"] != "this secret" else f"the value of {name}"
                out.append(build("frontend-secret", "env-file", root, file, n, secret=value, var=name, prefix=prefix[0],
                                 framework=FRAMEWORK[prefix[0]], noun=noun, doc=ENV_DOCS.get(prefix[0], SECRETS_DOC), what_cap=what[:1].upper() + what[1:],
                                 server_var=name[len(prefix[0]):], money_risk=info["money_risk"], rotate=info["rotate"]))
    return out


# --- hardcoded keys in code that ships to browsers ---------------------------------------------------------

KEY_LITERAL = re.compile(r"""(["'`])((?:sk-|sk_live_|rk_live_|gsk_|sk-ant-|sk-or-|sb_secret_|sbp_|AKIA|xox[bp]-|SG\.|ghp_|github_pat_|eyJ)[A-Za-z0-9_\-.=]{16,})\1""")
SERVER_PATH = re.compile(r"(^|/)(server|api|backend|functions|scripts|edge|workers?|cron|jobs|migrations|seeds?)/|\.server\.|"
                         r"(^|/)(middleware|route)\.[mc]?[jt]sx?$|\.config\.[mc]?[jt]s$")


def is_browser_code(file, text, next_app):
    """Code that ends up in the browser bundle: React/Vue components and modules under src/, Next.js client components."""
    if not file.endswith(JS + (".vue", ".svelte", ".html")) or SERVER_PATH.search(file) or TEST_PATH.search(file):
        return False
    head = text[:300]
    if re.search(r"""^\s*["']use client["']""", head, re.M):
        return True
    if re.search(r"""^\s*["']use server["']""", head, re.M) or "createServerFn" in text:
        return False
    if next_app:  # app/ files are server components unless marked "use client"; pages/ (non-API) ship to the browser
        return bool(re.match(r"(src/)?pages/", file))
    return file.startswith(("src/", "client/", "frontend/", "web/", "public/")) or "/src/" in file


def _client_literals(root, files, texts):
    next_app = '"next"' in texts["package.json"]
    out = []
    for file in files:
        if not file.endswith(JS + (".vue", ".svelte", ".html")):
            continue
        text = texts[file]
        if not KEY_LITERAL.search(text) or not is_browser_code(file, text, next_app):
            continue
        for n, line in enumerate(text.splitlines(), 1):
            for m in KEY_LITERAL.finditer(line):
                info = classify_secret(m[2], file, "")
                if info["false_positive"] or info["severity"] not in ("Critical", "High"):
                    continue
                noun = re.sub(r"^(Exposed |Hardcoded )|( exposed)$", "", info["title"])
                out.append(build("frontend-secret", "literal", root, file, n, secret=m[2], noun=noun, doc=SECRETS_DOC,
                                 server_var=info["env_var"], money_risk=info["money_risk"], rotate=info["rotate"],
                                 rotate_at=f" at {info['rotate']}" if info["rotate"] else ""))
    return out


# --- Supabase Row-Level Security, from migrations -----------------------------------------------------------

def _migrations(root, files, texts):
    sql = sorted(f for f in files if re.match(r"(.*/)?supabase/migrations/[^/]+\.sql$", f))
    return supabase_sql.read([(f, texts[f]) for f in sql]) if sql else supabase_sql.Schema()


def _owner(t):
    m = OWNER.search(t.columns)
    if m:
        return m[1]
    return "id" if re.search(r"\bid\b[^,]*references\s+auth\.users", t.columns) else None


def _policy_fix(t, cmd="all"):
    owner = _owner(t)
    if not owner:
        return "+ -- then add policies saying who may read and change rows, e.g. using ((select auth.uid()) = user_id)"
    verb = {"select": "read", "insert": "add", "update": "change", "delete": "delete"}.get(cmd, "read and change")
    clause = f"using ((select auth.uid()) = {owner})" + ("" if cmd in ("select", "delete") else f" with check ((select auth.uid()) = {owner})")
    if cmd == "insert":
        clause = f"with check ((select auth.uid()) = {owner})"
    return f"+ create policy \"Users {verb} their own rows\" on {t.name}\n+   for {cmd} to authenticated {clause};"


VERBS = {"all": "read, change or delete", "update": "change", "delete": "delete", "select": "read", "insert": "add"}


def _rls(root, tables):
    out = []
    for t in tables.values():
        if not supabase_sql.exposed(t) or t.name == "storage.objects":
            continue
        short = t.name.removeprefix("public.")
        if t.kind == "view":
            if not t.invoker:
                out.append(build("supabase-rls-off", "view", root, t.file, t.line, group=t.name, table=t.name))
            continue
        owner = _owner(t)
        base = {"table": t.name, "policy_fix": _policy_fix(t), "owner_hint": f" (where {owner} = auth.uid())" if owner else ""}
        if not t.rls:
            at = t.toggled
            line = at[1] if at else t.line
            out.append(build("supabase-rls-off", "", root, at[0] if at else t.file, line, group=t.name, **base,
                             disabled=f", because it was turned off at {at[0]}:{at[1]}" if at else "",
                             extra_evidence=[f"Created at {t.file}:{t.line}"] if at else []))
            continue
        for p in t.policies.values():
            audience = supabase_sql.who(p)
            if not audience:
                continue
            anyone = audience == "anyone"
            if p.cmd in ("all", "update", "delete"):
                variant = "open-write" if anyone else "signed-in-write"
            elif p.cmd == "select":
                if not SENSITIVE.search(short):
                    continue  # reference data (recipes, products, stations) is meant to be readable
                variant = "open-read" if anyone else "signed-in-read"
            else:  # insert
                if not SENSITIVE.search(short):
                    continue  # public forms (waitlist, contact) are meant to accept rows
                variant = "open-insert"
            conf = "Likely" if variant == "open-write" else "Needs review"
            out.append(build("supabase-rls-off", variant, root, p.file, p.line, None, conf, group=t.name, **(base | dict(
                policy=p.name, cmd=p.cmd, verbs=VERBS[p.cmd], policy_fix=_policy_fix(t, p.cmd), owner_or_user_id=owner or "user_id",
                cmd_text={"all": "do anything", "select": "read rows", "insert": "add rows", "update": "change rows", "delete": "delete rows"}[p.cmd],
                audience="anyone (signed in or not)" if anyone else "any signed-in user"))))
    return out


PRIV_KEYS = r"role|roles|user_role|is_admin|admin|is_staff|is_superuser|permissions?|access_level|user_type|account_type|" \
            r"plan|tier|is_premium|is_pro|is_paid|subscription_\w+|credits|balance"
CALLER = re.compile(r"auth\.uid\(\)|auth\.jwt\(\)|auth\.role\(\)|request\.jwt|current_setting\(\s*'request|has_role|has_any_role|is_admin|"
                    r"current_user|session_user")
WRITES = re.compile(r"\b(insert\s+into|update\s+[\w.\"]+\s+set|delete\s+from|truncate)\b")
OWN_ROW = re.compile(r"auth\.uid\(\)\)?(::\w+)?=\(?\w+|\w+=\(?(select)?auth\.uid\(\)")
ADMINISH = re.compile(r"has_role|has_any_role|is_admin|admin|is_staff|service_role")


def _find_line(text, start, needle):
    """Line number of the first line at or after `start` that matches `needle` (regex), else `start`."""
    lines = text.splitlines()
    return next((n for n in range(start, len(lines) + 1) if re.search(needle, lines[n - 1], re.I)), start)


def _col_label(col):
    if re.match(r"plan|tier|is_premium|is_pro|is_paid|subscription", col):
        return "a paid plan", "Users can give themselves a paid plan"
    if re.match(r"credits|balance", col):
        return "more credits", "Users can give themselves unlimited credits"
    return "admin", "Users can make themselves admins"


def _columns(t):
    """Column names of a CREATE TABLE (plus later ADD COLUMNs), constraints left out."""
    body = t.columns.split("(", 1)[-1]
    parts, depth, cur = [], 0, ""
    for c in body:
        depth += {"(": 1, ")": -1}.get(c, 0)
        if c == "," and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += c
    parts.append(cur)
    names = [p.strip().split(" ")[0].strip('"') for p in parts if p.strip()]
    return [n for n in names if n and n not in ("primary", "constraint", "unique", "foreign", "check", "exclude", "like")]


def _supabase_deep(root, schema, texts):
    """Privilege escalation, functions exposed over RPC, and open storage, from the migrations' final state."""
    out = []
    auth_triggers = {fn for table, _, fn, _, _ in schema.triggers if table == "auth.users"}
    # roles copied from sign-up metadata (the person signing up writes raw_user_meta_data)
    for f in schema.functions.values():
        m = re.search(rf"raw_user_meta_data\s*->>?\s*'({PRIV_KEYS})'", f.body)
        if m:
            line = _find_line(texts[f.file], f.line, rf"raw_user_meta_data\s*->>?\s*'{m[1]}'")
            target = re.search(r"insert into ([\w.]+)", f.body)
            out.append(build("supabase-privilege-escalation", "", root, f.file, line, None,
                             "Confirmed reachable" if f.name in auth_triggers else "Likely", group=f.name,
                             fn=f"{f.name}()", key=m[1], target=target[1] if target else "the new user's row",
                             extra_evidence=[f"{f.name}() runs on every sign-up (trigger on auth.users)"] if f.name in auth_triggers else []))
    privileged_cols = set()
    for t in schema.tables.values():
        for p in t.policies.values():
            privileged_cols |= {c for c in re.findall(PRIV_KEYS, p.using + p.check)}
    for f in schema.functions.values():
        privileged_cols |= {c for c in re.findall(rf"\b({PRIV_KEYS})\b", f.body)}
    for t in schema.tables.values():
        if t.kind != "table" or not supabase_sql.exposed(t) or not t.rls:
            continue
        short, cols = t.name.removeprefix("public."), _columns(t)
        for p in t.policies.values():
            expr = p.using + " " + p.check
            if not p.permissive or not (p.roles & {"authenticated", "anon", "public"}):
                continue
            if "user_metadata" in expr:  # every user edits their own user_metadata
                key = re.search(r"user_metadata'?\)?->>?'(\w+)'", expr)
                out.append(build("supabase-privilege-escalation", "metadata-policy", root, p.file, p.line, group=t.name,
                                 table=t.name, policy=p.name, key=key[1] if key else "role",
                                 key_text=f"'{key[1]}' value" if key else "value"))
                continue
            if not OWN_ROW.search(expr) or ADMINISH.search(expr):
                continue
            if p.cmd in ("insert", "update", "all") and re.search(r"(^|_)(roles?|permissions?|admins?)$", short):
                out.append(build("supabase-privilege-escalation", "role-self-grant", root, p.file, p.line, group=t.name,
                                 table=t.name, policy=p.name, cmd=p.cmd))
                continue
            if p.cmd not in ("update", "all"):
                continue
            granted = schema.column_grants.get((t.name, "authenticated"))
            for col in [c for c in cols if re.fullmatch(PRIV_KEYS, c)]:
                trigger_guard = any(table == t.name and "before" in timing and "update" in timing and fn in schema.functions
                                    and col in schema.functions[fn].body for table, timing, fn, _, _ in schema.triggers)
                if col in expr or (granted is not None and col not in granted) or trigger_guard:
                    continue
                label, title = _col_label(col)
                used = col in privileged_cols
                out.append(build("supabase-privilege-escalation", "self-update", root, p.file, p.line,
                                 None, "Likely", group=f"{t.name}.{col}", table=t.name, short=short, policy=p.name, col=col,
                                 col_label=label, title_text=title, safe_cols=", ".join(c for c in cols if c != col and not re.fullmatch(PRIV_KEYS, c))[:120] or "…",
                                 used_note=f" Your policies or functions also use {col} to decide access, so this is a direct way in." if used else ""))
                break
    # SECURITY DEFINER functions anyone can call over /rest/v1/rpc
    for f in schema.functions.values():
        if not f.definer or not f.name.startswith("public.") or "trigger" in f.returns or CALLER.search(f.body):
            continue
        callable_by = {"anon", "authenticated"} - f.revoked
        if not callable_by:
            continue
        writes = bool(WRITES.search(f.body))
        reads = bool(re.search(r"\b(setof|table|json|jsonb|record)\b", f.returns) and re.search(r"\bselect\b.+\bfrom\b", f.body))
        if not writes and not reads:
            continue  # scalar helpers (has_role-style booleans) leak little
        anyone = "anon" in callable_by
        audience = "anyone" if anyone else "any signed-in user"
        note = ("Revoking EXECUTE from PUBLIC isn't enough on Supabase: anon and authenticated are granted it directly."
                if "public" in f.revoked and anyone else "")
        variant = ("" if f.args else "job") if writes else "reads"  # with arguments, the caller picks the rows
        out.append(build("supabase-rpc-exposed", variant, root, f.file, f.line, None,
                         "Likely" if variant == "" and "raise exception" not in f.body else "Needs review", group=f.name,
                         fn=f"{f.name}({f.args})", short=f.name.removeprefix("public."), audience=audience,
                         audience_cap=audience[:1].upper() + audience[1:], revoke_note=note))
    # storage policies that check the bucket but not the owner
    storage = schema.tables.get("storage.objects")
    for p in (storage.policies.values() if storage else []):
        expr = p.using + " " + p.check
        if not p.permissive or not (p.roles & {"authenticated", "anon", "public"}) or OWN_ROW.search(expr) or re.search(
                r"auth\.uid\(\)|owner|foldername|has_role|has_any_role|is_admin|auth\.jwt\(\)", expr):
            continue
        anyone = bool(p.roles & {"anon", "public"})
        buckets = re.findall(r"'([^']+)'", expr)
        bucket = (f"the {buckets[0]} bucket" if len(buckets) == 1 else f"the {', '.join(buckets[:-1])} and {buckets[-1]} buckets"
                  if buckets else "every bucket")
        if p.cmd in ("update", "delete", "all"):
            variant, sev_conf = "", "Likely" if anyone else "Needs review"
        elif p.cmd == "insert" and anyone:
            variant, sev_conf = "upload", "Needs review"
        elif p.cmd == "select" and anyone and not all(schema.buckets.get(b, {}).get("public") for b in buckets or [""]):
            variant, sev_conf = "read", "Needs review"
        else:
            continue
        audience = "anyone" if anyone else "any signed-in user"
        out.append(build("supabase-storage-open", variant, root, p.file, p.line, None, sev_conf, group=f"storage:{bucket}",
                         bucket=bucket, bucket_id=buckets[0] if buckets else "…",
                         policy=p.name, audience=audience, audience_cap=audience[:1].upper() + audience[1:],
                         cmd_text={"update": "replace files", "delete": "delete files", "all": "upload, replace and delete files",
                                   "insert": "upload files", "select": "download files"}[p.cmd],
                         using_text=f"bucket_id = '{buckets[0]}'" if buckets else "true"))
    return out


def _server_guard(tables, table, cmd):
    """For a browser-gated Supabase write: (confidence, note) when the server lets it through, False when RLS stops it,
    None when we can't tell (no migrations for that table)."""
    t = tables.get(f"public.{table}")
    if not t or t.kind != "table":
        return None
    if not t.rls:
        where = f"{t.toggled[0]}:{t.toggled[1]}" if t.toggled else f"{t.file}:{t.line}"
        return "Confirmed reachable", f"Nothing on the server stops it either: Row-Level Security is off for {t.name} ({where})."
    for p in t.policies.values():
        if p.cmd in ("all", cmd) and supabase_sql.who(p):
            return "Confirmed reachable", f"Nothing on the server stops it either: policy \"{p.name}\" ({p.file}:{p.line}) lets {supabase_sql.who(p)} {cmd} any row."
    return False


# --- Firebase security rules ---------------------------------------------------------------------------------

ALLOW = re.compile(r"match\s+(/\S*)\s*\{|\{|\}|allow\s+([a-z,\s]+?)\s*(?::\s*if\s+([^;]+?))?\s*;", re.I)
WILDCARD = re.compile(r"\{(\w+)(=\*\*)?\}")


def _firebase(root, files, texts):
    out = []
    for file in files:
        text = texts[file]
        if file.endswith(".rules") and re.search(r"service\s+(cloud\.firestore|firebase\.storage)", text):
            out += _firebase_rules(root, file, text)
        elif file.endswith("database.rules.json") or (file.endswith(".json") and '"rules"' in text and '".read"' in text):
            out += _rtdb_rules(root, file, text)
    return out


def _firebase_rules(root, file, text):
    storage = "firebase.storage" in text
    service = "storage bucket" if storage else "database"
    stack, out = [], []
    for m in ALLOW.finditer(text):
        if m[1] is not None:
            stack.append(m[1])
        elif m[0] == "{":
            stack.append(None)
        elif m[0] == "}":
            if stack:
                stack.pop()
        else:
            ops = {o.strip().lower() for o in m[2].split(",") if o.strip()}
            cond = re.sub(r"\s+", " ", m[3] or "").strip()
            path = "".join(p for p in stack if p) or "/"
            if path.startswith("/databases/{database}/documents"):
                path = path.removeprefix("/databases/{database}/documents") or "/"
            elif path.startswith("/b/{bucket}/o"):
                path = path.removeprefix("/b/{bucket}/o") or "/"
            line = text.count("\n", 0, m.start()) + 1
            hit = _judge_rule(ops, cond, path)
            if hit:
                variant, conf, extra = hit
                writes = ops & {"write", "create", "update", "delete"}
                op_text = "read and write" if writes and ops - writes else "write to" if writes else "read"
                coll = re.sub(r"/\{[^}]*\}", "", path).strip("/").split("/")[-1] or "data"
                out.append(build("firebase-open-rules", variant, root, file, line, None, conf, service=service, path=path,
                                 ops=op_text, ops_verb="read, change or delete" if writes else "read",
                                 scope=("every file" if storage else "every document") if _root_wide(path) else path,
                                 scope_data="every file in your storage bucket" if storage else "every document in your database",
                                 cond="with no condition at all" if not cond else "with the condition `if true`, which lets everyone in"
                                 if cond == "true" else f"when `{cond}`", raw_ops=m[2].strip(),
                                 raw_cond=("if " + cond) if cond else "(no condition)", collection=coll, **extra))
    return out


def _root_wide(path):
    return path == "/" or bool(re.fullmatch(r"/\{\w+=\*\*\}", path))


def _judge_rule(ops, cond, path):
    """(variant, confidence, extra vars) for a risky allow statement, or None."""
    root_wide = _root_wide(path)
    writes = bool(ops & {"write", "create", "update", "delete"})
    test = re.match(r"request\.time\s*<\s*timestamp\.date\(\s*(\d{4})\s*,\s*(\d{1,2})\s*,\s*(\d{1,2})\s*\)$", cond)
    if test:
        until = date(*map(int, test.groups()))
        return ("test-mode", "Likely", {"until": until.isoformat()}) if until >= date.today() else None
    if cond in ("", "true"):
        if writes or root_wide:
            return "", "Likely", {}
        name = re.sub(r"/\{[^}]*\}", "", path)
        return ("open-read", "Needs review", {}) if SENSITIVE.search(name) else None
    if re.fullmatch(r"request\.auth\s*!=\s*null|request\.auth\.uid\s*!=\s*null|request\.auth\s*!=\s*null\s*&&\s*true", cond):
        if root_wide:
            return "signed-in-all", "Likely", {}
        var = next((m[1] for m in WILDCARD.finditer(path) if not m[2]), None)
        if var and SENSITIVE.search(path) and var not in cond:
            return "signed-in-other", "Likely", {"var": var}
    return None


def _rtdb_rules(root, file, text):
    try:
        rules = json.loads(text).get("rules", {})
    except (ValueError, AttributeError):
        return []
    out, lines = [], text.splitlines()

    def walk(node, path):
        if not isinstance(node, dict):
            return
        for key in (".read", ".write"):
            val = node.get(key)
            if val is True or (isinstance(val, str) and val.strip() in ("true", "auth != null", "auth !== null")):
                open_ = val is True or val.strip() == "true"
                if not open_ and path != "/":
                    continue
                line = next((n for n, x in enumerate(lines, 1) if f'"{key}"' in x and str(val).lower() in x.lower()), 0)
                ops = "write to" if key == ".write" else "read"
                out.append(build("firebase-open-rules", "" if open_ else "signed-in-all", root, file, line, None, "Likely",
                                 service="database", path=path, ops=ops, ops_verb="read, change or delete" if key == ".write" else "read",
                                 scope="your whole Realtime Database" if path == "/" else path,
                                 scope_data="everything in your Realtime Database", cond=f'with "{key}": {json.dumps(val)}',
                                 raw_ops=key, raw_cond=json.dumps(val), collection=path.strip("/") or "data"))
        for k, child in node.items():
            if not k.startswith("."):
                walk(child, path.rstrip("/") + "/" + k)

    walk(rules, "/")
    return out


# --- rate limits on auth and paid-AI endpoints (cross-file) ---------------------------------------------------

ROUTE = re.compile(r"\b(?:app|router|server|api|routes?)\.(post|put|patch|delete|all)\(\s*([\"'`])([^\"'`]*)\2", re.I)
MOUNT = re.compile(r"\b(?:app|router|server)\.use\(\s*([\"'`])([^\"'`]*)\1\s*,\s*(?:require\(\s*([\"'`])([^\"'`]+)\3\s*\)|(\w+))")
IMPORTED = re.compile(r"""(?:import\s+(\w+)\s+from|(?:const|let|var)\s+(\w+)\s*=\s*require\()\s*\(?\s*["'`](\.[^"'`]+)["'`]""")
AUTH_PATH = re.compile(r"(?i)(^|/)(log-?in|sign-?in|sign-?up|register|password|reset-?password|forgot|otp|magic-?link|verify|2fa|mfa|auth)(/|$)")
AI_CALL = re.compile(r"\.chat\.completions\.create|\.responses\.create|\.messages\.create|\b(generateText|streamText|generateObject|streamObject)\s*\(|"
                     r"\.generateContent\(|api\.openai\.com|api\.anthropic\.com|api\.groq\.com|generativelanguage\.googleapis\.com|"
                     r"ai\.gateway\.lovable\.dev|openrouter\.ai/api|api\.mistral\.ai|api\.perplexity\.ai|api\.deepseek\.com|replicate\.run\(|api\.elevenlabs\.io")
LIMITER = re.compile(r"(?i)rate.?limit|ratelimit|slow.?down|throttl|\blimiter\b|express-brute|rate-limiter-flexible")


def _rate_limits(root, files, texts):
    code = [f for f in files if f.endswith(JS) and not TEST_PATH.search(f)]
    if not code:
        return []
    # app-wide limiter (package or middleware); Edge Functions are separate deployments and are judged one by one below
    limited = bool(LIMITER.search(texts["package.json"])) or any(
        LIMITER.search(texts[f]) for f in code if (SERVER_PATH.search(f) or "express" in texts[f]) and "supabase/functions/" not in f)
    mounts = _mounts(files, texts)
    out = []
    for f in code:
        text = texts[f]
        edge = re.match(r"(.*/)?supabase/functions/([^/_][^/]*)/index\.[jt]s$", f)
        next_route = re.match(r"(?:src/)?app/(.*/)?route\.[jt]s$", f)
        pages_api = re.match(r"(?:src/)?pages/(api/.+)\.[jt]sx?$", f)
        if edge or next_route or pages_api:
            if edge:
                path, conf, method = f"/functions/v1/{edge[2]}", "Needs review", "POST"
                if LIMITER.search(text) or re.search(r"""from\s+["'][^"']*rate[^"']*["']""", text, re.I):
                    continue
            else:
                if limited:
                    continue
                parts = [p for p in ((next_route[1] or "") if next_route else pages_api[1]).split("/") if p and not p.startswith("(")]
                path = "/" + "/".join(parts)
                conf = "Likely"
                exported = re.search(r"export\s+(?:async\s+)?(?:function|const)\s+(POST|PUT|PATCH|DELETE)\b", text)
                if next_route and not exported:
                    continue
                method = exported[1] if exported else "POST"
            line = re.search(r"export\s+(?:async\s+)?(?:function|const)\s+(POST|PUT|PATCH|DELETE)\b|\b(?:Deno\.)?serve\(|export\s+default", text) or re.search(r"\S", text)
            n = text.count("\n", 0, line.start()) + 1 if line else 1
            out += _rate_finding(root, f, n, method, path, text, conf, "edge" if edge else "next")
            continue
        if limited:
            continue
        hits = list(ROUTE.finditer(text))
        for i, m in enumerate(hits):
            body = text[m.start() : hits[i + 1].start() if i + 1 < len(hits) else len(text)]
            path = ("/" + "/".join(x for x in (mounts.get(f, "") + "/" + m[3]).split("/") if x)) or "/"
            out += _rate_finding(root, f, text.count("\n", 0, m.start()) + 1, m[1].upper(), path, body, "Likely", "express")
    return out


def _rate_finding(root, file, line, method, path, body, conf, kind):
    variant = "ai" if AI_CALL.search(body) else "auth" if AUTH_PATH.search(path) else None
    if not variant:
        return []
    src = _read(root, file).splitlines()[line - 1].strip() if line else ""
    name = "aiLimit" if variant == "ai" else "authLimit"
    limited = re.sub(r"""(\.(?:post|put|patch|delete|all)\(\s*(["'`])[^"'`]*\2\s*,)""", rf"\1 {name},", src, count=1)
    fix = _fill(RATE_FIXES.get((variant, kind)) or RATE_FIXES.get((variant, "next")) or RATE_FIXES[("ai", "edge")],
                {"line_text": src, "line_limited": limited})
    return [build("no-rate-limit", variant, root, file, line, None, conf, method=method, path=path, fix_text=fix)]


def _resolve(importer, spec, files):
    if not spec.startswith("."):
        return None
    base = (Path(importer).parent / spec).as_posix()
    base = re.sub(r"(^|/)\./", r"\1", base)
    while "/../" in base:
        base = re.sub(r"[^/]+/\.\./", "", base, count=1)
    for cand in [base] + [base + e for e in JS] + [f"{base}/index{e}" for e in JS]:
        if cand in files:
            return cand
    return None


# --- login tokens nobody checks; server functions using the service role with no caller check -------------------

TOKEN_ISSUE = re.compile(r"\bjwt\.sign\(|new SignJWT\(|\bsignJwt\(")
TOKEN_CHECK = re.compile(r"jwt\.verify|jwtVerify|verifyJwt|verifyToken|expressjwt|express-jwt|passport\.(authenticate|use)|getServerSession|"
                         r"getToken\(|clerkMiddleware|requireAuth|verifyIdToken|\.auth\.getUser|auth\.api\.getSession|getIronSession|"
                         r"req\.user\b|req\.auth\b|res\.locals\.user|jwt\.decode")
ANY_ROUTE = re.compile(r"\b(?:app|router|server|api|routes?)\.(get|post|put|patch|delete)\(\s*([\"'`])([^\"'`]*)\2", re.I)
OPEN_OK = re.compile(r"(?i)log-?in|sign-?in|sign-?up|register|webhook|health|public|callback")
ADMIN_CLIENT = re.compile(r"supabaseAdmin|serviceRole|service_role|SERVICE_ROLE|createAdminClient|adminClient|getSupabaseAdmin")
ADMIN_WRITE = re.compile(r"\.(insert|update|upsert|delete)\(|\.rpc\(|auth\.admin\.")
GUARD = re.compile(r"\b(require|assert|ensure|check|verify|guard|protect|with|get)\w*(User|Auth|Admin|Staff|Session|Role|Access|Login|"
                   r"Permission|Caller|Claims)\w*\(|\.getUser\(|getClaims\(|currentUser\(|\bauth\(\)|getServerSession|\.middleware\(|"
                   r"headers\.get\(\s*[\"']authorization|context\.(user|userId|claims|session|auth)\b|clerk")


def _auth_checks(root, files, texts):
    next_app = '"next"' in texts["package.json"]
    server = [f for f in files if f.endswith(JS) and not TEST_PATH.search(f) and not is_browser_code(f, texts[f], next_app)]
    out = []
    issuers = [(f, m) for f in server for m in [TOKEN_ISSUE.search(texts[f])] if m]
    if issuers and not any(TOKEN_CHECK.search(texts[f]) for f in server):
        f, m = issuers[0]
        mounts = _mounts(files, texts)
        routes = []
        for g in server:
            for r in ANY_ROUTE.finditer(texts[g]):
                path = "/" + "/".join(x for x in (mounts.get(g, "") + "/" + r[3]).split("/") if x)
                if not OPEN_OK.search(path):
                    routes.append(f"{r[1].upper()} {path} ({g}:{texts[g].count(chr(10), 0, r.start()) + 1})")
        out.append(build("missing-auth", "", root, f, texts[f].count("\n", 0, m.start()) + 1, None, "Likely",
                         extra_evidence=([f"These endpoints answer anyone: {', '.join(routes[:8])}" + (" …" if len(routes) > 8 else "")]
                                         if routes else [])))
    for f in server:
        text = texts[f]
        if not ADMIN_CLIENT.search(text):
            continue
        if "createServerFn" in text:
            starts = [m.start() for m in re.finditer(r"createServerFn\(", text)]
        elif re.search(r"""^\s*["']use server["']""", text[:300], re.M) or re.search(r"(^|/)route\.[jt]s$", f):
            starts = [m.start() for m in re.finditer(r"export\s+(?:async\s+)?(?:function\s+\w+|const\s+(?:GET|POST|PUT|PATCH|DELETE)\b)", text)]
        else:
            continue
        for i, start in enumerate(starts):
            segment = text[start : starts[i + 1] if i + 1 < len(starts) else len(text)]
            # public reads through the admin client (a list of published items) are a smell, not a hole: flag writes
            if ADMIN_CLIENT.search(segment) and ADMIN_WRITE.search(segment) and not GUARD.search(segment):
                out.append(build("missing-auth", "admin-server-fn", root, f, text.count("\n", 0, start) + 1, None, "Needs review"))
    return out


def _mounts(files, texts):
    """file -> the path prefix an Express app mounts it under (app.use("/api/auth", require("./routes/auth")))."""
    mounts = {}
    for f in files:
        if not f.endswith(JS):
            continue
        imports = {m[1] or m[2]: m[3] for m in IMPORTED.finditer(texts[f])}
        for m in MOUNT.finditer(texts[f]):
            target = _resolve(f, m[4] or imports.get(m[5] or "", ""), files)
            if target:
                mounts[target] = m[2].rstrip("/")
    return mounts


# --- connections between findings, proof commands, and what passed ------------------------------------------------

SUPABASE_URL = re.compile(r"https://([a-z0-9]{6,40})\.supabase\.co")


def _where(file, text, offset):
    return f"{file}:{text.count(chr(10), 0, offset) + 1}"


def _connect(root, findings, files, texts):
    """Link findings that are one story (an env var and the code that reads it; an open table and the browser code that
    queries it), confirm open tables when the app ships what an attacker needs, and add a read-only check command."""
    next_app = '"next"' in texts["package.json"]
    browser = [f for f in files if is_browser_code(f, texts[f], next_app)]
    env = [f for f in files if ENV_FILE.search(f) and not ENV_EXAMPLE.search(f)]
    url = next(((m[0], _where(f, texts[f], m.start())) for f in env + browser for m in [SUPABASE_URL.search(texts[f])] if m), None)
    key = next((_where(f, texts[f], m.start()) for f in env + browser
                for m in [re.search(r"(ANON|PUBLISHABLE)_KEY\s*=|sb_publishable_|eyJ[\w-]+\.eyJ", texts[f])] if m), None)
    queries = {}
    for f in browser:
        for n, line in enumerate(texts[f].splitlines(), 1):
            for m in re.finditer(r"""\.from\(\s*["'`]([\w-]+)["'`]\s*\)|functions\.invoke\(\s*["'`]([\w-]+)["'`]""", line):
                queries.setdefault(m[1] or "fn:" + m[2], []).append(f"{f}:{n}")
    by_var = {}
    for f in findings:
        rule = f.raw_rule_id.split("@")[0]
        if rule in ("vibe.frontend-secret:env-file", "vibe.frontend-secret:code-env"):
            var = re.search(r"\b((?:VITE_|NEXT_PUBLIC_|REACT_APP_|EXPO_PUBLIC_|NUXT_PUBLIC_|GATSBY_|VUE_APP_|PUBLIC_)\w+)", f.title + " " + f.explanation)
            if var:
                by_var.setdefault(var[1], []).append(f)
    for group in by_var.values():
        defined = [f for f in group if f.raw_rule_id.startswith("vibe.frontend-secret:env-file")]
        read = [f for f in group if f.raw_rule_id.startswith("vibe.frontend-secret:code-env")]
        for d in defined:
            d.evidence += [f"Read by browser code at {r.file}:{r.line}" for r in read]
        for r in read:
            r.evidence += [f"Its value is set in {d.file}:{d.line}" for d in defined]
    for f in findings:
        rule = f.raw_rule_id.split("@")[0]
        table = f.raw_rule_id.split("@")[1] if "@" in f.raw_rule_id else ""
        short = table.removeprefix("public.")
        if rule in ("vibe.supabase-rls-off", "vibe.supabase-rls-off:open-read", "vibe.supabase-rls-off:open-write") and short:
            used = queries.get(short, [])
            if used:
                f.evidence.append(f"Your browser code already queries this table ({', '.join(used[:2])}), so the request an attacker "
                                  "needs is right there in your JavaScript.")
            if url:
                f.evidence.append(f"Check it yourself (read-only): curl '{url[0]}/rest/v1/{short}?select=*&limit=1' -H 'apikey: <your anon key>'. "
                                  "If rows come back, anyone can see them.")
                if key and rule == "vibe.supabase-rls-off":
                    f.confidence = "Confirmed reachable"
                    f.evidence.append(f"Your app ships the project URL ({url[1]}) and the anon key ({key}), which is all that request needs.")
        if rule.startswith("vibe.supabase-edge-service-role-no-auth"):
            name = re.search(r"functions/([^/]+)/", f.file)
            calls = queries.get("fn:" + name[1], []) if name else []
            if calls:
                f.evidence.append(f"Your site calls it from {', '.join(calls[:2])}: the same call works for anyone with the anon key.")


def _all(n, noun):
    return f"all {n} {noun}s" if n > 1 else f"your one {noun}"


def _passed(findings, files, texts, schema):
    """What we checked and found right: so a clean result means something (§15)."""
    hit = {f.raw_rule_id.removeprefix("vibe.").split(":")[0].split("@")[0] for f in findings if f.source == "vibeguard"}
    out = []
    tables = [t for t in schema.tables.values() if t.kind == "table" and supabase_sql.exposed(t) and t.name != "storage.objects"]
    if tables and "supabase-rls-off" not in hit:
        out.append(f"Row-Level Security is on for {_all(len(tables), 'table')}, with no wide-open policies")
    if tables and "supabase-privilege-escalation" not in hit:
        out.append("Users can't give themselves roles (sign-up metadata, role tables, self-edited role columns)")
    definers = [f for f in schema.functions.values() if f.definer and f.name.startswith("public.") and "trigger" not in f.returns]
    if definers and "supabase-rpc-exposed" not in hit:
        out.append(f"No SECURITY DEFINER function can be run by just anyone ({_all(len(definers), 'function')} checked)")
    if "storage.objects" in schema.tables and "supabase-storage-open" not in hit:
        out.append("Storage policies check who owns each file")
    edge = [f for f in files if re.search(r"supabase/functions/[^/_][^/]*/index\.[jt]s$", f) and ADMIN_CLIENT.search(texts[f])]
    if edge and "supabase-edge-service-role-no-auth" not in hit:
        out.append(f"Edge Functions that use the service-role key check who's calling ({_all(len(edge), 'function')} checked)")
    next_app = '"next"' in texts["package.json"]
    if any(is_browser_code(f, texts[f], next_app) for f in files) and "frontend-secret" not in hit:
        out.append("No secret keys in browser code or public env vars")
    if any(f.endswith(".rules") or f.endswith("database.rules.json") for f in files) and "firebase-open-rules" not in hit:
        out.append("Firebase rules don't leave data open to everyone")
    code = [texts[f] for f in files if f.endswith(JS) and not TEST_PATH.search(f)]
    if any(re.search(r"\.query\(|\.execute\(|\$queryRaw", t) for t in code) and "sql-string-concat" not in hit:
        out.append("SQL queries keep values separate from the query text")
    if any(re.search(r"(?i)webhook", t) and re.search(r"constructEvent|createHmac|svix|unmarshal|validateEvent", t) for t in code) \
            and not hit & {"stripe-webhook-unsigned", "webhook-unsigned"}:
        out.append("Payment webhooks verify their signatures")
    return out


# --- Vue v-html / Svelte {@html} ------------------------------------------------------------------------------

TEMPLATE_HTML = re.compile(r"""v-html\s*=\s*"(?!\s*['`])([^"]+)"|\{@html\s+(?!['"`])([^}]+)\}""")


def _template_html(root, files, texts):
    out = []
    for file in files:
        if file.endswith((".vue", ".svelte")) and not TEST_PATH.search(file):
            for n, line in enumerate(texts[file].splitlines(), 1):
                m = TEMPLATE_HTML.search(line)
                if m and not re.search(r"(?i)sanitiz|purify", m[1] or m[2]):
                    expr = (m[1] or m[2]).strip()
                    fix = f"- {line.strip()}\n+ {line.strip().replace(expr, f'DOMPurify.sanitize({expr})')}"
                    out.append(build("xss-sink", "pattern", root, file, n, None, "Needs review", value=expr, line_fix=fix))
    return out

