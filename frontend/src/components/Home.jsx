import { Boxes, CreditCard, Database, FileCode2, KeyRound, Workflow, Zap } from 'lucide-react'
import { Mark } from './Logo'

// What the review reads, named the way a builder would hit it. One line each, no chrome.
const CATCHES = [
  ['Keys in shipped code', 'service-role, OpenAI and Stripe keys in VITE_ / NEXT_PUBLIC_ vars or bundled JS.', KeyRound],
  ['Open databases', 'Supabase without Row-Level Security, Firebase rules open to everyone.', Database],
  ['Injection & XSS', 'SQL, shell and HTML built from request data, traced input to line.', Zap],
  ['Payments & auth', 'unsigned webhooks, plain-text passwords, tokens nobody verifies.', CreditCard],
  ['Vulnerable dependencies', 'known CVEs, split by what ships versus what only builds.', Boxes],
  ['CI risks', 'GitHub Actions that run untrusted code with your secrets.', Workflow],
]

// A file the way AI builders write one, with the comments VibeGuard posts under the exact lines.
const FILE = 'src/components/Comment.jsx'
const LINES = [
  'import OpenAI from "openai"',
  'import { supabase } from "../lib/supabase"',
  '',
  'const ai = new OpenAI({ apiKey: "sk-proj-9fQ…" })',
  '',
  'export function Comment({ id, body }) {',
  '  const isAdmin = localStorage.isAdmin === "true"',
  '  if (isAdmin) supabase.from("comments").delete().eq("id", id)',
  '  return <div dangerouslySetInnerHTML={{ __html: body }} />',
  '}',
]
const COMMENTS = {
  4: {
    sev: 'Critical', line: 4, post: 1400,
    title: 'OpenAI key ships to every visitor',
    body: 'Anyone can copy it out of your site JavaScript and run up your bill.',
    fix: 'const ai = new OpenAI({ apiKey: "sk-proj-9fQ…" })',
    replace: 'const ask = (q) => fetch("/api/ask", { method: "POST", body: q })',
  },
  7: {
    sev: 'High', line: 7, post: 2200,
    title: 'Admin check lives in the browser',
    body: ' Anyone can type localStorage.isAdmin = "true" in the console and delete anything.',
    fix: '  const isAdmin = localStorage.isAdmin === "true"',
    replace: '  const isAdmin = await supabase.rpc("is_admin")',
  },
  9: {
    sev: 'High', line: 9, post: 3000,
    title: 'Every comment is an XSS hole',
    body: 'A comment containing <script> runs in the browser of everyone who reads it.',
    fix: '  return <div dangerouslySetInnerHTML={{ __html: body }} />',
    replace: '  return <div>{body}</div>',
  },
}

const FILES = [
  [FILE, 3, true],
  ['.env', 2, false],
  ['supabase/migrations/users.sql', 1, false],
  ['firestore.rules', 1, false],
  ['server/routes/auth.js', 2, false],
  ['vite.config.ts', 0, false],
]

export default function Home() {
  return (
    <div>
      {/* hero: pinned to the same left edge everything else lives on */}
      <section className="pb-4 pt-16 sm:pt-24">
        <div className="px-4 sm:px-10">
          <p className="font-mono text-[12.5px] font-medium tracking-[0.2em] text-faint uppercase motion-safe:animate-[settle_700ms_cubic-bezier(0.16,1,0.3,1)_both]">
            Security reviews for apps your AI built
          </p>
          <h1 className="mt-7 font-display text-[3.8rem] leading-[1.02] font-bold tracking-[-0.05em] sm:text-[5.6rem]">
            <span className="motion-safe:block motion-safe:animate-[settle_700ms_cubic-bezier(0.16,1,0.3,1)_100ms_both]">AI wrote it.</span>
            <span className="motion-safe:block motion-safe:animate-[settle_700ms_cubic-bezier(0.16,1,0.3,1)_240ms_both]">
              Here&apos;s <span className="text-crit">what it leaked</span>.
            </span>
          </h1>
          <p className="mt-7 max-w-[46ch] text-[19px] leading-[1.65] text-muted motion-safe:animate-[settle_700ms_cubic-bezier(0.16,1,0.3,1)_420ms_both] sm:text-[20.5px]">
            One scan reads the whole project: env files, migrations, database rules, routes. It returns a real
            review, every finding pinned to its line, each with its fix.
          </p>
          <div className="mt-9 flex flex-wrap items-center gap-3 motion-safe:animate-[settle_700ms_cubic-bezier(0.16,1,0.3,1)_540ms_both]">
            <a href="#/scan" className="rounded-full bg-white px-6 py-3 text-[15px] font-semibold text-ink transition-colors hover:bg-[#d9d9de]">
              Review my code
            </a>
            <a href="#/demo" className="rounded-full border border-line-strong px-6 py-3 text-[15px] font-medium text-fg transition-colors hover:border-fg/50">
              See a live review
            </a>
          </div>
        </div>
      </section>

      {/* how it catches: comments posting under the exact lines, one after another */}
      <section className="mt-14 sm:mt-20" aria-label="Example review">
        <div className="flex items-center gap-4 border-t border-line pt-4">
          <span className="font-mono text-[11.5px] font-medium uppercase tracking-[0.2em] text-faint">How it reads your code</span>
          <span className="h-px flex-1 bg-line" aria-hidden />
          <span className="hidden text-[13.5px] text-faint sm:block">3 comments, arriving on their own lines</span>
        </div>

        <div className="mt-5 grid overflow-hidden rounded-lg border border-line lg:grid-cols-[260px_minmax(0,1fr)]">
          {/* file list: what a scan actually sees */}
          <aside className="hidden border-r border-line bg-surface px-3.5 py-4 lg:block">
            <p className="font-mono text-[11.5px] uppercase tracking-[0.15em] text-faint">18 files · 9 risky</p>
            <ul className="mt-3 font-mono text-[13px] leading-[1.6]">
              {FILES.map(([name, hits, active]) => (
                <li
                  key={name}
                  className={`flex items-center gap-2 rounded-md px-2.5 py-1.5 ${active ? 'bg-raised font-semibold text-fg' : 'text-muted'}`}
                >
                  <span className="min-w-0 truncate">{name}</span>
                  {hits > 0 && <span className="ml-auto shrink-0 text-[11.5px] font-semibold text-crit">{hits}</span>}
                </li>
              ))}
            </ul>
            <p className="mt-4 border-t border-line pt-3 text-[12.5px] leading-relaxed text-faint">
              The whole project, however you give it: pasted code, a zip, or a repo link.
            </p>
          </aside>

          <div>
            <div className="flex items-center gap-2.5 border-b border-line bg-surface px-4 py-2.5">
              <FileCode2 className="size-4 text-faint" strokeWidth={1.9} aria-hidden />
              <span className="min-w-0 truncate font-mono text-[13px]">{FILE}</span>
              <span className="ml-auto shrink-0 font-mono text-[12px] font-semibold text-crit">3 comments</span>
            </div>
            <div className="bg-inset py-2 font-mono text-[12.5px] leading-[1.9] sm:text-[13.5px]">
              {LINES.map((code, i) => {
                const n = i + 1
                const c = COMMENTS[n]
                return (
                  <div key={n}>
                    <div
                      className={`flex motion-safe:animate-[rise_400ms_cubic-bezier(0.16,1,0.3,1)_both] ${c ? 'bg-fg/[0.03]' : ''}`}
                      style={{ animationDelay: `${i * 55}ms` }}
                    >
                      <span className="w-10 shrink-0 pr-3 text-right text-faint select-none sm:w-12">{n}</span>
                      <code className="min-w-0 pr-4 break-words whitespace-pre-wrap text-muted">
                        {code.startsWith('  ') && '  '}
                        {code.trim() && <span className="text-fg">{tint(code.trim())}</span> || ' '}
                      </code>
                    </div>
                    {c && <Comment c={c} />}
                  </div>
                )
              })}
            </div>
          </div>
        </div>
        <p className="mt-3 text-[13.5px] text-faint">
          A real review takes about a minute, covers 18 files, and your code is deleted the moment it ends.
        </p>
      </section>

      {/* what it reads: a full-bleed hairline grid */}
      <section className="px-4 pt-24 sm:px-10 sm:pt-32">
        <h2 className="max-w-[24ch] font-display text-[2.4rem] leading-tight font-bold tracking-[-0.035em] sm:text-[2.9rem]">
          Knows the stack your AI picked.
        </h2>
        <p className="mt-4 max-w-[50ch] text-[17px] leading-relaxed text-muted">
          Generic scanners miss what breaks AI-built apps most. VibeGuard reads your migrations, rules and env files,
          not only your JavaScript.
        </p>
        <ul className="mt-12 grid gap-px overflow-hidden rounded-xl border border-line bg-line text-left sm:grid-cols-2 lg:grid-cols-3">
          {CATCHES.map(([name, what, Icon]) => (
            <li key={name} className="flex items-start gap-3 bg-ink px-4 py-4 transition-colors hover:bg-surface">
              <Icon className="mt-0.5 size-4 shrink-0 text-faint" strokeWidth={2} />
              <div className="min-w-0">
                <h3 className="text-[15.5px] font-semibold">{name}</h3>
                <p className="mt-1 text-[13.5px] leading-snug text-muted">{what}</p>
              </div>
            </li>
          ))}
        </ul>
        <p className="mt-5 font-mono text-[12.5px] text-faint">
          10 scanner engines, 260 of our own rules, one AI reviewer
        </p>
      </section>

      {/* the review in three steps, no essay */}
      <section className="px-4 pt-24 sm:px-10 sm:pt-32">
        <ol className="grid gap-6 sm:grid-cols-3 sm:gap-8">
          {[
            ['01', 'Point it at anything', 'Paste code, a zip, or a repo link'],
            ['02', 'It reads everything', 'Open-source scanners plus AI, line by line'],
            ['03', 'Fix in one paste', 'Suggested change plus a prompt for your builder'],
          ].map(([n, t, s]) => (
            <li key={n} className="border-t border-line pt-4">
              <span className="font-mono text-[12.5px] font-semibold text-faint">{n}</span>
              <h3 className="mt-1 text-[16.5px] font-semibold">{t}</h3>
              <p className="mt-1 max-w-[26ch] text-[13.5px] text-faint">{s}</p>
            </li>
          ))}
        </ol>
      </section>

      {/* closing */}
      <section className="mt-24 px-4 pb-10 sm:px-10 sm:mt-32">
        <h2 className="max-w-[24ch] font-display text-[1.9rem] font-bold tracking-[-0.03em] sm:text-[2.4rem]">
          Review your app before <span className="text-crit">someone else does</span>.
        </h2>
        <div className="mt-7 flex flex-wrap items-center gap-4">
          <a href="#/scan" className="rounded-full bg-white px-6 py-3 text-[15px] font-semibold text-ink transition-colors hover:bg-[#d9d9de]">
            Review my code
          </a>
          <p className="font-mono text-[13.5px] text-faint">free. your code is deleted when the review ends</p>
        </div>
      </section>
    </div>
  )
}

// A comment posting itself under the line it belongs to: the one authored moment.
function Comment({ c }) {
  const sevTone = c.sev === 'Critical' ? 'text-crit' : 'text-high'
  const sevBorder = c.sev === 'Critical' ? 'border-crit/40' : 'border-high/40'
  return (
    <div
      className={`mx-3 my-2 rounded-md border bg-surface motion-safe:animate-[post_420ms_cubic-bezier(0.16,1,0.3,1)_both] sm:mx-6 ${sevBorder}`}
      style={{ animationDelay: `${c.post}ms` }}
    >
      <div className="flex items-start gap-3 px-3.5 pt-3">
        <Mark size={24} />
        <div className="min-w-0 flex-1 pb-3.5">
          <p className="flex flex-wrap items-baseline gap-x-2 text-[14px]">
            <span className="font-semibold">VibeGuard</span>
            <span className={`font-semibold ${sevTone}`}>{c.sev}</span>
            <span className="text-faint">on line {c.line}</span>
          </p>
          <p className="mt-1 text-[14px] font-semibold text-fg">{c.title}</p>
          <p className="mt-0.5 text-[13.5px] leading-relaxed text-muted">{c.body}</p>
          <div className="mt-3 overflow-hidden rounded-md border border-line">
            <p className="border-b border-line bg-raised px-3 py-1.5 text-[12.5px] font-medium text-muted">Suggested change</p>
            <div className="bg-inset py-1 font-mono text-[12.5px] leading-[1.8]">
              <div className="flex bg-crit/[0.1]"><span className="w-6 shrink-0 text-center text-crit select-none">-</span><span className="min-w-0 pr-3 break-words whitespace-pre-wrap">{c.fix}</span></div>
              <div className="flex bg-fix/[0.1]"><span className="w-6 shrink-0 text-center text-fix select-none">+</span><span className="min-w-0 pr-3 break-words whitespace-pre-wrap">{c.replace}</span></div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

// strings a shade lighter than code, so lines read as code without a full highlighter
function tint(code) {
  return code.split(/("[^"]*")/).map((part, i) => (i % 2 ? <span key={i} className="text-[#a5d6ff]">{part}</span> : part))
}
