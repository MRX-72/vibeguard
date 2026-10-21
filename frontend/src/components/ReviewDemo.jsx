import { Check, ChevronDown, Copy, FileCode2, GitPullRequest, MessageSquare } from 'lucide-react'
import { useState } from 'react'
import { SEV } from '../severity'
import { Mark } from './Logo'

// An example review of a component written the way AI builders often write it. Static content, real behaviour:
// committing a suggestion swaps the line for its fix, and resolving every comment approves the review.
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
    sev: 'Critical',
    text: "Your OpenAI key ships to every visitor. Anyone can copy it out of your site's JavaScript and run up your bill.",
    fix: 'const ask = (q) => fetch("/api/ask", { method: "POST", body: q })  // the key stays on the server',
    prompt: 'Move every OpenAI call into a server route that reads OPENAI_API_KEY from the environment, call that route from the browser, and rotate the exposed key.',
  },
  7: {
    sev: 'High',
    text: 'Anyone can type localStorage.isAdmin = "true" in the browser console and get admin powers on this page.',
    fix: '  const isAdmin = useIsAdmin()  // decided by the database, not the browser',
    prompt: 'Store admin roles in a Supabase table users cannot edit, enforce them with Row-Level Security policies, and keep the React check only to hide buttons.',
  },
  9: {
    sev: 'High',
    text: "A comment containing a <script> runs in the browser of everyone who reads it, with their session.",
    fix: '  return <div>{body}</div>  // React escapes text for you',
    prompt: 'Render comment bodies as plain JSX text instead of dangerouslySetInnerHTML; if HTML is required, sanitize it with DOMPurify first.',
  },
}
const POSTED_AT = { 4: 300, 7: 900, 9: 1500 } // ms: the comments arrive one after another, once

export default function ReviewDemo() {
  const [fixed, setFixed] = useState({})
  const open = Object.keys(COMMENTS).filter((n) => !fixed[n]).length
  const approved = open === 0

  return (
    <figure className="overflow-hidden rounded-xl border border-line bg-surface shadow-[0_24px_60px_-28px_rgba(0,0,0,0.7)]" aria-label="Example review of an AI-built component">
      <figcaption className="border-b border-line px-4 py-4 sm:px-6">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
          <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[13px] font-semibold transition-colors ${approved ? 'border-fix/35 bg-fix/15 text-fix' : 'border-crit/35 bg-crit/15 text-crit'}`}>
            <GitPullRequest className="size-3.5" strokeWidth={2.2} />
            {approved ? 'Approved' : 'Changes requested'}
          </span>
          <span className="text-[17px] font-semibold tracking-[-0.01em]">Security review of comment-board</span>
          <span className="ml-auto rounded-md border border-line px-2 py-0.5 text-[12px] text-faint">Example</span>
        </div>
        <p className="mt-2 text-[14px] text-muted" aria-live="polite">
          <span className="font-semibold text-fg">VibeGuard</span>{' '}
          {approved ? 'approved after every suggestion was committed. Ship it.' : `left ${open} open comment${open === 1 ? '' : 's'} on 1 file.`}
        </p>
      </figcaption>

      <div className="flex items-center gap-2.5 border-b border-line bg-raised/50 px-4 py-2.5 text-[13.5px] sm:px-6">
        <ChevronDown className="size-4 text-faint" strokeWidth={2} />
        <FileCode2 className="size-4 text-faint" strokeWidth={1.9} />
        <span className="min-w-0 truncate font-mono text-[13px]">{FILE}</span>
        <span className="ml-auto flex shrink-0 items-center gap-1.5 text-faint">
          <MessageSquare className="size-3.5" strokeWidth={2} />{open}
        </span>
      </div>

      <ol className="bg-inset py-2 font-mono text-[12.5px] leading-[1.9] sm:text-[13px]">
        {LINES.map((code, i) => {
          const n = i + 1
          const c = COMMENTS[n]
          if (c && fixed[n])
            return (
              <li key={n}>
                <Row n={n} code={code} kind="del" />
                <Row n={n} code={c.fix} kind="add" />
                <p className="mx-3 my-1.5 flex items-center gap-2 rounded-md border border-fix/25 bg-fix/[0.06] px-3 py-1.5 font-sans text-[13px] text-fix sm:mx-6">
                  <Check className="size-4" strokeWidth={2.4} />Suggestion committed. Conversation resolved.
                </p>
              </li>
            )
          return (
            <li key={n}>
              <Row n={n} code={code} flagged={!!c} />
              {c && <Thread n={n} c={c} onCommit={() => setFixed((f) => ({ ...f, [n]: true }))} />}
            </li>
          )
        })}
      </ol>
    </figure>
  )
}

function Row({ n, code, kind, flagged }) {
  const tone = kind === 'del' ? 'bg-crit/[0.12] text-fg' : kind === 'add' ? 'bg-fix/[0.12] text-fg' : flagged ? 'text-fg' : 'text-muted'
  return (
    <div className={`flex ${tone}`}>
      <span className="w-10 shrink-0 pr-3 text-right text-faint select-none sm:w-12">{n}</span>
      <span className={`w-5 shrink-0 select-none ${kind === 'del' ? 'text-crit' : 'text-fix'}`}>{kind === 'del' ? '-' : kind === 'add' ? '+' : ' '}</span>
      <code className="min-w-0 pr-4 break-words whitespace-pre-wrap">{tint(code) || ' '}</code>
    </div>
  )
}

function Thread({ n, c, onCommit }) {
  const [copied, setCopied] = useState(false)
  const sev = SEV[c.sev]
  return (
    <div
      className={`mx-3 my-2 rounded-lg border bg-surface font-sans motion-safe:animate-[post_420ms_cubic-bezier(0.16,1,0.3,1)_both] sm:mx-6 ${sev.border}`}
      style={{ animationDelay: `${POSTED_AT[n]}ms` }}
    >
      <div className="flex items-start gap-3 px-3.5 pt-3 sm:px-4">
        <Mark size={24} round />
        <div className="min-w-0 flex-1 text-[14px] leading-relaxed">
          <p className="flex flex-wrap items-baseline gap-x-2">
            <span className="font-semibold">VibeGuard</span>
            <span className={`${sev.text} ${sev.weight}`}>{c.sev}</span>
            <span className="text-faint">on line {n}</span>
          </p>
          <p className="mt-1 text-fg/90">{c.text}</p>
        </div>
      </div>
      <div className="mx-3.5 mt-3 overflow-hidden rounded-md border border-line sm:mx-4">
        <p className="border-b border-line bg-raised/60 px-3 py-1.5 text-[12.5px] font-medium text-muted">Suggested change</p>
        <div className="bg-inset py-1.5 font-mono text-[12.5px] leading-[1.8]">
          <div className="flex bg-crit/[0.1]"><span className="w-6 shrink-0 text-center text-crit select-none">-</span><span className="min-w-0 pr-3 break-words whitespace-pre-wrap">{LINES[n - 1]}</span></div>
          <div className="flex bg-fix/[0.1]"><span className="w-6 shrink-0 text-center text-fix select-none">+</span><span className="min-w-0 pr-3 break-words whitespace-pre-wrap">{c.fix}</span></div>
        </div>
      </div>
      <div className="flex flex-wrap items-center gap-2 px-3.5 py-3 sm:px-4">
        <button
          type="button"
          onClick={onCommit}
          className="rounded-md bg-go px-3 py-1.5 text-[13px] font-semibold text-white transition-colors hover:bg-[#1a7a4b]"
        >
          Commit suggestion
        </button>
        <button
          type="button"
          onClick={() => navigator.clipboard?.writeText(c.prompt).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1500) })}
          className="flex items-center gap-1.5 rounded-md border border-line-strong px-3 py-1.5 text-[13px] text-muted transition-colors hover:bg-raised hover:text-fg"
        >
          {copied ? <Check className="size-3.5" strokeWidth={2.4} /> : <Copy className="size-3.5" strokeWidth={2} />}
          {copied ? 'Copied' : 'Copy prompt for your AI builder'}
        </button>
      </div>
    </div>
  )
}

// strings a shade lighter than code, so lines read as code without a full highlighter
function tint(code) {
  return code.split(/("[^"]*")/).map((part, i) => (i % 2 ? <span key={i} className="text-[#a5d6ff]">{part}</span> : part))
}
