import { ArrowRight, GitPullRequest, LoaderCircle } from 'lucide-react'
import { useState } from 'react'
import { useScans } from '../history'
import { SEV } from '../severity'
import { Mark } from './Logo'

// What's planted in sample-repo/, worst first; the review finds each one (the test suite pins its full report).
const PLANTED = [
  { sev: 'Critical', what: 'Supabase admin key and OpenAI key in public env vars', where: '.env' },
  { sev: 'Critical', what: 'Row-Level Security off: anyone can read and change two tables', where: 'supabase/migrations' },
  { sev: 'Critical', what: 'Anyone can sign up as an admin through sign-up metadata', where: 'supabase/migrations' },
  { sev: 'Critical', what: 'SQL built from the request, and request data run as code', where: 'server/routes' },
  { sev: 'Critical', what: 'Firebase rules open to everyone', where: 'firestore.rules' },
  { sev: 'High', what: 'Text from the URL rendered as HTML', where: 'src/pages/Search.jsx' },
  { sev: 'High', what: 'Admin checks done only in the browser', where: 'src/pages/Admin.jsx' },
  { sev: 'High', what: 'Stripe webhook that never checks the signature', where: 'server/routes/billing.js' },
  { sev: 'High', what: 'Plain-text passwords and login tokens nobody verifies', where: 'server/routes/auth.js' },
  { sev: 'Medium', what: 'No rate limit on login or the paid AI endpoint', where: 'server/routes' },
  { sev: 'Low', what: 'CORS open to every website', where: 'server/index.js' },
]

export default function Demo({ onSubmit, tick }) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const last = (useScans(tick, 20) ?? []).find((s) => s.source_type === 'demo' && s.status === 'done')

  async function run() {
    const form = new FormData()
    form.append('source_type', 'demo')
    setBusy(true)
    setError(null)
    try {
      await onSubmit(form)
    } catch (e) {
      setError(e.message)
      setBusy(false)
    }
  }

  return (
    <div className="pt-10 sm:pt-12">
      <div className="flex flex-col gap-5 border-b border-line pb-6 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <h1 className="text-[2rem] font-bold tracking-[-0.03em]">Review our demo app</h1>
          <p className="mt-3 flex flex-wrap items-center gap-x-3 gap-y-2 text-[14.5px] text-muted">
            <span className="inline-flex items-center gap-1.5 rounded-full border border-line-strong px-2.5 py-1 text-[13px] font-semibold text-muted">
              <GitPullRequest className="size-3.5" strokeWidth={2.2} />Ready for review
            </span>
            A small React, Express and Supabase app with 11 kinds of mistakes planted on purpose.
          </p>
        </div>
        <div className="flex shrink-0 flex-wrap items-center gap-2">
          {last && (
            <a href={`#/scan/${last.id}`} className="flex items-center gap-1.5 rounded-md border border-line-strong px-4 py-2 text-[14.5px] text-fg transition-colors hover:bg-raised">
              Open your last demo review <ArrowRight className="size-4" strokeWidth={2} />
            </a>
          )}
          <button
            type="button"
            onClick={run}
            disabled={busy}
            className="flex items-center gap-2 rounded-md bg-go px-4 py-2 text-[14.5px] font-semibold text-white transition-colors hover:bg-[#1a7a4b] disabled:opacity-60"
          >
            {busy && <LoaderCircle className="size-4 animate-spin" />}
            {busy ? 'Starting review…' : 'Review the demo app'}
          </button>
        </div>
      </div>
      {error && <p role="alert" className="mt-4 rounded-md border border-crit/30 bg-crit/[0.08] px-3 py-2 text-[14px] text-crit">{error}</p>}

      <div className="mt-8 grid gap-8 lg:grid-cols-[minmax(0,1fr)_280px]">
        <section className="rounded-lg border border-line bg-surface" aria-labelledby="desc">
          <p className="flex items-center gap-3 border-b border-line px-4 py-3 text-[14.5px]">
            <Mark size={24} round />
            <span><span className="font-semibold">VibeGuard</span> <span className="text-muted">wrote this description</span></span>
          </p>
          <div className="px-4 py-5 sm:px-6">
            <h2 id="desc" className="text-[1.15rem] font-bold">What this app gets wrong</h2>
            <p className="mt-2 max-w-[64ch] text-[15.5px] leading-relaxed text-muted">
              It's built the way AI tools often build apps: keys in the frontend, database rules left open, checks done in the browser.
              Review it to see a full report, every one of these as a comment on its line, before you review your own code.
            </p>
            <ul className="mt-5 flex flex-col">
              {PLANTED.map((p) => (
                <li key={p.what} className="flex items-start gap-3 border-t border-line py-3 first:border-t-0">
                  <input type="checkbox" disabled checked={!!last} aria-label={last ? 'Found in your last review' : 'Not reviewed yet'} className="mt-1 size-4 shrink-0" />
                  <span className="min-w-0">
                    <span className="text-[15px] leading-snug">
                      <span className={`${SEV[p.sev].text} ${SEV[p.sev].weight}`}>{p.sev}:</span> {p.what}
                    </span>
                    <span className="mt-0.5 block truncate font-mono text-[12.5px] text-faint">{p.where}</span>
                  </span>
                </li>
              ))}
            </ul>
          </div>
        </section>

        <aside className="flex flex-col gap-5 text-[14px]">
          <Fact label="Expected verdict"><span className="font-semibold text-crit">Changes requested, grade F</span></Fact>
          <Fact label="Comments">About 35, across 18 files</Fact>
          <Fact label="Takes">About a minute</Fact>
          <Fact label="Your code">None needed: the demo app is bundled with VibeGuard</Fact>
        </aside>
      </div>
    </div>
  )
}

function Fact({ label, children }) {
  return (
    <div className="border-b border-line pb-4">
      <p className="text-[13px] font-semibold text-muted">{label}</p>
      <p className="mt-1 text-fg">{children}</p>
    </div>
  )
}
