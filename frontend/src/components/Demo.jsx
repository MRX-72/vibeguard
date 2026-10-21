import { ArrowRight, LoaderCircle, Play } from 'lucide-react'
import { useState } from 'react'
import { useScans } from '../history'
import { SEV } from '../severity'

// What's planted in sample-repo/, worst first. The scan finds these (and the test suite pins the full report).
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
    <div className="pt-10 sm:pt-14">
      <section className="grid gap-10 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.1fr)] xl:gap-14">
        <div>
          <h1 className="text-[2.25rem] font-semibold tracking-[-0.03em]">Try it on our demo app</h1>
          <p className="mt-3 max-w-[50ch] text-[17px] leading-relaxed text-muted text-pretty">
            A small React, Express and Supabase app, built the way AI tools often build them, with real-world security mistakes
            planted on purpose. Scan it to see a full report before you scan your own code.
          </p>
          <div className="mt-8 flex flex-wrap items-center gap-3">
            <button
              type="button"
              onClick={run}
              disabled={busy}
              className="flex items-center gap-2 rounded-lg bg-hot px-5 py-3 text-[15px] font-semibold text-ink transition-colors hover:bg-white disabled:opacity-60"
            >
              {busy ? <LoaderCircle className="size-[18px] animate-spin" /> : <Play className="size-3.5 fill-current" strokeWidth={1.5} />}
              {busy ? 'Starting…' : 'Run the demo scan'}
            </button>
            {last && (
              <a href={`#/scan/${last.id}`} className="flex items-center gap-1.5 px-2 py-3 text-[15px] text-muted hover:text-fg">
                Open your last demo report <ArrowRight className="size-4" strokeWidth={2} />
              </a>
            )}
          </div>
          {error && <p role="alert" className="mt-4 rounded-lg border border-crit/25 bg-crit/[0.07] px-3.5 py-2.5 text-sm text-crit">{error}</p>}

          <dl className="mt-10 grid max-w-md grid-cols-3 divide-x divide-line rounded-xl border border-line">
            <Fact label="Expect" value="Grade F" tone="text-crit" />
            <Fact label="Findings" value="About 35" />
            <Fact label="Takes" value="About a minute" />
          </dl>
        </div>

        <div className="rounded-2xl border border-line bg-surface p-5 sm:p-7">
          <h2 className="text-xl font-semibold tracking-[-0.02em]">What's planted in it</h2>
          <p className="mt-1 text-[15px] text-muted">The mistakes VibeGuard sees most in AI-built apps, worst first.</p>
          <ul className="mt-5 divide-y divide-line">
            {PLANTED.map((p) => (
              <li key={p.what} className="flex items-start gap-4 py-3.5">
                <span className={`flex w-[5.25rem] shrink-0 items-center gap-2 pt-px text-[14px] font-medium ${SEV[p.sev].text}`}>
                  <span className={`size-2 rounded-full ${SEV[p.sev].bg}`} aria-hidden />{p.sev}
                </span>
                <span className="min-w-0">
                  <span className="block text-[15px] leading-snug">{p.what}</span>
                  <span className="mt-0.5 block truncate font-mono text-[12.5px] text-faint">{p.where}</span>
                </span>
              </li>
            ))}
          </ul>
        </div>
      </section>
    </div>
  )
}

function Fact({ label, value, tone = '' }) {
  return (
    <div className="px-4 py-3.5">
      <dt className="text-[13px] text-faint">{label}</dt>
      <dd className={`mt-1 text-[16px] font-semibold tracking-[-0.01em] ${tone}`}>{value}</dd>
    </div>
  )
}
