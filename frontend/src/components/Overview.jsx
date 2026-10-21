import { ShieldCheck } from 'lucide-react'
import { useScans } from '../history'
import { GRADE_COLOR } from '../severity'
import NewScan from './NewScan'
import ScanList from './ScanList'
import Specimen from './Specimen'

// the same bands as the backend's scoring.GRADES
const gradeOf = (score) => [[5, 'A'], [25, 'B'], [45, 'C'], [70, 'D'], [100, 'F']].find(([limit]) => score <= limit)[1]

export default function Overview({ onSubmit, tick, status }) {
  const rows = useScans(tick, 20)
  const done = (rows ?? []).filter((s) => s.status === 'done')
  const avg = done.length ? Math.round(done.reduce((n, s) => n + s.risk_score, 0) / done.length) : null

  return (
    <div className="pt-10 sm:pt-16">
      <section className="grid items-center gap-10 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.08fr)] xl:gap-14">
        <div>
          <h1 className="text-[3rem] leading-[0.98] font-semibold tracking-[-0.035em] sm:text-[4.5rem]">
            <span className="block">Ship fast.</span>
            <span className="block">Know what's exposed.</span>
          </h1>
          <p className="mt-6 max-w-[46ch] text-[18px] leading-[1.55] text-muted text-pretty">
            VibeGuard reads the code your AI builder wrote and shows you, line by line, what a stranger could do with it, plus
            the fix to paste back into Lovable, Bolt or Cursor.
          </p>
          <div className="mt-8 flex flex-wrap items-center gap-3">
            <button
              type="button"
              onClick={() => {
                document.getElementById('new-scan')?.scrollIntoView({ behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth' })
                document.getElementById('code')?.focus({ preventScroll: true })
              }}
              className="flex items-center gap-2 rounded-lg bg-hot px-5 py-3 text-[15px] font-semibold text-ink transition-colors hover:bg-white"
            >
              <ShieldCheck className="size-[18px]" strokeWidth={2} />Scan your code
            </button>
            <span className="text-[15px] text-faint">Free. Your code is deleted after the scan.</span>
          </div>
        </div>
        <Specimen />
      </section>

      {status === 'waking' && (
        <p role="status" className="mt-10 rounded-xl border border-med/25 bg-med/[0.06] px-4 py-3 text-[15px] leading-relaxed text-muted">
          <span className="font-medium text-med">Waking the scanner.</span> The free server sleeps when nobody's using it, so the first
          request takes about a minute. You can start your scan now; it will wait.
        </p>
      )}

      <section className="mt-14 grid gap-6 xl:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)]">
        <NewScan onSubmit={onSubmit} />
        <div className="flex flex-col rounded-2xl border border-line bg-surface p-5 sm:p-7">
          <h2 className="text-xl font-semibold tracking-[-0.02em]">Your scans</h2>
          <dl className="mt-5 grid grid-cols-3 divide-x divide-line rounded-xl border border-line bg-ink/60">
            <Stat label="Scans" value={rows ? rows.length : '–'} />
            <Stat label="Finished" value={rows ? done.length : '–'} />
            <Stat label="Avg. risk" value={avg ?? '–'} tone={avg == null ? '' : GRADE_COLOR[gradeOf(avg)]} />
          </dl>
          <div className="mt-3 flex-1">
            <ScanList rows={rows && rows.slice(0, 6)} limit={0} />
          </div>
          {rows?.length > 6 && (
            <a href="#/history" className="mt-2 border-t border-line pt-4 text-sm text-muted hover:text-fg">See all {rows.length} scans</a>
          )}
        </div>
      </section>

      <p className="mt-10 max-w-[70ch] text-[15px] leading-relaxed text-faint">
        Coming next: testing the live app as well as its code, with DOM-XSS fuzzing and checks of your deployed Supabase and Firebase settings.
      </p>
    </div>
  )
}

function Stat({ label, value, tone = '' }) {
  return (
    <div className="px-4 py-3.5">
      <dt className="text-[13px] text-faint">{label}</dt>
      <dd className={`mt-1 text-[1.6rem] leading-none font-semibold tracking-[-0.03em] tabular-nums ${tone}`}>{value}</dd>
    </div>
  )
}
