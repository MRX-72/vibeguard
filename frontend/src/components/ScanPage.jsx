import { useScans } from '../history'
import { GRADE_COLOR } from '../severity'
import NewScan from './NewScan'
import ScanList from './ScanList'

// the same bands as the backend's scoring.GRADES
const gradeOf = (score) => [[5, 'A'], [25, 'B'], [45, 'C'], [70, 'D'], [100, 'F']].find(([limit]) => score <= limit)[1]

export default function ScanPage({ onSubmit, tick }) {
  const rows = useScans(tick, 20)
  const done = (rows ?? []).filter((s) => s.status === 'done')
  const avg = done.length ? Math.round(done.reduce((n, s) => n + s.risk_score, 0) / done.length) : null

  return (
    <div className="pt-10 sm:pt-14">
      <h1 className="text-[2.25rem] font-semibold tracking-[-0.03em]">Scan your code</h1>
      <p className="mt-2 max-w-[62ch] text-[17px] text-muted">
        Paste a file, upload a zip, or link a public GitHub repo. Most scans take about a minute.
      </p>

      <section className="mt-8 grid gap-6 xl:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)]">
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
