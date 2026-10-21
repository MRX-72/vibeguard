import { Activity, Check, ShieldCheck, Sparkles, Target } from 'lucide-react'
import { GRADE_COLOR } from '../severity'

// the same bands as the backend's scoring.GRADES
const gradeOf = (score) => [[5, 'A'], [25, 'B'], [45, 'C'], [70, 'D'], [100, 'F']].find(([limit]) => score <= limit)[1]
import NewScan from './NewScan'
import { useScans } from '../history'
import ScanList from './ScanList'

export default function Overview({ onSubmit, tick, status }) {
  const rows = useScans(tick, 20)
  const done = (rows ?? []).filter((s) => s.status === 'done')
  const avg = done.length ? done.reduce((n, s) => n + s.risk_score, 0) / done.length : null

  return (
    <div className="pt-10 sm:pt-14">
      <section className="flex items-end justify-between gap-10">
        <div>
          <p className="eyebrow flex items-center gap-2.5">
            <span className="size-1.5 rounded-full bg-accent" />Security, without the noise
          </p>
          <h1 className="mt-5 text-[2.9rem] leading-[0.98] font-semibold tracking-[-0.045em] sm:text-[4.4rem]">
            Ship fast.
            <span className="block text-accent">Know what's exposed.</span>
          </h1>
          <p className="mt-6 max-w-[58ch] text-[17px] leading-relaxed text-muted text-pretty">
            A plain-English read on the risks hiding in your AI-built app, with fixes you can paste back into your builder.
          </p>
        </div>
        <div className="hidden shrink-0 items-center gap-4 pb-2 xl:flex" aria-hidden>
          <span className="relative grid size-[72px] place-items-center rounded-full border border-dashed border-line-strong">
            <span className="absolute inset-2 rounded-full border border-line" />
            <ShieldCheck className="size-7 text-accent" strokeWidth={1.6} />
          </span>
          <span className="eyebrow leading-[1.7]">Built for<br />the next push</span>
        </div>
      </section>

      {status === 'waking' && (
        <p role="status" className="mt-8 rounded-xl border border-med/25 bg-med/[0.06] px-4 py-3 text-sm leading-relaxed text-muted">
          <span className="font-medium text-med">Waking the scanner.</span> The free server sleeps when nobody's using it, so the first
          request takes about a minute. You can start your scan now; it will wait.
        </p>
      )}

      <section className="mt-10 grid grid-cols-3 gap-2.5 sm:gap-4" aria-label="Your scans">
        <Stat icon={Activity} label="Total scans" value={rows ? rows.length : '–'} note="started in this browser" />
        <Stat icon={Check} label="Completed" value={rows ? done.length : '–'} note="reports ready to review" />
        <Stat
          icon={Target}
          label="Avg. risk score"
          value={avg == null ? '–' : avg.toFixed(avg % 1 ? 1 : 0)}
          unit={avg == null ? null : '/ 100'}
          note="across completed scans"
          tone={avg == null ? '' : GRADE_COLOR[gradeOf(avg)]}
        />
      </section>

      <section className="mt-6 grid gap-6 xl:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)]">
        <NewScan onSubmit={onSubmit} />
        <div className="flex flex-col rounded-2xl border border-line bg-surface p-5 sm:p-7">
          <div className="flex items-start justify-between gap-4">
            <div>
              <p className="eyebrow">Activity</p>
              <h2 className="mt-2 text-xl font-semibold tracking-[-0.02em]">Recent scans</h2>
            </div>
            {rows?.length > 0 && (
              <span className="rounded-md border border-line px-2 py-1 font-mono text-xs text-muted tabular-nums">{rows.length}</span>
            )}
          </div>
          <div className="mt-4 flex-1 border-t border-line">
            <ScanList rows={rows && rows.slice(0, 8)} limit={0} />
          </div>
          <div className="mt-2 flex items-center justify-between border-t border-line pt-4 font-mono text-[11.5px] text-faint">
            <span className="flex items-center gap-2"><span className="size-1.5 rounded-full bg-accent" />Updates automatically</span>
            {rows?.length > 8 && <a href="#/history" className="tracking-[0.12em] uppercase hover:text-muted">All {rows.length}</a>}
          </div>
        </div>
      </section>

      <section className="mt-6 flex items-center gap-3 rounded-xl border border-line bg-surface px-5 py-4 text-[15px] text-muted">
        <Sparkles className="size-[18px] shrink-0 text-accent" strokeWidth={1.75} />
        Testing your live app too: DOM-XSS fuzzing and your deployed Supabase and Firebase settings
        <span className="eyebrow ml-auto hidden shrink-0 sm:block">Coming soon</span>
      </section>
    </div>
  )
}

function Stat({ icon: Icon, label, value, unit, note, tone = '' }) {
  return (
    <div className="relative flex flex-col overflow-hidden rounded-2xl border border-line bg-surface p-4 sm:p-6">
      {/* corner arcs: the card's one ornament */}
      <span className="absolute -top-14 -right-14 size-36 rounded-full border border-line" aria-hidden />
      <span className="absolute -top-7 -right-7 size-[5.5rem] rounded-full border border-line/70 bg-raised/40" aria-hidden />
      <Icon className="absolute top-5 right-5 hidden size-[18px] text-muted sm:block" strokeWidth={1.75} aria-hidden />
      <p className="eyebrow text-[10px] sm:text-[11.5px]">{label}</p>
      <p className={`mt-auto pt-3 text-[1.75rem] leading-none font-semibold tracking-[-0.03em] tabular-nums sm:pt-4 sm:text-[2.4rem] ${tone}`}>
        {value}
        {unit && <span className="ml-1.5 hidden font-mono text-[15px] font-normal tracking-normal text-faint sm:inline">{unit}</span>}
      </p>
      <p className="mt-3 hidden text-sm text-faint sm:block">{note}</p>
    </div>
  )
}
