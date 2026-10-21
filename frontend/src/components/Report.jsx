import { ArrowRight, Check, Code, Database, FileDown, KeyRound, Package, Printer, ShieldAlert } from 'lucide-react'
import { useEffect, useState } from 'react'
import { BASE } from '../api'
import { GRADE_COLOR, ORDER, SEV } from '../severity'
import FindingRow from './FindingRow'

// One section per kind of problem, so a founder sees "your keys" apart from "your dependencies".
const GROUPS = [
  { kind: 'secret', title: 'Keys and secrets', icon: KeyRound },
  { kind: 'config', title: 'Database, auth and setup', icon: Database },
  { kind: 'code', title: 'Your code', icon: Code },
  { kind: 'dependency', title: 'Dependencies', icon: Package },
]
const GRADE_TILE = {
  A: 'border-accent/30 bg-accent/[0.07]', B: 'border-low/30 bg-low/[0.07]', C: 'border-med/30 bg-med/[0.07]',
  D: 'border-high/30 bg-high/[0.07]', F: 'border-crit/30 bg-crit/[0.07]',
}
const when = new Intl.DateTimeFormat(undefined, { day: 'numeric', month: 'short', year: 'numeric', hour: 'numeric', minute: '2-digit' })

export default function Report({ report }) {
  const { scan, grade, findings, summary } = report
  const shown = findings.filter((f) => !f.is_false_positive)
  const noise = findings.filter((f) => f.is_false_positive)
  const steps = scan.steps ?? []
  const unchecked = steps.filter((s) => s.state === 'skipped' || s.state === 'failed')
  const checked = steps.filter((s) => s.state === 'done' && s.key !== 'ingest')
  const passed = steps.flatMap((s) => s.passed ?? [])
  const counts = Object.fromEntries(ORDER.map((s) => [s, shown.filter((f) => f.severity === s).length]))
  const top = (summary?.top ?? []).map((id) => shown.find((f) => f.id === id)).filter(Boolean)
  const groups = GROUPS.map((g) => ({ ...g, items: shown.filter((f) => f.kind === g.kind) })).filter((g) => g.items.length)
  const score = useCountUp(scan.risk_score ?? 0)
  let index = 0

  return (
    <article className="pt-10 sm:pt-14">
      <header className="rounded-2xl border border-line bg-surface p-5 sm:p-8">
        <div className="flex flex-col gap-7 sm:flex-row sm:items-center sm:gap-9">
          <div className={`grid size-32 shrink-0 place-items-center rounded-2xl border sm:size-40 ${GRADE_TILE[grade]}`} aria-label={`Grade ${grade}`}>
            <span className={`text-[5.5rem] leading-none font-semibold tracking-[-0.06em] sm:text-[7rem] ${GRADE_COLOR[grade]}`}>{grade}</span>
          </div>
          <div className="min-w-0 flex-1">
            <p className="eyebrow truncate">Security report · {scan.source_label || scan.source_type} · {when.format(new Date(scan.created_at))}</p>
            <h1 className="mt-3 max-w-[30ch] text-2xl leading-snug font-semibold tracking-[-0.025em] text-pretty sm:text-[1.9rem]">{summary?.verdict}</h1>
            <div className="mt-5 flex flex-wrap items-center gap-x-5 gap-y-3">
              <p className="font-mono text-sm text-muted">
                Risk <span className="text-lg font-medium text-fg tabular-nums">{score}</span><span className="text-faint"> / 100</span>
              </p>
              <ul className="flex flex-wrap gap-2">
                {ORDER.map((s) => (
                  <li key={s} className={`flex items-center gap-2 rounded-md px-2.5 py-1 text-[13px] ${counts[s] ? SEV[s].soft : 'bg-raised'}`}>
                    <span className={`size-1.5 rounded-full ${counts[s] ? SEV[s].bg : 'bg-faint'}`} />
                    <span className={counts[s] ? 'text-fg' : 'text-faint'}><span className="font-mono tabular-nums">{counts[s]}</span> {s}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
        <Exports scanId={scan.id} />
      </header>

      {top.length > 0 && (
        <section className="pt-12">
          <SectionTitle icon={ShieldAlert} eyebrow="Start here">This could hurt you</SectionTitle>
          <ol className="mt-5 grid gap-4 md:grid-cols-3">
            {top.map((f, i) => (
              <li key={f.id}>
                <button
                  type="button"
                  onClick={() => openFinding(f.id)}
                  className={`group relative flex h-full w-full flex-col gap-2.5 overflow-hidden rounded-2xl border border-line bg-surface p-5 text-left ring-1 ring-transparent transition-colors hover:bg-raised ${SEV[f.severity].hover}`}
                >
                  <span className={`absolute inset-x-0 top-0 h-0.5 ${SEV[f.severity].bg}`} aria-hidden />
                  <span className="flex items-center justify-between font-mono text-xs">
                    <span className={SEV[f.severity].text}>{f.severity.toUpperCase()}</span>
                    <span className="text-faint">0{i + 1}</span>
                  </span>
                  <span className="text-[16px] leading-snug font-medium">{f.title}</span>
                  <span className="text-sm leading-relaxed text-muted">{f.impact}</span>
                  <span className="mt-auto flex items-center gap-1.5 pt-2 text-sm text-faint group-hover:text-accent">
                    See the fix <ArrowRight className="size-3.5 transition-transform group-hover:translate-x-0.5" />
                  </span>
                </button>
              </li>
            ))}
          </ol>
        </section>
      )}

      {shown.length === 0 && (
        <section className="mt-10 rounded-2xl border border-accent/25 bg-accent/[0.05] p-6 sm:p-8">
          <h2 className="text-xl font-semibold tracking-tight">No major issues found</h2>
          <p className="mt-2 max-w-[62ch] leading-relaxed text-muted">
            Nothing in what we checked needs fixing. That isn't a guarantee: see below for what was checked, and scan again after big changes.
          </p>
        </section>
      )}

      {groups.map((g) => (
        <section key={g.kind} className="pt-12">
          <SectionTitle icon={g.icon} count={g.items.length}>{g.title}</SectionTitle>
          <ul className="mt-5 flex flex-col gap-2.5">
            {g.items.map((f) => <FindingRow key={f.id} finding={f} index={index++} />)}
          </ul>
        </section>
      ))}

      {passed.length > 0 && (
        <section className="pt-12">
          <SectionTitle icon={Check}>Already right</SectionTitle>
          <ul className="mt-5 grid gap-x-8 gap-y-3 rounded-2xl border border-line bg-surface p-5 sm:p-6 md:grid-cols-2">
            {passed.map((p) => (
              <li key={p} className="flex items-start gap-3 text-[15px] leading-snug text-muted">
                <span className="mt-0.5 grid size-5 shrink-0 place-items-center rounded-md bg-accent/10 text-accent"><Check className="size-3.5" strokeWidth={2.5} /></span>
                {p}
              </li>
            ))}
          </ul>
        </section>
      )}

      {noise.length > 0 && (
        <details className="group/noise mt-10">
          <summary className="cursor-pointer list-none text-sm text-muted hover:text-fg [&::-webkit-details-marker]:hidden">
            <span className="font-mono tabular-nums">{noise.length}</span> filtered out as not a real risk
            <span className="ml-1.5 text-faint group-open/noise:hidden">· show</span>
          </summary>
          <ul className="mt-4 flex flex-col gap-2.5">
            {noise.map((f, i) => <FindingRow key={f.id} finding={f} index={i} />)}
          </ul>
        </details>
      )}

      <section className="mt-14 rounded-2xl border border-line bg-surface p-5 text-sm leading-relaxed sm:p-7">
        <p className="eyebrow">What we checked</p>
        <ul className="mt-4 grid gap-x-10 gap-y-2.5 md:grid-cols-2">
          {checked.map((s) => (
            <li key={s.key} className="flex items-baseline justify-between gap-4 border-b border-line pb-2.5">
              <span className="text-muted">{s.label}</span>
              <span className="truncate text-right font-mono text-xs text-faint">{s.note}{s.checked ? ` · ${s.checked}` : ''}</span>
            </li>
          ))}
        </ul>
        {unchecked.length > 0 && (
          <p className="mt-5 text-faint">
            Not checked:{' '}
            {unchecked.map((s, i) => <span key={s.key}>{i > 0 && '; '}{s.label.toLowerCase()} ({s.note})</span>)}.
          </p>
        )}
      </section>
    </article>
  )
}

function SectionTitle({ icon: Icon, eyebrow, count, children }) {
  return (
    <div>
      {eyebrow && <p className="eyebrow mb-2">{eyebrow}</p>}
      <h2 className="flex items-center gap-3 text-xl font-semibold tracking-[-0.02em]">
        <Icon className="size-5 text-accent" strokeWidth={1.75} />
        {children}
        {count != null && <span className="rounded-md border border-line px-1.5 py-0.5 font-mono text-xs font-normal text-faint tabular-nums">{count}</span>}
      </h2>
    </div>
  )
}

function Exports({ scanId }) {
  const action = 'flex items-center gap-2 rounded-lg border border-line-strong px-3.5 py-2 text-sm text-muted transition-colors hover:bg-raised hover:text-fg'
  return (
    <div className="mt-7 flex flex-wrap gap-2.5 border-t border-line pt-6 print:hidden">
      <a className={action} href={`${BASE}/scan/${scanId}/report.md`} download><FileDown className="size-4" strokeWidth={1.75} />Markdown</a>
      <a className={action} href={`${BASE}/scan/${scanId}/report.sarif`} download title="For GitHub code scanning"><FileDown className="size-4" strokeWidth={1.75} />SARIF</a>
      <button type="button" className={action} onClick={printReport}><Printer className="size-4" strokeWidth={1.75} />Save as PDF</button>
    </div>
  )
}

// Print every card expanded, then put them back the way they were.
function printReport() {
  const closed = [...document.querySelectorAll('details:not([open])')]
  closed.forEach((d) => (d.open = true))
  window.print()
  closed.forEach((d) => (d.open = false))
}

function openFinding(id) {
  const el = document.getElementById(`f-${id}`)
  if (!el) return
  el.querySelector('details').open = true
  const still = matchMedia('(prefers-reduced-motion: reduce)').matches
  el.scrollIntoView({ behavior: still ? 'auto' : 'smooth', block: 'start' })
  el.querySelector('summary')?.focus({ preventScroll: true })
}

function useCountUp(target, ms = 700) {
  const [still] = useState(() => matchMedia('(prefers-reduced-motion: reduce)').matches)
  const [n, setN] = useState(still ? target : 0)
  useEffect(() => {
    if (still) return
    let raf
    const t0 = performance.now()
    const step = (t) => {
      const p = Math.min(1, (t - t0) / ms)
      setN(Math.round(target * (1 - (1 - p) ** 3)))
      if (p < 1) raf = requestAnimationFrame(step)
    }
    raf = requestAnimationFrame(step)
    return () => cancelAnimationFrame(raf)
  }, [target, ms, still])
  return still ? target : n
}
