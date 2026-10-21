import { useEffect, useState } from 'react'
import { BASE } from '../api'
import { GRADE_COLOR, ORDER, SEV } from '../severity'
import FindingRow from './FindingRow'

// One section per kind of problem, so a founder sees "your keys" apart from "your dependencies".
const GROUPS = [
  { kind: 'secret', title: 'Keys and secrets' },
  { kind: 'config', title: 'Database, auth and setup' },
  { kind: 'code', title: 'Your code' },
  { kind: 'dependency', title: 'Dependencies' },
]

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
    <article className="pt-6 sm:pt-10">
      <header className="border-b border-line pb-10">
        <div className="flex flex-col gap-6 sm:flex-row sm:items-end sm:gap-10">
          <div className={`text-[7rem] leading-[0.8] font-semibold tracking-[-0.06em] sm:text-[9rem] ${GRADE_COLOR[grade]}`} aria-label={`Grade ${grade}`}>
            {grade}
          </div>
          <div className="flex-1">
            <p className="text-muted">
              Risk score <span className="font-semibold text-fg tabular-nums">{score}</span>
              <span className="text-faint">/100</span>
              {scan.source_label && <span className="text-faint"> · {scan.source_label}</span>}
            </p>
            <p className="mt-2 max-w-[52ch] text-xl leading-snug font-medium text-pretty">{summary?.verdict}</p>
            <ul className="mt-4 flex flex-wrap gap-2">
              {ORDER.map((s) => (
                <li key={s} className={`flex items-center gap-2 rounded-md px-2.5 py-1 text-sm ${counts[s] ? SEV[s].soft : 'bg-raised'}`}>
                  <span className={`size-2 rounded-full ${counts[s] ? SEV[s].bg : 'bg-faint'}`} />
                  <span className={counts[s] ? 'text-fg' : 'text-faint'}>
                    <span className="tabular-nums">{counts[s]}</span> {s}
                  </span>
                </li>
              ))}
            </ul>
          </div>
        </div>
        <Exports scanId={scan.id} />
      </header>

      {top.length > 0 && (
        <section className="pt-10">
          <h2 className="text-lg font-semibold tracking-tight">This could hurt you</h2>
          <ol className="mt-4 grid gap-3 sm:grid-cols-3">
            {top.map((f) => (
              <li key={f.id}>
                <button
                  type="button"
                  onClick={() => openFinding(f.id)}
                  className={`flex h-full w-full flex-col gap-2 rounded-lg border border-line bg-surface p-4 text-left ring-1 ring-transparent transition-colors hover:bg-raised ${SEV[f.severity].hover}`}
                >
                  <span className={`text-sm font-medium ${SEV[f.severity].text}`}>{f.severity}</span>
                  <span className="font-medium leading-snug">{f.title}</span>
                  <span className="text-sm leading-relaxed text-muted">{f.impact}</span>
                </button>
              </li>
            ))}
          </ol>
        </section>
      )}

      {shown.length === 0 && (
        <section className="pt-10">
          <h2 className="text-lg font-semibold tracking-tight">No major issues found</h2>
          <p className="mt-2 max-w-[60ch] text-muted">
            Nothing in what we checked needs fixing. That's not a guarantee: see below for what was checked, and scan again after big changes.
          </p>
        </section>
      )}

      {groups.map((g) => (
        <section key={g.kind} className="pt-10">
          <h2 className="text-lg font-semibold tracking-tight">
            {g.title} <span className="font-normal text-faint tabular-nums">{g.items.length}</span>
          </h2>
          <ul className="mt-4 flex flex-col gap-2">
            {g.items.map((f) => <FindingRow key={f.id} finding={f} index={index++} />)}
          </ul>
        </section>
      ))}

      {passed.length > 0 && (
        <section className="pt-10">
          <h2 className="text-lg font-semibold tracking-tight">Already right</h2>
          <ul className="mt-4 flex flex-col gap-2.5">
            {passed.map((p) => (
              <li key={p} className="flex items-start gap-3 text-[15px] leading-snug text-muted">
                <svg viewBox="0 0 16 16" className="mt-0.5 size-4 shrink-0 text-fix" aria-hidden="true">
                  <path d="m3.5 8.3 2.9 2.9 6.1-6.3" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
                {p}
              </li>
            ))}
          </ul>
        </section>
      )}

      {noise.length > 0 && (
        <details className="mt-10">
          <summary className="cursor-pointer text-sm text-muted hover:text-fg">
            {noise.length} filtered out as not a real risk
          </summary>
          <ul className="mt-3 flex flex-col gap-2">
            {noise.map((f, i) => <FindingRow key={f.id} finding={f} index={i} />)}
          </ul>
        </details>
      )}

      <section className="mt-12 border-t border-line pt-8 text-sm leading-relaxed text-faint">
        <h2 className="font-medium text-muted">What we checked</h2>
        <ul className="mt-3 grid gap-x-8 gap-y-1.5 sm:grid-cols-2">
          {checked.map((s) => (
            <li key={s.key}>
              <span className="text-muted">{s.label}</span>: {s.note}{s.checked ? ` in ${s.checked}` : ''}
            </li>
          ))}
        </ul>
        {unchecked.length > 0 && (
          <p className="mt-4">
            Not checked:{' '}
            {unchecked.map((s, i) => (
              <span key={s.key}>{i > 0 && '; '}{s.label.toLowerCase()} ({s.tool}, {s.note})</span>
            ))}
            .
          </p>
        )}
        <p className="mt-4">
          Coming soon: testing your live app too (DOM-XSS fuzzing and your deployed Supabase/Firebase settings), not just its code.
        </p>
      </section>
    </article>
  )
}

function Exports({ scanId }) {
  const link = 'rounded-md border border-line px-3 py-1.5 text-sm text-muted hover:bg-raised hover:text-fg'
  return (
    <div className="mt-8 flex flex-wrap gap-2 print:hidden">
      <a className={link} href={`${BASE}/scan/${scanId}/report.md`} download>Download Markdown</a>
      <a className={link} href={`${BASE}/scan/${scanId}/report.sarif`} download title="For GitHub code scanning">Download SARIF</a>
      <button type="button" className={link} onClick={printReport}>Save as PDF</button>
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
