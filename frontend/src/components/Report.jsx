import { useEffect, useState } from 'react'
import { GRADE_COLOR, ORDER, SEV } from '../severity'
import FindingRow from './FindingRow'

export default function Report({ report }) {
  const { scan, grade, findings } = report
  const shown = findings.filter((f) => !f.is_false_positive)
  const noise = findings.filter((f) => f.is_false_positive)
  const unchecked = (scan.steps ?? []).filter((s) => s.state === 'skipped' || s.state === 'failed')
  const passed = (scan.steps ?? []).flatMap((s) => s.passed ?? [])
  const counts = Object.fromEntries(ORDER.map((s) => [s, shown.filter((f) => f.severity === s).length]))
  const score = useCountUp(scan.risk_score ?? 0)

  return (
    <article className="pt-6 sm:pt-10">
      <header className="flex flex-col gap-6 border-b border-line pb-10 sm:flex-row sm:items-end sm:gap-10">
        <div className={`text-[7rem] leading-[0.8] font-semibold tracking-[-0.06em] sm:text-[9rem] ${GRADE_COLOR[grade]}`} aria-label={`Grade ${grade}`}>
          {grade}
        </div>
        <div className="flex-1">
          <p className="text-muted">
            Risk score <span className="font-semibold text-fg tabular-nums">{score}</span>
            <span className="text-faint">/100</span>
          </p>
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
      </header>

      <section className="pt-10">
        <h2 className="text-lg font-semibold tracking-tight">Findings</h2>
        {shown.length === 0 && <p className="mt-4 text-muted">No issues found in what we checked.</p>}
        <ul className="mt-4 flex flex-col gap-2">
          {shown.map((f, i) => <FindingRow key={f.id} finding={f} index={i} />)}
        </ul>
      </section>

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
        <details className="mt-8">
          <summary className="cursor-pointer text-sm text-muted hover:text-fg">
            {noise.length} filtered out as not a real risk
          </summary>
          <ul className="mt-3 flex flex-col gap-2">
            {noise.map((f, i) => <FindingRow key={f.id} finding={f} index={i} />)}
          </ul>
        </details>
      )}

      {unchecked.length > 0 && (
        <p className="mt-8 text-sm leading-relaxed text-faint">
          Not checked:{' '}
          {unchecked.map((s, i) => (
            <span key={s.key}>{i > 0 && '; '}{s.label.toLowerCase()} ({s.tool}, {s.note})</span>
          ))}
          .
        </p>
      )}
    </article>
  )
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
