import { CircleCheck, CircleMinus, CircleX, FileCode2, FileDown, GitPullRequest, MessageSquare, Printer } from 'lucide-react'
import { useEffect, useState } from 'react'
import { BASE } from '../api'
import { GRADE_COLOR, ORDER, SEV, VERDICT } from '../severity'
import FindingRow from './FindingRow'
import Check from './Check'
import { Mark } from './Logo'

const when = new Intl.DateTimeFormat(undefined, { day: 'numeric', month: 'short', year: 'numeric', hour: 'numeric', minute: '2-digit' })

export default function Report({ report }) {
  const { scan, grade, findings, summary } = report
  const shown = findings.filter((f) => !f.is_false_positive)
  const noise = findings.filter((f) => f.is_false_positive)
  const steps = scan.steps ?? []
  const passed = steps.flatMap((s) => s.passed ?? [])
  const counts = Object.fromEntries(ORDER.map((s) => [s, shown.filter((f) => f.severity === s).length]))
  const top = (summary?.top ?? []).map((id) => shown.find((f) => f.id === id)).filter(Boolean)
  const files = byFile(shown)
  const [resolved, toggle] = useResolved(scan.id)
  const done = shown.filter((f) => resolved.has(f.id)).length
  const verdict = VERDICT[grade]
  const score = useCountUp(scan.risk_score ?? 0)
  const name = scan.source_label || 'your code'

  return (
    <article className="pt-10 sm:pt-12">
      <header className="flex flex-col gap-5 border-b border-line pb-6 lg:flex-row lg:items-end lg:justify-between">
        <div className="min-w-0">
          <h1 className="text-[1.9rem] leading-tight font-bold tracking-[-0.025em] text-balance">Security review of {name}</h1>
          <p className="mt-3 flex flex-wrap items-center gap-x-3 gap-y-2 text-[14.5px] text-muted">
            <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[13px] font-semibold ${verdict.chip}`}>
              <GitPullRequest className="size-3.5" strokeWidth={2.2} />{verdict.label}
            </span>
            <span>
              <span className="font-semibold text-fg">VibeGuard</span> reviewed it on {when.format(new Date(scan.created_at))} and left{' '}
              {shown.length} comment{shown.length === 1 ? '' : 's'}.
            </span>
          </p>
        </div>
        <Exports scanId={scan.id} />
      </header>

      <section className="mt-8 rounded-lg border border-line bg-surface" aria-label="Review summary">
        <div className="flex items-center gap-3 border-b border-line px-4 py-3 text-[14.5px]">
          <Mark size={24} round />
          <span><span className="font-semibold">VibeGuard</span> <span className="text-muted">{grade === 'A' || grade === 'B' ? 'approved these changes' : 'requested changes'}</span></span>
        </div>
        <div className="grid gap-8 px-4 py-6 sm:px-6 md:grid-cols-[auto_minmax(0,1fr)] md:gap-10">
          <div className="flex items-center gap-4 md:block">
            <p className={`grid size-16 place-items-center rounded-lg border border-line-strong bg-inset text-[2.25rem] leading-none font-bold ${GRADE_COLOR[grade]}`} aria-label={`Grade ${grade}`}>{grade}</p>
            <p className="text-[14px] text-muted md:mt-3">
              Risk <span className="text-[16px] font-semibold text-fg">{score}</span> of 100
            </p>
          </div>
          <div className="min-w-0">
            <p className="max-w-[46ch] text-[1.35rem] leading-snug font-semibold tracking-[-0.015em] text-balance">{summary?.verdict}</p>
            <ul className="mt-4 flex flex-wrap gap-x-5 gap-y-2 text-[14px]">
              {ORDER.map((s) => (
                <li key={s} className={`flex items-center gap-2 ${counts[s] ? '' : 'text-faint'}`}>
                  <span className={`size-2.5 rounded-full ${counts[s] ? SEV[s].bg : 'bg-line-strong'}`} aria-hidden />
                  <span className={counts[s] ? SEV[s].weight : ''}>{counts[s]} {s}</span>
                </li>
              ))}
            </ul>
            {shown.length > 0 && <CommentMap findings={shown} resolved={resolved} />}
            {top.length > 0 && (
              <div className="mt-6">
                <h2 className="text-[15px] font-semibold">Fix these first</h2>
                <ul className="mt-2.5 flex flex-col gap-2">
                  {top.map((f) => (
                    <li key={f.id} className="flex items-start gap-2.5 text-[15px]">
                      <Check checked={resolved.has(f.id)} onChange={() => toggle(f.id)} label={`Mark "${f.title}" resolved`} className="mt-1" />
                      <button type="button" onClick={() => openFinding(f.id)} className={`text-left hover:underline ${resolved.has(f.id) ? 'text-muted line-through' : ''}`}>
                        <span className={`${SEV[f.severity].text} font-semibold`}>{f.severity}:</span> {f.title}
                        {f.file && <span className="ml-1.5 font-mono text-[13px] break-all text-faint">{f.file}{f.line ? `:${f.line}` : ''}</span>}
                      </button>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </div>
        {shown.length > 0 && (
          <p className="border-t border-line px-4 py-2.5 text-[13.5px] text-muted sm:px-6">
            {done} of {shown.length} conversation{shown.length === 1 ? '' : 's'} resolved. Your progress stays in this browser.
          </p>
        )}
      </section>

      {shown.length === 0 && (
        <section className="mt-8 rounded-lg border border-fix/30 bg-fix/[0.06] px-6 py-6">
          <h2 className="flex items-center gap-2 text-[1.25rem] font-bold"><CircleCheck className="size-5 text-fix" strokeWidth={2.2} />No major issues found</h2>
          <p className="mt-2 max-w-[62ch] text-[15.5px] leading-relaxed text-muted">
            Nothing in what we checked needs fixing. That isn't a guarantee: see below for what was checked, and review again after big changes.
          </p>
        </section>
      )}

      {files.length > 0 && (
        <section className="mt-12">
          <h2 className="text-[1.35rem] font-bold tracking-[-0.015em]">Files with comments <span className="font-normal text-faint">{files.length}</span></h2>
          <div className="mt-5 flex flex-col gap-6">
            {files.map(({ file, items }) => (
              <div key={file} className="overflow-hidden rounded-lg border border-line">
                <p className="flex items-center gap-2.5 border-b border-line bg-surface px-4 py-2.5 text-[13.5px]">
                  <FileCode2 className="size-4 shrink-0 text-faint" strokeWidth={1.9} />
                  <span className="min-w-0 truncate font-mono">{file}</span>
                  <span className="ml-auto flex shrink-0 items-center gap-1.5 text-faint"><MessageSquare className="size-3.5" strokeWidth={2} />{items.length}</span>
                </p>
                <ul className="flex flex-col gap-2.5 bg-ink p-2.5 sm:p-3">
                  {items.map((f) => <FindingRow key={f.id} finding={f} resolved={resolved.has(f.id)} onResolve={() => toggle(f.id)} />)}
                </ul>
              </div>
            ))}
          </div>
        </section>
      )}

      {passed.length > 0 && (
        <section className="mt-12 overflow-hidden rounded-lg border border-line">
          <h2 className="flex items-center gap-2 border-b border-line bg-surface px-4 py-3 text-[14.5px] font-semibold">
            <CircleCheck className="size-4 text-fix" strokeWidth={2.2} />Checks that passed
          </h2>
          <ul className="divide-y divide-line">
            {passed.map((p) => (
              <li key={p} className="flex items-start gap-3 px-4 py-2.5 text-[14.5px]">
                <CircleCheck className="mt-0.5 size-4 shrink-0 text-fix" strokeWidth={2} />{p}
              </li>
            ))}
          </ul>
        </section>
      )}

      {noise.length > 0 && (
        <details className="group/noise mt-8">
          <summary className="cursor-pointer list-none text-[14.5px] text-muted hover:text-fg [&::-webkit-details-marker]:hidden">
            {noise.length} comment{noise.length === 1 ? '' : 's'} hidden as not a real risk
            <span className="ml-1.5 text-low group-open/noise:hidden">Show</span>
          </summary>
          <ul className="mt-4 flex flex-col gap-2.5">
            {noise.map((f) => <FindingRow key={f.id} finding={f} />)}
          </ul>
        </details>
      )}

      <section className="mt-12 overflow-hidden rounded-lg border border-line">
        <h2 className="border-b border-line bg-surface px-4 py-3 text-[14.5px] font-semibold">Checks run on this review</h2>
        <ul className="divide-y divide-line">
          {steps.filter((s) => s.key !== 'ingest').map((s) => (
            <li key={s.key} className="flex items-center gap-3 px-4 py-2.5 text-[14px]">
              {s.state === 'done' ? <CircleCheck className="size-4 shrink-0 text-fix" strokeWidth={2} />
                : s.state === 'failed' ? <CircleX className="size-4 shrink-0 text-crit" strokeWidth={2} />
                : <CircleMinus className="size-4 shrink-0 text-faint" strokeWidth={2} />}
              <span className={s.state === 'done' ? '' : 'text-muted'}>{s.label}</span>
              <span className="ml-auto truncate text-right text-[13px] text-faint">{s.note}{s.checked ? ` in ${s.checked}` : ''}</span>
            </li>
          ))}
        </ul>
        <p className="border-t border-line px-4 py-2.5 text-[13.5px] text-faint">
          Coming next: reviewing the live app too, with DOM-XSS fuzzing and checks of your deployed Supabase and Firebase settings.
        </p>
      </section>
    </article>
  )
}

// Comments grouped by file, the worst file first (by its worst comment, then by how many).
function byFile(findings) {
  const groups = {}
  for (const f of findings) (groups[f.file || 'Project'] ??= []).push(f)
  const worst = (items) => Math.min(...items.map((f) => ORDER.indexOf(f.severity)))
  return Object.entries(groups)
    .map(([file, items]) => ({ file, items: items.sort((a, b) => ORDER.indexOf(a.severity) - ORDER.indexOf(b.severity) || a.line - b.line) }))
    .sort((a, b) => worst(a.items) - worst(b.items) || b.items.length - a.items.length)
}

// Which conversations the user has resolved, per report, kept in this browser only.
function useResolved(scanId) {
  const key = `vibeguard:resolved:${scanId}`
  const [ids, setIds] = useState(() => {
    try {
      return new Set(JSON.parse(localStorage.getItem(key) ?? '[]'))
    } catch {
      return new Set()
    }
  })
  function toggle(id) {
    setIds((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      try {
        localStorage.setItem(key, JSON.stringify([...next]))
      } catch {
        // storage off: resolving still works for this visit
      }
      return next
    })
  }
  return [ids, toggle]
}

// Every comment as one mark, worst first: the shape of the review at a glance, and a way into each comment.
function CommentMap({ findings, resolved }) {
  const sorted = [...findings].sort((a, b) => ORDER.indexOf(a.severity) - ORDER.indexOf(b.severity))
  return (
    <ol className="mt-5 flex h-6 gap-[3px]" aria-label="Comments by severity, worst first">
      {sorted.map((f) => (
        <li key={f.id} className="min-w-[4px] flex-1">
          <button
            type="button"
            onClick={() => openFinding(f.id)}
            title={`${f.severity}: ${f.title}`}
            aria-label={`${f.severity}: ${f.title}`}
            className={`block h-full w-full rounded-[3px] transition-[opacity,transform] hover:-translate-y-0.5 ${resolved.has(f.id) ? 'bg-line-strong' : SEV[f.severity].bg}`}
          />
        </li>
      ))}
    </ol>
  )
}

function Exports({ scanId }) {
  const action = 'flex items-center gap-1.5 rounded-md border border-line-strong px-3 py-1.5 text-[13.5px] text-muted transition-colors hover:bg-raised hover:text-fg'
  return (
    <div className="flex shrink-0 flex-wrap gap-2 print:hidden">
      <a className={action} href={`${BASE}/scan/${scanId}/report.md`} download><FileDown className="size-4" strokeWidth={1.9} />Markdown</a>
      <a className={action} href={`${BASE}/scan/${scanId}/report.sarif`} download title="For GitHub code scanning"><FileDown className="size-4" strokeWidth={1.9} />SARIF</a>
      <button type="button" className={action} onClick={printReport}><Printer className="size-4" strokeWidth={1.9} />Save as PDF</button>
    </div>
  )
}

// Print every thread expanded, then put them back the way they were.
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
