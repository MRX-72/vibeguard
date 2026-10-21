import { Check, LoaderCircle, Minus, X } from 'lucide-react'

const FINISHED = new Set(['done', 'skipped', 'failed', 'na'])

export default function ScanProgress({ status }) {
  const steps = status?.steps ?? []
  const queued = status?.status === 'queued'
  const finished = steps.filter((s) => FINISHED.has(s.state)).length
  const pct = steps.length ? Math.round((finished / steps.length) * 100) : 0

  return (
    <section className="mx-auto max-w-3xl pt-10 sm:pt-14" aria-live="polite">
      <p className="eyebrow flex items-center gap-2.5"><span className="size-1.5 animate-pulse rounded-full bg-accent" />{queued ? 'Queued' : 'Scanning'}</p>
      <h1 className="mt-4 text-3xl font-semibold tracking-[-0.03em]">{queued ? 'Waiting for a free scanner' : 'Reading your code'}</h1>
      <p className="mt-2 text-muted">
        {queued ? 'Another scan is running. Yours starts as soon as it finishes.' : status?.stage ?? 'Starting…'}
      </p>

      <div className="mt-8 rounded-2xl border border-line bg-surface p-5 sm:p-7">
        <div className="flex items-baseline justify-between font-mono text-xs text-faint">
          <span>{finished} of {steps.length || '…'} steps</span>
          <span className="tabular-nums">{pct}%</span>
        </div>
        <div className="mt-2.5 h-1.5 overflow-hidden rounded-full bg-raised">
          <div className="h-full rounded-full bg-accent transition-[width] duration-500 ease-out" style={{ width: `${pct}%` }} />
        </div>

        <ol className="mt-6 divide-y divide-line">
          {steps.map((s) => (
            <li key={s.key} className="flex items-center gap-4 py-3">
              <StepIcon state={s.state} />
              <span className="min-w-0 flex-1">
                <span className={`block text-[15px] ${s.state === 'running' ? 'text-fg' : s.state === 'pending' || s.state === 'na' ? 'text-faint' : 'text-muted'}`}>
                  {s.label}
                </span>
                {s.tool && <span className="font-mono text-xs text-faint">{s.tool}</span>}
              </span>
              {s.note && (
                <span className="max-w-[45%] truncate text-right text-[13px] text-faint">{s.note}{s.checked ? ` in ${s.checked}` : ''}</span>
              )}
            </li>
          ))}
        </ol>
      </div>
    </section>
  )
}

function StepIcon({ state }) {
  const box = 'grid size-7 shrink-0 place-items-center rounded-lg border'
  if (state === 'running') return <span className={`${box} border-accent/40 bg-accent/10 text-accent`} aria-label="In progress"><LoaderCircle className="size-4 animate-spin" /></span>
  if (state === 'done') return <span className={`${box} border-accent/25 bg-accent/10 text-accent`} aria-label="Done"><Check className="size-4" strokeWidth={2.25} /></span>
  if (state === 'failed') return <span className={`${box} border-crit/30 bg-crit/10 text-crit`} aria-label="Didn't finish"><X className="size-4" strokeWidth={2.25} /></span>
  if (state === 'skipped' || state === 'na')
    return <span className={`${box} border-line text-faint`} aria-label={state === 'na' ? 'Not needed' : 'Skipped'}><Minus className="size-4" /></span>
  return <span className={`${box} border-line`} aria-label="Pending" />
}
