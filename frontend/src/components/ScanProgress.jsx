export default function ScanProgress({ status }) {
  const steps = status?.steps ?? []
  const queued = status?.status === 'queued'

  return (
    <section className="pt-10 sm:pt-16" aria-live="polite">
      <h1 className="text-2xl font-semibold tracking-tight">{queued ? 'Waiting for a free scanner…' : 'Scanning your code'}</h1>
      <p className="mt-2 text-muted">
        {queued ? 'Another scan is running. Yours starts as soon as it finishes.' : status?.stage ?? 'Starting…'}
      </p>

      <ol className="mt-10 border-l border-line">
        {steps.map((s) => (
          <li key={s.key} className="relative flex flex-wrap items-baseline gap-x-3 py-2.5 pl-6">
            <StepIcon state={s.state} />
            <span className={s.state === 'pending' || s.state === 'na' ? 'text-faint' : s.state === 'running' ? 'text-fg' : 'text-muted'}>
              {s.label}
            </span>
            {s.tool && <span className="text-sm text-faint">{s.tool}</span>}
            {s.note && <span className="ml-auto text-sm text-faint">{s.note}{s.checked ? ` in ${s.checked}` : ''}</span>}
          </li>
        ))}
      </ol>
    </section>
  )
}

function StepIcon({ state }) {
  const base = 'absolute top-1/2 -left-[7px] size-3.5 -translate-y-1/2 rounded-full'
  if (state === 'running')
    return <span className={`${base} animate-spin border-2 border-accent border-t-transparent bg-ink`} aria-label="In progress" />
  if (state === 'done')
    return (
      <span className={`${base} grid place-items-center bg-fg`} aria-label="Done">
        <svg viewBox="0 0 12 12" className="size-2.5 text-ink"><path d="m2.5 6.2 2.2 2.2 4.8-4.9" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" /></svg>
      </span>
    )
  if (state === 'skipped' || state === 'failed' || state === 'na')
    return (
      <span className={`${base} border border-faint bg-ink`} aria-label={state === 'na' ? 'Not needed' : 'Skipped'}>
        <span className="absolute inset-x-[3px] top-1/2 h-px bg-faint" />
      </span>
    )
  return <span className={`${base} border border-line bg-ink`} aria-label="Pending" />
}
