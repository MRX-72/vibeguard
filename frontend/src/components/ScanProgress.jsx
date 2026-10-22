import { CircleCheck, CircleDashed, CircleMinus, CircleX, LoaderCircle } from 'lucide-react'

const FINISHED = new Set(['done', 'skipped', 'failed', 'na'])
const SEGMENT = { done: 'bg-fix', failed: 'bg-crit', skipped: 'bg-line-strong', na: 'bg-line-strong', running: 'bg-med', pending: 'bg-raised' }

// The review running as status checks: one unbroken row of steps with a light on the one running now, then each check.
export default function ScanProgress({ status }) {
  const steps = status?.steps ?? []
  const queued = status?.status === 'queued'
  const finished = steps.filter((s) => FINISHED.has(s.state)).length

  return (
    <section className="mx-auto max-w-3xl pt-10 sm:pt-12" aria-live="polite">
      <h1 className="text-[2rem] font-bold tracking-[-0.03em]">{queued ? 'Waiting for a free reviewer' : 'Reading your code'}</h1>
      <p className="mt-2 text-[16px] text-muted">
        {queued ? 'Another review is running. Yours starts as soon as it finishes.' : status?.stage ?? 'Starting…'}
      </p>

      <div className="mt-8 overflow-hidden rounded-lg border border-line">
        <div className="border-b border-line bg-surface px-4 py-3.5">
          <p className="text-[14.5px] font-semibold">
            {finished === steps.length && steps.length ? 'All checks have finished' : "Some checks haven't completed yet"}
          </p>
          <p className="mt-0.5 text-[13.5px] text-faint">{finished} of {steps.length || '…'} checks finished</p>
          <ol className="mt-3 flex h-2 overflow-hidden rounded-full bg-raised" aria-hidden>
            {steps.map((s) => (
              <li key={s.key} className={`relative flex-1 overflow-hidden border-r border-ink/70 last:border-r-0 ${SEGMENT[s.state] ?? 'bg-raised'}`}>
                {s.state === 'running' && <span className="absolute inset-y-0 w-1/3 bg-white/60 motion-safe:animate-[scan-light_1.1s_linear_infinite]" />}
              </li>
            ))}
          </ol>
        </div>
        <ol className="divide-y divide-line">
          {steps.map((s) => (
            <li key={s.key} className="flex items-center gap-3 px-4 py-3">
              <StepIcon state={s.state} />
              <span className="min-w-0 flex-1">
                <span className={`text-[14.5px] ${s.state === 'running' ? 'font-semibold text-fg' : s.state === 'pending' || s.state === 'na' ? 'text-faint' : 'text-fg'}`}>
                  {s.label}
                </span>
              </span>
              {s.note && <span className="max-w-[45%] truncate text-right text-[13px] text-faint">{s.note}{s.checked ? ` in ${s.checked}` : ''}</span>}
            </li>
          ))}
        </ol>
      </div>
    </section>
  )
}

function StepIcon({ state }) {
  const c = 'size-[18px] shrink-0'
  if (state === 'running') return <LoaderCircle className={`${c} animate-spin text-med`} strokeWidth={2.2} aria-label="In progress" />
  if (state === 'done') return <CircleCheck className={`${c} text-fix`} strokeWidth={2.2} aria-label="Passed" />
  if (state === 'failed') return <CircleX className={`${c} text-crit`} strokeWidth={2.2} aria-label="Didn't finish" />
  if (state === 'skipped' || state === 'na') return <CircleMinus className={`${c} text-faint`} strokeWidth={2} aria-label={state === 'na' ? 'Not needed' : 'Skipped'} />
  return <CircleDashed className={`${c} text-faint`} strokeWidth={2} aria-label="Waiting" />
}
