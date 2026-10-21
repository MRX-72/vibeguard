import { CircleX, GitPullRequest, LoaderCircle, MessageSquare } from 'lucide-react'
import { useScans } from '../history'
import { GRADE_CHIP, VERDICT } from '../severity'

const when = new Intl.DateTimeFormat(undefined, { day: 'numeric', month: 'short', hour: 'numeric', minute: '2-digit' })
const STATE_ICON = { A: 'text-fix', B: 'text-fix', C: 'text-med', D: 'text-high', F: 'text-crit' }
const SOURCE = { demo: 'demo app', paste: 'pasted code', zip: 'zip upload', github: 'GitHub repo' }

// Reviews listed the way a repository lists pull requests: state, name, when, verdict, comment count.
export default function ScanList({ tick, limit = 8, rows: given, compact }) {
  const own = useScans(tick, limit)
  const rows = given !== undefined ? given : own
  if (rows === null) return <div className="h-40 animate-pulse bg-surface/50" aria-label="Loading reviews" />
  if (!rows.length)
    return (
      <div className="px-6 py-12 text-center">
        <GitPullRequest className="mx-auto size-6 text-faint" strokeWidth={1.7} />
        <p className="mt-3 text-[15px] font-semibold">No reviews yet</p>
        <p className="mt-1 text-[14px] text-muted">
          Start one above, or <a href="#/demo" className="text-low hover:underline">review the demo app</a> to see a full report.
        </p>
      </div>
    )
  return (
    <ul className="divide-y divide-line">
      {rows.map((s) => (
        <li key={s.id}>
          <a href={`#/scan/${s.id}`} className="group flex items-start gap-3 px-4 py-3.5 transition-colors hover:bg-surface">
            <StateIcon scan={s} />
            <span className="min-w-0 flex-1">
              <span className="flex flex-wrap items-center gap-x-2.5 gap-y-1">
                <span className="truncate text-[15px] font-semibold group-hover:text-low">{s.source_label || 'Pasted code'}</span>
                {s.status === 'done' && (
                  <span className={`rounded-full px-2 py-px text-[12px] font-semibold ${GRADE_CHIP[s.grade]}`}>
                    Grade {s.grade}{compact ? '' : `, ${VERDICT[s.grade].label.toLowerCase()}`}
                  </span>
                )}
                {s.status === 'failed' && <span className="rounded-full bg-crit/12 px-2 py-px text-[12px] font-semibold text-crit">Didn't finish</span>}
              </span>
              <span className="mt-1 block text-[13px] text-faint">
                {SOURCE[s.source_type] ?? 'code'}, reviewed {when.format(new Date(s.created_at))}
                {s.status === 'done' && !compact ? `, risk ${s.risk_score} of 100` : ''}
              </span>
            </span>
            {s.status === 'done' && (
              <span className="flex shrink-0 items-center gap-1.5 pt-0.5 text-[13.5px] text-faint" title={`${s.findings} comments`}>
                <MessageSquare className="size-4" strokeWidth={1.9} />{s.findings}
              </span>
            )}
          </a>
        </li>
      ))}
    </ul>
  )
}

function StateIcon({ scan }) {
  if (scan.status === 'done') return <GitPullRequest className={`mt-0.5 size-[18px] shrink-0 ${STATE_ICON[scan.grade]}`} strokeWidth={2} aria-label={VERDICT[scan.grade].label} />
  if (scan.status === 'failed') return <CircleX className="mt-0.5 size-[18px] shrink-0 text-crit" strokeWidth={2} aria-label="Didn't finish" />
  return <LoaderCircle className="mt-0.5 size-[18px] shrink-0 animate-spin text-med" strokeWidth={2} aria-label="In progress" />
}
