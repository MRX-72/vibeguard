import { ArrowRight, CloudUpload, Code, FolderGit2, LoaderCircle, Sparkles, X } from 'lucide-react'
import { useScans } from '../history'

const SOURCE = { demo: Sparkles, paste: Code, zip: CloudUpload, github: FolderGit2 }
// the score chip takes the colour of the grade it earned
const GRADE_CHIP = {
  A: 'bg-accent/10 text-accent', B: 'bg-low/10 text-low', C: 'bg-med/10 text-med', D: 'bg-high/10 text-high', F: 'bg-crit/10 text-crit',
}
const when = new Intl.DateTimeFormat(undefined, { day: 'numeric', month: 'short', hour: 'numeric', minute: '2-digit' })

export default function ScanList({ tick, limit = 8, rows: given }) {
  const own = useScans(tick, limit)
  const rows = given !== undefined ? given : own
  if (rows === null) return <div className="h-40 animate-pulse" aria-label="Loading scans" />
  if (!rows.length)
    return (
      <p className="py-10 text-center text-[15px] leading-relaxed text-faint">
        No scans yet. Run the demo to see what a report looks like.
      </p>
    )
  return (
    <ul className="divide-y divide-line">
      {rows.map((s) => {
        const Icon = SOURCE[s.source_type] ?? Code
        return (
          <li key={s.id}>
            <a href={`#/scan/${s.id}`} className="group -mx-2 flex items-center gap-4 rounded-lg px-2 py-4 transition-colors hover:bg-raised/60">
              <span className="grid size-10 shrink-0 place-items-center rounded-lg border border-line bg-ink text-med">
                <Icon className="size-[18px]" strokeWidth={1.75} />
              </span>
              <span className="min-w-0 flex-1">
                <span className="block truncate text-[15px] font-medium">{s.source_label || 'Scan'}</span>
                <span className="mt-0.5 block font-mono text-[12.5px] text-faint">{when.format(new Date(s.created_at))}</span>
              </span>
              <span className="flex flex-col items-end gap-1">
                <Chip scan={s} />
                {s.status === 'done' && (
                  <span className="text-[12.5px] text-faint"><span className="font-mono tabular-nums">{s.findings}</span> finding{s.findings === 1 ? '' : 's'}</span>
                )}
              </span>
              <ArrowRight className="size-4 shrink-0 text-faint transition-transform group-hover:translate-x-0.5 group-hover:text-muted" strokeWidth={1.75} />
            </a>
          </li>
        )
      })}
    </ul>
  )
}

function Chip({ scan }) {
  const base = 'inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 font-mono text-[12.5px] tabular-nums'
  if (scan.status === 'done') return <span className={`${base} ${GRADE_CHIP[scan.grade]}`} title={`Grade ${scan.grade}`}>{scan.grade} · {scan.risk_score}</span>
  if (scan.status === 'failed') return <span className={`${base} bg-crit/10 text-crit`}><X className="size-3.5" strokeWidth={2} />Failed</span>
  return <span className={`${base} bg-raised text-muted`}><LoaderCircle className="size-3.5 animate-spin" strokeWidth={2} />Scanning</span>
}
