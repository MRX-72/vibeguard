import { SEV } from '../severity'

export default function FindingRow({ finding: f, index }) {
  const sev = SEV[f.severity]
  return (
    <li className="animate-[rise_400ms_ease-out_both]" style={{ animationDelay: `${Math.min(index, 12) * 35}ms` }}>
      <details className="group relative overflow-hidden rounded-lg border border-line bg-surface open:bg-surface">
        <span className={`absolute inset-y-0 left-0 w-[3px] ${sev.bg}`} aria-hidden />
        <summary className="flex cursor-pointer list-none flex-col gap-1 py-3.5 pr-4 pl-5 hover:bg-raised sm:flex-row sm:items-baseline sm:gap-4 [&::-webkit-details-marker]:hidden">
          <span className={`w-16 shrink-0 text-sm font-medium ${sev.text}`}>{f.severity}</span>
          <span className="flex-1 font-medium">
            {f.title}
            {f.money_risk && (
              <span className="ml-2 inline-flex translate-y-[-1px] rounded bg-med/10 px-1.5 py-0.5 align-middle text-xs font-medium text-med" title="Could run up a bill or drain an API quota">
                $ risk
              </span>
            )}
          </span>
          {f.file && <span className="truncate font-mono text-[12.5px] text-faint">{f.file}{f.line ? `:${f.line}` : ''}</span>}
        </summary>

        <div className="flex flex-col gap-5 border-t border-line px-5 py-5">
          {f.impact && <p className="text-[17px] leading-relaxed text-pretty">{f.impact}</p>}
          {f.explanation && <p className="leading-relaxed text-muted text-pretty">{f.explanation}</p>}
          {f.code_snippet && <Code label="Evidence" code={f.code_snippet} />}
          {f.fix_diff && <Code label="Suggested fix" code={f.fix_diff} diff />}
        </div>
      </details>
    </li>
  )
}

function Code({ label, code, diff }) {
  return (
    <figure>
      <figcaption className="mb-2 text-sm text-muted">{label}</figcaption>
      <pre className="overflow-x-auto rounded-md border border-line bg-ink py-3 font-mono text-[12.5px] leading-relaxed">
        {code.split('\n').map((line, i) => (
          <div
            key={i}
            className={`px-3 ${diff && line.startsWith('+') ? 'bg-fix/10 text-fix' : diff && line.startsWith('-') ? 'bg-crit/10 text-crit' : ''}`}
          >
            {line || ' '}
          </div>
        ))}
      </pre>
    </figure>
  )
}
