import { SEV } from '../severity'

const CONFIDENCE = {
  'Confirmed reachable': 'text-fg bg-fg/10',
  Likely: 'text-muted bg-raised',
  'Needs review': 'text-faint bg-raised',
}

export default function FindingRow({ finding: f, index }) {
  const sev = SEV[f.severity]
  const where = f.file ? `${f.file}${f.line ? `:${f.line}` : ''}` : ''
  return (
    <li className="animate-[rise_400ms_ease-out_both]" style={{ animationDelay: `${Math.min(index, 12) * 35}ms` }}>
      <details className="group relative overflow-hidden rounded-lg border border-line bg-surface">
        <span className={`absolute inset-y-0 left-0 w-[3px] ${f.is_false_positive ? 'bg-line' : sev.bg}`} aria-hidden />
        <summary className="flex cursor-pointer list-none flex-col gap-1 py-3.5 pr-4 pl-5 hover:bg-raised sm:flex-row sm:items-baseline sm:gap-4 [&::-webkit-details-marker]:hidden">
          <span className={`w-16 shrink-0 text-sm font-medium ${f.is_false_positive ? 'text-faint' : sev.text}`}>{f.severity}</span>
          <span className="flex-1 font-medium">
            {f.title}
            {f.money_risk && !f.is_false_positive && (
              <span className="ml-2 inline-flex translate-y-[-1px] rounded bg-med/10 px-1.5 py-0.5 align-middle text-xs font-medium text-med" title="Could run up a bill or drain an API quota">
                $ risk
              </span>
            )}
          </span>
          {where && <span className="truncate font-mono text-[12.5px] text-faint">{where}</span>}
        </summary>

        <div className="flex flex-col gap-5 border-t border-line px-5 py-5">
          {f.impact && <p className="text-[17px] leading-relaxed text-pretty">{f.impact}</p>}

          <div className="flex flex-wrap items-center gap-x-3 gap-y-2 text-sm">
            <span className={`rounded px-2 py-0.5 text-xs font-medium ${CONFIDENCE[f.confidence]}`}>
              {f.kind === 'secret' && f.confidence === 'Confirmed reachable' ? 'Confirmed live' : f.confidence}
            </span>
            {f.detected_by?.length > 0 && <span className="text-faint">Found by {f.detected_by.join(', ')}</span>}
          </div>

          {f.triage_note && <p className="text-sm leading-relaxed text-muted">{f.triage_note}</p>}
          {f.severity_reason && !f.triage_note?.includes(f.severity_reason) && (
            <p className="text-sm leading-relaxed text-muted"><span className="text-faint">Why {f.severity.toLowerCase()}: </span>{f.severity_reason}</p>
          )}
          {f.explanation && <p className="leading-relaxed text-muted text-pretty">{f.explanation}</p>}
          {f.code_snippet && (
            <Code label={where || 'Evidence'} code={f.code_snippet} start={f.snippet_start} from={f.line} to={f.end_line || f.line} />
          )}
          {f.evidence?.length > 0 && (
            <div>
              <p className="mb-2 text-sm text-muted">{f.kind === 'dependency' ? 'Advisories' : 'How the data gets there'}</p>
              <ul className="flex flex-col gap-1.5 text-sm leading-relaxed text-muted">
                {f.evidence.map((e, i) => <li key={i} className="break-words">{e}</li>)}
              </ul>
            </div>
          )}
          {f.fix_diff && <Code label="Suggested fix" code={f.fix_diff} diff />}
          {f.refs?.length > 0 && (
            <ul className="flex flex-wrap gap-x-4 gap-y-1 text-sm">
              {f.refs.map((r) => (
                <li key={r}><a href={r} target="_blank" rel="noreferrer" className="text-faint underline decoration-line underline-offset-4 hover:text-fg">{refLabel(r)}</a></li>
              ))}
            </ul>
          )}
        </div>
      </details>
    </li>
  )
}

function refLabel(url) {
  const cwe = url.match(/cwe\.mitre\.org\/data\/definitions\/(\d+)/)
  if (cwe) return `CWE-${cwe[1]}`
  const osv = url.match(/osv\.dev\/vulnerability\/([\w-]+)/)
  if (osv) return osv[1]
  try {
    return new URL(url).hostname.replace(/^www\./, '')
  } catch {
    return url
  }
}

function Code({ label, code, diff, start, from, to }) {
  const numbered = start > 0
  return (
    <figure>
      <figcaption className="mb-2 font-mono text-[12.5px] text-faint">{label}</figcaption>
      <pre className="overflow-x-auto rounded-md border border-line bg-ink py-3 font-mono text-[12.5px] leading-relaxed">
        {code.split('\n').map((line, i) => {
          const n = start + i
          const hit = numbered && n >= from && n <= to
          const tone = diff && line.startsWith('+') ? 'bg-fix/10 text-fix' : diff && line.startsWith('-') ? 'bg-crit/10 text-crit' : hit ? 'bg-fg/[0.06]' : numbered ? 'text-muted' : ''
          return (
            <div key={i} className={`flex min-w-max ${tone}`}>
              {numbered && (
                <span className={`w-12 shrink-0 pr-4 text-right select-none ${hit ? 'text-fg' : 'text-faint'}`} aria-hidden>{n}</span>
              )}
              <span className={numbered ? 'pr-4' : 'px-3'}>{line || ' '}</span>
            </div>
          )
        })}
      </pre>
    </figure>
  )
}
