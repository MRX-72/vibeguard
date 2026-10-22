import { Check, CircleCheck, Copy as CopyIcon } from 'lucide-react'
import { useState } from 'react'
import { CONFIDENCE_LINE, SEV } from '../severity'
import { Mark } from './Logo'

const AI = { real: 'AI review agrees', false_positive: 'AI review: not a real risk', unsure: 'AI review: unsure' }
const CONFIDENCE_TEXT = { 'Confirmed reachable': 'Confirmed reachable', Likely: 'Likely', 'Needs review': 'Needs review' }

// One finding as a review thread: the code it is about, then VibeGuard's comment under it. The collapsed line is the
// whole summary (severity, title, line, how sure); opening it is detail. Line style draws confidence.
export default function FindingRow({ finding: f, resolved = false, onResolve }) {
  const sev = SEV[f.severity]
  const noise = f.is_false_positive
  const line = f.line ? `line ${f.line}` : ''
  return (
    <li id={`f-${f.id}`} className="scroll-mt-32">
      <details
        className={`group rounded-lg border bg-surface ${CONFIDENCE_LINE[f.confidence]} ${
          noise || resolved ? 'border-line opacity-75' : sev.border
        } open:opacity-100`}
      >
        <summary className="flex cursor-pointer list-none items-start gap-3 px-4 py-3 hover:bg-raised/50 [&::-webkit-details-marker]:hidden">
          <Mark size={22} round />
          <span className="min-w-0 flex-1">
            <span className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
              <span className={`text-[14px] ${noise ? 'text-faint' : `${sev.text} ${sev.weight}`}`}>{f.severity}</span>
              <span className={`text-[15px] leading-snug ${resolved ? 'text-muted line-through decoration-faint' : 'font-semibold'}`}>{f.title}</span>
              {f.money_risk && !noise && (
                <span className="rounded-full border border-line-strong px-1.5 text-[12px] font-medium text-muted" title="Could run up a bill or drain an API quota">$ risk</span>
              )}
              {resolved && <span className="rounded-full bg-fix/15 px-2 text-[12px] font-semibold text-fix">Resolved</span>}
            </span>
            <span className="mt-0.5 block text-[13px] text-faint">
              {f.kind === 'dependency' ? f.package : line}
              {line || f.kind === 'dependency' ? ', ' : ''}
              {CONFIDENCE_TEXT[f.confidence].toLowerCase()}
              {f.ai_verdict ? `, ${AI[f.ai_verdict].toLowerCase()}` : ''}
            </span>
          </span>
        </summary>

        <div className="border-t border-line">
          {f.code_snippet && <Code code={f.code_snippet} start={f.snippet_start} from={f.line} to={f.end_line || f.line} tone={noise ? { soft: 'bg-line/60', text: 'text-muted' } : sev} />}

          <div className="flex flex-col gap-4 px-4 py-4 sm:pl-[3.25rem]">
            {f.impact && <p className="text-[16.5px] leading-relaxed font-medium text-pretty">{f.impact}</p>}
            {f.severity_reason && !f.triage_note?.includes(f.severity_reason) && (
              <p className="text-[14.5px] leading-relaxed text-muted"><span className="font-semibold text-fg">Why {f.severity.toLowerCase()}:</span> {f.severity_reason}</p>
            )}
            {f.triage_note && <p className="text-[14.5px] leading-relaxed text-muted">{f.triage_note}</p>}
            {f.ai_note && (
              <p className="text-[14.5px] leading-relaxed text-muted"><span className="font-semibold text-fg">{AI[f.ai_verdict] ?? 'AI review'}:</span> {f.ai_note}</p>
            )}
            {f.explanation && <p className="text-[15px] leading-relaxed text-muted text-pretty">{f.explanation}</p>}
            {f.evidence?.length > 0 && (
              <div>
                <p className="mb-1.5 text-[13.5px] font-semibold">{f.kind === 'dependency' ? 'Advisories' : 'Evidence'}</p>
                <ul className="flex list-disc flex-col gap-1 pl-5 text-[14px] leading-relaxed text-muted marker:text-faint">
                  {f.evidence.map((e, i) => <li key={i} className="break-words">{mono(e)}</li>)}
                </ul>
              </div>
            )}
            {f.fix_diff && <Suggestion diff={f.fix_diff} />}
            {f.reprompt && (
              <div className="overflow-hidden rounded-md border border-line">
                <p className="flex items-center justify-between gap-3 border-b border-line bg-raised/60 px-3 py-1.5 text-[12.5px] font-medium text-muted">
                  Prompt for your AI builder
                  <Copy text={f.reprompt} />
                </p>
                <p className="bg-inset px-3 py-2.5 text-[14px] leading-relaxed text-muted">{f.reprompt}</p>
              </div>
            )}
            <div className="flex flex-wrap items-center gap-x-4 gap-y-2 pt-1">
              {onResolve && !noise && (
                <button
                  type="button"
                  onClick={onResolve}
                  className={`flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-[13.5px] font-medium transition-colors print:hidden ${
                    resolved ? 'border-line-strong text-muted hover:text-fg' : 'border-fix/40 text-fix hover:bg-fix/10'
                  }`}
                >
                  <CircleCheck className="size-4" strokeWidth={2} />{resolved ? 'Reopen conversation' : 'Resolve conversation'}
                </button>
              )}
              {f.refs?.length > 0 && (
                <ul className="flex flex-wrap gap-x-3 gap-y-1 text-[13px]">
                  {f.refs.map((r) => (
                    <li key={r}><a href={r} target="_blank" rel="noreferrer" className="text-low hover:underline">{refLabel(r)}</a></li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        </div>
      </details>
    </li>
  )
}

// Paths, path:line references and shell commands are code: set them in the code face.
function mono(text) {
  return text.split(/(\b[\w./-]+\.\w{1,5}:\d+\b|\bcurl '[^']*'[^.]*?(?=\. |$)|`[^`]+`)/).map((part, i) =>
    i % 2 ? <code key={i} className="rounded bg-raised px-1 py-px font-mono text-[12.5px] text-fg">{part.replace(/^`|`$/g, '')}</code> : part)
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

// The new code only: what someone pastes in place of the old lines.
const fixText = (diff) => diff.split('\n').filter((l) => !l.startsWith('-')).map((l) => l.replace(/^\+ ?/, '')).join('\n')

function Copy({ text }) {
  const [done, setDone] = useState(false)
  return (
    <button
      type="button"
      onClick={() => navigator.clipboard?.writeText(text).then(() => { setDone(true); setTimeout(() => setDone(false), 1500) })}
      className="flex shrink-0 items-center gap-1 rounded px-1.5 py-0.5 font-sans text-[12.5px] text-muted hover:bg-raised hover:text-fg print:hidden"
    >
      {done ? <Check className="size-3.5" strokeWidth={2.4} /> : <CopyIcon className="size-3.5" strokeWidth={2} />}
      {done ? 'Copied' : 'Copy'}
    </button>
  )
}

function Suggestion({ diff }) {
  return (
    <div className="overflow-hidden rounded-md border border-line">
      <p className="flex items-center justify-between gap-3 border-b border-line bg-raised/60 px-3 py-1.5 text-[12.5px] font-medium text-muted">
        Suggested change
        <Copy text={fixText(diff)} />
      </p>
      <pre className="overflow-x-auto bg-inset py-2 font-mono text-[12.5px] leading-[1.75]">
        {diff.split('\n').map((l, i) => {
          const tone = l.startsWith('+') ? 'bg-fix/[0.1] text-fg' : l.startsWith('-') ? 'bg-crit/[0.1] text-fg' : 'text-muted'
          const sign = l.startsWith('+') ? 'text-fix' : l.startsWith('-') ? 'text-crit' : 'text-faint'
          return (
            <div key={i} className={`flex min-w-max ${tone}`}>
              <span className={`w-6 shrink-0 text-center select-none ${sign}`}>{/^[+-]/.test(l) ? l[0] : ' '}</span>
              <span className="pr-4">{(/^[+-] ?/.test(l) ? l.replace(/^[+-] ?/, '') : l) || ' '}</span>
            </div>
          )
        })}
      </pre>
    </div>
  )
}

// The code the comment is about, numbered, with the flagged lines marked like a selected range in a review.
function Code({ code, start, from, to, tone }) {
  const numbered = start > 0
  return (
    <pre className="overflow-x-auto border-b border-line bg-inset py-2 font-mono text-[12.5px] leading-[1.75]">
      {code.split('\n').map((l, i) => {
        const n = start + i
        const hit = numbered && n >= from && n <= to
        return (
          <div key={i} className={`flex min-w-max ${hit ? `${tone.soft} text-fg` : 'text-muted'}`}>
            {numbered && <span className={`w-12 shrink-0 pr-4 text-right select-none ${hit ? tone.text : 'text-faint'}`} aria-hidden>{n}</span>}
            <span className={numbered ? 'pr-4' : 'px-4'}>{l || ' '}</span>
          </div>
        )
      })}
    </pre>
  )
}
