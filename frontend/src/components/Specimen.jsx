import { SEV } from '../severity'

// A component the way AI builders often write it, with what a scan finds in it. Static: it explains the product, it isn't a scan.
const LINES = [
  { code: 'import OpenAI from "openai"' },
  { code: '' },
  { code: 'const ai = new OpenAI({ apiKey: "sk-proj-9fQ…" })',
    sev: 'Critical', note: 'Your OpenAI key ships to every visitor, who can run up your bill.' },
  { code: '' },
  { code: 'export function Comment({ id, body }) {' },
  { code: '  const isAdmin = localStorage.isAdmin === "true"',
    sev: 'High', note: 'Anyone can make themselves admin from the browser console.' },
  { code: '  if (isAdmin) supabase.from("comments").delete()' },
  { code: '  return <div dangerouslySetInnerHTML={{ __html: body }} />',
    sev: 'High', note: 'A comment can run code in the browser of everyone who reads it.' },
  { code: '}' },
]
const SWEEP_MS = 1600

export default function Specimen() {
  const rows = LINES.length
  return (
    <figure className="relative overflow-hidden rounded-2xl border border-line bg-side" aria-label="Example: three problems VibeGuard finds in a typical AI-built component">
      <figcaption className="flex items-center justify-between gap-4 border-b border-line px-5 py-3 text-[13px]">
        <span className="min-w-0 truncate font-mono text-muted">src/components/Comment.jsx</span>
        <span className="flex shrink-0 items-center gap-2 whitespace-nowrap text-faint">
          <span className="heat-ramp h-1.5 w-14 rounded-full" aria-hidden />
          3 problems
        </span>
      </figcaption>
      <div className="relative py-3">
        {/* the scan line: passes once, top to bottom */}
        <div
          className="pointer-events-none absolute inset-x-0 top-0 z-10 h-px bg-hot/80 shadow-[0_0_18px_4px_rgba(246,241,255,0.35)] motion-safe:animate-[sweep_var(--d)_cubic-bezier(.45,0,.25,1)_250ms_both] motion-reduce:hidden"
          style={{ '--d': `${SWEEP_MS}ms` }}
          aria-hidden
        />
        <ol className="font-mono text-[12px] leading-[1.85] sm:text-[13px]">
          {LINES.map((l, i) => {
            const delay = `${250 + (i / rows) * SWEEP_MS}ms`
            return (
              <li key={i} className="relative">
                {l.sev && (
                  <span
                    className={`absolute inset-0 border-l-2 bg-linear-to-r to-transparent motion-safe:animate-[heat-up_500ms_ease-out_both] ${SEV[l.sev].glow} ${SEV[l.sev].border}`}
                    style={{ animationDelay: delay }}
                    aria-hidden
                  />
                )}
                <span className="relative flex pr-4 sm:pr-6">
                  <span className="w-9 shrink-0 pr-3 text-right text-faint/70 select-none sm:w-11 sm:pr-4">{i + 1}</span>
                  {/* wraps on phones instead of hiding the end of the line */}
                  <code className={`min-w-0 break-words whitespace-pre-wrap ${l.sev ? 'text-fg' : 'text-muted'}`}>{tint(l.code) || ' '}</code>
                </span>
                {l.sev && (
                  <span
                    className="relative block pr-4 pb-1.5 pl-9 font-sans text-[13px] leading-snug motion-safe:animate-[heat-up_500ms_ease-out_both] sm:pl-11"
                    style={{ animationDelay: delay }}
                  >
                    <span className={`mr-2 font-medium ${SEV[l.sev].text}`}>{l.sev}</span>
                    <span className="text-muted">{l.note}</span>
                  </span>
                )}
              </li>
            )
          })}
        </ol>
      </div>
    </figure>
  )
}

// strings a little lighter than code, so the line reads as code without a full highlighter
function tint(code) {
  return code.split(/("[^"]*")/).map((part, i) => (i % 2 ? <span key={i} className="text-[#d9c9ff]">{part}</span> : part))
}
