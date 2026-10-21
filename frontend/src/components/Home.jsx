import { ArrowRight, Play, ShieldCheck } from 'lucide-react'
import Specimen from './Specimen'

const STEPS = [
  { title: 'Give it your code', text: 'Paste a file, upload a zip, or link a public GitHub repo. Nothing to install, no account.' },
  { title: 'It reads everything', text: 'Open-source scanners plus our own rules check your keys, dependencies, Supabase and Firebase setup, and code. An AI double-checks anything uncertain.' },
  { title: 'Fix what matters', text: 'Each problem in plain English, on its exact line, with a fix and a prompt to paste back into your AI builder.' },
]

export default function Home({ status }) {
  return (
    <div className="pt-10 sm:pt-16">
      <section className="grid items-center gap-10 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.08fr)] xl:gap-14">
        <div>
          <h1 className="text-[3rem] leading-[0.98] font-semibold tracking-[-0.035em] sm:text-[4.5rem]">
            <span className="block">Ship fast.</span>
            <span className="block">Know what's exposed.</span>
          </h1>
          <p className="mt-6 max-w-[46ch] text-[18px] leading-[1.55] text-muted text-pretty">
            VibeGuard reads the code your AI builder wrote and shows you, line by line, what a stranger could do with it, plus
            the fix to paste back into Lovable, Bolt or Cursor.
          </p>
          <div className="mt-8 flex flex-wrap items-center gap-3">
            <a href="#/scan" className="flex items-center gap-2 rounded-lg bg-hot px-5 py-3 text-[15px] font-semibold text-ink transition-colors hover:bg-white">
              <ShieldCheck className="size-[18px]" strokeWidth={2} />Scan your code
            </a>
            <a href="#/demo" className="flex items-center gap-2 rounded-lg border border-line-strong px-5 py-3 text-[15px] text-muted transition-colors hover:bg-raised hover:text-fg">
              <Play className="size-3.5 fill-current" strokeWidth={1.5} />See the demo
            </a>
          </div>
          <p className="mt-4 text-[14px] text-faint">Free. Your code is deleted when the scan ends.</p>
        </div>
        <Specimen />
      </section>

      {status === 'down' && (
        <p role="alert" className="mt-10 rounded-xl border border-crit/25 bg-crit/[0.06] px-4 py-3 text-[15px] leading-relaxed text-muted">
          <span className="font-medium text-crit">The scanner isn't answering.</span> Try again in a few minutes.
        </p>
      )}
      {status === 'waking' && (
        <p role="status" className="mt-10 rounded-xl border border-med/25 bg-med/[0.06] px-4 py-3 text-[15px] leading-relaxed text-muted">
          <span className="font-medium text-med">Waking the scanner.</span> The free server sleeps when nobody's using it, so the first
          scan takes about a minute longer.
        </p>
      )}

      <section className="mt-20" aria-labelledby="how">
        <h2 id="how" className="text-2xl font-semibold tracking-[-0.025em]">How it works</h2>
        <ol className="mt-6 grid gap-4 md:grid-cols-3">
          {STEPS.map((s, i) => (
            <li key={s.title} className="rounded-2xl border border-line bg-surface p-6">
              <span className="grid size-8 place-items-center rounded-lg bg-raised text-[15px] font-semibold tabular-nums text-muted">{i + 1}</span>
              <h3 className="mt-5 text-[17px] font-semibold tracking-[-0.01em]">{s.title}</h3>
              <p className="mt-2 text-[15px] leading-relaxed text-muted">{s.text}</p>
            </li>
          ))}
        </ol>
        <div className="mt-8 flex flex-wrap items-center justify-between gap-4 rounded-2xl border border-line px-6 py-5">
          <p className="max-w-[60ch] text-[15px] leading-relaxed text-muted">
            Knows the stacks AI builders use: React, Next.js and Vite, Express, Supabase and Firebase, and Python backends.
          </p>
          <a href="#/scan" className="flex items-center gap-1.5 text-[15px] font-medium text-fg hover:underline">
            Start a scan <ArrowRight className="size-4" strokeWidth={2} />
          </a>
        </div>
      </section>
    </div>
  )
}
