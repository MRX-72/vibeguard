import { ArrowRight, CircleCheck, GitCommitHorizontal, GitPullRequest, MessageSquare } from 'lucide-react'
import ReviewDemo from './ReviewDemo'

// What a review checks, written as the status checks a builder would see on their own pull request.
const CHECKS = [
  ['Keys in browser code', 'service-role, OpenAI and Stripe keys in VITE_ and NEXT_PUBLIC_ variables or bundled code'],
  ['Supabase', 'Row-Level Security, open policies, SECURITY DEFINER functions, storage buckets, sign-up roles'],
  ['Firebase', 'Firestore, Storage and Realtime Database rules open to everyone'],
  ['Injection', 'SQL, shell commands and code built from request data, traced from input to line'],
  ['Cross-site scripting', 'HTML rendered from the URL, comments or other user text'],
  ['Payments and auth', 'unsigned Stripe and Lemon Squeezy webhooks, plain-text passwords, tokens nobody checks'],
  ['Dependencies', 'packages with known vulnerabilities, split into what ships and what only builds'],
  ['CI', 'GitHub Actions that run untrusted code with your secrets'],
]
// the review as it happens: a real sequence, so it reads as a timeline
const STEPS = [
  { icon: GitPullRequest, title: 'You open a review', text: 'Paste a file, upload a zip, or link a public GitHub repo. No account, nothing to install.' },
  { icon: MessageSquare, title: 'VibeGuard comments on the lines', text: 'Open-source scanners and our own rules read everything; an AI double-checks the uncertain ones. Each problem lands as a comment on its line, in plain English.' },
  { icon: GitCommitHorizontal, title: 'You commit the fixes', text: 'Every comment carries a suggested change and a prompt to paste back into Lovable, Bolt or Cursor. Your code is deleted when the review ends.' },
]

export default function Home() {
  return (
    <div>
      <section className="pt-12 sm:pt-16">
        <h1 className="max-w-[16ch] text-[2.9rem] leading-[1.02] font-bold tracking-[-0.035em] text-balance sm:text-[4.25rem]">
          Your AI wrote the code. VibeGuard reviews it.
        </h1>
        <div className="mt-6 flex flex-col gap-8 lg:flex-row lg:items-end lg:justify-between">
          <p className="max-w-[54ch] text-[18px] leading-[1.6] text-muted text-pretty">
            Every leaked key, open database table and injectable line, pinned to the exact line as a review comment in plain English,
            with the fix and a prompt to paste back into your builder.
          </p>
          <div className="flex shrink-0 flex-wrap items-center gap-3">
            <a href="#/scan" className="rounded-md bg-go px-5 py-3 text-[15px] font-semibold text-white transition-colors hover:bg-[#1a7a4b]">
              Review my code
            </a>
            <a href="#/demo" className="flex items-center gap-1.5 rounded-md border border-line-strong px-5 py-3 text-[15px] font-medium text-fg transition-colors hover:bg-raised">
              See a demo review <ArrowRight className="size-4" strokeWidth={2} />
            </a>
          </div>
        </div>
      </section>

      <section className="mt-10 sm:mt-12" aria-label="Example review">
        <ReviewDemo />
        <p className="mt-3 text-[13.5px] text-faint">Try it: commit a suggestion, or copy the prompt for your AI builder.</p>
      </section>

      <section className="mt-24 grid gap-10 lg:grid-cols-[minmax(0,0.85fr)_minmax(0,1.15fr)] lg:gap-16">
        <div>
          <h2 className="text-[1.9rem] leading-tight font-bold tracking-[-0.025em]">Knows the stack your AI picked.</h2>
          <p className="mt-4 max-w-[46ch] text-[16.5px] leading-relaxed text-muted">
            Generic scanners miss what breaks AI-built apps most: a Supabase table without Row-Level Security, a service-role key in a
            public env var, a Firebase rule set to <code className="rounded bg-raised px-1.5 py-0.5 font-mono text-[14px] text-fg">if true</code>.
            VibeGuard reads your migrations, rules and env files, not only your JavaScript.
          </p>
        </div>
        <div className="overflow-hidden rounded-lg border border-line">
          <p className="flex items-center gap-2 border-b border-line bg-surface px-4 py-3 text-[14.5px] font-semibold">
            <CircleCheck className="size-4 text-fix" strokeWidth={2.2} />
            {CHECKS.length} checks run on every review
          </p>
          <ul className="divide-y divide-line">
            {CHECKS.map(([name, what]) => (
              <li key={name} className="flex items-start gap-3 px-4 py-3">
                <CircleCheck className="mt-0.5 size-4 shrink-0 text-fix" strokeWidth={2} />
                <p className="text-[14.5px] leading-snug">
                  <span className="font-semibold">{name}</span> <span className="text-muted">{what}</span>
                </p>
              </li>
            ))}
          </ul>
        </div>
      </section>

      <section className="mt-24">
        <h2 className="text-[1.9rem] leading-tight font-bold tracking-[-0.025em]">How a review goes</h2>
        <ol className="relative mt-8 max-w-3xl">
          <span className="absolute top-2 bottom-2 left-[15px] w-px bg-line-strong" aria-hidden />
          {STEPS.map(({ icon: Icon, title, text }) => (
            <li key={title} className="relative flex gap-5 pb-9 last:pb-0">
              <span className="relative z-10 grid size-8 shrink-0 place-items-center rounded-full border border-line-strong bg-ink text-muted">
                <Icon className="size-4" strokeWidth={1.9} />
              </span>
              <div className="pt-0.5">
                <h3 className="text-[17px] font-semibold">{title}</h3>
                <p className="mt-1.5 max-w-[60ch] text-[15.5px] leading-relaxed text-muted">{text}</p>
              </div>
            </li>
          ))}
        </ol>
      </section>

      <section className="mt-24 flex flex-col items-start gap-6 border-t border-line pt-12 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h2 className="text-[1.6rem] font-bold tracking-[-0.02em]">Review your app before you share the link.</h2>
          <p className="mt-2 text-[16px] text-muted">Free, about a minute, and your code is deleted when it ends.</p>
        </div>
        <a href="#/scan" className="shrink-0 rounded-md bg-go px-5 py-3 text-[15px] font-semibold text-white transition-colors hover:bg-[#1a7a4b]">
          Review my code
        </a>
      </section>
    </div>
  )
}
