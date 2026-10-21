import { CircleAlert, FlaskConical, GitPullRequest, History, House, RefreshCw } from 'lucide-react'
import { useCallback, useEffect, useState } from 'react'
import { getReport, getStatus, health, startScan } from './api'
import { rememberScan, scanIds } from './history'
import Demo from './components/Demo'
import Home from './components/Home'
import Logo from './components/Logo'
import Report from './components/Report'
import ScanList from './components/ScanList'
import ScanPage from './components/ScanPage'
import ScanProgress from './components/ScanProgress'

const PAGES = [
  { page: 'home', href: '#/', label: 'Home', icon: House },
  { page: 'scan', href: '#/scan', label: 'Scan', icon: GitPullRequest },
  { page: 'demo', href: '#/demo', label: 'Demo', icon: FlaskConical },
  { page: 'history', href: '#/history', label: 'History', icon: History },
]

function route() {
  const id = location.hash.match(/^#\/scan\/([\w-]+)/)?.[1]
  if (id) return { page: 'report', id }
  const page = location.hash.match(/^#\/(scan|demo|history)\b/)?.[1]
  return { page: page ?? 'home' }
}

export default function App() {
  const [at, setAt] = useState(route)
  const [tick, setTick] = useState(0) // bumps when the user asks for fresh data
  const status = useHealth(tick)
  const [label, setLabel] = useState(null) // the open report's name, for the header

  useEffect(() => {
    const onHash = () => { setAt(route()); setLabel(null); window.scrollTo(0, 0) }
    addEventListener('hashchange', onHash)
    return () => removeEventListener('hashchange', onHash)
  }, [])

  async function submit(form) {
    const { scan_id } = await startScan(form)
    rememberScan(scan_id)
    location.hash = `#/scan/${scan_id}`
  }

  const count = scanIds().length
  const active = at.page === 'report' ? 'history' : at.page

  return (
    <div className="min-h-dvh">
      <header className="sticky top-0 z-30 border-b border-line bg-ink/90 backdrop-blur-md print:hidden">
        <div className="mx-auto flex h-14 max-w-[1240px] items-center gap-3 px-4 sm:px-8">
          <a href="#/" aria-label="VibeGuard home" className="rounded-md"><Logo /></a>
          {at.page === 'report' && label && (
            <span className="hidden min-w-0 items-center gap-3 text-[15px] sm:flex">
              <span className="text-line-strong">/</span>
              <span className="truncate font-semibold">{label}</span>
            </span>
          )}
          <div className="ml-auto flex items-center gap-2">
            <button
              type="button"
              onClick={() => setTick((t) => t + 1)}
              className="grid size-8 place-items-center rounded-md border border-line text-muted transition-colors hover:border-line-strong hover:text-fg"
              aria-label="Refresh your reviews"
              title="Refresh"
            >
              <RefreshCw className="size-[15px]" strokeWidth={1.9} />
            </button>
            {at.page !== 'scan' && (
              <a href="#/scan" className="rounded-md bg-go px-3 py-1.5 text-[14px] font-semibold text-white transition-colors hover:bg-[#1a7a4b]">
                Start a review
              </a>
            )}
          </div>
        </div>
        <nav className="mx-auto flex max-w-[1240px] gap-1 overflow-x-auto px-2 sm:px-6" aria-label="Pages">
          {PAGES.map(({ page, href, label: text, icon: Icon }) => (
            <a
              key={page}
              href={href}
              aria-current={active === page ? 'page' : undefined}
              className={`relative flex shrink-0 items-center gap-2 rounded-md px-2.5 pt-2 pb-3 text-[14.5px] transition-colors sm:px-3 ${
                active === page ? 'font-semibold text-fg' : 'text-muted hover:text-fg'
              }`}
            >
              <Icon className="hidden size-4 text-faint sm:block" strokeWidth={1.9} />
              {text}
              {page === 'history' && count > 0 && (
                <span className="rounded-full bg-raised px-1.5 text-[12px] font-medium text-muted">{count}</span>
              )}
              {active === page && <span className="absolute inset-x-2 -bottom-px h-[2px] rounded-full bg-crit" aria-hidden />}
            </a>
          ))}
        </nav>
      </header>

      {status === 'waking' || status === 'down' ? (
        <p role="status" className={`border-b px-4 py-2.5 text-center text-[14px] ${status === 'down' ? 'border-crit/25 bg-crit/[0.07] text-crit' : 'border-med/25 bg-med/[0.07] text-med'}`}>
          <CircleAlert className="mr-1.5 inline size-4 -translate-y-px" strokeWidth={2} />
          {status === 'down'
            ? "The scanner isn't answering. Try again in a few minutes."
            : 'Waking the scanner. The free server sleeps when idle, so the first review takes about a minute longer.'}
        </p>
      ) : null}

      <main className="mx-auto w-full max-w-[1240px] px-4 pb-28 sm:px-8">
        {at.page === 'home' && <Home />}
        {at.page === 'scan' && <ScanPage onSubmit={submit} tick={tick} />}
        {at.page === 'demo' && <Demo onSubmit={submit} tick={tick} />}
        {at.page === 'history' && <HistoryPage tick={tick} />}
        {at.page === 'report' && <ScanView key={at.id} scanId={at.id} onLabel={setLabel} />}
      </main>
    </div>
  )
}

// Render's free server sleeps after 15 idle minutes and takes about a minute to wake: say so instead of looking broken.
function useHealth(tick) {
  const [state, setState] = useState('checking')
  useEffect(() => {
    let stopped = false
    const started = Date.now()
    const slow = setTimeout(() => !stopped && setState((s) => (s === 'checking' ? 'waking' : s)), 1500)
    const ping = () =>
      health().then(
        () => !stopped && setState('ready'),
        () => !stopped && (Date.now() - started < 150_000 ? setTimeout(ping, 3000) : setState('down')),
      )
    ping()
    return () => { stopped = true; clearTimeout(slow) }
  }, [tick])
  return state
}

function HistoryPage({ tick }) {
  return (
    <section className="pt-10 sm:pt-12">
      <h1 className="text-[2rem] font-bold tracking-[-0.03em]">Your reviews</h1>
      <p className="mt-2 max-w-[62ch] text-[16px] text-muted">Every review started in this browser, newest first. Reports are kept until the server restarts.</p>
      <div className="mt-7 overflow-hidden rounded-lg border border-line">
        <ScanList tick={tick} limit={20} />
      </div>
    </section>
  )
}

// Keyed by scan id, so switching scans starts from fresh state.
function ScanView({ scanId, onLabel }) {
  const [status, setStatus] = useState(null)
  const [report, setReport] = useState(null)
  const [error, setError] = useState(null)
  const label = useCallback((r) => onLabel(r?.scan?.source_label || null), [onLabel])

  useEffect(() => {
    let stopped = false
    let misses = 0
    const tick = async () => {
      try {
        const s = await getStatus(scanId)
        if (stopped) return
        misses = 0
        setStatus(s)
        if (s.status === 'done') {
          const r = await getReport(scanId)
          if (!stopped) { setReport(r); label(r) }
        } else if (s.status !== 'failed') setTimeout(tick, 800)
      } catch (e) {
        if (stopped) return
        // a dropped connection or a busy server mid-scan isn't a failed scan: try again a few times
        if ((e.status ?? 503) >= 500 && ++misses <= 4) setTimeout(tick, 2000)
        else setError(e.message)
      }
    }
    tick()
    return () => { stopped = true }
  }, [scanId, label])

  const failed = error || (status?.status === 'failed' && (status.error || 'The scan stopped unexpectedly.'))
  if (failed) return <Failed message={failed} />
  if (report) return <Report report={report} />
  return <ScanProgress status={status} />
}

function Failed({ message }) {
  return (
    <section className="mx-auto max-w-xl pt-20" role="alert">
      <h1 className="text-[1.75rem] font-bold tracking-[-0.02em]">The review didn't finish</h1>
      <p className="mt-3 text-[16px] leading-relaxed text-muted">{message}</p>
      <a href="#/scan" className="mt-8 inline-flex rounded-md bg-go px-4 py-2.5 text-[15px] font-semibold text-white hover:bg-[#1a7a4b]">
        Start a new review
      </a>
    </section>
  )
}
