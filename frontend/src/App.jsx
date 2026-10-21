import { Activity, FileText, Lock, RefreshCw } from 'lucide-react'
import { useCallback, useEffect, useState } from 'react'
import { getReport, getStatus, health, startScan } from './api'
import { rememberScan, scanIds } from './history'
import Overview from './components/Overview'
import Report from './components/Report'
import ScanList from './components/ScanList'
import ScanProgress from './components/ScanProgress'

function route() {
  const scan = location.hash.match(/^#\/scan\/([\w-]+)/)?.[1]
  if (scan) return { page: 'scan', id: scan }
  return { page: location.hash.startsWith('#/history') ? 'history' : 'overview' }
}

export default function App() {
  const [at, setAt] = useState(route)
  const [tick, setTick] = useState(0) // bumps when the user asks for fresh data
  const status = useHealth(tick)
  const [label, setLabel] = useState(null) // the open scan's name, for the breadcrumb

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

  const crumb = { overview: 'Overview', history: 'Scan history', scan: label ?? 'Scan' }[at.page]

  return (
    <div className="min-h-dvh lg:grid lg:grid-cols-[264px_minmax(0,1fr)]">
      <Sidebar page={at.page} />
      <div className="min-w-0">
        <header className="sticky top-0 z-20 border-b border-line bg-ink/85 backdrop-blur-md print:hidden">
          <div className="flex h-16 items-center gap-4 px-4 sm:px-8 lg:px-12">
            <a href="#/" className="lg:hidden" aria-label="VibeGuard home"><Logo compact /></a>
            <nav aria-label="Breadcrumb" className="hidden min-w-0 items-center gap-2.5 text-[15px] sm:flex">
              <a href="#/" className="text-faint hover:text-muted">Workspace</a>
              <span className="text-line-strong">/</span>
              <span className="truncate text-fg">{crumb}</span>
            </nav>
            <div className="ml-auto flex items-center gap-3">
              <Status state={status} />
              <button
                type="button"
                onClick={() => setTick((t) => t + 1)}
                className="grid size-9 place-items-center rounded-lg border border-line text-muted transition-colors hover:border-line-strong hover:text-fg"
                aria-label="Refresh"
                title="Refresh"
              >
                <RefreshCw className="size-4" strokeWidth={1.75} />
              </button>
            </div>
          </div>
          <nav className="flex gap-1 border-t border-line px-3 lg:hidden" aria-label="Sections">
            <MobileTab href="#/" active={at.page === 'overview'}>Overview</MobileTab>
            <MobileTab href="#/history" active={at.page === 'history'}>Scan history</MobileTab>
          </nav>
        </header>

        <main className="mx-auto w-full max-w-[1200px] px-4 pb-24 sm:px-8 lg:px-12">
          {at.page === 'overview' && <Overview onSubmit={submit} tick={tick} status={status} />}
          {at.page === 'history' && <HistoryPage tick={tick} />}
          {at.page === 'scan' && <ScanView key={at.id} scanId={at.id} onLabel={setLabel} />}
        </main>
      </div>
    </div>
  )
}

export function Logo({ compact }) {
  return (
    <span className="flex items-center gap-3">
      <span className="grid size-9 place-items-center rounded-[10px] bg-accent text-accent-ink shadow-[0_0_0_1px_rgba(114,216,168,0.25),0_8px_24px_-8px_rgba(114,216,168,0.45)]">
        <svg viewBox="0 0 24 24" className="size-[19px]" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
          <path d="M12 3 4.5 6v5.5c0 4.6 3.1 8.2 7.5 9.5 4.4-1.3 7.5-4.9 7.5-9.5V6L12 3Z" />
          <path d="m8.8 12.2 2.2 2.2 4.3-4.4" />
        </svg>
      </span>
      <span className="text-[19px] font-semibold tracking-[-0.02em]">
        vibe<span className="font-normal text-muted">guard</span>
      </span>
      {!compact && <span className="rounded-md border border-line-strong px-1.5 py-0.5 font-mono text-[10.5px] tracking-[0.16em] text-faint">BETA</span>}
    </span>
  )
}

function Sidebar({ page }) {
  const count = scanIds().length
  return (
    <aside className="sticky top-0 hidden h-dvh flex-col border-r border-line bg-side px-4 py-6 lg:flex print:hidden">
      <a href="#/" className="px-2"><Logo /></a>
      <p className="eyebrow mt-10 px-3">Workspace</p>
      <nav className="mt-3 flex flex-col gap-1" aria-label="Sections">
        <NavItem href="#/" icon={Activity} active={page === 'overview'}>Overview</NavItem>
        <NavItem href="#/history" icon={FileText} active={page === 'history'} badge={count || null}>Scan history</NavItem>
      </nav>
      <div className="mt-auto rounded-xl border border-line bg-surface p-4">
        <p className="flex items-center gap-2.5 text-[14px] font-medium">
          <Lock className="size-4 text-accent" strokeWidth={1.75} /> Your code isn't kept
        </p>
        <p className="mt-1.5 text-[13px] leading-relaxed text-faint">
          Submitted files are deleted when the scan ends. Reports stay until the server restarts.
        </p>
      </div>
      <p className="mt-4 px-2 text-[12.5px] leading-relaxed text-faint">
        Scan history is kept in this browser only.
      </p>
    </aside>
  )
}

function NavItem({ href, icon: Icon, active, badge, children }) {
  return (
    <a
      href={href}
      aria-current={active ? 'page' : undefined}
      className={`flex items-center gap-3 rounded-lg px-3 py-2.5 text-[15px] transition-colors ${
        active ? 'bg-accent/[0.09] text-accent' : 'text-muted hover:bg-raised hover:text-fg'
      }`}
    >
      <Icon className="size-[18px]" strokeWidth={1.75} />
      {children}
      {badge != null && <span className={`ml-auto font-mono text-xs tabular-nums ${active ? 'text-accent/80' : 'text-faint'}`}>{badge}</span>}
    </a>
  )
}

function MobileTab({ href, active, children }) {
  return (
    <a href={href} className={`relative px-3 py-3 text-sm ${active ? 'text-fg' : 'text-muted'}`}>
      {children}
      {active && <span className="absolute inset-x-3 -bottom-px h-0.5 rounded-full bg-accent" />}
    </a>
  )
}

const STATUS = {
  checking: ['bg-faint', 'Checking scanner…'],
  ready: ['bg-accent', 'All systems normal'],
  waking: ['bg-med animate-pulse', 'Waking the scanner…'],
  down: ['bg-crit', 'Scanner offline'],
}

function Status({ state }) {
  const [dot, text] = STATUS[state]
  return (
    <span className="flex items-center gap-2 font-mono text-[12.5px] text-muted" role="status">
      <span className={`size-2 rounded-full ${dot}`} />
      <span className="hidden sm:inline">{text}</span>
    </span>
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
    <section className="pt-10 sm:pt-14">
      <p className="eyebrow">Activity</p>
      <h1 className="mt-3 text-3xl font-semibold tracking-[-0.03em]">Scan history</h1>
      <p className="mt-2 max-w-[60ch] text-muted">Every scan started in this browser, newest first. Reports are kept until the server restarts.</p>
      <div className="mt-8 rounded-2xl border border-line bg-surface px-5 py-2 sm:px-6">
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
    <section className="mx-auto max-w-xl pt-20 text-center" role="alert">
      <div className="mx-auto grid size-12 place-items-center rounded-xl border border-crit/30 bg-crit/10 text-crit">
        <svg viewBox="0 0 24 24" className="size-5" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden><path d="M12 8v5M12 16.5v.01" /><circle cx="12" cy="12" r="9" /></svg>
      </div>
      <h1 className="mt-6 text-2xl font-semibold tracking-tight">The scan didn't finish</h1>
      <p className="mt-3 text-muted">{message}</p>
      <a href="#/" className="mt-8 inline-flex rounded-lg bg-accent px-4 py-2.5 text-sm font-semibold text-accent-ink hover:brightness-110">
        Start a new scan
      </a>
    </section>
  )
}
