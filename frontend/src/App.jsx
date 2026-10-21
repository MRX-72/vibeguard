import { useEffect, useState } from 'react'
import { getReport, getStatus, startScan } from './api'
import InputCard from './components/InputCard'
import ScanProgress from './components/ScanProgress'
import Report from './components/Report'

const idFromHash = () => location.hash.match(/^#\/scan\/([\w-]+)/)?.[1] ?? null

export default function App() {
  const [scanId, setScanId] = useState(idFromHash)

  useEffect(() => {
    const onHash = () => setScanId(idFromHash())
    addEventListener('hashchange', onHash)
    return () => removeEventListener('hashchange', onHash)
  }, [])

  async function submit(form) {
    const { scan_id } = await startScan(form)
    location.hash = `#/scan/${scan_id}`
  }

  return (
    <div className="mx-auto max-w-[880px] px-4 pb-24 sm:px-6">
      <header className="flex items-center justify-between py-6">
        <a href="#" className="flex items-center gap-2 rounded-md">
          <img src="/favicon.svg" alt="" className="size-6" />
          <span className="font-semibold tracking-tight">VibeGuard</span>
        </a>
        {scanId && (
          <a href="#" className="rounded-md px-3 py-1.5 text-sm text-muted hover:bg-raised hover:text-fg">New scan</a>
        )}
      </header>

      <main>{scanId ? <ScanView key={scanId} scanId={scanId} /> : <Home onSubmit={submit} />}</main>
    </div>
  )
}

// Keyed by scan id, so switching scans starts from fresh state.
function ScanView({ scanId }) {
  const [status, setStatus] = useState(null)
  const [report, setReport] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    let stopped = false
    let misses = 0
    const tick = async () => {
      try {
        const s = await getStatus(scanId)
        if (stopped) return
        misses = 0
        setStatus(s)
        if (s.status === 'done') setReport(await getReport(scanId))
        else if (s.status !== 'failed') setTimeout(tick, 800)
      } catch (e) {
        if (stopped) return
        // a dropped connection or a busy server mid-scan isn't a failed scan: try again a few times
        if ((e.status ?? 503) >= 500 && ++misses <= 4) setTimeout(tick, 2000)
        else setError(e.message)
      }
    }
    tick()
    return () => { stopped = true }
  }, [scanId])

  const failed = error || (status?.status === 'failed' && (status.error || 'The scan stopped unexpectedly.'))
  if (failed) return <Failed message={failed} />
  if (report) return <Report report={report} />
  return <ScanProgress status={status} />
}

function Home({ onSubmit }) {
  return (
    <section className="pt-10 sm:pt-16">
      <h1 className="max-w-[18ch] text-[2.5rem] leading-[1.08] font-semibold tracking-[-0.025em] text-balance sm:text-[3.25rem]">
        Find the security holes your AI builder left in.
      </h1>
      <p className="mt-5 max-w-[60ch] text-lg leading-relaxed text-muted text-pretty">
        Paste code, upload a zip, or link a public GitHub repo. You get a plain-English report of what's exposed and
        exactly what to change. VibeGuard only reads your code and deletes it when the scan ends.
      </p>
      <div className="mt-10">
        <InputCard onSubmit={onSubmit} />
      </div>
    </section>
  )
}

function Failed({ message }) {
  return (
    <section className="pt-16" role="alert">
      <h1 className="text-2xl font-semibold tracking-tight">The scan didn't finish</h1>
      <p className="mt-3 max-w-[60ch] text-muted">{message}</p>
      <a href="#" className="mt-8 inline-flex rounded-lg bg-fg px-4 py-2.5 text-sm font-medium text-ink hover:bg-white">
        Start a new scan
      </a>
    </section>
  )
}
