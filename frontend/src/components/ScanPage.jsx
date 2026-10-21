import { useScans } from '../history'
import NewScan from './NewScan'
import ScanList from './ScanList'

export default function ScanPage({ onSubmit, tick }) {
  const rows = useScans(tick, 20)
  return (
    <div className="pt-10 sm:pt-12">
      <h1 className="text-[2rem] font-bold tracking-[-0.03em]">Open a review</h1>
      <p className="mt-2 max-w-[62ch] text-[16px] text-muted">
        Give VibeGuard a file, a zip or a public GitHub repo. It comments on every risky line, usually within a minute.
      </p>

      <div className="mt-7 grid items-start gap-6 xl:grid-cols-[minmax(0,1.55fr)_minmax(0,1fr)]">
        <NewScan onSubmit={onSubmit} />
        <section className="overflow-hidden rounded-lg border border-line" aria-labelledby="recent">
          <h2 id="recent" className="flex items-center justify-between border-b border-line bg-surface px-4 py-3 text-[14.5px] font-semibold">
            Your recent reviews
            {rows?.length > 0 && <a href="#/history" className="text-[13.5px] font-normal text-muted hover:text-fg">All {rows.length}</a>}
          </h2>
          <ScanList rows={rows && rows.slice(0, 6)} limit={0} compact />
        </section>
      </div>
    </div>
  )
}
