import { ArrowRight, CloudUpload, Code, FolderGit2, KeyRound, LoaderCircle, Lock, Play, ShieldCheck } from 'lucide-react'
import { useRef, useState } from 'react'

const TABS = [
  { id: 'paste', label: 'Paste code', icon: Code },
  { id: 'zip', label: 'ZIP upload', icon: CloudUpload },
  { id: 'github', label: 'GitHub repo', icon: FolderGit2 },
]
const MAX_ZIP = 50 * 1024 * 1024
const PLACEHOLDER = '// Paste a component, an API route, a .env file,\n// Firebase rules or a Supabase migration.\n// We look for exposed keys, open data and risky patterns.'

export default function NewScan({ onSubmit }) {
  const [tab, setTab] = useState('paste')
  const [code, setCode] = useState('')
  const [filename, setFilename] = useState('')
  const [file, setFile] = useState(null)
  const [url, setUrl] = useState('')
  const [busy, setBusy] = useState(null) // 'scan' | 'demo' while a request is out
  const [error, setError] = useState(null)
  const [dragging, setDragging] = useState(false)
  const [verify, setVerify] = useState(false)

  const ready = { paste: code.trim(), zip: file, github: url.trim() }[tab]

  async function send(sourceType, payload) {
    const form = new FormData()
    form.append('source_type', sourceType)
    if (payload != null) form.append('payload', payload)
    if (sourceType === 'paste' && filename.trim()) form.append('filename', filename.trim())
    if (verify) form.append('verify_secrets', '1')
    setBusy(sourceType === 'demo' ? 'demo' : 'scan')
    setError(null)
    try {
      await onSubmit(form)
    } catch (e) {
      setError(e.message)
      setBusy(null)
    }
  }

  function pickFile(f) {
    setError(null)
    if (!f) return
    if (!f.name.toLowerCase().endsWith('.zip')) return setError('Choose a .zip file.')
    if (f.size > MAX_ZIP) return setError('That zip is over 50 MB. Leave out node_modules, build output and media, then try again.')
    setFile(f)
  }

  function submit(e) {
    e.preventDefault()
    if (ready && !busy) send(tab, { paste: code, zip: file, github: url.trim() }[tab])
  }

  return (
    <form id="new-scan" onSubmit={submit} className="flex scroll-mt-28 flex-col rounded-2xl border border-line bg-surface p-5 sm:p-7">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h2 className="text-xl font-semibold tracking-[-0.02em]">New scan</h2>
          <p className="mt-1 text-[15px] text-muted">Paste a file, upload a zip, or link a public GitHub repo.</p>
        </div>
        <button
          type="button"
          disabled={!!busy}
          onClick={() => send('demo')}
          className="flex shrink-0 items-center gap-2 self-start rounded-lg border border-line-strong px-3.5 py-2 text-sm text-muted transition-colors hover:bg-raised hover:text-fg disabled:opacity-50"
        >
          {busy === 'demo' ? <LoaderCircle className="size-4 animate-spin" /> : <Play className="size-3.5 fill-current" strokeWidth={1.5} />}
          Try the demo app
        </button>
      </div>

      <div role="tablist" aria-label="How to provide code" className="mt-6 flex gap-1 overflow-x-auto border-b border-line">
        {TABS.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            type="button"
            role="tab"
            id={`tab-${id}`}
            aria-selected={tab === id}
            aria-controls="scan-panel"
            onClick={() => { setTab(id); setError(null) }}
            className={`relative flex shrink-0 items-center gap-2 px-2.5 pt-1 pb-3.5 text-[14px] transition-colors sm:px-3 sm:text-[15px] ${tab === id ? 'text-fg' : 'text-muted hover:text-fg'}`}
          >
            <Icon className="hidden size-[18px] sm:block" strokeWidth={1.75} />
            {label}
            {tab === id && <span className="absolute inset-x-1 -bottom-px h-0.5 rounded-full bg-hot" />}
          </button>
        ))}
      </div>

      <div id="scan-panel" role="tabpanel" aria-labelledby={`tab-${tab}`} className="mt-5">
        {tab === 'paste' && <Editor code={code} setCode={setCode} filename={filename} setFilename={setFilename} />}

        {tab === 'zip' && (
          <label
            onDragOver={(e) => { e.preventDefault(); setDragging(true) }}
            onDragLeave={() => setDragging(false)}
            onDrop={(e) => { e.preventDefault(); setDragging(false); pickFile(e.dataTransfer.files[0]) }}
            className={`flex min-h-[260px] cursor-pointer flex-col items-center justify-center gap-3 rounded-xl border border-dashed px-4 text-center transition-colors ${
              dragging ? 'border-hot bg-hot/[0.04]' : 'border-line-strong bg-ink hover:border-faint'
            }`}
          >
            <input type="file" accept=".zip,application/zip" className="sr-only" onChange={(e) => pickFile(e.target.files[0])} />
            <span className="grid size-11 place-items-center rounded-xl border border-line bg-surface text-muted">
              <CloudUpload className="size-5" strokeWidth={1.75} />
            </span>
            {file ? (
              <>
                <span className="font-mono text-sm">{file.name}</span>
                <span className="text-sm text-faint">{(file.size / 1024 / 1024).toFixed(1)} MB · click to choose another</span>
              </>
            ) : (
              <>
                <span className="text-[15px]">Drop a .zip here, or click to choose one</span>
                <span className="text-sm text-faint">Up to 50 MB. Leave out node_modules and build output.</span>
              </>
            )}
          </label>
        )}

        {tab === 'github' && (
          <div className="flex min-h-[260px] flex-col justify-center gap-3 rounded-xl border border-line bg-ink px-5 py-8">
            <label className="text-sm text-muted" htmlFor="repo">Public repository URL</label>
            <div className="flex items-center gap-3 rounded-lg border border-line-strong bg-surface px-3.5 focus-within:border-faint">
              <FolderGit2 className="size-[18px] shrink-0 text-faint" strokeWidth={1.75} />
              <input
                id="repo"
                type="url"
                inputMode="url"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://github.com/owner/repo"
                className="w-full bg-transparent py-3 font-mono text-[14px] outline-none placeholder:text-faint"
              />
            </div>
            <p className="text-sm text-faint">We clone the default branch, scan it, and delete it. Private repositories aren't supported.</p>
          </div>
        )}
      </div>

      <label className="mt-5 flex cursor-pointer items-start gap-3 text-sm">
        <input type="checkbox" checked={verify} onChange={(e) => setVerify(e.target.checked)} className="peer sr-only" />
        <span className="mt-0.5 grid size-[18px] shrink-0 place-items-center rounded-[5px] border border-line-strong bg-ink transition-colors peer-checked:border-hot peer-checked:bg-hot peer-focus-visible:outline-2 peer-focus-visible:outline-offset-2 peer-focus-visible:outline-hot">
          {verify && <svg viewBox="0 0 12 12" className="size-3 text-ink"><path d="m2.5 6.2 2.2 2.2 4.8-4.9" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" /></svg>}
        </span>
        <span>
          <span className="flex items-center gap-2 text-fg"><KeyRound className="size-3.5 text-faint" strokeWidth={1.75} />Test any keys we find</span>
          <span className="mt-0.5 block text-faint">Sends each key to its own provider once, read-only, to see if it still works. Only for code you own.</span>
        </span>
      </label>

      {error && <p role="alert" className="mt-4 rounded-lg border border-crit/25 bg-crit/[0.07] px-3.5 py-2.5 text-sm text-crit">{error}</p>}

      <div className="mt-6 flex flex-wrap items-center justify-between gap-4 border-t border-line pt-5">
        <p className="flex max-w-[44ch] items-start gap-2.5 text-[13px] leading-relaxed text-faint">
          <Lock className="mt-0.5 size-3.5 shrink-0" strokeWidth={1.75} />
          Your code is used for this scan only. An AI model on Groq double-checks uncertain findings, with secrets masked.
        </p>
        <button
          type="submit"
          disabled={!ready || !!busy}
          className="flex items-center gap-2.5 rounded-lg bg-hot px-5 py-3 text-[15px] font-semibold text-ink transition-[background-color,opacity] hover:bg-white disabled:cursor-not-allowed disabled:opacity-35"
        >
          {busy === 'scan' ? <LoaderCircle className="size-[18px] animate-spin" /> : <ShieldCheck className="size-[18px]" strokeWidth={2} />}
          {busy === 'scan' ? 'Starting…' : 'Start scan'}
          {busy !== 'scan' && <ArrowRight className="size-4" strokeWidth={2} />}
        </button>
      </div>
    </form>
  )
}

function Editor({ code, setCode, filename, setFilename }) {
  const gutter = useRef(null)
  const lines = Math.max(code.split('\n').length, 10)
  return (
    <div className="overflow-hidden rounded-xl border border-line bg-ink focus-within:border-line-strong">
      <div className="flex items-center gap-3 border-b border-line px-4 py-2.5">
        <Code className="size-4 shrink-0 text-faint" strokeWidth={1.75} aria-hidden />
        <label className="sr-only" htmlFor="filename">File name (optional)</label>
        <input
          id="filename"
          value={filename}
          onChange={(e) => setFilename(e.target.value)}
          placeholder="File name, e.g. src/App.tsx"
          spellCheck={false}
          className="min-w-0 flex-1 bg-transparent font-mono text-[13px] text-muted outline-none placeholder:text-faint"
        />
      </div>
      <div className="flex">
        <div ref={gutter} className="w-12 shrink-0 overflow-hidden py-4 pr-3 text-right font-mono text-[13px] leading-[1.75] text-faint/70 select-none" aria-hidden>
          {Array.from({ length: lines }, (_, i) => <div key={i}>{String(i + 1).padStart(2, '0')}</div>)}
        </div>
        <label className="sr-only" htmlFor="code">Code</label>
        <textarea
          id="code"
          value={code}
          onChange={(e) => setCode(e.target.value)}
          onScroll={(e) => { if (gutter.current) gutter.current.scrollTop = e.target.scrollTop }}
          spellCheck={false}
          wrap="off"
          rows={10}
          placeholder={PLACEHOLDER}
          className="block h-[260px] w-full resize-y bg-transparent py-4 pr-4 font-mono text-[13px] leading-[1.75] text-fg outline-none placeholder:text-faint/80"
        />
      </div>
    </div>
  )
}
