import { CloudUpload, Code, FolderGit2, KeyRound, LoaderCircle, Lock } from 'lucide-react'
import { useRef, useState } from 'react'
import Check from './Check'

const TABS = [
  { id: 'paste', label: 'Paste code', short: 'Paste', icon: Code },
  { id: 'zip', label: 'Upload zip', short: 'Zip', icon: CloudUpload },
  { id: 'github', label: 'GitHub repo', short: 'GitHub', icon: FolderGit2 },
]
const MAX_ZIP = 50 * 1024 * 1024
const PLACEHOLDER = 'Paste a component, route, .env file,\nFirebase rules or Supabase migration.'

export default function NewScan({ onSubmit }) {
  const [tab, setTab] = useState('paste')
  const [code, setCode] = useState('')
  const [filename, setFilename] = useState('')
  const [file, setFile] = useState(null)
  const [url, setUrl] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const [dragging, setDragging] = useState(false)
  const [verify, setVerify] = useState(false)

  const ready = { paste: code.trim(), zip: file, github: url.trim() }[tab]

  async function submit(e) {
    e.preventDefault()
    if (!ready || busy) return
    const form = new FormData()
    form.append('source_type', tab)
    form.append('payload', { paste: code, zip: file, github: url.trim() }[tab])
    if (tab === 'paste' && filename.trim()) form.append('filename', filename.trim())
    if (verify) form.append('verify_secrets', '1')
    setBusy(true)
    setError(null)
    try {
      await onSubmit(form)
    } catch (err) {
      setError(err.message)
      setBusy(false)
    }
  }

  function pickFile(f) {
    setError(null)
    if (!f) return
    if (!f.name.toLowerCase().endsWith('.zip')) return setError('Choose a .zip file.')
    if (f.size > MAX_ZIP) return setError('That zip is over 50 MB. Leave out node_modules, build output and media, then try again.')
    setFile(f)
  }

  return (
    <form id="new-scan" onSubmit={submit} className="overflow-hidden rounded-lg border border-line bg-surface">
      <div role="tablist" aria-label="How to provide code" className="flex gap-1 overflow-x-auto border-b border-line bg-raised/50 px-2 pt-2">
        {TABS.map(({ id, label, short, icon: Icon }) => (
          <button
            key={id}
            type="button"
            role="tab"
            id={`tab-${id}`}
            aria-selected={tab === id}
            aria-controls="scan-panel"
            onClick={() => { setTab(id); setError(null) }}
            className={`-mb-px flex shrink-0 items-center gap-2 rounded-t-md border px-3.5 py-2 text-[14px] transition-colors ${
              tab === id ? 'border-line border-b-surface bg-surface font-semibold text-fg' : 'border-transparent text-muted hover:text-fg'
            }`}
          >
            <Icon className="size-4" strokeWidth={1.9} />
            <span className="sm:hidden">{short}</span><span className="hidden sm:inline">{label}</span>
          </button>
        ))}
      </div>

      <div id="scan-panel" role="tabpanel" aria-labelledby={`tab-${tab}`} className="p-3 sm:p-4">
        {tab === 'paste' && <Editor code={code} setCode={setCode} filename={filename} setFilename={setFilename} />}

        {tab === 'zip' && (
          <label
            onDragOver={(e) => { e.preventDefault(); setDragging(true) }}
            onDragLeave={() => setDragging(false)}
            onDrop={(e) => { e.preventDefault(); setDragging(false); pickFile(e.dataTransfer.files[0]) }}
            className={`flex min-h-[280px] cursor-pointer flex-col items-center justify-center gap-3 rounded-md border border-dashed px-4 text-center transition-colors ${
              dragging ? 'border-fix bg-fix/[0.05]' : 'border-line-strong bg-inset hover:border-faint'
            }`}
          >
            <input type="file" accept=".zip,application/zip" className="sr-only" onChange={(e) => pickFile(e.target.files[0])} />
            <CloudUpload className="size-6 text-muted" strokeWidth={1.7} />
            {file ? (
              <>
                <span className="font-mono text-[14px]">{file.name}</span>
                <span className="text-[14px] text-faint">{(file.size / 1024 / 1024).toFixed(1)} MB. Click to choose another.</span>
              </>
            ) : (
              <>
                <span className="text-[15px] font-medium">Drop a .zip here, or click to choose one</span>
                <span className="text-[14px] text-faint">Up to 50 MB. Leave out node_modules and build output.</span>
              </>
            )}
          </label>
        )}

        {tab === 'github' && (
          <div className="flex min-h-[280px] flex-col justify-center gap-3 rounded-md border border-line bg-inset px-5 py-8">
            <label className="text-[14px] font-medium" htmlFor="repo">Public repository URL</label>
            <div className="flex items-center gap-3 rounded-md border border-line-strong bg-surface px-3 focus-within:border-low">
              <FolderGit2 className="size-4 shrink-0 text-faint" strokeWidth={1.9} />
              <input
                id="repo"
                type="url"
                inputMode="url"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://github.com/owner/repo"
                className="w-full bg-transparent py-2.5 font-mono text-[14px] outline-none placeholder:text-faint"
              />
            </div>
            <p className="text-[14px] text-faint">We clone the default branch, review it, and delete it. Private repositories aren't supported.</p>
          </div>
        )}
      </div>

      <div className="flex flex-col gap-4 border-t border-line px-3 py-3.5 sm:px-4">
        <label className="flex cursor-pointer items-start gap-3 text-[14px]">
          <Check checked={verify} onChange={setVerify} className="mt-0.5" />
          <span>
            <span className="flex items-center gap-1.5 font-medium"><KeyRound className="size-3.5 text-faint" strokeWidth={2} />Test any keys we find</span>
            <span className="mt-0.5 block text-faint">Sends each key to its own provider once, read-only, to see if it still works. Only for code you own.</span>
          </span>
        </label>

        {error && <p role="alert" className="rounded-md border border-crit/30 bg-crit/[0.08] px-3 py-2 text-[14px] text-crit">{error}</p>}

        <div className="flex flex-wrap items-center justify-between gap-3">
          <p className="flex max-w-[52ch] items-start gap-2 text-[13px] leading-relaxed text-faint">
            <Lock className="mt-0.5 size-3.5 shrink-0" strokeWidth={2} />
            Used for this review only, then deleted. Code near uncertain comments is sent to an AI provider (Groq) to double-check, with secrets masked.
          </p>
          <button
            type="submit"
            disabled={!ready || busy}
            className="flex items-center gap-2 rounded-md bg-go px-4 py-2 text-[14.5px] font-semibold text-white transition-[background-color,opacity] hover:bg-[#1a7a4b] disabled:cursor-not-allowed disabled:opacity-45"
          >
            {busy && <LoaderCircle className="size-4 animate-spin" />}
            {busy ? 'Starting review…' : 'Start review'}
          </button>
        </div>
      </div>
    </form>
  )
}

function Editor({ code, setCode, filename, setFilename }) {
  const gutter = useRef(null)
  const lines = Math.max(code.split('\n').length, 12)
  return (
    <div className="overflow-hidden rounded-md border border-line bg-inset focus-within:border-line-strong">
      <div className="flex items-center gap-2.5 border-b border-line bg-surface px-3 py-2">
        <Code className="size-4 shrink-0 text-faint" strokeWidth={1.9} aria-hidden />
        <label className="sr-only" htmlFor="filename">File name (optional)</label>
        <input
          id="filename"
          value={filename}
          onChange={(e) => setFilename(e.target.value)}
          placeholder="File name, e.g. src/App.tsx"
          spellCheck={false}
          className="min-w-0 flex-1 bg-transparent font-mono text-[13px] outline-none placeholder:text-faint"
        />
      </div>
      <div className="flex">
        <div ref={gutter} className="w-11 shrink-0 overflow-hidden py-3 pr-3 text-right font-mono text-[13px] leading-[1.75] text-faint select-none" aria-hidden>
          {Array.from({ length: lines }, (_, i) => <div key={i}>{i + 1}</div>)}
        </div>
        <label className="sr-only" htmlFor="code">Code</label>
        <textarea
          id="code"
          value={code}
          onChange={(e) => setCode(e.target.value)}
          onScroll={(e) => { if (gutter.current) gutter.current.scrollTop = e.target.scrollTop }}
          spellCheck={false}
          wrap="off"
          rows={12}
          placeholder={PLACEHOLDER}
          className="block h-[280px] w-full resize-y bg-transparent py-3 pr-3 font-mono text-[13px] leading-[1.75] outline-none placeholder:text-faint"
        />
      </div>
    </div>
  )
}
