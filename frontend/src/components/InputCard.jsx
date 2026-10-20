import { useState } from 'react'

const TABS = [
  { id: 'paste', label: 'Paste code', cta: 'Scan code' },
  { id: 'zip', label: 'Upload .zip', cta: 'Scan zip' },
  { id: 'github', label: 'GitHub repo', cta: 'Scan repository' },
]
const MAX_ZIP = 50 * 1024 * 1024

export default function InputCard({ onSubmit }) {
  const [tab, setTab] = useState('paste')
  const [code, setCode] = useState('')
  const [filename, setFilename] = useState('')
  const [file, setFile] = useState(null)
  const [url, setUrl] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const [dragging, setDragging] = useState(false)

  const ready = { paste: code.trim(), zip: file, github: url.trim() }[tab]

  async function send(sourceType, payload) {
    const form = new FormData()
    form.append('source_type', sourceType)
    if (payload != null) form.append('payload', payload)
    if (sourceType === 'paste' && filename.trim()) form.append('filename', filename.trim())
    setBusy(true)
    setError(null)
    try {
      await onSubmit(form)
    } catch (e) {
      setError(e.message)
      setBusy(false)
    }
  }

  function pickFile(f) {
    setError(null)
    if (!f) return
    if (!f.name.toLowerCase().endsWith('.zip')) return setError('Choose a .zip file.')
    if (f.size > MAX_ZIP) return setError('That zip is over 50 MB. Remove node_modules, build output and media, then try again.')
    setFile(f)
  }

  function submit(e) {
    e.preventDefault()
    if (ready) send(tab, { paste: code, zip: file, github: url.trim() }[tab])
  }

  return (
    <div>
      <form onSubmit={submit} className="rounded-xl border border-line bg-surface">
        <div role="tablist" aria-label="How to provide code" className="flex gap-1 overflow-x-auto border-b border-line px-2 pt-2">
          {TABS.map((t) => (
            <button
              key={t.id}
              type="button"
              role="tab"
              id={`tab-${t.id}`}
              aria-selected={tab === t.id}
              aria-controls="input-panel"
              onClick={() => { setTab(t.id); setError(null) }}
              className={`relative shrink-0 rounded-t-md px-3 pt-2 pb-3 text-sm transition-colors ${
                tab === t.id ? 'text-fg' : 'text-muted hover:text-fg'
              }`}
            >
              {t.label}
              {tab === t.id && <span className="absolute inset-x-3 -bottom-px h-0.5 rounded-full bg-accent" />}
            </button>
          ))}
        </div>

        <div id="input-panel" role="tabpanel" aria-labelledby={`tab-${tab}`} className="p-4 sm:p-5">
          {tab === 'paste' && (
            <div className="flex flex-col gap-3">
              <label className="sr-only" htmlFor="filename">File name (optional)</label>
              <input
                id="filename"
                value={filename}
                onChange={(e) => setFilename(e.target.value)}
                placeholder="File name, e.g. src/App.jsx (optional)"
                className="w-full rounded-md border border-line bg-ink px-3 py-2 font-mono text-[13px] placeholder:font-sans placeholder:text-faint"
              />
              <label className="sr-only" htmlFor="code">Code</label>
              <textarea
                id="code"
                value={code}
                onChange={(e) => setCode(e.target.value)}
                spellCheck={false}
                rows={12}
                placeholder="Paste a component, an API route, a .env file, Firebase rules, a Supabase migration…"
                className="block w-full resize-y rounded-md border border-line bg-ink px-3 py-2.5 font-mono text-[13px] leading-relaxed placeholder:font-sans placeholder:text-faint"
              />
            </div>
          )}

          {tab === 'zip' && (
            <label
              onDragOver={(e) => { e.preventDefault(); setDragging(true) }}
              onDragLeave={() => setDragging(false)}
              onDrop={(e) => { e.preventDefault(); setDragging(false); pickFile(e.dataTransfer.files[0]) }}
              className={`flex min-h-56 cursor-pointer flex-col items-center justify-center gap-2 rounded-lg border border-dashed px-4 text-center transition-colors ${
                dragging ? 'border-accent bg-accent/5' : 'border-line hover:border-faint'
              }`}
            >
              <input type="file" accept=".zip,application/zip" className="sr-only" onChange={(e) => pickFile(e.target.files[0])} />
              {file ? (
                <>
                  <span className="font-mono text-sm">{file.name}</span>
                  <span className="text-sm text-muted">{(file.size / 1024 / 1024).toFixed(1)} MB. Click to choose a different file.</span>
                </>
              ) : (
                <>
                  <span className="text-[15px]">Drop a .zip here, or click to choose one</span>
                  <span className="text-sm text-muted">Up to 50 MB. Leave out node_modules and build output.</span>
                </>
              )}
            </label>
          )}

          {tab === 'github' && (
            <div className="flex flex-col gap-2">
              <label className="text-sm text-muted" htmlFor="repo">Public repository URL</label>
              <input
                id="repo"
                type="url"
                inputMode="url"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://github.com/owner/repo"
                className="w-full rounded-md border border-line bg-ink px-3 py-2.5 font-mono text-[13px] placeholder:text-faint"
              />
              <p className="text-sm text-faint">Private repositories aren't supported. We clone the default branch and delete it after the scan.</p>
            </div>
          )}

          {error && <p role="alert" className="mt-3 text-sm text-crit">{error}</p>}

          <div className="mt-4 flex flex-wrap items-center justify-between gap-3">
            <p className="text-sm text-faint">Read-only. Nothing is stored after the scan.</p>
            <button
              type="submit"
              disabled={!ready || busy}
              className="rounded-lg bg-fg px-4 py-2.5 text-sm font-medium text-ink transition-colors hover:bg-white disabled:cursor-not-allowed disabled:opacity-40"
            >
              {busy ? 'Starting…' : TABS.find((t) => t.id === tab).cta}
            </button>
          </div>
        </div>
      </form>

      <div className="mt-6 flex flex-col gap-3 rounded-xl border border-line px-4 py-4 sm:flex-row sm:items-center sm:justify-between sm:px-5">
        <p className="text-[15px] text-muted">
          No code handy? Scan our deliberately insecure demo app, built the way AI tools build them.
        </p>
        <button
          type="button"
          disabled={busy}
          onClick={() => send('demo')}
          className="shrink-0 rounded-lg border border-line px-4 py-2 text-sm font-medium hover:bg-raised disabled:opacity-40"
        >
          Try the demo app
        </button>
      </div>
    </div>
  )
}
