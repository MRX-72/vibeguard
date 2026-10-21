export const BASE = import.meta.env.VITE_API_BASE_URL ?? ''

async function req(path, opts) {
  const res = await fetch(BASE + path, opts)
  const body = await res.json().catch(() => ({}))
  if (!res.ok) throw Object.assign(new Error(body.detail || `The scanner returned an error (${res.status}).`), { status: res.status })
  return body
}

export const health = () => req('/health')
export const startScan = (form) => req('/scan', { method: 'POST', body: form })
export const getStatus = (id) => req(`/scan/${id}/status`)
export const getReport = (id) => req(`/scan/${id}`)
