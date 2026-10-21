import { useEffect, useState } from 'react'
import { getScans } from './api'

// The scans this browser started. Only their ids are kept here: there's no shared list of everyone's scans.
const KEY = 'vibeguard:scans'

export function scanIds() {
  try {
    const ids = JSON.parse(localStorage.getItem(KEY) ?? '[]')
    return Array.isArray(ids) ? ids.filter((x) => typeof x === 'string') : []
  } catch {
    return []
  }
}

export function rememberScan(id) {
  try {
    localStorage.setItem(KEY, JSON.stringify([id, ...scanIds().filter((x) => x !== id)].slice(0, 20)))
  } catch {
    // private mode or storage off: the scan still works, it just won't be listed
  }
}

// The scans this browser started (newest first), refreshed while any is still running.
export function useScans(tick, limit) {
  const [rows, setRows] = useState(null)
  useEffect(() => {
    let stopped = false
    let timer
    const load = () =>
      getScans(scanIds().slice(0, limit)).then(
        (r) => {
          if (stopped) return
          setRows(r)
          if (r.some((s) => s.status === 'queued' || s.status === 'running')) timer = setTimeout(load, 4000)
        },
        () => !stopped && setRows((r) => r ?? []),
      )
    load()
    return () => { stopped = true; clearTimeout(timer) }
  }, [tick, limit])
  return rows
}
