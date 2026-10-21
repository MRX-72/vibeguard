// A "V" read as a diff: the left stroke is the line removed (red), the right stroke the fix (green).
export function Mark({ size = 28, round = false }) {
  return (
    <svg viewBox="0 0 32 32" width={size} height={size} aria-hidden className="shrink-0">
      {round ? <circle cx="16" cy="16" r="15.5" fill="#1d2128" stroke="#363c46" /> : <rect x=".5" y=".5" width="31" height="31" rx="8" fill="#1d2128" stroke="#363c46" />}
      <path d="M9 9.5 16 23" stroke="#f2555a" strokeWidth="3.6" strokeLinecap="round" />
      <path d="M16 23 23 9.5" stroke="#43c286" strokeWidth="3.6" strokeLinecap="round" />
    </svg>
  )
}

export default function Logo({ size = 28 }) {
  return (
    <span className="flex items-center gap-2.5">
      <Mark size={size} />
      <span className="text-[18px] font-bold tracking-[-0.02em]">VibeGuard</span>
    </span>
  )
}
