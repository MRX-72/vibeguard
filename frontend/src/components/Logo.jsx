import { useId } from 'react'

// A "V" drawn as a heat trace, cool to hot, crossed by the scan line: the product in one mark.
export default function Logo({ size = 32 }) {
  const id = useId()
  return (
    <span className="flex items-center gap-2.5">
      <svg viewBox="0 0 32 32" width={size} height={size} aria-hidden className="shrink-0">
        <defs>
          <linearGradient id={id} x1="6" y1="0" x2="26" y2="0" gradientUnits="userSpaceOnUse">
            <stop offset="0" stopColor="#6f8cff" />
            <stop offset=".35" stopColor="#b06cff" />
            <stop offset=".6" stopColor="#ff3e6c" />
            <stop offset=".8" stopColor="#ff7a3c" />
            <stop offset="1" stopColor="#f4b740" />
          </linearGradient>
        </defs>
        <rect x=".5" y=".5" width="31" height="31" rx="8" fill="#1b1624" stroke="#3a3148" />
        <path d="M8.5 9 16 23.5 23.5 9" fill="none" stroke={`url(#${id})`} strokeWidth="3.4" strokeLinecap="round" strokeLinejoin="round" />
        <path d="M5 15.5h22" stroke="#f6f1ff" strokeWidth="1.3" strokeLinecap="round" opacity=".9" />
      </svg>
      <span className="text-[19px] font-semibold tracking-[-0.025em]">VibeGuard</span>
    </span>
  )
}
