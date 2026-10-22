import { Check as CheckIcon } from 'lucide-react'

// A task-list box in the app's own colours (the native checkbox ships a browser-blue tick that belongs to no design).
export default function Check({ checked, onChange, label, className = '' }) {
  return (
    <span className={`relative inline-grid size-4 shrink-0 ${className}`}>
      <input
        type="checkbox"
        checked={checked}
        onChange={onChange ? (e) => onChange(e.target.checked) : undefined}
        readOnly={!onChange}
        aria-label={label}
        className="peer absolute inset-0 size-4 cursor-pointer appearance-none rounded-[4px] border border-line-strong bg-inset transition-colors checked:border-fix checked:bg-fix"
      />
      <CheckIcon className="pointer-events-none absolute inset-0 m-auto size-3 text-ink opacity-0 peer-checked:opacity-100" strokeWidth={3.2} aria-hidden />
    </span>
  )
}
