// Literal class names so Tailwind can see them. Severity is heat: cool blue to hottest magenta-red.
export const SEV = {
  Critical: { text: 'text-crit', bg: 'bg-crit', soft: 'bg-crit/12', ring: 'ring-crit/30', hover: 'hover:ring-crit/40', glow: 'from-crit/22', border: 'border-crit' },
  High: { text: 'text-high', bg: 'bg-high', soft: 'bg-high/12', ring: 'ring-high/30', hover: 'hover:ring-high/40', glow: 'from-high/20', border: 'border-high' },
  Medium: { text: 'text-med', bg: 'bg-med', soft: 'bg-med/12', ring: 'ring-med/30', hover: 'hover:ring-med/40', glow: 'from-med/18', border: 'border-med' },
  Low: { text: 'text-low', bg: 'bg-low', soft: 'bg-low/12', ring: 'ring-low/30', hover: 'hover:ring-low/40', glow: 'from-low/18', border: 'border-low' },
}
export const ORDER = ['Critical', 'High', 'Medium', 'Low']

// A grade takes the heat of the severity it corresponds to; A is the cool "safe" teal.
export const GRADE_COLOR = { A: 'text-fix', B: 'text-low', C: 'text-med', D: 'text-high', F: 'text-crit' }
export const GRADE_TILE = {
  A: 'border-fix/30 bg-fix/[0.07]', B: 'border-low/30 bg-low/[0.07]', C: 'border-med/30 bg-med/[0.07]',
  D: 'border-high/30 bg-high/[0.07]', F: 'border-crit/30 bg-crit/[0.08]',
}
export const GRADE_CHIP = { A: 'bg-fix/12 text-fix', B: 'bg-low/12 text-low', C: 'bg-med/12 text-med', D: 'bg-high/12 text-high', F: 'bg-crit/12 text-crit' }
