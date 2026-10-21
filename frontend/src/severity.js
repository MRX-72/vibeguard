// Literal class names so Tailwind can see them. Red is Critical and a removed line; green is a fix and a passed check.
export const SEV = {
  Critical: { text: 'text-crit', bg: 'bg-crit', soft: 'bg-crit/12', border: 'border-crit/45', hover: 'hover:border-crit/60', weight: 'font-bold' },
  High: { text: 'text-high', bg: 'bg-high', soft: 'bg-high/12', border: 'border-high/40', hover: 'hover:border-high/60', weight: 'font-semibold' },
  Medium: { text: 'text-med', bg: 'bg-med', soft: 'bg-med/12', border: 'border-med/35', hover: 'hover:border-med/55', weight: 'font-medium' },
  Low: { text: 'text-low', bg: 'bg-low', soft: 'bg-low/12', border: 'border-low/30', hover: 'hover:border-low/50', weight: 'font-normal' },
}
export const ORDER = ['Critical', 'High', 'Medium', 'Low']

export const GRADE_COLOR = { A: 'text-fix', B: 'text-low', C: 'text-med', D: 'text-high', F: 'text-crit' }
export const GRADE_CHIP = { A: 'bg-fix/12 text-fix', B: 'bg-low/12 text-low', C: 'bg-med/12 text-med', D: 'bg-high/12 text-high', F: 'bg-crit/12 text-crit' }

// a review's state, from its grade: what a reviewer would mark
export const VERDICT = {
  A: { label: 'Approved', chip: 'bg-fix/15 text-fix border-fix/30' },
  B: { label: 'Approved with comments', chip: 'bg-fix/15 text-fix border-fix/30' },
  C: { label: 'Changes requested', chip: 'bg-med/15 text-med border-med/30' },
  D: { label: 'Changes requested', chip: 'bg-high/15 text-high border-high/30' },
  F: { label: 'Changes requested', chip: 'bg-crit/15 text-crit border-crit/35' },
}

// how sure we are, drawn rather than labelled: proven is solid, likely is regular, unconfirmed is a dashed thread
export const CONFIDENCE_LINE = { 'Confirmed reachable': 'border-solid border-2', Likely: 'border-solid', 'Needs review': 'border-dashed' }
