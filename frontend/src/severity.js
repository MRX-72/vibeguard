// Literal class names so Tailwind can see them.
export const SEV = {
  Critical: { text: 'text-crit', bg: 'bg-crit', soft: 'bg-crit/10', ring: 'ring-crit/30' },
  High: { text: 'text-high', bg: 'bg-high', soft: 'bg-high/10', ring: 'ring-high/30' },
  Medium: { text: 'text-med', bg: 'bg-med', soft: 'bg-med/10', ring: 'ring-med/30' },
  Low: { text: 'text-low', bg: 'bg-low', soft: 'bg-low/10', ring: 'ring-low/30' },
}
export const ORDER = ['Critical', 'High', 'Medium', 'Low']

// A grade takes the colour of the severity it corresponds to.
export const GRADE_COLOR = { A: 'text-accent', B: 'text-low', C: 'text-med', D: 'text-high', F: 'text-crit' }
