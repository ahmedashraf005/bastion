import type { StatsSummary } from '../api/types'

type Props = { stats: StatsSummary | null }

const cards: Array<{ key: keyof StatsSummary; label: string }> = [
  { key: 'activeCampaigns', label: 'Active campaigns' },
  { key: 'confirmedBypasses', label: 'Confirmed bypasses' },
  { key: 'rulesApplied', label: 'Rules applied' },
  { key: 'requestsBlocked24h', label: 'Requests blocked 24h' },
]

export function StatsRow({ stats }: Props) {
  return (
    <section className="stats-row" aria-label="Operational statistics">
      {cards.map(({ key, label }) => (
        <article className="stat-card" key={key}>
          <span>{label}</span>
          <strong>{stats ? stats[key] : '—'}</strong>
        </article>
      ))}
    </section>
  )
}
