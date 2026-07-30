import type { CampaignSummary } from '../api/types'

const terminalFailures = new Set(['error', 'failed_after_progress', 'interrupted'])

export function CampaignStatusPanel({ campaigns }: { campaigns: CampaignSummary[] }) {
  const visible = campaigns.filter((campaign) => terminalFailures.has(campaign.status))

  return (
    <section className="panel campaign-status-panel red-top">
      <div className="panel-heading"><div><p className="eyebrow">Campaign diagnostics</p><h2>Terminal failures</h2></div><span className="panel-note">local-only detail</span></div>
      {visible.length === 0 ? <p className="empty">No failed, partial, or interrupted campaigns in this view.</p> : (
        <div className="campaign-status-list">
          {visible.map((campaign) => (
            <article key={campaign.id} className="campaign-status-entry">
              <p><span className={`badge ${campaign.status}`}>{campaign.status}</span> <span className="mono">{campaign.id}</span></p>
              {campaign.status === 'failed_after_progress' && <p className="partial-note">Partial result: persisted attempts are shown as partial and excluded from completed-run comparisons.</p>}
              <p className="error-type">{campaign.errorType ?? (campaign.status === 'interrupted' ? 'Lease recovery' : 'No exception type recorded')}</p>
              {campaign.errorDetail && <details><summary>Exception traceback (local only)</summary><pre>{campaign.errorDetail}</pre></details>}
            </article>
          ))}
        </div>
      )}
    </section>
  )
}
