import type { FindingSummary, ProposedRuleSummary } from '../api/types'

function statusFor(finding: FindingSummary, rules: ProposedRuleSummary[]) {
  return rules.find((rule) => rule.findingId === finding.id)?.status ?? 'not synthesized'
}

export function FindingsTable({ findings, rules }: { findings: FindingSummary[]; rules: ProposedRuleSummary[] }) {
  return (
    <section className="panel findings-panel">
      <div className="panel-heading"><div><p className="eyebrow">Confirmed evidence</p><h2>Findings</h2></div><span className="panel-note">most recent first</span></div>
      <div className="table-scroll">
        <table>
          <thead><tr><th>Finding</th><th>OWASP</th><th>Campaign</th><th>Gate request</th><th>Rule state</th></tr></thead>
          <tbody>{findings.map((finding) => {
            const status = statusFor(finding, rules)
            return <tr key={finding.id}>
              <td className="mono">{finding.id.slice(0, 8)}</td><td>{finding.owaspId}</td><td className="mono">{finding.campaignId.slice(0, 8)}</td><td className="mono">{finding.gateRequestId?.slice(0, 8) ?? '—'}</td>
              <td><span className={`badge ${status}`}>{status.replace('_', ' ')}</span></td>
            </tr>
          })}</tbody>
        </table>
      </div>
    </section>
  )
}
