import type { GateRequestSummary } from '../api/types'

export function LogPanel({ requests }: { requests: GateRequestSummary[] }) {
  return (
    <section className="panel log-panel">
      <div className="panel-heading"><div><p className="eyebrow">Gate audit trail</p><h2>Live campaign log</h2></div><span className="panel-note">latest requests</span></div>
      <div className="log-lines">
        {requests.length === 0 ? <p className="empty">No Gate traffic loaded.</p> : requests.map((request, index) => (
          <p className={index === 0 ? 'log-line highlighted' : 'log-line'} key={request.id}>
            req {request.id.slice(0, 8)} model={request.model} status={request.upstreamStatus ?? 'none'} action={request.policyAction ?? 'none'}{request.error ? ` error=${request.error}` : ''}
          </p>
        ))}
      </div>
    </section>
  )
}
