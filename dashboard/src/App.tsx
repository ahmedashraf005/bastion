import { useCallback } from 'react'
import { controlApi } from './api/client'
import type { AttemptSummary, CampaignSummary, FindingSummary, GateRequestSummary, ProposedRuleSummary, StatsSummary } from './api/types'
import { AttackSuccessChart, AttemptsBreakdownChart, type CampaignSeries } from './components/CampaignCharts'
import { FindingsTable } from './components/FindingsTable'
import { LogPanel } from './components/LogPanel'
import { RadarPanel } from './components/RadarPanel'
import { StatsRow } from './components/StatsRow'
import { usePolling } from './hooks/usePolling'

type DashboardSnapshot = {
  stats: StatsSummary
  campaigns: CampaignSummary[]
  attemptsByCampaign: Record<string, AttemptSummary[]>
  findings: FindingSummary[]
  rules: ProposedRuleSummary[]
  requests: GateRequestSummary[]
}

async function loadDashboardSnapshot(): Promise<DashboardSnapshot> {
  const [stats, campaigns, findings, rules, requests] = await Promise.all([
    controlApi.getStats(),
    controlApi.getCampaigns(10),
    controlApi.getFindings(50),
    controlApi.getProposedRules(100),
    controlApi.getRecentGateRequests(25),
  ])
  // N+1 attempt reads are deliberate at today’s scale: dozens of campaigns, not thousands.
  const entries = await Promise.all(campaigns.map(async (campaign) => [campaign.id, await controlApi.getCampaignAttempts(campaign.id)] as const))
  return { stats, campaigns, attemptsByCampaign: Object.fromEntries(entries), findings, rules, requests }
}

export default function App() {
  const fetchSnapshot = useCallback(loadDashboardSnapshot, [])
  const { data, error, lastUpdated } = usePolling(fetchSnapshot, 5000)
  const snapshot = data
  const isLive = snapshot !== null && error === null
  const campaignSeries: CampaignSeries[] = (snapshot?.campaigns ?? []).slice().reverse().map((campaign) => ({ campaign, attempts: snapshot?.attemptsByCampaign[campaign.id] ?? [] }))

  return (
    <div className="dashboard-shell">
      <header className="masthead">
        <div><p className="eyebrow">DEFENSIVE OBSERVABILITY CONSOLE</p><h1>BASTION</h1></div>
        <div className={`connection-state ${isLive ? 'live' : 'stale'}`} role="status" aria-live="polite">
          <span className="status-dot" />
          <div><strong>{isLive ? 'LIVE · GATE + STRIKE CONNECTED' : 'RECONNECTING'}</strong><small>{lastUpdated ? `last poll ${lastUpdated.toLocaleTimeString()}` : 'awaiting first poll'}</small></div>
        </div>
      </header>

      {error && <div className="stale-banner">Control API unavailable — showing last known good data and retrying every 5 seconds.</div>}

      <main>
        <StatsRow stats={snapshot?.stats ?? null} />
        <div className="dashboard-grid charts-grid">
          <AttackSuccessChart series={campaignSeries} />
          <AttemptsBreakdownChart series={campaignSeries} />
        </div>
        <div className="dashboard-grid operational-grid">
          <RadarPanel findings={snapshot?.findings ?? []} campaigns={snapshot?.campaigns ?? []} />
          <LogPanel requests={snapshot?.requests ?? []} />
        </div>
        <FindingsTable findings={snapshot?.findings ?? []} rules={snapshot?.rules ?? []} />
      </main>
    </div>
  )
}
