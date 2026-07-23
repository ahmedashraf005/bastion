import type {
  AttemptSummary,
  CampaignSummary,
  FindingSummary,
  GateRequestSummary,
  ProposedRuleSummary,
  StatsSummary,
} from './types'

const baseUrl = (import.meta.env.VITE_CONTROL_BASE_URL ?? 'http://localhost:5080').replace(/\/$/, '')

async function getJson<T>(path: string): Promise<T> {
  const response = await fetch(`${baseUrl}${path}`)
  if (!response.ok) throw new Error(`Control API ${response.status} for ${path}`)
  return response.json() as Promise<T>
}

export const controlApi = {
  getStats: () => getJson<StatsSummary>('/api/stats/summary'),
  getCampaigns: (limit = 10) => getJson<CampaignSummary[]>(`/api/campaigns?limit=${limit}`),
  getCampaignAttempts: (campaignId: string) => getJson<AttemptSummary[]>(`/api/campaigns/${campaignId}/attempts`),
  getFindings: (limit = 50) => getJson<FindingSummary[]>(`/api/findings?limit=${limit}`),
  getProposedRules: (limit = 100) => getJson<ProposedRuleSummary[]>(`/api/proposed-rules?limit=${limit}`),
  getRecentGateRequests: (limit = 25) => getJson<GateRequestSummary[]>(`/api/gate-requests/recent?limit=${limit}`),
}
