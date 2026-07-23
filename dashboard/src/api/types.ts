export type CampaignSummary = {
  id: string
  objective: string
  owaspId: string
  targetKey: string
  status: string
  startedAt: string
  endedAt: string | null
  maxQueries: number
  queriesUsed: number
  maxWallClockSeconds: number
}

export type AttemptSummary = {
  id: string
  sequenceNumber: number
  source: 'static' | 'planner' | 'branching'
  roundNumber: number
  matched: boolean
  pruned: boolean
  targetStatus: number | null
  createdAt: string
}

export type FindingSummary = {
  id: string
  campaignId: string
  owaspId: string
  matchedPattern: string
  gateRequestId: string | null
  promotedStrategyId: string | null
  foundAt: string
}

export type ProposedRuleSummary = {
  id: string
  findingId: string
  proposedId: string
  proposedPattern: string
  proposedPatternType: string
  proposedNormalize: string
  proposedDescription: string
  verificationPassed: boolean
  status: 'pending_review' | 'approved' | 'rejected' | 'applied'
  reviewerNote: string | null
  reviewedAt: string | null
  appliedAt: string | null
  createdAt: string
}

export type GateRequestSummary = {
  id: string
  receivedAt: string
  model: string
  streamRequested: boolean
  upstreamStatus: number | null
  policyAction: string | null
  error: string | null
}

export type StatsSummary = {
  activeCampaigns: number
  confirmedBypasses: number
  rulesApplied: number
  requestsBlocked24h: number
}
