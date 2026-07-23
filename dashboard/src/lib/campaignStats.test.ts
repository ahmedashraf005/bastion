import { describe, expect, it } from 'vitest'
import type { AttemptSummary } from '../api/types'
import { computeCampaignStats } from './campaignStats'

const attempt = (overrides: Partial<AttemptSummary>): AttemptSummary => ({
  id: crypto.randomUUID(),
  sequenceNumber: 1,
  source: 'branching',
  roundNumber: 1,
  matched: false,
  pruned: false,
  targetStatus: 200,
  createdAt: '2026-07-23T00:00:00Z',
  ...overrides,
})

describe('computeCampaignStats', () => {
  it('excludes pruned candidates from every denominator and count', () => {
    const stats = computeCampaignStats([
      attempt({ targetStatus: 400 }),
      attempt({ targetStatus: 200, matched: true }),
      attempt({ pruned: true, targetStatus: null, matched: true }),
    ])

    expect(stats).toEqual({ total: 2, blocked: 1, passed: 1, matched: 1, successRatePercent: 50 })
  })
})
