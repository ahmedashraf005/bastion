import type { AttemptSummary } from '../api/types'

export function computeCampaignStats(attempts: AttemptSummary[]) {
  const queriedAttempts = attempts.filter((attempt) => !attempt.pruned)
  const total = queriedAttempts.length
  const blocked = queriedAttempts.filter((attempt) => attempt.targetStatus === 400).length
  const passed = queriedAttempts.filter((attempt) => attempt.targetStatus === 200).length
  const matched = queriedAttempts.filter((attempt) => attempt.matched).length

  return {
    total,
    blocked,
    passed,
    matched,
    successRatePercent: total === 0 ? 0 : (matched / total) * 100,
  }
}
