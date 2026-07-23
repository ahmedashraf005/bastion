import { render, screen } from '@testing-library/react'
import { expect, it } from 'vitest'
import { StatsRow } from './StatsRow'

it('renders all four live statistic values', () => {
  render(<StatsRow stats={{ activeCampaigns: 2, confirmedBypasses: 3, rulesApplied: 4, requestsBlocked24h: 5 }} />)

  expect(screen.getByText('Active campaigns')).toBeInTheDocument()
  expect(screen.getByText('Confirmed bypasses')).toBeInTheDocument()
  expect(screen.getByText('Rules applied')).toBeInTheDocument()
  expect(screen.getByText('Requests blocked 24h')).toBeInTheDocument()
  expect(screen.getByText('2')).toBeInTheDocument()
  expect(screen.getByText('5')).toBeInTheDocument()
})
