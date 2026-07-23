import {
  CategoryScale,
  Chart as ChartJS,
  Filler,
  Legend,
  LineElement,
  LinearScale,
  PointElement,
  Tooltip,
} from 'chart.js'
import type { TooltipItem } from 'chart.js'
import { Line } from 'react-chartjs-2'
import type { CampaignSummary } from '../api/types'
import { computeCampaignStats } from '../lib/campaignStats'
import type { AttemptSummary } from '../api/types'

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Tooltip, Legend, Filler)

export type CampaignSeries = { campaign: CampaignSummary; attempts: AttemptSummary[] }

const axisColor = '#7c8a80'
const gridColor = 'rgba(57,255,143,0.08)'
const commonOptions = {
  responsive: true,
  maintainAspectRatio: false,
  plugins: {
    legend: { labels: { color: '#e4ede7', usePointStyle: true, font: { family: 'JetBrains Mono' } } },
    tooltip: { backgroundColor: '#0e1510', borderColor: '#22362a', borderWidth: 1, titleColor: '#ffffff', bodyColor: '#e4ede7' },
  },
  scales: {
    x: { ticks: { color: axisColor, font: { family: 'JetBrains Mono', size: 10 } }, grid: { color: gridColor } },
    y: { ticks: { color: axisColor, font: { family: 'JetBrains Mono', size: 10 } }, grid: { color: gridColor }, beginAtZero: true },
  },
}

function labelsFor(series: CampaignSeries[]) {
  return series.map((_, index) => `C${index + 1}`)
}

function optionsFor(series: CampaignSeries[]) {
  return {
    ...commonOptions,
    plugins: {
      ...commonOptions.plugins,
      tooltip: {
        ...commonOptions.plugins.tooltip,
        callbacks: {
          afterTitle: (items: TooltipItem<'line'>[]) => {
            const campaign = series[items[0]?.dataIndex]?.campaign
            return campaign ? `Campaign ID: ${campaign.id}` : ''
          },
        },
      },
    },
  }
}

export function AttackSuccessChart({ series }: { series: CampaignSeries[] }) {
  const stats = series.map(({ attempts }) => computeCampaignStats(attempts))
  return (
    <section className="panel chart-panel accent-top">
      <div className="panel-heading"><div><p className="eyebrow">Campaign telemetry</p><h2>Attack success rate</h2></div><span className="panel-note">queried attempts only</span></div>
      <div className="chart-wrap">
        <Line
          aria-label="Attack success rate by campaign"
          data={{ labels: labelsFor(series), datasets: [{ label: 'Success rate %', data: stats.map((stat) => stat.successRatePercent), borderColor: '#39ff8f', backgroundColor: 'rgba(57,255,143,.13)', fill: true, tension: .35, pointRadius: 4, pointBackgroundColor: '#39ff8f' }] }}
          options={{
            ...optionsFor(series),
            scales: {
              ...commonOptions.scales,
              y: {
                ...commonOptions.scales.y,
                max: 100,
                ticks: { ...commonOptions.scales.y.ticks, callback: (value) => `${value}%` },
              },
            },
          }}
        />
      </div>
    </section>
  )
}

export function AttemptsBreakdownChart({ series }: { series: CampaignSeries[] }) {
  const stats = series.map(({ attempts }) => computeCampaignStats(attempts))
  return (
    <section className="panel chart-panel red-top">
      <div className="panel-heading"><div><p className="eyebrow">Execution accounting</p><h2>Attempts breakdown</h2></div><span className="panel-note">pruned excluded</span></div>
      <div className="chart-wrap">
        <Line
          aria-label="Campaign attempts breakdown"
          data={{ labels: labelsFor(series), datasets: [
            { label: 'Total', data: stats.map((stat) => stat.total), borderColor: '#ffffff', tension: .35, pointRadius: 3 },
            { label: 'Blocked', data: stats.map((stat) => stat.blocked), borderColor: '#ff2d4d', tension: .35, pointRadius: 3 },
            { label: 'Passed', data: stats.map((stat) => stat.passed), borderColor: '#39ff8f', tension: .35, pointRadius: 3 },
          ] }}
          options={optionsFor(series)}
        />
      </div>
    </section>
  )
}
