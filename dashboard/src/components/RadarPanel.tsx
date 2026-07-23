import { useEffect, useRef, useState } from 'react'
import type { CampaignSummary, FindingSummary } from '../api/types'

type Blip = { angle: number; bornAt: number }

export function RadarPanel({ findings, campaigns }: { findings: FindingSummary[]; campaigns: CampaignSummary[] }) {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const angleRef = useRef(0)
  const seenIdsRef = useRef<Set<string> | null>(null)
  const blipsRef = useRef<Blip[]>([])
  const [announcement, setAnnouncement] = useState('')

  useEffect(() => {
    const currentIds = new Set(findings.map((finding) => finding.id))
    if (seenIdsRef.current !== null) {
      const newFindings = findings.filter((finding) => !seenIdsRef.current?.has(finding.id))
      newFindings.forEach(() => {
        blipsRef.current.push({ angle: angleRef.current, bornAt: performance.now() })
      })
      if (newFindings.length > 0) {
        setAnnouncement(`${newFindings.length} new finding${newFindings.length === 1 ? '' : 's'} detected`)
      }
    }
    seenIdsRef.current = currentIds
  }, [findings])

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return undefined
    const context = canvas.getContext('2d')
    if (!context) return undefined
    let frame = 0
    let previous = performance.now()
    const render = (now: number) => {
      const rect = canvas.getBoundingClientRect()
      const scale = window.devicePixelRatio || 1
      if (canvas.width !== rect.width * scale || canvas.height !== rect.height * scale) {
        canvas.width = rect.width * scale
        canvas.height = rect.height * scale
        context.setTransform(scale, 0, 0, scale, 0, 0)
      }
      const delta = now - previous
      previous = now
      angleRef.current = (angleRef.current + delta * 0.00065) % (Math.PI * 2)
      const width = rect.width
      const height = rect.height
      const radius = Math.min(width, height) * .4
      const centerX = width / 2
      const centerY = height / 2
      context.clearRect(0, 0, width, height)
      context.save()
      context.translate(centerX, centerY)
      context.strokeStyle = 'rgba(57,255,143,.22)'
      context.lineWidth = 1
      for (let ring = 1; ring <= 4; ring += 1) {
        context.beginPath(); context.arc(0, 0, radius * ring / 4, 0, Math.PI * 2); context.stroke()
      }
      for (let spoke = 0; spoke < 8; spoke += 1) {
        const angle = (Math.PI * 2 * spoke) / 8
        context.beginPath(); context.moveTo(0, 0); context.lineTo(Math.cos(angle) * radius, Math.sin(angle) * radius); context.stroke()
      }
      const trail = context.createConicGradient(angleRef.current - Math.PI / 2, 0, 0)
      trail.addColorStop(0, 'rgba(57,255,143,.38)'); trail.addColorStop(.12, 'rgba(57,255,143,.03)'); trail.addColorStop(.35, 'rgba(57,255,143,0)'); trail.addColorStop(1, 'rgba(57,255,143,0)')
      context.fillStyle = trail; context.beginPath(); context.moveTo(0, 0); context.arc(0, 0, radius, 0, Math.PI * 2); context.fill()
      context.strokeStyle = '#39ff8f'; context.shadowColor = '#39ff8f'; context.shadowBlur = 14
      context.beginPath(); context.moveTo(0, 0); context.lineTo(Math.cos(angleRef.current) * radius, Math.sin(angleRef.current) * radius); context.stroke()
      context.shadowBlur = 0
      blipsRef.current = blipsRef.current.filter((blip) => now - blip.bornAt < 3200)
      blipsRef.current.forEach((blip) => {
        const age = (now - blip.bornAt) / 3200
        context.globalAlpha = 1 - age
        context.fillStyle = '#ff2d4d'; context.shadowColor = '#ff2d4d'; context.shadowBlur = 16
        context.beginPath(); context.arc(Math.cos(blip.angle) * radius * .68, Math.sin(blip.angle) * radius * .68, 5 + age * 5, 0, Math.PI * 2); context.fill()
      })
      context.restore()
      frame = requestAnimationFrame(render)
    }
    frame = requestAnimationFrame(render)
    return () => cancelAnimationFrame(frame)
  }, [])

  const active = campaigns.find((campaign) => campaign.status === 'running')
  return (
    <section className="panel radar-panel accent-top">
      <div className="panel-heading"><div><p className="eyebrow">Live discovery signal</p><h2>Radar sweep</h2></div><span className="radar-key">RED = NEW FINDING</span></div>
      <canvas ref={canvasRef} className="radar" aria-label="Live campaign finding radar" />
      <span className="sr-only" role="status">{announcement}</span>
      <p className="radar-caption">{active ? `active ${active.id.slice(0, 8)} · target=${active.targetKey}` : 'idle — no active campaign'}</p>
    </section>
  )
}
