import { useEffect, useRef, useState } from 'react'

export type PollingState<T> = {
  data: T | null
  error: Error | null
  lastUpdated: Date | null
}

export function usePolling<T>(fetcher: () => Promise<T>, intervalMs = 5000): PollingState<T> {
  const fetcherRef = useRef(fetcher)
  fetcherRef.current = fetcher
  const [state, setState] = useState<PollingState<T>>({ data: null, error: null, lastUpdated: null })

  useEffect(() => {
    let disposed = false
    const poll = async () => {
      try {
        const data = await fetcherRef.current()
        if (!disposed) setState({ data, error: null, lastUpdated: new Date() })
      } catch (error) {
        if (!disposed) {
          // Preserve last known good data while the Control API reconnects.
          setState((previous) => ({ ...previous, error: error instanceof Error ? error : new Error('Polling failed') }))
        }
      }
    }
    void poll()
    const timer = window.setInterval(() => void poll(), intervalMs)
    return () => {
      disposed = true
      window.clearInterval(timer)
    }
  }, [intervalMs])

  return state
}
