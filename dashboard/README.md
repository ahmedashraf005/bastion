# Bastion Dashboard

The dashboard is a read-only client of Bastion.Control. It has no mock-data
mode, so start Control locally first (see `control/README.md`).

```sh
pnpm install
pnpm dev
```

Vite serves the dashboard at `http://localhost:5173` by default. Configure
the Control API base URL with `VITE_CONTROL_BASE_URL` (default:
`http://localhost:5080`).
