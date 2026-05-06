# ROOC Feather Optimizer

Ragnarok Origin Classic Feather Build Optimizer — v8.1

## Features
- Pool-based inventory (shared copies across feathers in the same pool)
- Raven's Hour set enforcement (4 Yellow + 1 Purple per statue)
- Two-phase engine: tier floor + global surplus distribution by score-per-copy
- 6 presets: PvE DPS, PvP DPS, Tank PvE, Tank PvP, PvE ATK / PvP DEF, Balanced
- Custom stat weight sliders (0.0–2.0) with tooltip explanation
- Top 20 builds across 500+ tier distribution strategies
- Manual Build Editor with live validation

## Deploy to Railway

### Option A — GitHub + Railway (recommended)
1. Push this folder to a GitHub repository
2. Go to [railway.app](https://railway.app) → New Project → Deploy from GitHub
3. Select your repository
4. Railway auto-detects Node.js and runs `npm start`
5. Your app is live at the generated Railway URL

### Option B — Railway CLI
```bash
npm install -g @railway/cli
railway login
railway init
railway up
```

## Run locally
```bash
npm install
npm start
# Open http://localhost:3000
```

## Project structure
```
rooc-optimizer/
├── server.js          # Express static file server
├── package.json       # Node dependencies
├── railway.toml       # Railway deployment config
├── .gitignore
└── public/
    └── index.html     # Full optimizer (single file, no build step)
```

## Adding new set data
When you extract other set compositions from the game (3Y+2P, 5Y, etc.),
add them to the `PRESETS` and set bonus tables in `public/index.html`.
