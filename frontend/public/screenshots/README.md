# Screenshots

This directory contains screenshots for the landing page.

## Required Screenshots

The landing page expects the following screenshots in both light and dark themes:

| Page | Light | Dark |
|------|-------|------|
| Dashboard | `dashboard-light.png` | `dashboard-dark.png` |
| Devices | `devices-light.png` | `devices-dark.png` |
| Alerts | `alerts-light.png` | `alerts-dark.png` |
| Anomalies | `anomalies-light.png` | `anomalies-dark.png` |
| Events | `events-light.png` | `events-dark.png` |
| Topology | `topology-light.png` | `topology-dark.png` |
| Rules | `rules-light.png` | `rules-dark.png` |
| Chat | `chat-light.png` | `chat-dark.png` |
| Settings | `settings-light.png` | `settings-dark.png` |

## Capturing Screenshots

Screenshots should be captured at 1200x700 pixels for optimal display.

### Using Playwright

```bash
cd frontend
npx playwright screenshot --viewport-size=1200,700 http://localhost:5173/dashboard screenshots/dashboard-light.png
```

### Manual Capture

1. Login to the application
2. Navigate to each page
3. Set the theme (light/dark)
4. Capture a screenshot at 1200x700 resolution
5. Save with the naming convention: `{page}-{theme}.png`

## Fallback

If screenshots are missing, the landing page displays a placeholder SVG with the page name.
