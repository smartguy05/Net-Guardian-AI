import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import {
  Shield,
  Monitor,
  Bell,
  Brain,
  Network,
  ShieldOff,
  MessageSquare,
  Activity,
  Github,
  ExternalLink,
  Sun,
  Moon,
  ChevronRight,
  Check,
  Server,
  Database,
  Cpu,
  Terminal,
} from 'lucide-react';
import { useThemeStore } from '../stores/theme';
import clsx from 'clsx';

// Feature data
const features = [
  {
    icon: Monitor,
    title: 'Device Inventory',
    description:
      'Automatically discover and track all devices on your network with real-time status monitoring.',
  },
  {
    icon: Bell,
    title: 'Smart Alerts',
    description:
      'Rule-based and AI-powered alerting that reduces false positives and catches real threats.',
  },
  {
    icon: Brain,
    title: 'AI-Powered Analysis',
    description:
      'Claude AI integration for natural language queries and intelligent threat investigation.',
  },
  {
    icon: Activity,
    title: 'Anomaly Detection',
    description:
      'Behavioral baselines detect unusual patterns like data exfiltration or lateral movement.',
  },
  {
    icon: Network,
    title: 'Network Topology',
    description:
      'Interactive visualization of your network structure and device relationships.',
  },
  {
    icon: ShieldOff,
    title: 'Automated Quarantine',
    description:
      'Instantly isolate compromised devices via router or DNS-level blocking.',
  },
  {
    icon: MessageSquare,
    title: 'AI Chat Assistant',
    description:
      'Ask questions about your network in plain English and get actionable insights.',
  },
  {
    icon: Shield,
    title: 'Threat Intelligence',
    description:
      'Correlate traffic with known IOCs from multiple threat intelligence feeds.',
  },
];

// Screenshot pages for carousel
const screenshotPages = [
  { id: 'dashboard', name: 'Dashboard' },
  { id: 'devices', name: 'Devices' },
  { id: 'alerts', name: 'Alerts' },
  { id: 'anomalies', name: 'Anomalies' },
  { id: 'events', name: 'Events' },
  { id: 'topology', name: 'Topology' },
  { id: 'rules', name: 'Rules' },
  { id: 'chat', name: 'AI Chat' },
  { id: 'settings', name: 'Settings' },
];

// Architecture components
const architectureComponents = [
  {
    icon: Server,
    title: 'FastAPI Backend',
    description: 'High-performance async Python API with WebSocket support',
  },
  {
    icon: Database,
    title: 'TimescaleDB',
    description: 'Time-series optimized PostgreSQL for efficient event storage',
  },
  {
    icon: Cpu,
    title: 'Redis Streams',
    description: 'Real-time event bus for async processing and caching',
  },
  {
    icon: Brain,
    title: 'Claude AI',
    description: 'Anthropic Claude for threat analysis and natural language queries',
  },
];

export default function LandingPage() {
  const { theme, setTheme, resolvedTheme } = useThemeStore();
  const [screenshotTheme, setScreenshotTheme] = useState<'light' | 'dark'>('dark');
  const [activeScreenshot, setActiveScreenshot] = useState('dashboard');

  // Sync screenshot theme with resolved theme
  useEffect(() => {
    setScreenshotTheme(resolvedTheme === 'dark' ? 'dark' : 'light');
  }, [resolvedTheme]);

  const toggleTheme = () => {
    if (theme === 'system') {
      setTheme(resolvedTheme === 'dark' ? 'light' : 'dark');
    } else {
      setTheme(theme === 'dark' ? 'light' : 'dark');
    }
  };

  return (
    <div className="min-h-screen bg-white dark:bg-zinc-900 text-gray-900 dark:text-gray-100">
      {/* Header */}
      <header className="fixed top-0 inset-x-0 z-50 bg-white/80 dark:bg-zinc-900/80 backdrop-blur-md border-b border-gray-200 dark:border-zinc-700">
        <nav className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            {/* Logo */}
            <Link to="/" className="flex items-center gap-2">
              <Shield className="h-8 w-8 text-primary-600" />
              <span className="text-xl font-bold">NetGuardian AI</span>
            </Link>

            {/* Nav Links */}
            <div className="hidden md:flex items-center gap-8">
              <a href="#features" className="text-sm font-medium hover:text-primary-600 transition-colors">
                Features
              </a>
              <a href="#screenshots" className="text-sm font-medium hover:text-primary-600 transition-colors">
                Screenshots
              </a>
              <a href="#architecture" className="text-sm font-medium hover:text-primary-600 transition-colors">
                Architecture
              </a>
              <a href="#quickstart" className="text-sm font-medium hover:text-primary-600 transition-colors">
                Quick Start
              </a>
            </div>

            {/* Actions */}
            <div className="flex items-center gap-4">
              <button
                onClick={toggleTheme}
                className="p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-zinc-800 transition-colors"
                aria-label="Toggle theme"
              >
                {resolvedTheme === 'dark' ? (
                  <Sun className="h-5 w-5" />
                ) : (
                  <Moon className="h-5 w-5" />
                )}
              </button>
              <a
                href="https://github.com/netguardian-ai/netguardian"
                target="_blank"
                rel="noopener noreferrer"
                className="p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-zinc-800 transition-colors"
                aria-label="GitHub"
              >
                <Github className="h-5 w-5" />
              </a>
              <Link
                to="/login"
                className="btn-primary"
              >
                Login
              </Link>
            </div>
          </div>
        </nav>
      </header>

      {/* Hero Section */}
      <section className="pt-32 pb-20 px-4 sm:px-6 lg:px-8">
        <div className="max-w-7xl mx-auto">
          <div className="text-center max-w-3xl mx-auto mb-12">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-primary-100 dark:bg-primary-900/30 text-primary-700 dark:text-primary-400 text-sm font-medium mb-6">
              <Shield className="h-4 w-4" />
              AI-Powered Network Security
            </div>
            <h1 className="text-4xl sm:text-5xl lg:text-6xl font-bold tracking-tight mb-6">
              Protect Your Home Network with{' '}
              <span className="text-primary-600">AI Intelligence</span>
            </h1>
            <p className="text-lg sm:text-xl text-gray-600 dark:text-gray-400 mb-8">
              NetGuardian AI monitors your network traffic, detects anomalies, and uses Claude AI to help you investigate and respond to threats in real-time.
            </p>
            <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
              <Link
                to="/login"
                className="btn-primary text-base px-6 py-3 flex items-center gap-2"
              >
                Get Started
                <ChevronRight className="h-4 w-4" />
              </Link>
              <a
                href="https://github.com/netguardian-ai/netguardian"
                target="_blank"
                rel="noopener noreferrer"
                className="btn-secondary text-base px-6 py-3 flex items-center gap-2"
              >
                <Github className="h-4 w-4" />
                View on GitHub
              </a>
            </div>
          </div>

          {/* Hero Screenshot */}
          <div className="relative max-w-5xl mx-auto">
            <div className="absolute inset-0 bg-gradient-to-r from-primary-500/20 via-primary-500/10 to-primary-500/20 blur-3xl" />
            <div className="relative rounded-xl overflow-hidden border border-gray-200 dark:border-zinc-700 shadow-2xl">
              <img
                src={`/screenshots/dashboard-${screenshotTheme}.png`}
                alt="NetGuardian Dashboard"
                className="w-full"
                onError={(e) => {
                  // Fallback for missing screenshots
                  (e.target as HTMLImageElement).src = 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 700"><rect fill="%23374151" width="1200" height="700"/><text x="600" y="350" text-anchor="middle" fill="%239CA3AF" font-family="system-ui" font-size="24">Dashboard Preview</text></svg>';
                }}
              />
            </div>
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section id="features" className="py-20 px-4 sm:px-6 lg:px-8 bg-gray-50 dark:bg-zinc-800/50">
        <div className="max-w-7xl mx-auto">
          <div className="text-center mb-12">
            <h2 className="text-3xl sm:text-4xl font-bold mb-4">
              Comprehensive Security Features
            </h2>
            <p className="text-lg text-gray-600 dark:text-gray-400 max-w-2xl mx-auto">
              Everything you need to monitor, detect, and respond to threats on your home network.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            {features.map((feature, index) => {
              const Icon = feature.icon;
              return (
                <div
                  key={index}
                  className="p-6 rounded-xl bg-white dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700 hover:shadow-lg hover:border-primary-300 dark:hover:border-primary-600 transition-all"
                >
                  <div className="w-12 h-12 rounded-lg bg-primary-100 dark:bg-primary-900/30 flex items-center justify-center mb-4">
                    <Icon className="h-6 w-6 text-primary-600 dark:text-primary-400" />
                  </div>
                  <h3 className="text-lg font-semibold mb-2">{feature.title}</h3>
                  <p className="text-sm text-gray-600 dark:text-gray-400">
                    {feature.description}
                  </p>
                </div>
              );
            })}
          </div>
        </div>
      </section>

      {/* Screenshots Section */}
      <section id="screenshots" className="py-20 px-4 sm:px-6 lg:px-8">
        <div className="max-w-7xl mx-auto">
          <div className="text-center mb-12">
            <h2 className="text-3xl sm:text-4xl font-bold mb-4">
              See It in Action
            </h2>
            <p className="text-lg text-gray-600 dark:text-gray-400 max-w-2xl mx-auto mb-6">
              Explore the interface across different pages and themes.
            </p>

            {/* Theme Toggle for Screenshots */}
            <div className="inline-flex items-center gap-2 p-1 bg-gray-100 dark:bg-zinc-800 rounded-lg">
              <button
                onClick={() => setScreenshotTheme('light')}
                className={clsx(
                  'flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-colors',
                  screenshotTheme === 'light'
                    ? 'bg-white dark:bg-zinc-700 shadow text-gray-900 dark:text-white'
                    : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'
                )}
              >
                <Sun className="h-4 w-4" />
                Light
              </button>
              <button
                onClick={() => setScreenshotTheme('dark')}
                className={clsx(
                  'flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-colors',
                  screenshotTheme === 'dark'
                    ? 'bg-white dark:bg-zinc-700 shadow text-gray-900 dark:text-white'
                    : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'
                )}
              >
                <Moon className="h-4 w-4" />
                Dark
              </button>
            </div>
          </div>

          {/* Screenshot Tabs */}
          <div className="mb-6 flex justify-center">
            <div className="flex flex-wrap justify-center gap-2">
              {screenshotPages.map((page) => (
                <button
                  key={page.id}
                  onClick={() => setActiveScreenshot(page.id)}
                  className={clsx(
                    'px-4 py-2 rounded-lg text-sm font-medium transition-colors',
                    activeScreenshot === page.id
                      ? 'bg-primary-600 text-white'
                      : 'bg-gray-100 dark:bg-zinc-800 text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-zinc-700'
                  )}
                >
                  {page.name}
                </button>
              ))}
            </div>
          </div>

          {/* Screenshot Display */}
          <div className="relative max-w-5xl mx-auto">
            <div className="rounded-xl overflow-hidden border border-gray-200 dark:border-zinc-700 shadow-xl">
              <img
                src={`/screenshots/${activeScreenshot}-${screenshotTheme}.png`}
                alt={`${activeScreenshot} page screenshot`}
                className="w-full"
                onError={(e) => {
                  // Fallback for missing screenshots
                  (e.target as HTMLImageElement).src = `data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 700"><rect fill="${screenshotTheme === 'dark' ? '%23374151' : '%23F3F4F6'}" width="1200" height="700"/><text x="600" y="350" text-anchor="middle" fill="${screenshotTheme === 'dark' ? '%239CA3AF' : '%236B7280'}" font-family="system-ui" font-size="24">${activeScreenshot.charAt(0).toUpperCase() + activeScreenshot.slice(1)} Preview</text></svg>`;
                }}
              />
            </div>
          </div>
        </div>
      </section>

      {/* Architecture Section */}
      <section id="architecture" className="py-20 px-4 sm:px-6 lg:px-8 bg-gray-50 dark:bg-zinc-800/50">
        <div className="max-w-7xl mx-auto">
          <div className="text-center mb-12">
            <h2 className="text-3xl sm:text-4xl font-bold mb-4">
              Modern Architecture
            </h2>
            <p className="text-lg text-gray-600 dark:text-gray-400 max-w-2xl mx-auto">
              Built with best-in-class technologies for reliability, performance, and scalability.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-12">
            {architectureComponents.map((component, index) => {
              const Icon = component.icon;
              return (
                <div
                  key={index}
                  className="p-6 rounded-xl bg-white dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700 text-center"
                >
                  <div className="w-12 h-12 rounded-full bg-primary-100 dark:bg-primary-900/30 flex items-center justify-center mx-auto mb-4">
                    <Icon className="h-6 w-6 text-primary-600 dark:text-primary-400" />
                  </div>
                  <h3 className="text-lg font-semibold mb-2">{component.title}</h3>
                  <p className="text-sm text-gray-600 dark:text-gray-400">
                    {component.description}
                  </p>
                </div>
              );
            })}
          </div>

          {/* Architecture Diagram */}
          <div className="max-w-4xl mx-auto p-8 rounded-xl bg-white dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700">
            <div className="grid grid-cols-3 gap-4 text-center text-sm">
              {/* Data Sources */}
              <div className="space-y-2">
                <div className="font-semibold text-gray-500 dark:text-gray-400 mb-4">Data Sources</div>
                {['AdGuard Home', 'Router Logs', 'Syslog', 'Custom APIs'].map((source) => (
                  <div key={source} className="px-3 py-2 rounded-lg bg-gray-100 dark:bg-zinc-700 text-gray-700 dark:text-gray-300">
                    {source}
                  </div>
                ))}
              </div>

              {/* Processing */}
              <div className="space-y-2">
                <div className="font-semibold text-gray-500 dark:text-gray-400 mb-4">Processing</div>
                <div className="px-3 py-2 rounded-lg bg-primary-100 dark:bg-primary-900/30 text-primary-700 dark:text-primary-400">
                  Collectors
                </div>
                <div className="text-gray-400">|</div>
                <div className="px-3 py-2 rounded-lg bg-primary-100 dark:bg-primary-900/30 text-primary-700 dark:text-primary-400">
                  Parsers
                </div>
                <div className="text-gray-400">|</div>
                <div className="px-3 py-2 rounded-lg bg-primary-100 dark:bg-primary-900/30 text-primary-700 dark:text-primary-400">
                  Anomaly Detection
                </div>
                <div className="text-gray-400">|</div>
                <div className="px-3 py-2 rounded-lg bg-primary-100 dark:bg-primary-900/30 text-primary-700 dark:text-primary-400">
                  Claude AI Analysis
                </div>
              </div>

              {/* Storage & Output */}
              <div className="space-y-2">
                <div className="font-semibold text-gray-500 dark:text-gray-400 mb-4">Output</div>
                {['TimescaleDB', 'Redis Cache', 'Real-time UI', 'Notifications'].map((output) => (
                  <div key={output} className="px-3 py-2 rounded-lg bg-gray-100 dark:bg-zinc-700 text-gray-700 dark:text-gray-300">
                    {output}
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Quick Start Section */}
      <section id="quickstart" className="py-20 px-4 sm:px-6 lg:px-8">
        <div className="max-w-4xl mx-auto">
          <div className="text-center mb-12">
            <h2 className="text-3xl sm:text-4xl font-bold mb-4">
              Quick Start
            </h2>
            <p className="text-lg text-gray-600 dark:text-gray-400">
              Get NetGuardian running in minutes with Docker Compose.
            </p>
          </div>

          {/* Prerequisites */}
          <div className="mb-8">
            <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
              <Check className="h-5 w-5 text-success-500" />
              Prerequisites
            </h3>
            <ul className="space-y-2 text-gray-600 dark:text-gray-400">
              <li className="flex items-center gap-2">
                <Check className="h-4 w-4 text-success-500" />
                Docker and Docker Compose (or Podman)
              </li>
              <li className="flex items-center gap-2">
                <Check className="h-4 w-4 text-success-500" />
                At least 4GB RAM available
              </li>
              <li className="flex items-center gap-2">
                <Check className="h-4 w-4 text-success-500" />
                Anthropic API key (optional, for AI features)
              </li>
            </ul>
          </div>

          {/* Installation Steps */}
          <div className="space-y-4">
            <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
              <Terminal className="h-5 w-5" />
              Installation
            </h3>

            <div className="rounded-xl overflow-hidden border border-gray-200 dark:border-zinc-700">
              <div className="bg-gray-100 dark:bg-zinc-800 px-4 py-2 border-b border-gray-200 dark:border-zinc-700">
                <span className="text-sm font-medium text-gray-600 dark:text-gray-400">Terminal</span>
              </div>
              <pre className="p-4 bg-gray-900 dark:bg-zinc-950 text-gray-100 text-sm overflow-x-auto">
                <code>{`# Clone the repository
git clone https://github.com/netguardian-ai/netguardian.git
cd netguardian

# Copy environment template
cp deploy/.env.example deploy/.env

# Edit .env with your settings (API keys, etc.)
nano deploy/.env

# Start all services
cd deploy
docker-compose up -d

# Run database migrations
docker exec netguardian-backend alembic upgrade head

# View initial admin password
docker logs netguardian-backend | grep "Initial admin"`}</code>
              </pre>
            </div>

            <p className="text-sm text-gray-600 dark:text-gray-400 mt-4">
              Once running, access the dashboard at{' '}
              <code className="px-2 py-1 bg-gray-100 dark:bg-zinc-800 rounded text-primary-600 dark:text-primary-400">
                http://localhost:5173
              </code>
            </p>
          </div>

          {/* CTA */}
          <div className="mt-12 text-center">
            <a
              href="https://github.com/netguardian-ai/netguardian#readme"
              target="_blank"
              rel="noopener noreferrer"
              className="btn-primary text-base px-6 py-3 inline-flex items-center gap-2"
            >
              View Full Documentation
              <ExternalLink className="h-4 w-4" />
            </a>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-gray-200 dark:border-zinc-700 py-12 px-4 sm:px-6 lg:px-8">
        <div className="max-w-7xl mx-auto">
          <div className="flex flex-col md:flex-row items-center justify-between gap-6">
            <div className="flex items-center gap-2">
              <Shield className="h-6 w-6 text-primary-600" />
              <span className="font-semibold">NetGuardian AI</span>
            </div>
            <p className="text-sm text-gray-500 dark:text-gray-400">
              Open source home network security monitoring
            </p>
            <div className="flex items-center gap-6">
              <a
                href="https://github.com/netguardian-ai/netguardian"
                target="_blank"
                rel="noopener noreferrer"
                className="text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200 transition-colors"
              >
                <Github className="h-5 w-5" />
              </a>
            </div>
          </div>
          <div className="mt-8 pt-8 border-t border-gray-200 dark:border-zinc-700 text-center text-sm text-gray-500 dark:text-gray-400">
            Built with FastAPI, React, TimescaleDB, and Claude AI
          </div>
        </div>
      </footer>
    </div>
  );
}
