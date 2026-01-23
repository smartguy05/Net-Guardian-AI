import { useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Shield,
  ChevronRight,
  ChevronDown,
  Monitor,
  Bell,
  Brain,
  Activity,
  Network,
  ShieldOff,
  MessageSquare,
  Settings,
  Users,
  FileText,
  Database,
  Server,
  Terminal,
  AlertTriangle,
  Check,
  Copy,
  Sun,
  Moon,
  Eye,
  Zap,
  Target,
  Play,
  Key,
  Cpu,
  BarChart3,
  Webhook,
  Mail,
  Hash,
  Lightbulb,
  Scan,
} from 'lucide-react';
import { useThemeStore } from '../stores/theme';
import clsx from 'clsx';

interface Section {
  id: string;
  title: string;
  icon: React.ElementType;
  subsections?: { id: string; title: string }[];
}

const sections: Section[] = [
  {
    id: 'overview',
    title: 'Overview',
    icon: Shield,
    subsections: [
      { id: 'overview-intro', title: 'Introduction' },
      { id: 'overview-architecture', title: 'Architecture' },
      { id: 'overview-features', title: 'Key Features' },
    ],
  },
  {
    id: 'getting-started',
    title: 'Getting Started',
    icon: Terminal,
    subsections: [
      { id: 'getting-started-requirements', title: 'Requirements' },
      { id: 'getting-started-installation', title: 'Installation' },
      { id: 'getting-started-first-login', title: 'First Login' },
    ],
  },
  {
    id: 'dashboard',
    title: 'Dashboard',
    icon: BarChart3,
  },
  {
    id: 'devices',
    title: 'Device Management',
    icon: Monitor,
    subsections: [
      { id: 'devices-inventory', title: 'Device Inventory' },
      { id: 'devices-details', title: 'Device Details' },
      { id: 'devices-tagging', title: 'Tagging & Organization' },
      { id: 'devices-baselines', title: 'Behavioral Baselines' },
    ],
  },
  {
    id: 'events',
    title: 'Event Monitoring',
    icon: FileText,
  },
  {
    id: 'alerts',
    title: 'Alert Management',
    icon: Bell,
    subsections: [
      { id: 'alerts-overview', title: 'Alert Overview' },
      { id: 'alerts-lifecycle', title: 'Alert Lifecycle' },
      { id: 'alerts-ai-analysis', title: 'AI-Powered Analysis' },
    ],
  },
  {
    id: 'anomalies',
    title: 'Anomaly Detection',
    icon: Activity,
    subsections: [
      { id: 'anomalies-types', title: 'Anomaly Types' },
      { id: 'anomalies-detection', title: 'Detection Algorithm' },
      { id: 'anomalies-review', title: 'Review Process' },
    ],
  },
  {
    id: 'rules',
    title: 'Detection Rules',
    icon: Target,
    subsections: [
      { id: 'rules-creating', title: 'Creating Rules' },
      { id: 'rules-conditions', title: 'Rule Conditions' },
      { id: 'rules-actions', title: 'Response Actions' },
    ],
  },
  {
    id: 'semantic-analysis',
    title: 'Semantic Log Analysis',
    icon: Scan,
    subsections: [
      { id: 'semantic-overview', title: 'Overview' },
      { id: 'semantic-patterns', title: 'Log Patterns' },
      { id: 'semantic-review', title: 'Semantic Review' },
      { id: 'semantic-rules', title: 'Suggested Rules' },
      { id: 'semantic-config', title: 'Configuration' },
    ],
  },
  {
    id: 'quarantine',
    title: 'Device Quarantine',
    icon: ShieldOff,
    subsections: [
      { id: 'quarantine-overview', title: 'Quarantine Overview' },
      { id: 'quarantine-integrations', title: 'Integration Status' },
      { id: 'quarantine-actions', title: 'Quarantine Actions' },
    ],
  },
  {
    id: 'ai-assistant',
    title: 'AI Assistant',
    icon: MessageSquare,
    subsections: [
      { id: 'ai-chat', title: 'Chat Interface' },
      { id: 'ai-models', title: 'Model Selection' },
      { id: 'ai-queries', title: 'Example Queries' },
    ],
  },
  {
    id: 'topology',
    title: 'Network Topology',
    icon: Network,
  },
  {
    id: 'threat-intel',
    title: 'Threat Intelligence',
    icon: AlertTriangle,
    subsections: [
      { id: 'threat-intel-feeds', title: 'Managing Feeds' },
      { id: 'threat-intel-indicators', title: 'Indicators' },
      { id: 'threat-intel-lookup', title: 'Manual Lookup' },
    ],
  },
  {
    id: 'sources',
    title: 'Log Sources',
    icon: Database,
    subsections: [
      { id: 'sources-types', title: 'Source Types' },
      { id: 'sources-parsers', title: 'Parser Types' },
      { id: 'sources-api-push', title: 'API Push Integration' },
    ],
  },
  {
    id: 'playbooks',
    title: 'Automation Playbooks',
    icon: Play,
    subsections: [
      { id: 'playbooks-triggers', title: 'Trigger Types' },
      { id: 'playbooks-actions', title: 'Action Types' },
      { id: 'playbooks-examples', title: 'Example Playbooks' },
    ],
  },
  {
    id: 'users',
    title: 'User Management',
    icon: Users,
    subsections: [
      { id: 'users-roles', title: 'User Roles' },
      { id: 'users-2fa', title: 'Two-Factor Authentication' },
    ],
  },
  {
    id: 'notifications',
    title: 'Notifications',
    icon: Mail,
    subsections: [
      { id: 'notifications-email', title: 'Email Notifications' },
      { id: 'notifications-push', title: 'Push Notifications' },
    ],
  },
  {
    id: 'integrations',
    title: 'Integrations',
    icon: Webhook,
    subsections: [
      { id: 'integrations-adguard', title: 'AdGuard Home' },
      { id: 'integrations-router', title: 'Router Integration' },
      { id: 'integrations-ollama', title: 'Ollama Monitoring' },
    ],
  },
  {
    id: 'configuration',
    title: 'Configuration',
    icon: Settings,
    subsections: [
      { id: 'configuration-env', title: 'Environment Variables' },
      { id: 'configuration-retention', title: 'Data Retention' },
    ],
  },
  {
    id: 'api',
    title: 'API Reference',
    icon: Server,
    subsections: [
      { id: 'api-auth', title: 'Authentication' },
      { id: 'api-endpoints', title: 'Endpoints' },
      { id: 'api-rate-limiting', title: 'Rate Limiting' },
    ],
  },
];

function CodeBlock({ children, language = 'bash' }: { children: string; language?: string }) {
  const [copied, setCopied] = useState(false);

  const copyCode = () => {
    navigator.clipboard.writeText(children);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="relative group rounded-lg overflow-hidden border border-gray-200 dark:border-zinc-700 my-4">
      <div className="flex items-center justify-between bg-gray-100 dark:bg-zinc-800 px-4 py-2 border-b border-gray-200 dark:border-zinc-700">
        <span className="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">{language}</span>
        <button
          onClick={copyCode}
          className="flex items-center gap-1 text-xs text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200"
        >
          {copied ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
          {copied ? 'Copied!' : 'Copy'}
        </button>
      </div>
      <pre className="p-4 bg-gray-900 dark:bg-zinc-950 text-gray-100 text-sm overflow-x-auto">
        <code>{children}</code>
      </pre>
    </div>
  );
}

function TableOfContents({
  activeSection,
  onSectionClick,
}: {
  activeSection: string;
  onSectionClick: (id: string) => void;
}) {
  const [expandedSections, setExpandedSections] = useState<Set<string>>(new Set(['overview', 'getting-started']));

  const toggleSection = (sectionId: string) => {
    setExpandedSections((prev) => {
      const next = new Set(prev);
      if (next.has(sectionId)) {
        next.delete(sectionId);
      } else {
        next.add(sectionId);
      }
      return next;
    });
  };

  return (
    <nav className="space-y-1">
      {sections.map((section) => {
        const Icon = section.icon;
        const isExpanded = expandedSections.has(section.id);
        const isActive = activeSection === section.id || section.subsections?.some((sub) => activeSection === sub.id);

        return (
          <div key={section.id}>
            <button
              onClick={() => {
                if (section.subsections) {
                  toggleSection(section.id);
                }
                onSectionClick(section.id);
              }}
              className={clsx(
                'w-full flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-colors text-left',
                isActive
                  ? 'bg-primary-100 dark:bg-primary-900/30 text-primary-700 dark:text-primary-400'
                  : 'text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-zinc-800'
              )}
            >
              <Icon className="h-4 w-4 flex-shrink-0" />
              <span className="flex-1">{section.title}</span>
              {section.subsections && (
                <span className="text-gray-400">
                  {isExpanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
                </span>
              )}
            </button>
            {section.subsections && isExpanded && (
              <div className="ml-6 mt-1 space-y-1">
                {section.subsections.map((sub) => (
                  <button
                    key={sub.id}
                    onClick={() => onSectionClick(sub.id)}
                    className={clsx(
                      'w-full text-left px-3 py-1.5 rounded text-sm transition-colors',
                      activeSection === sub.id
                        ? 'text-primary-600 dark:text-primary-400 font-medium'
                        : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-200'
                    )}
                  >
                    {sub.title}
                  </button>
                ))}
              </div>
            )}
          </div>
        );
      })}
    </nav>
  );
}

export default function DocsPage() {
  const { theme, setTheme, resolvedTheme } = useThemeStore();
  const [activeSection, setActiveSection] = useState('overview');

  const toggleTheme = () => {
    if (theme === 'system') {
      setTheme(resolvedTheme === 'dark' ? 'light' : 'dark');
    } else {
      setTheme(theme === 'dark' ? 'light' : 'dark');
    }
  };

  const scrollToSection = (sectionId: string) => {
    setActiveSection(sectionId);
    const element = document.getElementById(sectionId);
    if (element) {
      element.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  };

  return (
    <div className="min-h-screen bg-white dark:bg-zinc-900 text-gray-900 dark:text-gray-100">
      {/* Header */}
      <header className="fixed top-0 inset-x-0 z-50 bg-white/80 dark:bg-zinc-900/80 backdrop-blur-md border-b border-gray-200 dark:border-zinc-700">
        <nav className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <Link to="/" className="flex items-center gap-2">
              <Shield className="h-8 w-8 text-primary-600" />
              <span className="text-xl font-bold">NetGuardian AI</span>
              <span className="text-sm text-gray-500 dark:text-gray-400 ml-2">Documentation</span>
            </Link>
            <div className="flex items-center gap-4">
              <button
                onClick={toggleTheme}
                className="p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-zinc-800 transition-colors"
                aria-label="Toggle theme"
              >
                {resolvedTheme === 'dark' ? <Sun className="h-5 w-5" /> : <Moon className="h-5 w-5" />}
              </button>
              <Link to="/login" className="btn-primary">
                Login
              </Link>
            </div>
          </div>
        </nav>
      </header>

      <div className="pt-16 flex">
        {/* Sidebar */}
        <aside className="fixed left-0 top-16 bottom-0 w-64 overflow-y-auto border-r border-gray-200 dark:border-zinc-700 bg-gray-50 dark:bg-zinc-800/50 p-4">
          <TableOfContents activeSection={activeSection} onSectionClick={scrollToSection} />
        </aside>

        {/* Main Content */}
        <main className="ml-64 flex-1 p-8 max-w-4xl">
          {/* Overview Section */}
          <section id="overview" className="mb-16">
            <h1 className="text-4xl font-bold mb-6">NetGuardian AI Documentation</h1>
            <p className="text-lg text-gray-600 dark:text-gray-400 mb-8">
              Comprehensive guide to using NetGuardian AI for home network security monitoring.
            </p>

            <div id="overview-intro" className="mb-12">
              <h2 className="text-2xl font-bold mb-4">Introduction</h2>
              <p className="text-gray-600 dark:text-gray-400 mb-4">
                NetGuardian AI is an AI-powered home network security monitoring system that provides:
              </p>
              <ul className="list-disc list-inside space-y-2 text-gray-600 dark:text-gray-400 mb-4">
                <li>Multi-source log collection from various network devices</li>
                <li>Automatic device discovery and inventory management</li>
                <li>Behavioral baseline learning and anomaly detection</li>
                <li>AI-assisted threat analysis using Claude</li>
                <li>Automated response capabilities including device quarantine</li>
                <li>Interactive network topology visualization</li>
                <li>Threat intelligence feed integration</li>
              </ul>
            </div>

            <div id="overview-architecture" className="mb-12">
              <h2 className="text-2xl font-bold mb-4">Architecture</h2>
              <p className="text-gray-600 dark:text-gray-400 mb-4">
                NetGuardian AI uses a modern microservices architecture:
              </p>
              <div className="grid grid-cols-2 gap-4 mb-6">
                <div className="p-4 rounded-lg bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700">
                  <div className="flex items-center gap-2 mb-2">
                    <Server className="h-5 w-5 text-primary-600" />
                    <span className="font-medium">FastAPI Backend</span>
                  </div>
                  <p className="text-sm text-gray-600 dark:text-gray-400">
                    High-performance async Python API with WebSocket support for real-time updates.
                  </p>
                </div>
                <div className="p-4 rounded-lg bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700">
                  <div className="flex items-center gap-2 mb-2">
                    <Database className="h-5 w-5 text-primary-600" />
                    <span className="font-medium">TimescaleDB</span>
                  </div>
                  <p className="text-sm text-gray-600 dark:text-gray-400">
                    Time-series optimized PostgreSQL for efficient event storage and querying.
                  </p>
                </div>
                <div className="p-4 rounded-lg bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700">
                  <div className="flex items-center gap-2 mb-2">
                    <Cpu className="h-5 w-5 text-primary-600" />
                    <span className="font-medium">Redis Streams</span>
                  </div>
                  <p className="text-sm text-gray-600 dark:text-gray-400">
                    Real-time event bus for async processing, caching, and pub/sub messaging.
                  </p>
                </div>
                <div className="p-4 rounded-lg bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700">
                  <div className="flex items-center gap-2 mb-2">
                    <Brain className="h-5 w-5 text-primary-600" />
                    <span className="font-medium">Claude AI</span>
                  </div>
                  <p className="text-sm text-gray-600 dark:text-gray-400">
                    Anthropic Claude for threat analysis, natural language queries, and incident summaries.
                  </p>
                </div>
              </div>
            </div>

            <div id="overview-features" className="mb-12">
              <h2 className="text-2xl font-bold mb-4">Key Features</h2>
              <div className="space-y-4">
                <div className="flex items-start gap-3">
                  <div className="w-8 h-8 rounded-lg bg-primary-100 dark:bg-primary-900/30 flex items-center justify-center flex-shrink-0">
                    <Monitor className="h-4 w-4 text-primary-600" />
                  </div>
                  <div>
                    <h3 className="font-medium">Device Inventory</h3>
                    <p className="text-sm text-gray-600 dark:text-gray-400">
                      Automatically discover and track all devices with status monitoring and tagging.
                    </p>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <div className="w-8 h-8 rounded-lg bg-primary-100 dark:bg-primary-900/30 flex items-center justify-center flex-shrink-0">
                    <Activity className="h-4 w-4 text-primary-600" />
                  </div>
                  <div>
                    <h3 className="font-medium">Anomaly Detection</h3>
                    <p className="text-sm text-gray-600 dark:text-gray-400">
                      Statistical analysis detects unusual patterns like data exfiltration or lateral movement.
                    </p>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <div className="w-8 h-8 rounded-lg bg-primary-100 dark:bg-primary-900/30 flex items-center justify-center flex-shrink-0">
                    <ShieldOff className="h-4 w-4 text-primary-600" />
                  </div>
                  <div>
                    <h3 className="font-medium">Automated Response</h3>
                    <p className="text-sm text-gray-600 dark:text-gray-400">
                      Instantly quarantine devices via router or DNS-level blocking with audit trails.
                    </p>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <div className="w-8 h-8 rounded-lg bg-primary-100 dark:bg-primary-900/30 flex items-center justify-center flex-shrink-0">
                    <MessageSquare className="h-4 w-4 text-primary-600" />
                  </div>
                  <div>
                    <h3 className="font-medium">AI Assistant</h3>
                    <p className="text-sm text-gray-600 dark:text-gray-400">
                      Ask questions about your network in plain English and get actionable insights.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </section>

          {/* Getting Started Section */}
          <section id="getting-started" className="mb-16">
            <h1 className="text-3xl font-bold mb-6">Getting Started</h1>

            <div id="getting-started-requirements" className="mb-12">
              <h2 className="text-2xl font-bold mb-4">Requirements</h2>
              <ul className="space-y-2">
                <li className="flex items-center gap-2 text-gray-600 dark:text-gray-400">
                  <Check className="h-4 w-4 text-green-500" />
                  Docker and Docker Compose (or Podman)
                </li>
                <li className="flex items-center gap-2 text-gray-600 dark:text-gray-400">
                  <Check className="h-4 w-4 text-green-500" />
                  At least 4GB RAM available
                </li>
                <li className="flex items-center gap-2 text-gray-600 dark:text-gray-400">
                  <Check className="h-4 w-4 text-green-500" />
                  Anthropic API key (optional, for AI features)
                </li>
                <li className="flex items-center gap-2 text-gray-600 dark:text-gray-400">
                  <Check className="h-4 w-4 text-green-500" />
                  AdGuard Home or supported router (optional, for blocking)
                </li>
              </ul>
            </div>

            <div id="getting-started-installation" className="mb-12">
              <h2 className="text-2xl font-bold mb-4">Installation</h2>
              <p className="text-gray-600 dark:text-gray-400 mb-4">
                Clone the repository and start the services with Docker Compose:
              </p>
              <CodeBlock>{`# Clone the repository
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
docker logs netguardian-backend | grep "Initial admin"`}</CodeBlock>
            </div>

            <div id="getting-started-first-login" className="mb-12">
              <h2 className="text-2xl font-bold mb-4">First Login</h2>
              <ol className="list-decimal list-inside space-y-3 text-gray-600 dark:text-gray-400">
                <li>Navigate to <code className="px-2 py-1 bg-gray-100 dark:bg-zinc-800 rounded">http://localhost:5173</code></li>
                <li>Click "Login" in the top right corner</li>
                <li>Use the default credentials:
                  <ul className="list-disc list-inside ml-6 mt-2">
                    <li>Username: <code className="px-2 py-1 bg-gray-100 dark:bg-zinc-800 rounded">admin</code></li>
                    <li>Password: Check the backend logs for the initial admin password</li>
                  </ul>
                </li>
                <li>You will be prompted to change your password on first login</li>
                <li>Configure two-factor authentication for added security (recommended)</li>
              </ol>
            </div>
          </section>

          {/* Dashboard Section */}
          <section id="dashboard" className="mb-16">
            <h1 className="text-3xl font-bold mb-6">Dashboard</h1>
            <p className="text-gray-600 dark:text-gray-400 mb-4">
              The dashboard provides a real-time overview of your network security status.
            </p>
            <h3 className="text-lg font-medium mb-3">Key Metrics</h3>
            <ul className="list-disc list-inside space-y-2 text-gray-600 dark:text-gray-400 mb-4">
              <li><strong>Active Devices</strong> - Number of devices currently active on your network</li>
              <li><strong>Events (24h)</strong> - Total network events in the last 24 hours</li>
              <li><strong>Active Alerts</strong> - Unresolved security alerts requiring attention</li>
              <li><strong>Log Sources</strong> - Number of configured log collection sources</li>
              <li><strong>DNS Block Rate</strong> - Percentage of DNS queries blocked by your DNS filter</li>
              <li><strong>Top Queried Domains</strong> - Most frequently accessed domains</li>
              <li><strong>Recent Alerts</strong> - Latest security alerts with severity indicators</li>
            </ul>
          </section>

          {/* Devices Section */}
          <section id="devices" className="mb-16">
            <h1 className="text-3xl font-bold mb-6">Device Management</h1>

            <div id="devices-inventory" className="mb-12">
              <h2 className="text-2xl font-bold mb-4">Device Inventory</h2>
              <p className="text-gray-600 dark:text-gray-400 mb-4">
                The device inventory automatically tracks all devices discovered on your network.
              </p>
              <h3 className="text-lg font-medium mb-3">Device Information</h3>
              <ul className="list-disc list-inside space-y-2 text-gray-600 dark:text-gray-400 mb-4">
                <li><strong>Hostname</strong> - Device name (auto-discovered or manually set)</li>
                <li><strong>MAC Address</strong> - Unique hardware identifier</li>
                <li><strong>IP Addresses</strong> - Current and historical IP addresses</li>
                <li><strong>Manufacturer</strong> - Detected from MAC address OUI lookup</li>
                <li><strong>Device Type</strong> - PC, Mobile, IoT, Server, Network, or Unknown</li>
                <li><strong>Status</strong> - Active, Inactive, or Quarantined</li>
                <li><strong>First/Last Seen</strong> - Discovery and activity timestamps</li>
              </ul>
              <h3 className="text-lg font-medium mb-3">Filtering & Search</h3>
              <p className="text-gray-600 dark:text-gray-400 mb-4">
                Use the search bar to find devices by hostname or MAC address. Filter by status (active, inactive, quarantined) or by tags for organized device management.
              </p>
            </div>

            <div id="devices-details" className="mb-12">
              <h2 className="text-2xl font-bold mb-4">Device Details</h2>
              <p className="text-gray-600 dark:text-gray-400 mb-4">
                Click on any device to view its detailed information page with multiple tabs:
              </p>
              <ul className="list-disc list-inside space-y-2 text-gray-600 dark:text-gray-400">
                <li><strong>Events</strong> - All network events associated with this device</li>
                <li><strong>Alerts</strong> - Security alerts specific to this device</li>
                <li><strong>Baselines</strong> - Behavioral baseline data and learning status</li>
                <li><strong>Anomalies</strong> - Detected behavioral anomalies</li>
              </ul>
            </div>

            <div id="devices-tagging" className="mb-12">
              <h2 className="text-2xl font-bold mb-4">Tagging & Organization</h2>
              <p className="text-gray-600 dark:text-gray-400 mb-4">
                Tags help organize devices into logical groups for filtering and rule targeting.
              </p>
              <h3 className="text-lg font-medium mb-3">Tag Operations</h3>
              <ul className="list-disc list-inside space-y-2 text-gray-600 dark:text-gray-400">
                <li><strong>Add Tags</strong> - Add one or more tags to a device</li>
                <li><strong>Remove Tags</strong> - Remove specific tags from a device</li>
                <li><strong>Bulk Tagging</strong> - Select multiple devices and add/remove tags in bulk</li>
                <li><strong>Filter by Tags</strong> - Click tags in the filter panel to show matching devices</li>
              </ul>
            </div>

            <div id="devices-baselines" className="mb-12">
              <h2 className="text-2xl font-bold mb-4">Behavioral Baselines</h2>
              <p className="text-gray-600 dark:text-gray-400 mb-4">
                NetGuardian AI learns normal behavior patterns for each device to detect anomalies.
              </p>
              <h3 className="text-lg font-medium mb-3">Baseline Types</h3>
              <ul className="list-disc list-inside space-y-2 text-gray-600 dark:text-gray-400 mb-4">
                <li><strong>DNS Baseline</strong> - Normal DNS query patterns, domains accessed, hourly distribution</li>
                <li><strong>Traffic Baseline</strong> - Connection patterns, protocols, port usage</li>
                <li><strong>Connection Baseline</strong> - Target IPs and services typically contacted</li>
              </ul>
              <h3 className="text-lg font-medium mb-3">Baseline Status</h3>
              <ul className="list-disc list-inside space-y-2 text-gray-600 dark:text-gray-400">
                <li><strong>Learning</strong> - Still collecting data (typically needs 7+ days)</li>
                <li><strong>Ready</strong> - Sufficient data for anomaly detection</li>
                <li><strong>Stale</strong> - Needs recalculation due to age or changes</li>
              </ul>
            </div>
          </section>

          {/* Events Section */}
          <section id="events" className="mb-16">
            <h1 className="text-3xl font-bold mb-6">Event Monitoring</h1>
            <p className="text-gray-600 dark:text-gray-400 mb-4">
              The Events page shows all raw log events collected from your network.
            </p>
            <h3 className="text-lg font-medium mb-3">Event Types</h3>
            <div className="grid grid-cols-2 gap-4 mb-6">
              <div className="p-3 rounded-lg bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700">
                <span className="font-medium">DNS</span>
                <p className="text-sm text-gray-600 dark:text-gray-400">Domain name resolution queries</p>
              </div>
              <div className="p-3 rounded-lg bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700">
                <span className="font-medium">Firewall</span>
                <p className="text-sm text-gray-600 dark:text-gray-400">Firewall allow/block decisions</p>
              </div>
              <div className="p-3 rounded-lg bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700">
                <span className="font-medium">Auth</span>
                <p className="text-sm text-gray-600 dark:text-gray-400">Authentication attempts</p>
              </div>
              <div className="p-3 rounded-lg bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700">
                <span className="font-medium">HTTP</span>
                <p className="text-sm text-gray-600 dark:text-gray-400">Web traffic metadata</p>
              </div>
              <div className="p-3 rounded-lg bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700">
                <span className="font-medium">System</span>
                <p className="text-sm text-gray-600 dark:text-gray-400">System-level events</p>
              </div>
              <div className="p-3 rounded-lg bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700">
                <span className="font-medium">Network</span>
                <p className="text-sm text-gray-600 dark:text-gray-400">General network activity</p>
              </div>
            </div>
            <h3 className="text-lg font-medium mb-3">Filtering Events</h3>
            <p className="text-gray-600 dark:text-gray-400 mb-4">
              Filter events by type, severity, or search for specific domains. Click on any event row to expand and view the full raw message and parsed fields.
            </p>
          </section>

          {/* Alerts Section */}
          <section id="alerts" className="mb-16">
            <h1 className="text-3xl font-bold mb-6">Alert Management</h1>

            <div id="alerts-overview" className="mb-12">
              <h2 className="text-2xl font-bold mb-4">Alert Overview</h2>
              <p className="text-gray-600 dark:text-gray-400 mb-4">
                Alerts are generated when detection rules match or anomalies are detected.
              </p>
              <h3 className="text-lg font-medium mb-3">Severity Levels</h3>
              <div className="space-y-2 mb-4">
                <div className="flex items-center gap-2">
                  <span className="w-3 h-3 rounded-full bg-red-500"></span>
                  <span className="font-medium">Critical</span>
                  <span className="text-sm text-gray-600 dark:text-gray-400">- Immediate action required</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="w-3 h-3 rounded-full bg-orange-500"></span>
                  <span className="font-medium">High</span>
                  <span className="text-sm text-gray-600 dark:text-gray-400">- Urgent attention needed</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="w-3 h-3 rounded-full bg-yellow-500"></span>
                  <span className="font-medium">Medium</span>
                  <span className="text-sm text-gray-600 dark:text-gray-400">- Should be reviewed soon</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="w-3 h-3 rounded-full bg-blue-500"></span>
                  <span className="font-medium">Low</span>
                  <span className="text-sm text-gray-600 dark:text-gray-400">- Informational, review when time permits</span>
                </div>
              </div>
            </div>

            <div id="alerts-lifecycle" className="mb-12">
              <h2 className="text-2xl font-bold mb-4">Alert Lifecycle</h2>
              <ol className="list-decimal list-inside space-y-3 text-gray-600 dark:text-gray-400">
                <li><strong>New</strong> - Alert just created, needs attention</li>
                <li><strong>Acknowledged</strong> - Someone is reviewing the alert</li>
                <li><strong>Resolved</strong> - Issue addressed, alert closed</li>
                <li><strong>False Positive</strong> - Alert was incorrect, marked for rule tuning</li>
              </ol>
            </div>

            <div id="alerts-ai-analysis" className="mb-12">
              <h2 className="text-2xl font-bold mb-4">AI-Powered Analysis</h2>
              <p className="text-gray-600 dark:text-gray-400 mb-4">
                Request Claude AI to analyze any alert by clicking the "Analyze" button. The AI will:
              </p>
              <ul className="list-disc list-inside space-y-2 text-gray-600 dark:text-gray-400">
                <li>Examine the alert context and related events</li>
                <li>Check device behavioral baseline data</li>
                <li>Assess the threat level and provide a confidence score</li>
                <li>Estimate false positive likelihood</li>
                <li>Recommend specific remediation actions</li>
              </ul>
            </div>
          </section>

          {/* Anomalies Section */}
          <section id="anomalies" className="mb-16">
            <h1 className="text-3xl font-bold mb-6">Anomaly Detection</h1>

            <div id="anomalies-types" className="mb-12">
              <h2 className="text-2xl font-bold mb-4">Anomaly Types</h2>
              <div className="space-y-4">
                <div className="p-4 rounded-lg bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700">
                  <h3 className="font-medium mb-1">NEW_DOMAIN</h3>
                  <p className="text-sm text-gray-600 dark:text-gray-400">
                    Device queries a domain never seen before in its baseline period.
                  </p>
                </div>
                <div className="p-4 rounded-lg bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700">
                  <h3 className="font-medium mb-1">VOLUME_SPIKE</h3>
                  <p className="text-sm text-gray-600 dark:text-gray-400">
                    Unusual spike in query volume exceeding normal statistical bounds (z-score based).
                  </p>
                </div>
                <div className="p-4 rounded-lg bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700">
                  <h3 className="font-medium mb-1">TIME_ANOMALY</h3>
                  <p className="text-sm text-gray-600 dark:text-gray-400">
                    Network activity at unusual hours for this specific device.
                  </p>
                </div>
                <div className="p-4 rounded-lg bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700">
                  <h3 className="font-medium mb-1">NEW_CONNECTION</h3>
                  <p className="text-sm text-gray-600 dark:text-gray-400">
                    New connection type or target not previously seen.
                  </p>
                </div>
                <div className="p-4 rounded-lg bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700">
                  <h3 className="font-medium mb-1">NEW_PORT</h3>
                  <p className="text-sm text-gray-600 dark:text-gray-400">
                    Device connects on a port not in its normal behavior profile.
                  </p>
                </div>
                <div className="p-4 rounded-lg bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700">
                  <h3 className="font-medium mb-1">BLOCKED_SPIKE</h3>
                  <p className="text-sm text-gray-600 dark:text-gray-400">
                    Sudden increase in blocked DNS queries from a device.
                  </p>
                </div>
                <div className="p-4 rounded-lg bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700">
                  <h3 className="font-medium mb-1">PATTERN_CHANGE</h3>
                  <p className="text-sm text-gray-600 dark:text-gray-400">
                    Significant deviation from established behavioral patterns.
                  </p>
                </div>
              </div>
            </div>

            <div id="anomalies-detection" className="mb-12">
              <h2 className="text-2xl font-bold mb-4">Detection Algorithm</h2>
              <p className="text-gray-600 dark:text-gray-400 mb-4">
                Anomaly detection uses statistical analysis comparing current behavior against learned baselines:
              </p>
              <ul className="list-disc list-inside space-y-2 text-gray-600 dark:text-gray-400">
                <li>Z-score calculation for volume-based metrics</li>
                <li>Threshold levels: 2.0 (normal), 3.0 (high), 4.0+ (critical)</li>
                <li>Hourly distribution analysis for time-based anomalies</li>
                <li>Set comparison for new domain/port/connection detection</li>
              </ul>
            </div>

            <div id="anomalies-review" className="mb-12">
              <h2 className="text-2xl font-bold mb-4">Review Process</h2>
              <p className="text-gray-600 dark:text-gray-400 mb-4">
                When reviewing anomalies, you can mark them as:
              </p>
              <ul className="list-disc list-inside space-y-2 text-gray-600 dark:text-gray-400">
                <li><strong>Reviewed</strong> - Acknowledged but not a threat</li>
                <li><strong>False Positive</strong> - Expected behavior, helps tune detection</li>
                <li><strong>Confirmed</strong> - Verified as a real security concern</li>
              </ul>
            </div>
          </section>

          {/* Rules Section */}
          <section id="rules" className="mb-16">
            <h1 className="text-3xl font-bold mb-6">Detection Rules</h1>

            <div id="rules-creating" className="mb-12">
              <h2 className="text-2xl font-bold mb-4">Creating Rules</h2>
              <p className="text-gray-600 dark:text-gray-400 mb-4">
                Detection rules allow you to create custom alert triggers based on network events.
              </p>
              <ol className="list-decimal list-inside space-y-3 text-gray-600 dark:text-gray-400">
                <li>Click "Create Rule" in the Rules page</li>
                <li>Define rule name, description, and severity</li>
                <li>Add one or more conditions (AND/OR logic)</li>
                <li>Configure response actions to take when triggered</li>
                <li>Set cooldown period to prevent alert spam</li>
                <li>Enable the rule when ready</li>
              </ol>
            </div>

            <div id="rules-conditions" className="mb-12">
              <h2 className="text-2xl font-bold mb-4">Rule Conditions</h2>
              <h3 className="text-lg font-medium mb-3">Available Fields</h3>
              <ul className="list-disc list-inside space-y-2 text-gray-600 dark:text-gray-400 mb-4">
                <li><code className="px-2 py-1 bg-gray-100 dark:bg-zinc-800 rounded">event_type</code> - Type of event (DNS, Firewall, etc.)</li>
                <li><code className="px-2 py-1 bg-gray-100 dark:bg-zinc-800 rounded">domain</code> - Domain name in the event</li>
                <li><code className="px-2 py-1 bg-gray-100 dark:bg-zinc-800 rounded">source_ip</code> / <code className="px-2 py-1 bg-gray-100 dark:bg-zinc-800 rounded">target_ip</code> - IP addresses</li>
                <li><code className="px-2 py-1 bg-gray-100 dark:bg-zinc-800 rounded">port</code> - Port number</li>
                <li><code className="px-2 py-1 bg-gray-100 dark:bg-zinc-800 rounded">action</code> - Event action (blocked, allowed)</li>
                <li><code className="px-2 py-1 bg-gray-100 dark:bg-zinc-800 rounded">device_type</code> - Type of device</li>
                <li><code className="px-2 py-1 bg-gray-100 dark:bg-zinc-800 rounded">device_tags</code> - Tags assigned to device</li>
              </ul>
              <h3 className="text-lg font-medium mb-3">Operators</h3>
              <ul className="list-disc list-inside space-y-2 text-gray-600 dark:text-gray-400">
                <li><code className="px-2 py-1 bg-gray-100 dark:bg-zinc-800 rounded">eq</code>, <code className="px-2 py-1 bg-gray-100 dark:bg-zinc-800 rounded">ne</code> - Equals, Not equals</li>
                <li><code className="px-2 py-1 bg-gray-100 dark:bg-zinc-800 rounded">contains</code>, <code className="px-2 py-1 bg-gray-100 dark:bg-zinc-800 rounded">regex</code> - Pattern matching</li>
                <li><code className="px-2 py-1 bg-gray-100 dark:bg-zinc-800 rounded">gt</code>, <code className="px-2 py-1 bg-gray-100 dark:bg-zinc-800 rounded">lt</code>, <code className="px-2 py-1 bg-gray-100 dark:bg-zinc-800 rounded">gte</code>, <code className="px-2 py-1 bg-gray-100 dark:bg-zinc-800 rounded">lte</code> - Numeric comparisons</li>
                <li><code className="px-2 py-1 bg-gray-100 dark:bg-zinc-800 rounded">in</code>, <code className="px-2 py-1 bg-gray-100 dark:bg-zinc-800 rounded">not_in</code> - List membership</li>
                <li><code className="px-2 py-1 bg-gray-100 dark:bg-zinc-800 rounded">starts_with</code>, <code className="px-2 py-1 bg-gray-100 dark:bg-zinc-800 rounded">ends_with</code> - String prefixes/suffixes</li>
              </ul>
            </div>

            <div id="rules-actions" className="mb-12">
              <h2 className="text-2xl font-bold mb-4">Response Actions</h2>
              <div className="space-y-3">
                <div className="flex items-start gap-3">
                  <Bell className="h-5 w-5 text-primary-600 flex-shrink-0 mt-0.5" />
                  <div>
                    <span className="font-medium">create_alert</span>
                    <p className="text-sm text-gray-600 dark:text-gray-400">Generate a security alert</p>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <ShieldOff className="h-5 w-5 text-primary-600 flex-shrink-0 mt-0.5" />
                  <div>
                    <span className="font-medium">quarantine_device</span>
                    <p className="text-sm text-gray-600 dark:text-gray-400">Isolate the device from the network</p>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <Mail className="h-5 w-5 text-primary-600 flex-shrink-0 mt-0.5" />
                  <div>
                    <span className="font-medium">send_notification</span>
                    <p className="text-sm text-gray-600 dark:text-gray-400">Send email or push notification</p>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <Webhook className="h-5 w-5 text-primary-600 flex-shrink-0 mt-0.5" />
                  <div>
                    <span className="font-medium">execute_webhook</span>
                    <p className="text-sm text-gray-600 dark:text-gray-400">Call an external webhook URL</p>
                  </div>
                </div>
              </div>
            </div>
          </section>

          {/* Semantic Log Analysis Section */}
          <section id="semantic-analysis" className="mb-16">
            <h1 className="text-3xl font-bold mb-6">Semantic Log Analysis</h1>

            <div id="semantic-overview" className="mb-12">
              <h2 className="text-2xl font-bold mb-4">Overview</h2>
              <p className="text-gray-600 dark:text-gray-400 mb-4">
                Semantic Log Analysis uses AI to identify unusual log messages that differ from normal patterns.
                Unlike volume-based anomaly detection, this feature analyzes the <em>content</em> of logs to find
                security-relevant irregularities.
              </p>
              <h3 className="text-lg font-medium mb-3">How It Works</h3>
              <ol className="list-decimal list-inside space-y-2 text-gray-600 dark:text-gray-400 mb-4">
                <li><strong>Pattern Learning</strong> - Logs are normalized into templates (replacing IPs, timestamps, UUIDs with placeholders)</li>
                <li><strong>Rarity Detection</strong> - Patterns seen fewer than the threshold count are flagged as irregular</li>
                <li><strong>LLM Analysis</strong> - Irregular logs are batched and sent to an LLM (Claude or Ollama) for security review</li>
                <li><strong>Rule Suggestions</strong> - The LLM can suggest detection rules based on its findings</li>
              </ol>
              <div className="grid grid-cols-2 gap-4 mb-4">
                <div className="p-4 rounded-lg bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700">
                  <div className="flex items-center gap-2 mb-2">
                    <Hash className="h-5 w-5 text-primary-600" />
                    <span className="font-medium">Pattern Learning</span>
                  </div>
                  <p className="text-sm text-gray-600 dark:text-gray-400">
                    Automatically learns normal log patterns from your environment.
                  </p>
                </div>
                <div className="p-4 rounded-lg bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700">
                  <div className="flex items-center gap-2 mb-2">
                    <Lightbulb className="h-5 w-5 text-primary-600" />
                    <span className="font-medium">AI-Powered Rules</span>
                  </div>
                  <p className="text-sm text-gray-600 dark:text-gray-400">
                    LLM suggests detection rules you can approve and enable.
                  </p>
                </div>
              </div>
            </div>

            <div id="semantic-patterns" className="mb-12">
              <h2 className="text-2xl font-bold mb-4">Log Patterns</h2>
              <p className="text-gray-600 dark:text-gray-400 mb-4">
                Access via <strong>Log Patterns</strong> in the sidebar. This page shows learned patterns from your log sources.
              </p>
              <h3 className="text-lg font-medium mb-3">Pattern Information</h3>
              <ul className="list-disc list-inside space-y-2 text-gray-600 dark:text-gray-400 mb-4">
                <li><strong>Pattern</strong> - Normalized log template with placeholders like {"<IP>"}, {"<TIMESTAMP>"}, {"<UUID>"}</li>
                <li><strong>Source</strong> - Log source this pattern belongs to</li>
                <li><strong>Count</strong> - Number of times this pattern was seen</li>
                <li><strong>First/Last Seen</strong> - When the pattern was first observed and most recent occurrence</li>
                <li><strong>Status</strong> - Normal or Ignored (ignored patterns won't be flagged as irregular)</li>
              </ul>
              <h3 className="text-lg font-medium mb-3">Managing Patterns</h3>
              <ul className="list-disc list-inside space-y-2 text-gray-600 dark:text-gray-400">
                <li><strong>Ignore Pattern</strong> - Click the ignore toggle to exclude a pattern from irregularity detection</li>
                <li><strong>Filter by Source</strong> - Use the source dropdown to view patterns from specific log sources</li>
                <li><strong>Search</strong> - Find patterns containing specific text</li>
              </ul>
            </div>

            <div id="semantic-review" className="mb-12">
              <h2 className="text-2xl font-bold mb-4">Semantic Review</h2>
              <p className="text-gray-600 dark:text-gray-400 mb-4">
                Access via <strong>Semantic Review</strong> in the sidebar. This shows logs flagged as irregular
                with LLM analysis of potential security concerns.
              </p>
              <h3 className="text-lg font-medium mb-3">Irregular Log Information</h3>
              <ul className="list-disc list-inside space-y-2 text-gray-600 dark:text-gray-400 mb-4">
                <li><strong>Timestamp</strong> - When the log was received</li>
                <li><strong>Source</strong> - Log source</li>
                <li><strong>Message</strong> - Original log message</li>
                <li><strong>Reason</strong> - Why it was flagged as irregular</li>
                <li><strong>Severity</strong> - LLM-assigned severity score (0.0-1.0)</li>
                <li><strong>LLM Analysis</strong> - Detailed security analysis from the AI</li>
              </ul>
              <h3 className="text-lg font-medium mb-3">Review Actions</h3>
              <ol className="list-decimal list-inside space-y-2 text-gray-600 dark:text-gray-400">
                <li>Click a row to expand the full log details and LLM analysis</li>
                <li>Review the AI's assessment of security concerns</li>
                <li>Click <strong>Mark Reviewed</strong> to acknowledge the log</li>
                <li>If it's a false positive, consider ignoring the pattern on the Patterns page</li>
              </ol>
            </div>

            <div id="semantic-rules" className="mb-12">
              <h2 className="text-2xl font-bold mb-4">Suggested Rules</h2>
              <p className="text-gray-600 dark:text-gray-400 mb-4">
                Access via <strong>Suggested Rules</strong> in the sidebar. The LLM can suggest detection rules
                based on its analysis of irregular logs.
              </p>
              <h3 className="text-lg font-medium mb-3">Pending Rules</h3>
              <p className="text-gray-600 dark:text-gray-400 mb-4">
                Each suggested rule includes:
              </p>
              <ul className="list-disc list-inside space-y-2 text-gray-600 dark:text-gray-400 mb-4">
                <li><strong>Name</strong> - Descriptive rule name</li>
                <li><strong>Description</strong> - What the rule detects</li>
                <li><strong>Reason</strong> - Why the LLM suggested this rule</li>
                <li><strong>Benefit</strong> - How it improves your security posture</li>
                <li><strong>Rule Type</strong> - Pattern match, threshold, or sequence</li>
              </ul>
              <h3 className="text-lg font-medium mb-3">Rule Actions</h3>
              <div className="space-y-3">
                <div className="flex items-start gap-3">
                  <Check className="h-5 w-5 text-green-600 flex-shrink-0 mt-0.5" />
                  <div>
                    <span className="font-medium">Approve</span>
                    <p className="text-sm text-gray-600 dark:text-gray-400">Accept the rule and optionally enable it immediately</p>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <AlertTriangle className="h-5 w-5 text-red-600 flex-shrink-0 mt-0.5" />
                  <div>
                    <span className="font-medium">Reject</span>
                    <p className="text-sm text-gray-600 dark:text-gray-400">Decline with a reason (prevents re-suggestion of similar rules)</p>
                  </div>
                </div>
              </div>
              <h3 className="text-lg font-medium mb-3 mt-4">History Tab</h3>
              <p className="text-gray-600 dark:text-gray-400">
                View previously approved or rejected rules. Filter by status, source, or date range to review past decisions.
              </p>
            </div>

            <div id="semantic-config" className="mb-12">
              <h2 className="text-2xl font-bold mb-4">Configuration</h2>
              <p className="text-gray-600 dark:text-gray-400 mb-4">
                Configure Semantic Analysis per log source or globally via environment variables.
              </p>
              <h3 className="text-lg font-medium mb-3">Per-Source Settings</h3>
              <ul className="list-disc list-inside space-y-2 text-gray-600 dark:text-gray-400 mb-4">
                <li><strong>LLM Provider</strong> - Choose between Claude (cloud) or Ollama (local)</li>
                <li><strong>Ollama Model</strong> - If using Ollama, select the model (llama3.2, mistral, etc.)</li>
                <li><strong>Rarity Threshold</strong> - Patterns seen fewer than N times are irregular (default: 3)</li>
                <li><strong>Batch Size</strong> - Maximum logs per LLM analysis batch (default: 50)</li>
                <li><strong>Batch Interval</strong> - Minutes between automated analysis runs (default: 60)</li>
              </ul>
              <h3 className="text-lg font-medium mb-3">Environment Variables</h3>
              <CodeBlock language="env">{`# Enable semantic analysis globally
SEMANTIC_ANALYSIS_ENABLED=true
SEMANTIC_DEFAULT_LLM_PROVIDER=claude  # or: ollama
SEMANTIC_DEFAULT_RARITY_THRESHOLD=3
SEMANTIC_DEFAULT_BATCH_SIZE=50
SEMANTIC_DEFAULT_BATCH_INTERVAL_MINUTES=60

# Ollama settings (if using local LLM)
OLLAMA_URL=http://localhost:11434
OLLAMA_DEFAULT_MODEL=llama3.2
OLLAMA_TIMEOUT_SECONDS=120`}</CodeBlock>
              <h3 className="text-lg font-medium mb-3 mt-4">Manual Analysis Trigger</h3>
              <p className="text-gray-600 dark:text-gray-400 mb-4">
                To run analysis immediately instead of waiting for the scheduled interval:
              </p>
              <CodeBlock language="bash">{`# Via API
curl -X POST http://localhost:8000/api/v1/semantic/runs/{source_id}/trigger \\
  -H "Authorization: Bearer YOUR_TOKEN"`}</CodeBlock>
            </div>
          </section>

          {/* Quarantine Section */}
          <section id="quarantine" className="mb-16">
            <h1 className="text-3xl font-bold mb-6">Device Quarantine</h1>

            <div id="quarantine-overview" className="mb-12">
              <h2 className="text-2xl font-bold mb-4">Quarantine Overview</h2>
              <p className="text-gray-600 dark:text-gray-400 mb-4">
                Quarantine isolates potentially compromised devices from your network by blocking their traffic at the DNS or router level.
              </p>
              <div className="p-4 rounded-lg bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 mb-4">
                <div className="flex items-start gap-2">
                  <AlertTriangle className="h-5 w-5 text-amber-600 flex-shrink-0 mt-0.5" />
                  <p className="text-sm text-amber-700 dark:text-amber-400">
                    Quarantine is a disruptive action. Use it only when necessary and ensure you have a way to access the device for remediation.
                  </p>
                </div>
              </div>
            </div>

            <div id="quarantine-integrations" className="mb-12">
              <h2 className="text-2xl font-bold mb-4">Integration Status</h2>
              <p className="text-gray-600 dark:text-gray-400 mb-4">
                The Quarantine page shows the status of your blocking integrations:
              </p>
              <ul className="list-disc list-inside space-y-2 text-gray-600 dark:text-gray-400">
                <li><strong>AdGuard Home</strong> - DNS-level blocking via AdGuard API</li>
                <li><strong>Router Integration</strong> - Device blocking via pfSense, OPNsense, or UniFi</li>
              </ul>
            </div>

            <div id="quarantine-actions" className="mb-12">
              <h2 className="text-2xl font-bold mb-4">Quarantine Actions</h2>
              <h3 className="text-lg font-medium mb-3">To Quarantine a Device:</h3>
              <ol className="list-decimal list-inside space-y-2 text-gray-600 dark:text-gray-400 mb-4">
                <li>Navigate to the device in the Devices page</li>
                <li>Click the "Quarantine" button</li>
                <li>Enter a reason for the quarantine</li>
                <li>Confirm the action</li>
              </ol>
              <h3 className="text-lg font-medium mb-3">To Release a Device:</h3>
              <ol className="list-decimal list-inside space-y-2 text-gray-600 dark:text-gray-400">
                <li>Go to the Quarantine page</li>
                <li>Find the device in the quarantined list</li>
                <li>Click the "Release" button</li>
                <li>Enter a reason for the release</li>
              </ol>
            </div>
          </section>

          {/* AI Assistant Section */}
          <section id="ai-assistant" className="mb-16">
            <h1 className="text-3xl font-bold mb-6">AI Assistant</h1>

            <div id="ai-chat" className="mb-12">
              <h2 className="text-2xl font-bold mb-4">Chat Interface</h2>
              <p className="text-gray-600 dark:text-gray-400 mb-4">
                The AI Assistant powered by Claude can answer questions about your network security in natural language.
              </p>
              <p className="text-gray-600 dark:text-gray-400 mb-4">
                The assistant has access to:
              </p>
              <ul className="list-disc list-inside space-y-2 text-gray-600 dark:text-gray-400">
                <li>Current device inventory and status</li>
                <li>Recent alerts and anomalies</li>
                <li>Network activity statistics</li>
                <li>Behavioral baseline data</li>
              </ul>
            </div>

            <div id="ai-models" className="mb-12">
              <h2 className="text-2xl font-bold mb-4">Model Selection</h2>
              <div className="space-y-4">
                <div className="flex items-start gap-3">
                  <Zap className="h-5 w-5 text-primary-600 flex-shrink-0 mt-0.5" />
                  <div>
                    <span className="font-medium">Fast Model (Haiku)</span>
                    <p className="text-sm text-gray-600 dark:text-gray-400">Quick responses for simple queries</p>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <Brain className="h-5 w-5 text-primary-600 flex-shrink-0 mt-0.5" />
                  <div>
                    <span className="font-medium">Balanced Model (Sonnet)</span>
                    <p className="text-sm text-gray-600 dark:text-gray-400">Best quality for most queries</p>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <Eye className="h-5 w-5 text-primary-600 flex-shrink-0 mt-0.5" />
                  <div>
                    <span className="font-medium">Deep Model (Opus)</span>
                    <p className="text-sm text-gray-600 dark:text-gray-400">Detailed analysis for complex investigations</p>
                  </div>
                </div>
              </div>
            </div>

            <div id="ai-queries" className="mb-12">
              <h2 className="text-2xl font-bold mb-4">Example Queries</h2>
              <ul className="list-disc list-inside space-y-2 text-gray-600 dark:text-gray-400">
                <li>"What devices are most active right now?"</li>
                <li>"Are there any security concerns I should know about?"</li>
                <li>"Show me the top blocked domains today"</li>
                <li>"Which devices have anomalies?"</li>
                <li>"Summarize my network activity for the last 24 hours"</li>
                <li>"Explain the alert about suspicious DNS queries"</li>
                <li>"What is device X doing that's unusual?"</li>
              </ul>
            </div>
          </section>

          {/* Topology Section */}
          <section id="topology" className="mb-16">
            <h1 className="text-3xl font-bold mb-6">Network Topology</h1>
            <p className="text-gray-600 dark:text-gray-400 mb-4">
              The interactive network topology visualization shows device connections and traffic patterns.
            </p>
            <h3 className="text-lg font-medium mb-3">Features</h3>
            <ul className="list-disc list-inside space-y-2 text-gray-600 dark:text-gray-400 mb-4">
              <li>Force-directed graph layout showing device relationships</li>
              <li>Color-coded nodes by device type (Router, Server, Mobile, IoT, etc.)</li>
              <li>Node size based on event volume</li>
              <li>Line thickness indicates traffic volume between devices</li>
              <li>Blocked traffic shown as dashed red lines</li>
              <li>Quarantined devices highlighted in red</li>
            </ul>
            <h3 className="text-lg font-medium mb-3">Controls</h3>
            <ul className="list-disc list-inside space-y-2 text-gray-600 dark:text-gray-400">
              <li>Drag nodes to reposition them</li>
              <li>Click nodes to view device details in the sidebar</li>
              <li>Use zoom controls or scroll to zoom in/out</li>
              <li>Adjust time range to show traffic over different periods</li>
              <li>Toggle inactive devices visibility</li>
            </ul>
          </section>

          {/* Threat Intel Section */}
          <section id="threat-intel" className="mb-16">
            <h1 className="text-3xl font-bold mb-6">Threat Intelligence</h1>

            <div id="threat-intel-feeds" className="mb-12">
              <h2 className="text-2xl font-bold mb-4">Managing Feeds</h2>
              <p className="text-gray-600 dark:text-gray-400 mb-4">
                Configure threat intelligence feeds to automatically import known malicious indicators.
              </p>
              <h3 className="text-lg font-medium mb-3">Feed Types</h3>
              <ul className="list-disc list-inside space-y-2 text-gray-600 dark:text-gray-400">
                <li><strong>IP List</strong> - Plain text lists of malicious IP addresses</li>
                <li><strong>Domain List</strong> - Lists of malicious domains</li>
                <li><strong>CSV</strong> - Comma-separated indicator files</li>
                <li><strong>JSON</strong> - Structured JSON feeds</li>
                <li><strong>STIX</strong> - STIX 2.x formatted intelligence</li>
              </ul>
            </div>

            <div id="threat-intel-indicators" className="mb-12">
              <h2 className="text-2xl font-bold mb-4">Indicators</h2>
              <p className="text-gray-600 dark:text-gray-400 mb-4">
                Indicators are imported from feeds and matched against network traffic:
              </p>
              <ul className="list-disc list-inside space-y-2 text-gray-600 dark:text-gray-400">
                <li><strong>IP Addresses</strong> - Known malicious IPs</li>
                <li><strong>Domains</strong> - Malicious domain names</li>
                <li><strong>URLs</strong> - Specific malicious URLs</li>
                <li><strong>File Hashes</strong> - Known malware hashes</li>
                <li><strong>CIDRs</strong> - IP range indicators</li>
              </ul>
            </div>

            <div id="threat-intel-lookup" className="mb-12">
              <h2 className="text-2xl font-bold mb-4">Manual Lookup</h2>
              <p className="text-gray-600 dark:text-gray-400 mb-4">
                Use the Lookup tab to manually check if an IP, domain, or other indicator is in your threat intelligence database.
              </p>
            </div>
          </section>

          {/* Sources Section */}
          <section id="sources" className="mb-16">
            <h1 className="text-3xl font-bold mb-6">Log Sources</h1>

            <div id="sources-types" className="mb-12">
              <h2 className="text-2xl font-bold mb-4">Source Types</h2>
              <div className="space-y-4">
                <div className="p-4 rounded-lg bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700">
                  <h3 className="font-medium mb-1">API Pull</h3>
                  <p className="text-sm text-gray-600 dark:text-gray-400">
                    Periodically fetches logs from REST APIs (e.g., AdGuard Home API).
                  </p>
                </div>
                <div className="p-4 rounded-lg bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700">
                  <h3 className="font-medium mb-1">File Watch</h3>
                  <p className="text-sm text-gray-600 dark:text-gray-400">
                    Monitors log files for new entries (e.g., syslog files).
                  </p>
                </div>
                <div className="p-4 rounded-lg bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700">
                  <h3 className="font-medium mb-1">API Push</h3>
                  <p className="text-sm text-gray-600 dark:text-gray-400">
                    External systems push events to the NetGuardian API.
                  </p>
                </div>
                <div className="p-4 rounded-lg bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700">
                  <h3 className="font-medium mb-1">UDP Listener</h3>
                  <p className="text-sm text-gray-600 dark:text-gray-400">
                    Receives syslog-style events over UDP.
                  </p>
                </div>
              </div>
            </div>

            <div id="sources-parsers" className="mb-12">
              <h2 className="text-2xl font-bold mb-4">Parser Types</h2>
              <ul className="list-disc list-inside space-y-2 text-gray-600 dark:text-gray-400">
                <li><strong>adguard</strong> - AdGuard Home DNS query logs</li>
                <li><strong>syslog</strong> - Standard syslog format</li>
                <li><strong>json</strong> - Generic JSON log parsing</li>
                <li><strong>custom</strong> - User-defined parsing rules</li>
                <li><strong>netflow</strong> - NetFlow v5/v9 data</li>
                <li><strong>sflow</strong> - sFlow traffic data</li>
                <li><strong>endpoint</strong> - Endpoint agent events</li>
                <li><strong>ollama</strong> - Ollama LLM interaction logs</li>
              </ul>
            </div>

            <div id="sources-api-push" className="mb-12">
              <h2 className="text-2xl font-bold mb-4">API Push Integration</h2>
              <p className="text-gray-600 dark:text-gray-400 mb-4">
                For API Push sources, you'll receive an API key to authenticate event submissions:
              </p>
              <CodeBlock language="bash">{`curl -X POST https://your-netguardian/api/v1/logs/ingest \\
  -H "Authorization: Bearer YOUR_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{
    "events": [
      {
        "timestamp": "2024-01-15T10:30:00Z",
        "event_type": "dns",
        "source_ip": "192.168.1.100",
        "domain": "example.com",
        "action": "allowed"
      }
    ]
  }'`}</CodeBlock>
            </div>
          </section>

          {/* Playbooks Section */}
          <section id="playbooks" className="mb-16">
            <h1 className="text-3xl font-bold mb-6">Automation Playbooks</h1>
            <p className="text-gray-600 dark:text-gray-400 mb-4">
              Playbooks automate responses to security events.
            </p>

            <div id="playbooks-triggers" className="mb-12">
              <h2 className="text-2xl font-bold mb-4">Trigger Types</h2>
              <ul className="list-disc list-inside space-y-2 text-gray-600 dark:text-gray-400">
                <li><strong>ANOMALY_DETECTED</strong> - When an anomaly is detected</li>
                <li><strong>ALERT_CREATED</strong> - When a new alert is generated</li>
                <li><strong>DEVICE_NEW</strong> - When a new device is discovered</li>
                <li><strong>DEVICE_STATUS_CHANGE</strong> - When device status changes</li>
                <li><strong>THRESHOLD_EXCEEDED</strong> - When a metric exceeds a threshold</li>
                <li><strong>SCHEDULE</strong> - On a scheduled interval</li>
                <li><strong>MANUAL</strong> - Manually triggered only</li>
              </ul>
            </div>

            <div id="playbooks-actions" className="mb-12">
              <h2 className="text-2xl font-bold mb-4">Action Types</h2>
              <ul className="list-disc list-inside space-y-2 text-gray-600 dark:text-gray-400">
                <li><strong>QUARANTINE_DEVICE</strong> - Isolate a device</li>
                <li><strong>RELEASE_DEVICE</strong> - Release from quarantine</li>
                <li><strong>BLOCK_DOMAIN</strong> - Block a domain in DNS</li>
                <li><strong>SEND_NOTIFICATION</strong> - Send alert notification</li>
                <li><strong>CREATE_ALERT</strong> - Generate an alert</li>
                <li><strong>RUN_LLM_ANALYSIS</strong> - Analyze with AI</li>
                <li><strong>EXECUTE_WEBHOOK</strong> - Call external webhook</li>
                <li><strong>TAG_DEVICE</strong> - Add tags to a device</li>
              </ul>
            </div>

            <div id="playbooks-examples" className="mb-12">
              <h2 className="text-2xl font-bold mb-4">Example Playbooks</h2>
              <div className="space-y-4">
                <div className="p-4 rounded-lg bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700">
                  <h3 className="font-medium mb-2">Auto-Quarantine on Critical Anomaly</h3>
                  <p className="text-sm text-gray-600 dark:text-gray-400 mb-2">
                    Trigger: ANOMALY_DETECTED (severity: critical)
                  </p>
                  <p className="text-sm text-gray-600 dark:text-gray-400">
                    Actions: Send notification, Quarantine device, Run LLM analysis
                  </p>
                </div>
                <div className="p-4 rounded-lg bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700">
                  <h3 className="font-medium mb-2">New IoT Device Alert</h3>
                  <p className="text-sm text-gray-600 dark:text-gray-400 mb-2">
                    Trigger: DEVICE_NEW (device_type: iot)
                  </p>
                  <p className="text-sm text-gray-600 dark:text-gray-400">
                    Actions: Tag device as "unreviewed", Create alert, Send notification
                  </p>
                </div>
              </div>
            </div>
          </section>

          {/* Users Section */}
          <section id="users" className="mb-16">
            <h1 className="text-3xl font-bold mb-6">User Management</h1>

            <div id="users-roles" className="mb-12">
              <h2 className="text-2xl font-bold mb-4">User Roles</h2>
              <div className="space-y-4">
                <div className="p-4 rounded-lg bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700">
                  <div className="flex items-center gap-2 mb-2">
                    <Key className="h-5 w-5 text-red-600" />
                    <span className="font-medium">Admin</span>
                  </div>
                  <p className="text-sm text-gray-600 dark:text-gray-400">
                    Full system access including user management, configuration, and data retention.
                  </p>
                </div>
                <div className="p-4 rounded-lg bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700">
                  <div className="flex items-center gap-2 mb-2">
                    <Settings className="h-5 w-5 text-blue-600" />
                    <span className="font-medium">Operator</span>
                  </div>
                  <p className="text-sm text-gray-600 dark:text-gray-400">
                    Manage devices, acknowledge alerts, run playbooks, and view all data.
                  </p>
                </div>
                <div className="p-4 rounded-lg bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700">
                  <div className="flex items-center gap-2 mb-2">
                    <Eye className="h-5 w-5 text-green-600" />
                    <span className="font-medium">Viewer</span>
                  </div>
                  <p className="text-sm text-gray-600 dark:text-gray-400">
                    Read-only access to dashboards, events, and reports.
                  </p>
                </div>
              </div>
            </div>

            <div id="users-2fa" className="mb-12">
              <h2 className="text-2xl font-bold mb-4">Two-Factor Authentication</h2>
              <p className="text-gray-600 dark:text-gray-400 mb-4">
                Enable 2FA for additional security using any TOTP-compatible authenticator app.
              </p>
              <ol className="list-decimal list-inside space-y-2 text-gray-600 dark:text-gray-400">
                <li>Go to Settings &gt; Security</li>
                <li>Click "Enable Two-Factor Authentication"</li>
                <li>Scan the QR code with your authenticator app</li>
                <li>Enter the verification code</li>
                <li>Save your backup codes securely</li>
              </ol>
            </div>
          </section>

          {/* Notifications Section */}
          <section id="notifications" className="mb-16">
            <h1 className="text-3xl font-bold mb-6">Notifications</h1>

            <div id="notifications-email" className="mb-12">
              <h2 className="text-2xl font-bold mb-4">Email Notifications</h2>
              <p className="text-gray-600 dark:text-gray-400 mb-4">
                Receive alerts via email when security events occur.
              </p>
              <h3 className="text-lg font-medium mb-3">Configuration</h3>
              <p className="text-gray-600 dark:text-gray-400 mb-4">
                SMTP settings are configured in the backend environment:
              </p>
              <CodeBlock language="env">{`SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
SMTP_USE_TLS=true
SMTP_SENDER_EMAIL=alerts@your-domain.com`}</CodeBlock>
            </div>

            <div id="notifications-push" className="mb-12">
              <h2 className="text-2xl font-bold mb-4">Push Notifications (ntfy.sh)</h2>
              <p className="text-gray-600 dark:text-gray-400 mb-4">
                Get instant push notifications on your phone using ntfy.sh.
              </p>
              <ol className="list-decimal list-inside space-y-2 text-gray-600 dark:text-gray-400 mb-4">
                <li>Install the ntfy app on your phone</li>
                <li>Create or subscribe to a topic</li>
                <li>Configure the topic in NetGuardian Settings</li>
                <li>Select which alert severities should send notifications</li>
              </ol>
              <CodeBlock language="env">{`NTFY_SERVER_URL=https://ntfy.sh
NTFY_DEFAULT_TOPIC=your-topic-name
NTFY_AUTH_TOKEN=your-token  # Optional for private topics`}</CodeBlock>
            </div>
          </section>

          {/* Integrations Section */}
          <section id="integrations" className="mb-16">
            <h1 className="text-3xl font-bold mb-6">Integrations</h1>

            <div id="integrations-adguard" className="mb-12">
              <h2 className="text-2xl font-bold mb-4">AdGuard Home</h2>
              <p className="text-gray-600 dark:text-gray-400 mb-4">
                AdGuard Home provides DNS-level filtering and blocking capabilities.
              </p>
              <h3 className="text-lg font-medium mb-3">Features</h3>
              <ul className="list-disc list-inside space-y-2 text-gray-600 dark:text-gray-400 mb-4">
                <li>Collect DNS query logs for analysis</li>
                <li>Block devices at the DNS level (quarantine)</li>
                <li>View blocked queries and statistics</li>
              </ul>
              <h3 className="text-lg font-medium mb-3">Configuration</h3>
              <CodeBlock language="env">{`ADGUARD_ENABLED=true
ADGUARD_URL=http://192.168.1.1:3000
ADGUARD_USERNAME=admin
ADGUARD_PASSWORD=your-password`}</CodeBlock>
            </div>

            <div id="integrations-router" className="mb-12">
              <h2 className="text-2xl font-bold mb-4">Router Integration</h2>
              <p className="text-gray-600 dark:text-gray-400 mb-4">
                Supported routers for device blocking:
              </p>
              <ul className="list-disc list-inside space-y-2 text-gray-600 dark:text-gray-400 mb-4">
                <li><strong>pfSense</strong> - Block via firewall rules</li>
                <li><strong>OPNsense</strong> - Block via firewall rules</li>
                <li><strong>UniFi</strong> - Block via controller API</li>
              </ul>
              <CodeBlock language="env">{`ROUTER_INTEGRATION_TYPE=pfsense  # or unifi, opnsense
ROUTER_URL=https://192.168.1.1
ROUTER_USERNAME=admin
ROUTER_PASSWORD=your-password
ROUTER_VERIFY_SSL=true`}</CodeBlock>
            </div>

            <div id="integrations-ollama" className="mb-12">
              <h2 className="text-2xl font-bold mb-4">Ollama Monitoring</h2>
              <p className="text-gray-600 dark:text-gray-400 mb-4">
                Monitor local LLM interactions for prompt injection and jailbreak attempts.
              </p>
              <CodeBlock language="env">{`OLLAMA_ENABLED=true
OLLAMA_URL=http://localhost:11434
OLLAMA_POLL_INTERVAL_SECONDS=30
OLLAMA_DETECTION_ENABLED=true
OLLAMA_ALERT_ON_INJECTION=true`}</CodeBlock>
            </div>
          </section>

          {/* Configuration Section */}
          <section id="configuration" className="mb-16">
            <h1 className="text-3xl font-bold mb-6">Configuration</h1>

            <div id="configuration-env" className="mb-12">
              <h2 className="text-2xl font-bold mb-4">Environment Variables</h2>
              <p className="text-gray-600 dark:text-gray-400 mb-4">
                NetGuardian AI is configured via environment variables in the <code className="px-2 py-1 bg-gray-100 dark:bg-zinc-800 rounded">.env</code> file.
              </p>
              <h3 className="text-lg font-medium mb-3">Core Settings</h3>
              <div className="overflow-x-auto">
                <table className="w-full text-sm border-collapse">
                  <thead>
                    <tr className="border-b border-gray-200 dark:border-zinc-700">
                      <th className="text-left py-2 px-3 font-medium">Variable</th>
                      <th className="text-left py-2 px-3 font-medium">Description</th>
                      <th className="text-left py-2 px-3 font-medium">Default</th>
                    </tr>
                  </thead>
                  <tbody className="text-gray-600 dark:text-gray-400">
                    <tr className="border-b border-gray-200 dark:border-zinc-700">
                      <td className="py-2 px-3"><code>SECRET_KEY</code></td>
                      <td className="py-2 px-3">JWT signing key (64+ hex chars)</td>
                      <td className="py-2 px-3">Required</td>
                    </tr>
                    <tr className="border-b border-gray-200 dark:border-zinc-700">
                      <td className="py-2 px-3"><code>DATABASE_URL</code></td>
                      <td className="py-2 px-3">PostgreSQL connection string</td>
                      <td className="py-2 px-3">localhost</td>
                    </tr>
                    <tr className="border-b border-gray-200 dark:border-zinc-700">
                      <td className="py-2 px-3"><code>REDIS_URL</code></td>
                      <td className="py-2 px-3">Redis connection string</td>
                      <td className="py-2 px-3">localhost</td>
                    </tr>
                    <tr className="border-b border-gray-200 dark:border-zinc-700">
                      <td className="py-2 px-3"><code>ANTHROPIC_API_KEY</code></td>
                      <td className="py-2 px-3">Claude API key for AI features</td>
                      <td className="py-2 px-3">Optional</td>
                    </tr>
                    <tr className="border-b border-gray-200 dark:border-zinc-700">
                      <td className="py-2 px-3"><code>DEBUG</code></td>
                      <td className="py-2 px-3">Enable debug mode</td>
                      <td className="py-2 px-3">false</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>

            <div id="configuration-retention" className="mb-12">
              <h2 className="text-2xl font-bold mb-4">Data Retention</h2>
              <p className="text-gray-600 dark:text-gray-400 mb-4">
                Admins can configure data retention policies in Settings &gt; Data Retention:
              </p>
              <ul className="list-disc list-inside space-y-2 text-gray-600 dark:text-gray-400">
                <li><strong>Raw Events</strong> - Default 30 days</li>
                <li><strong>Alerts</strong> - Default 90 days</li>
                <li><strong>Audit Logs</strong> - Default 365 days</li>
                <li><strong>Anomalies</strong> - Default 90 days</li>
              </ul>
            </div>
          </section>

          {/* API Section */}
          <section id="api" className="mb-16">
            <h1 className="text-3xl font-bold mb-6">API Reference</h1>

            <div id="api-auth" className="mb-12">
              <h2 className="text-2xl font-bold mb-4">Authentication</h2>
              <p className="text-gray-600 dark:text-gray-400 mb-4">
                The API uses JWT (JSON Web Tokens) for authentication.
              </p>
              <h3 className="text-lg font-medium mb-3">Login</h3>
              <CodeBlock language="bash">{`curl -X POST http://localhost:8000/api/v1/auth/login \\
  -H "Content-Type: application/json" \\
  -d '{"username": "admin", "password": "your-password"}'`}</CodeBlock>
              <h3 className="text-lg font-medium mb-3 mt-4">Using the Token</h3>
              <CodeBlock language="bash">{`curl http://localhost:8000/api/v1/devices \\
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"`}</CodeBlock>
            </div>

            <div id="api-endpoints" className="mb-12">
              <h2 className="text-2xl font-bold mb-4">API Endpoints</h2>
              <p className="text-gray-600 dark:text-gray-400 mb-4">
                Full API documentation is available at:
              </p>
              <ul className="list-disc list-inside space-y-2 text-gray-600 dark:text-gray-400">
                <li><strong>Swagger UI</strong>: <code className="px-2 py-1 bg-gray-100 dark:bg-zinc-800 rounded">http://localhost:8000/docs</code></li>
                <li><strong>ReDoc</strong>: <code className="px-2 py-1 bg-gray-100 dark:bg-zinc-800 rounded">http://localhost:8000/redoc</code></li>
              </ul>
              <h3 className="text-lg font-medium mb-3 mt-4">Key Endpoints</h3>
              <div className="overflow-x-auto">
                <table className="w-full text-sm border-collapse">
                  <thead>
                    <tr className="border-b border-gray-200 dark:border-zinc-700">
                      <th className="text-left py-2 px-3 font-medium">Endpoint</th>
                      <th className="text-left py-2 px-3 font-medium">Description</th>
                    </tr>
                  </thead>
                  <tbody className="text-gray-600 dark:text-gray-400">
                    <tr className="border-b border-gray-200 dark:border-zinc-700">
                      <td className="py-2 px-3"><code>GET /api/v1/devices</code></td>
                      <td className="py-2 px-3">List all devices</td>
                    </tr>
                    <tr className="border-b border-gray-200 dark:border-zinc-700">
                      <td className="py-2 px-3"><code>GET /api/v1/alerts</code></td>
                      <td className="py-2 px-3">List alerts</td>
                    </tr>
                    <tr className="border-b border-gray-200 dark:border-zinc-700">
                      <td className="py-2 px-3"><code>GET /api/v1/events</code></td>
                      <td className="py-2 px-3">Query events</td>
                    </tr>
                    <tr className="border-b border-gray-200 dark:border-zinc-700">
                      <td className="py-2 px-3"><code>POST /api/v1/chat/query</code></td>
                      <td className="py-2 px-3">AI natural language query</td>
                    </tr>
                    <tr className="border-b border-gray-200 dark:border-zinc-700">
                      <td className="py-2 px-3"><code>POST /api/v1/logs/ingest</code></td>
                      <td className="py-2 px-3">Push events to API</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>

            <div id="api-rate-limiting" className="mb-12">
              <h2 className="text-2xl font-bold mb-4">Rate Limiting</h2>
              <p className="text-gray-600 dark:text-gray-400 mb-4">
                API endpoints are rate limited to prevent abuse:
              </p>
              <ul className="list-disc list-inside space-y-2 text-gray-600 dark:text-gray-400">
                <li><strong>Default endpoints</strong>: 60 requests per minute</li>
                <li><strong>Auth endpoints</strong>: 10 requests per minute</li>
                <li><strong>Chat endpoints</strong>: 20 requests per minute</li>
                <li><strong>Export endpoints</strong>: 5 requests per minute</li>
              </ul>
            </div>
          </section>

          {/* Footer */}
          <div className="mt-16 pt-8 border-t border-gray-200 dark:border-zinc-700">
            <div className="flex items-center justify-between">
              <p className="text-sm text-gray-500 dark:text-gray-400">
                NetGuardian AI Documentation
              </p>
              <Link to="/" className="text-sm text-primary-600 hover:text-primary-700">
                Back to Home
              </Link>
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}
