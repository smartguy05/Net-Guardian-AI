export interface HelpShortcut {
  key: string;
  action: string;
}

export interface HelpSection {
  title: string;
  description: string;
  tips: string[];
  shortcuts?: HelpShortcut[];
}

export interface HelpContent {
  title: string;
  overview: string;
  sections: HelpSection[];
  shortcuts?: HelpShortcut[];
}

// Map route paths to help content
export const helpContent: Record<string, HelpContent> = {
  '/dashboard': {
    title: 'Dashboard',
    overview:
      'The Dashboard provides a real-time overview of your network security status, including key metrics, recent alerts, and system health indicators.',
    sections: [
      {
        title: 'Key Metrics',
        description:
          'Monitor critical security indicators at a glance including total devices, active alerts, events processed, and threat detection counts.',
        tips: [
          'Click on any metric card to navigate to its detailed view',
          'Metrics update automatically every 30 seconds',
          'Red indicators require immediate attention',
        ],
      },
      {
        title: 'Recent Alerts',
        description:
          'View the most recent security alerts detected across your network with severity levels and timestamps.',
        tips: [
          'Critical alerts are highlighted in red',
          'Click "View All" to see the complete alert history',
          'Alerts can be acknowledged or dismissed from the Alerts page',
        ],
      },
      {
        title: 'Activity Feed',
        description:
          'Real-time stream of network events including device connections, DNS queries, and security events.',
        tips: [
          'The feed updates in real-time via WebSocket connection',
          'Filter the feed by event type using the dropdown',
          'Suspicious activities are automatically flagged',
        ],
      },
    ],
  },

  '/dashboard/devices': {
    title: 'Devices',
    overview:
      'View and manage all devices detected on your network. Monitor device status, network activity, and apply security policies.',
    sections: [
      {
        title: 'Device Inventory',
        description:
          'Complete list of all devices that have been detected on your network, with status and metadata.',
        tips: [
          'Use the search bar to find devices by name, IP, or MAC address',
          'Sort by any column by clicking the column header',
          'Filter by device status using the status dropdown',
        ],
      },
      {
        title: 'Device Status',
        description:
          'Each device shows its current status: Online (active in last 5 minutes), Idle (no recent activity), or Offline.',
        tips: [
          'Green dot indicates online devices',
          'Gray dot indicates idle or offline devices',
          'Click a device row to view detailed information',
        ],
      },
      {
        title: 'Device Actions',
        description:
          'Perform actions on devices including renaming, adding notes, or initiating quarantine.',
        tips: [
          'Right-click a device for quick actions',
          'Quarantined devices are blocked at the network level',
          'Device names can be customized for easier identification',
        ],
      },
    ],
  },

  '/dashboard/devices/': {
    title: 'Device Details',
    overview:
      'View detailed information about a specific device including network activity, event history, and security assessments.',
    sections: [
      {
        title: 'Device Information',
        description:
          'View device metadata including MAC address, IP address, hostname, manufacturer, and first/last seen timestamps.',
        tips: [
          'Edit the device name or add notes using the edit button',
          'MAC address can help identify the device manufacturer',
          'First seen date shows when the device joined the network',
        ],
      },
      {
        title: 'Activity Timeline',
        description:
          'Chronological view of all network events associated with this device.',
        tips: [
          'Filter by event type to focus on specific activities',
          'Zoom in on time ranges for detailed analysis',
          'Export activity data for external analysis',
        ],
      },
      {
        title: 'Security Status',
        description:
          'AI-powered security assessment based on device behavior patterns.',
        tips: [
          'Risk score is calculated from behavioral analysis',
          'Anomalies are highlighted with explanations',
          'Historical trends show device behavior over time',
        ],
      },
    ],
  },

  '/dashboard/events': {
    title: 'Events',
    overview:
      'Browse and search all raw network events collected from your log sources. Events are the foundation for alert generation and anomaly detection.',
    sections: [
      {
        title: 'Event Browser',
        description:
          'Paginated view of all collected events with filtering and search capabilities.',
        tips: [
          'Use the search box to filter by any field',
          'Select a date range to narrow results',
          'Click any event to view full details',
        ],
      },
      {
        title: 'Event Types',
        description:
          'Events are categorized by type: DNS queries, network connections, authentication attempts, and more.',
        tips: [
          'DNS events show domain resolution requests',
          'Connection events track network flows',
          'Authentication events monitor login attempts',
        ],
      },
      {
        title: 'Source Filtering',
        description:
          'Filter events by the log source they originated from.',
        tips: [
          'Each source has a unique identifier',
          'Sources can be enabled/disabled from the Sources page',
          'Event counts per source help identify high-volume sources',
        ],
      },
    ],
  },

  '/dashboard/alerts': {
    title: 'Alerts',
    overview:
      'Manage security alerts generated by detection rules and anomaly detection. Investigate, acknowledge, and resolve alerts.',
    sections: [
      {
        title: 'Alert Management',
        description:
          'View all alerts with severity levels, timestamps, and current status.',
        tips: [
          'Critical and high severity alerts appear at the top',
          'Acknowledge alerts to indicate you are investigating',
          'Resolve alerts once the issue is addressed',
        ],
      },
      {
        title: 'Alert Details',
        description:
          'Each alert includes the triggering event, detection rule, and affected device.',
        tips: [
          'Click an alert to see the full context',
          'Related events are linked for investigation',
          'AI analysis provides threat assessment when available',
        ],
      },
      {
        title: 'Alert Actions',
        description:
          'Take action on alerts including quarantine, creating rules, or dismissing false positives.',
        tips: [
          'Quarantine immediately isolates the device',
          'Dismissed alerts update the AI model to reduce false positives',
          'Create rules from alerts to automate future responses',
        ],
      },
    ],
    shortcuts: [
      { key: 'a', action: 'Acknowledge selected alert' },
      { key: 'r', action: 'Resolve selected alert' },
      { key: 'q', action: 'Quarantine associated device' },
    ],
  },

  '/dashboard/anomalies': {
    title: 'Anomalies',
    overview:
      'View behavioral anomalies detected by the AI engine. Anomalies represent deviations from established baseline patterns.',
    sections: [
      {
        title: 'Anomaly Detection',
        description:
          'AI-powered analysis identifies unusual patterns in device behavior and network traffic.',
        tips: [
          'Anomaly scores indicate deviation severity',
          'Baseline is established over the first 7 days',
          'New devices have limited anomaly detection until baseline is built',
        ],
      },
      {
        title: 'Anomaly Types',
        description:
          'Different anomaly categories including traffic volume, timing, destination, and protocol anomalies.',
        tips: [
          'Volume anomalies indicate unusual data transfer amounts',
          'Timing anomalies flag activity at unusual hours',
          'Destination anomalies show connections to new hosts',
        ],
      },
      {
        title: 'Investigation',
        description:
          'Tools to investigate and understand anomaly context.',
        tips: [
          'View the specific events that triggered the anomaly',
          'Compare current behavior to historical baseline',
          'Mark anomalies as expected to train the model',
        ],
      },
    ],
  },

  '/dashboard/rules': {
    title: 'Detection Rules',
    overview:
      'Create and manage custom detection rules. Rules define conditions that trigger alerts when matched.',
    sections: [
      {
        title: 'Rule Management',
        description:
          'View, enable, disable, and edit detection rules.',
        tips: [
          'Disabled rules stop generating alerts but are preserved',
          'Rule priority determines which rule fires first on match',
          'Test rules against historical data before enabling',
        ],
      },
      {
        title: 'Rule Conditions',
        description:
          'Rules match events based on field conditions, thresholds, and patterns.',
        tips: [
          'Use regex patterns for flexible matching',
          'Threshold rules count events over time windows',
          'Combine multiple conditions with AND/OR logic',
        ],
      },
      {
        title: 'Rule Actions',
        description:
          'Configure what happens when a rule matches: create alert, execute playbook, or notify.',
        tips: [
          'Severity determines alert priority',
          'Playbooks can automate response actions',
          'Notifications can be sent via email, webhook, or ntfy',
        ],
      },
    ],
  },

  '/dashboard/threat-intel': {
    title: 'Threat Intelligence',
    overview:
      'Manage threat intelligence feeds and indicators of compromise (IOCs). Correlate network activity with known threats.',
    sections: [
      {
        title: 'Threat Feeds',
        description:
          'Subscribe to and manage external threat intelligence feeds.',
        tips: [
          'Feeds update automatically on configured intervals',
          'Enable/disable feeds based on relevance',
          'Custom feeds can be added via URL',
        ],
      },
      {
        title: 'IOC Matching',
        description:
          'Automatic correlation of network events with threat indicators.',
        tips: [
          'Matches generate alerts with threat context',
          'IOC types include domains, IPs, hashes, and URLs',
          'Confidence scores indicate match reliability',
        ],
      },
      {
        title: 'Manual IOCs',
        description:
          'Add custom indicators from your own intelligence sources.',
        tips: [
          'Import IOCs from CSV or STIX format',
          'Set expiration dates for time-limited threats',
          'Tag IOCs for organization and filtering',
        ],
      },
    ],
  },

  '/dashboard/quarantine': {
    title: 'Quarantine',
    overview:
      'Manage quarantined devices that have been isolated from the network due to security concerns.',
    sections: [
      {
        title: 'Quarantined Devices',
        description:
          'List of devices currently blocked from network access.',
        tips: [
          'Quarantine blocks device at the router/firewall level',
          'AdGuard integration blocks DNS resolution',
          'Devices can be released when threat is resolved',
        ],
      },
      {
        title: 'Quarantine Actions',
        description:
          'Manage quarantine status and investigate blocked devices.',
        tips: [
          'Release removes network blocks immediately',
          'View the alert that triggered quarantine',
          'Extend quarantine duration if needed',
        ],
      },
      {
        title: 'Integration Status',
        description:
          'View which integrations are active for quarantine enforcement.',
        tips: [
          'Green checkmarks show active integrations',
          'Multiple integrations provide defense in depth',
          'Test integrations before relying on them',
        ],
      },
    ],
  },

  '/dashboard/chat': {
    title: 'AI Chat',
    overview:
      'Interact with the AI assistant to investigate threats, query your data, and get security recommendations.',
    sections: [
      {
        title: 'Natural Language Queries',
        description:
          'Ask questions about your network in plain English.',
        tips: [
          'Ask "What devices connected in the last hour?"',
          'Ask "Show me all DNS queries to .ru domains"',
          'Ask "Explain the recent critical alert"',
        ],
      },
      {
        title: 'Threat Investigation',
        description:
          'Get AI assistance investigating security incidents.',
        tips: [
          'Provide alert IDs for focused analysis',
          'Ask for remediation recommendations',
          'Request threat intel correlation',
        ],
      },
      {
        title: 'Chat History',
        description:
          'Previous conversations are saved for reference.',
        tips: [
          'Start a new chat for unrelated topics',
          'Reference previous messages for context',
          'Export chat history for documentation',
        ],
      },
    ],
    shortcuts: [
      { key: 'Enter', action: 'Send message' },
      { key: 'Shift+Enter', action: 'New line' },
      { key: 'Ctrl+/', action: 'Focus chat input' },
    ],
  },

  '/dashboard/sources': {
    title: 'Log Sources',
    overview:
      'Configure and manage log collection sources. Sources feed data into NetGuardian for analysis.',
    sections: [
      {
        title: 'Source Types',
        description:
          'Different methods for collecting logs: API pull, file watch, and API push.',
        tips: [
          'API Pull polls external systems on an interval',
          'File Watch monitors mounted log files',
          'API Push receives logs from external senders',
        ],
      },
      {
        title: 'Parser Configuration',
        description:
          'Each source uses a parser to normalize log formats.',
        tips: [
          'Built-in parsers support common formats',
          'Custom parsers use regex patterns',
          'Test parsers with sample data before deployment',
        ],
      },
      {
        title: 'Source Health',
        description:
          'Monitor collection status and error rates.',
        tips: [
          'Green status indicates healthy collection',
          'Red status shows collection failures',
          'Click a source to see detailed error logs',
        ],
      },
    ],
  },

  '/dashboard/users': {
    title: 'User Management',
    overview:
      'Manage user accounts and access permissions. Admin-only feature for controlling system access.',
    sections: [
      {
        title: 'User Accounts',
        description:
          'Create, edit, and disable user accounts.',
        tips: [
          'Disabled accounts cannot log in but are preserved',
          'Reset passwords for users who forget credentials',
          'View last login time to identify inactive accounts',
        ],
      },
      {
        title: 'Roles & Permissions',
        description:
          'Assign roles to control what users can access.',
        tips: [
          'Admin role has full access to all features',
          'Operator role can view and acknowledge alerts',
          'Viewer role has read-only access',
        ],
      },
      {
        title: 'Two-Factor Authentication',
        description:
          'Manage 2FA settings for enhanced security.',
        tips: [
          'Admins can require 2FA for all users',
          'Reset 2FA if user loses their device',
          'Backup codes should be stored securely',
        ],
      },
    ],
  },

  '/dashboard/settings': {
    title: 'Settings',
    overview:
      'Configure system settings, integrations, and personal preferences.',
    sections: [
      {
        title: 'General Settings',
        description:
          'System-wide configuration options.',
        tips: [
          'Set data retention period for events',
          'Configure timezone for consistent timestamps',
          'Enable/disable specific features',
        ],
      },
      {
        title: 'Integrations',
        description:
          'Connect NetGuardian to external services.',
        tips: [
          'AdGuard integration enables DNS-level blocking',
          'Router integration enables network quarantine',
          'Notification services send alerts externally',
        ],
      },
      {
        title: 'Personal Preferences',
        description:
          'Customize your own experience.',
        tips: [
          'Theme preference: light, dark, or system',
          'Notification preferences for alert types',
          'Dashboard layout customization',
        ],
      },
    ],
  },

  '/dashboard/topology': {
    title: 'Network Topology',
    overview:
      'Visualize your network structure and device relationships. Interactive graph showing connections between devices.',
    sections: [
      {
        title: 'Topology View',
        description:
          'Interactive network graph showing devices and connections.',
        tips: [
          'Drag nodes to rearrange the layout',
          'Scroll to zoom in/out',
          'Click a device to see details',
        ],
      },
      {
        title: 'Connection Analysis',
        description:
          'View traffic flows between devices.',
        tips: [
          'Line thickness indicates traffic volume',
          'Hover over connections to see details',
          'Red lines indicate suspicious connections',
        ],
      },
      {
        title: 'Filtering',
        description:
          'Filter the topology view to focus on specific devices or connections.',
        tips: [
          'Filter by device type or status',
          'Show only devices with anomalies',
          'Highlight specific traffic patterns',
        ],
      },
    ],
    shortcuts: [
      { key: 'r', action: 'Reset view' },
      { key: '+/-', action: 'Zoom in/out' },
      { key: 'f', action: 'Fit to screen' },
    ],
  },

  '/dashboard/patterns': {
    title: 'Log Patterns',
    overview:
      'View and manage learned log patterns. Patterns are normalized templates extracted from your log messages to identify irregular activity.',
    sections: [
      {
        title: 'Pattern Learning',
        description:
          'NetGuardian automatically learns patterns from your logs by normalizing variables like IPs, timestamps, and UUIDs into placeholders.',
        tips: [
          'Patterns with <IP>, <TIMESTAMP>, <UUID> show where variables were extracted',
          'Occurrence count shows how often a pattern appears',
          'Rare patterns (below threshold) may indicate unusual activity',
        ],
      },
      {
        title: 'Pattern Management',
        description:
          'Control which patterns are monitored for irregularities.',
        tips: [
          'Toggle "Ignore" to exclude known benign rare patterns',
          'Ignored patterns won\'t trigger semantic analysis',
          'Filter by source to focus on specific log sources',
        ],
      },
      {
        title: 'Rarity Detection',
        description:
          'Patterns seen fewer times than the rarity threshold are flagged as irregular.',
        tips: [
          'Default threshold is 3 occurrences',
          'Adjust threshold per-source in Settings',
          'New patterns are automatically flagged until they become common',
        ],
      },
    ],
  },

  '/dashboard/semantic-review': {
    title: 'Semantic Review',
    overview:
      'Review logs flagged as irregular by the semantic analysis system. AI-powered analysis helps identify potential security concerns in unusual log messages.',
    sections: [
      {
        title: 'Irregular Logs',
        description:
          'Logs that match rare or new patterns are queued for review with AI-generated analysis.',
        tips: [
          'Severity score (0.0-1.0) indicates AI-assessed risk level',
          'Click a row to expand and see the full LLM analysis',
          'High severity items (≥0.7) require priority attention',
        ],
      },
      {
        title: 'LLM Analysis',
        description:
          'Each irregular log is analyzed by an AI (Claude or Ollama) to assess security relevance.',
        tips: [
          'Analysis includes threat assessment and recommendations',
          'Context from similar patterns helps identify false positives',
          'Analysis runs in batches based on configured interval',
        ],
      },
      {
        title: 'Review Actions',
        description:
          'Mark logs as reviewed after investigation.',
        tips: [
          'Mark Reviewed acknowledges you\'ve investigated the log',
          'If a pattern is consistently benign, ignore it on the Patterns page',
          'Filter by "Pending" to see items needing review',
        ],
      },
    ],
  },

  '/dashboard/suggested-rules': {
    title: 'Suggested Rules',
    overview:
      'Review and approve detection rules suggested by AI analysis. The LLM can identify patterns worth monitoring and propose rules to catch similar issues.',
    sections: [
      {
        title: 'Pending Rules',
        description:
          'Rules awaiting your review, suggested based on irregular log analysis.',
        tips: [
          'Each rule shows the reason it was suggested',
          'Review the linked irregular log for context',
          'Rule types include pattern match, threshold, and sequence',
        ],
      },
      {
        title: 'Rule Approval',
        description:
          'Approve rules to add them to your detection rule set.',
        tips: [
          'Approved rules can be enabled immediately or kept disabled',
          'Edit rule configuration before approving if needed',
          'Approved rules appear in the Detection Rules page',
        ],
      },
      {
        title: 'Rule Rejection',
        description:
          'Reject rules that aren\'t applicable to your environment.',
        tips: [
          'Provide a reason when rejecting for future reference',
          'Rejected rule patterns won\'t be suggested again',
          'View rejection history in the History tab',
        ],
      },
    ],
  },
};

// Get help content for a given path
export function getHelpForPath(pathname: string): HelpContent | null {
  // Exact match first
  if (helpContent[pathname]) {
    return helpContent[pathname];
  }

  // Check for device detail page (dynamic route)
  if (pathname.startsWith('/dashboard/devices/') && pathname !== '/dashboard/devices') {
    return helpContent['/dashboard/devices/'];
  }

  // Default to dashboard help if no match
  return helpContent['/dashboard'] || null;
}
