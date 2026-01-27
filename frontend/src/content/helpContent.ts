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
      'The Dashboard provides a real-time overview of your network security status, including key metrics, recent alerts, and top queried domains.',
    sections: [
      {
        title: 'Key Metrics',
        description:
          'Monitor critical security indicators at a glance including active devices, events (24h), active alerts, and log source counts.',
        tips: [
          'Active devices shows devices seen recently vs total discovered',
          'Events card shows DNS query counts alongside total events',
          'Critical alert count is highlighted when alerts need attention',
        ],
      },
      {
        title: 'DNS Block Rate',
        description:
          'Visual indicator showing the percentage of DNS queries that were blocked in the last 24 hours.',
        tips: [
          'Shows blocked queries out of total DNS queries',
          'Higher block rates may indicate active threat blocking',
          'Review blocked domains on the Events page for details',
        ],
      },
      {
        title: 'Top Queried Domains',
        description:
          'Ranked list of the most frequently queried domains across your network in the last 24 hours.',
        tips: [
          'Useful for identifying high-traffic services',
          'Unexpected domains may warrant investigation',
          'Bar charts show relative query volumes',
        ],
      },
      {
        title: 'Recent Alerts',
        description:
          'View the most recent security alerts detected across your network with severity levels and timestamps.',
        tips: [
          'Critical and high severity alerts appear with colored badges',
          'Click on the Alerts page link to see the complete alert history',
          'Alerts can be acknowledged or resolved from the Alerts page',
        ],
      },
    ],
  },

  '/dashboard/devices': {
    title: 'Devices',
    overview:
      'View and manage all devices detected on your network. Monitor device status, apply tags, export device lists, and manage quarantine status.',
    sections: [
      {
        title: 'Device Inventory',
        description:
          'Complete list of all devices discovered on your network with status, IP, MAC, manufacturer, and last seen time.',
        tips: [
          'Use the search bar to find devices by name, IP, or MAC address',
          'Filter by device status (Active, Inactive, Quarantined) using the dropdown',
          'Filter by tags to find devices with specific labels',
          'Click a device row to view detailed information',
        ],
      },
      {
        title: 'Tagging and Bulk Actions',
        description:
          'Organize devices with tags and apply bulk actions to multiple devices at once.',
        tips: [
          'Select multiple devices using checkboxes to manage tags in bulk',
          'Use the Tag Filter dropdown to view only devices with specific tags',
          'Tags help categorize devices (e.g., "trusted", "family", "work")',
        ],
      },
      {
        title: 'Export',
        description:
          'Export your device list for reporting or external analysis.',
        tips: [
          'Click the Export button to download devices as CSV or PDF',
          'Exports respect your current filters',
          'Use CSV for data analysis, PDF for reports',
        ],
      },
      {
        title: 'Device Actions',
        description:
          'Quarantine suspicious devices or release them when cleared.',
        tips: [
          'Click Quarantine to block a device at the network level',
          'Click Release to restore network access for quarantined devices',
          'Requires Operator or Admin role to manage quarantine',
        ],
      },
    ],
  },

  '/dashboard/devices/': {
    title: 'Device Details',
    overview:
      'View detailed information about a specific device including metadata, events, alerts, baselines, and anomalies across multiple tabs.',
    sections: [
      {
        title: 'Device Information',
        description:
          'View and edit device metadata including hostname, MAC address, IP addresses, manufacturer, device type, and tags.',
        tips: [
          'Click Edit to modify the device name, type, or tags',
          'Tags can be comma-separated (e.g., "trusted, family, work")',
          'First seen and last seen times show device network history',
        ],
      },
      {
        title: 'Events Tab',
        description:
          'Browse paginated network events (DNS, firewall, etc.) for this device with timestamps and actions.',
        tips: [
          'Events show domain/target, event type, and action (allowed/blocked)',
          'Use pagination to navigate through event history',
          'Useful for investigating specific device activity',
        ],
      },
      {
        title: 'Baselines Tab',
        description:
          'View learned behavioral baselines for DNS activity, traffic patterns, and connections.',
        tips: [
          'Baselines have status: Learning (building), Ready (usable), or Stale',
          'Admins can click Recalculate to update baselines',
          'Sample count shows how much data informed the baseline',
        ],
      },
      {
        title: 'Anomalies Tab',
        description:
          'View anomalies detected for this device that deviate from its established baseline.',
        tips: [
          'Anomaly types include New Domain, Volume Spike, Time Anomaly, etc.',
          'Severity and score indicate how unusual the behavior is',
          'Click "View all anomalies" to see the full list',
        ],
      },
    ],
  },

  '/dashboard/events': {
    title: 'Events',
    overview:
      'Browse and search all raw network events collected from your log sources. Filter by source, type, and severity, and export data for analysis.',
    sections: [
      {
        title: 'Event Browser',
        description:
          'Paginated table of all collected events showing time, source, type, severity, client IP, domain, and action.',
        tips: [
          'Search by domain using the search box',
          'Click any event row to expand and see full details',
          'Expanded view shows raw message and parsed fields',
        ],
      },
      {
        title: 'Filtering',
        description:
          'Filter events by source, event type, and severity level.',
        tips: [
          'Use the Source dropdown to see events from specific log sources',
          'Event types include DNS, Firewall, Auth, HTTP, System, Flow, Endpoint, LLM',
          'Severity levels: Critical, Error, Warning, Info, Debug',
        ],
      },
      {
        title: 'Export',
        description:
          'Export filtered events to CSV or PDF for reporting and analysis.',
        tips: [
          'Click the Export button and choose CSV or PDF format',
          'Exports respect your current filter settings',
          'Use CSV for data analysis, PDF for documentation',
        ],
      },
    ],
  },

  '/dashboard/alerts': {
    title: 'Alerts',
    overview:
      'Manage security alerts generated by detection rules and anomaly detection. Acknowledge, resolve, or mark alerts as false positives.',
    sections: [
      {
        title: 'Alert Management',
        description:
          'View all alerts as cards with severity levels, timestamps, descriptions, and current status.',
        tips: [
          'Filter alerts by status (New, Acknowledged, Resolved, False Positive)',
          'Filter by severity (Critical, High, Medium, Low)',
          'Search alerts by title or description',
        ],
      },
      {
        title: 'Alert Actions',
        description:
          'Take action on alerts to update their status.',
        tips: [
          'Click Acknowledge to indicate you are investigating',
          'Click Resolve once the issue is addressed',
          'Click False Positive to dismiss and improve detection accuracy',
        ],
      },
      {
        title: 'AI Analysis',
        description:
          'When available, alerts include AI-generated analysis for context.',
        tips: [
          'AI Analysis appears in a highlighted box on the alert card',
          'Analysis provides threat assessment and context',
          'Not all alerts have AI analysis - depends on configuration',
        ],
      },
      {
        title: 'Export',
        description:
          'Export alerts to CSV or PDF for reporting.',
        tips: [
          'Click the Export button to download filtered alerts',
          'Exports respect your current filter settings',
        ],
      },
    ],
  },

  '/dashboard/anomalies': {
    title: 'Anomalies',
    overview:
      'View behavioral anomalies detected by comparing device activity to established baselines. Review, confirm, or dismiss anomalies.',
    sections: [
      {
        title: 'Stats Overview',
        description:
          'Quick stats cards show active anomalies, high/critical count, reviewed count, and total anomalies.',
        tips: [
          'Active anomalies require attention',
          'High/Critical count shows urgent items',
          'Reviewed count tracks your investigation progress',
        ],
      },
      {
        title: 'Filtering',
        description:
          'Filter anomalies by status, type, and severity.',
        tips: [
          'Status options: Active, Reviewed, Confirmed, False Positive',
          'Types: New Domain, Volume Spike, Time Anomaly, New Connection, New Port, Blocked Spike, Pattern Change',
          'Severity levels: Critical, High, Medium, Low, Info',
        ],
      },
      {
        title: 'Anomaly Actions',
        description:
          'Review anomalies and update their status based on investigation.',
        tips: [
          'Click the eye icon to view full anomaly details',
          'Click checkmark to mark as Reviewed',
          'Click X to mark as False Positive',
          'Use Confirm Threat for confirmed security issues',
        ],
      },
      {
        title: 'Run Detection',
        description:
          'Admins can manually trigger anomaly detection for all devices.',
        tips: [
          'Click "Run Detection" to analyze all devices with ready baselines',
          'Detection compares current behavior to learned patterns',
          'New anomalies will appear after detection completes',
        ],
      },
    ],
  },

  '/dashboard/rules': {
    title: 'Detection Rules',
    overview:
      'Create and manage custom detection rules that trigger alerts when conditions are matched. Test rules before enabling.',
    sections: [
      {
        title: 'Rule Management',
        description:
          'View, create, edit, enable/disable, and delete detection rules.',
        tips: [
          'Click Create Rule to define a new detection rule',
          'Toggle the power icon to enable or disable a rule',
          'Click the chevron to expand and see rule details',
          'Filter by enabled status or severity',
        ],
      },
      {
        title: 'Rule Conditions',
        description:
          'Rules match events based on field conditions combined with AND/OR logic.',
        tips: [
          'Each condition specifies a field, operator, and value',
          'View conditions in expanded rule details',
          'Cooldown minutes prevent repeated alerts for the same event',
        ],
      },
      {
        title: 'Test Rules',
        description:
          'Test rules against historical data before enabling in production.',
        tips: [
          'Click the play icon to open the Test Rule modal',
          'Testing shows what events would have matched',
          'Useful for validating rule logic before enabling',
        ],
      },
      {
        title: 'Rule Actions',
        description:
          'Configure response actions that execute when a rule triggers.',
        tips: [
          'Actions can include creating alerts, sending notifications, or quarantining devices',
          'Multiple actions can be configured per rule',
          'View configured actions in expanded rule details',
        ],
      },
    ],
  },

  '/dashboard/threat-intel': {
    title: 'Threat Intelligence',
    overview:
      'Manage threat intelligence feeds, look up indicators, and maintain local indicator lists for detection.',
    sections: [
      {
        title: 'Feeds Tab',
        description:
          'Manage external threat intelligence feed subscriptions.',
        tips: [
          'Click Add Feed to subscribe to a new threat intelligence source',
          'Toggle feeds to enable/disable indicator matching',
          'Sync button manually refreshes feed data',
          'Delete feeds you no longer need',
        ],
      },
      {
        title: 'Lookup Tab',
        description:
          'Query threat intelligence sources to check if an indicator is known malicious.',
        tips: [
          'Enter a domain, IP address, or hash to lookup',
          'Select indicator type (domain, ip, hash)',
          'Results show matches from enabled feeds',
          'Useful for ad-hoc investigation of suspicious indicators',
        ],
      },
      {
        title: 'Local Indicators Tab',
        description:
          'Create and manage your own indicator lists for organization-specific threats.',
        tips: [
          'Add indicators manually based on incident investigations',
          'Local indicators have highest priority in matching',
          'Edit or delete indicators as threats evolve',
        ],
      },
    ],
  },

  '/dashboard/quarantine': {
    title: 'Quarantine Management',
    overview:
      'Manage quarantined devices, view integration status, and monitor quarantine activity.',
    sections: [
      {
        title: 'Stats Overview',
        description:
          'Quick stats showing quarantined device count and recent activity.',
        tips: [
          'Quarantined Devices shows current blocked count',
          'Quarantines (24h) shows recent isolation actions',
          'Releases (24h) shows devices restored to network',
          'Total Actions (24h) combines both metrics',
        ],
      },
      {
        title: 'Integration Status',
        description:
          'View the status of AdGuard Home and router integrations.',
        tips: [
          'Green "Active" indicates integration is working',
          'Yellow "Disabled" means configured but not enabled',
          'Gray "Not configured" requires setup in environment variables',
        ],
      },
      {
        title: 'Quarantined Devices Table',
        description:
          'List of all quarantined devices with blocking status.',
        tips: [
          'Click device name to view device details page',
          'AdGuard column shows if DNS blocking is active',
          'Router column shows if network blocking is active',
          'Click Release to restore network access (Operator/Admin only)',
        ],
      },
      {
        title: 'Recent Activity',
        description:
          'Log of recent quarantine and release actions.',
        tips: [
          'Shows timestamp, action type, device, and user',
          'Red badge indicates quarantine action',
          'Green badge indicates release action',
          'Click "View all audit logs" for complete history',
        ],
      },
      {
        title: 'Sync Status',
        description:
          'Admins can manually sync quarantine state with integrations.',
        tips: [
          'Click Sync Status to check all integrations',
          'Results show devices checked, synced, and any errors',
          'Useful when integrations may be out of sync',
        ],
      },
    ],
  },

  '/dashboard/chat': {
    title: 'AI Assistant',
    overview:
      'Chat with Claude AI about your network security. Ask questions in plain English and get intelligent analysis.',
    sections: [
      {
        title: 'Model Selection',
        description:
          'Choose the AI model based on your needs.',
        tips: [
          'Fast: Quick responses for simple queries (Haiku)',
          'Balanced: Best quality for most questions (Sonnet)',
          'Deep: Detailed analysis for complex investigations (Opus)',
          'Model names are shown next to each option',
        ],
      },
      {
        title: 'Suggested Queries',
        description:
          'Click suggested queries to quickly ask common questions.',
        tips: [
          'Suggested queries appear when chat is empty',
          'Click any suggestion to use it as your query',
          'Questions cover devices, security, domains, and activity',
        ],
      },
      {
        title: 'Asking Questions',
        description:
          'Type natural language questions about your network.',
        tips: [
          'Ask "What devices are most active right now?"',
          'Ask "Are there any security concerns I should know about?"',
          'Ask "Which devices have anomalies?"',
          'The AI has access to your current network state',
        ],
      },
      {
        title: 'LLM Configuration',
        description:
          'The AI requires Anthropic API key configuration.',
        tips: [
          'Set ANTHROPIC_API_KEY environment variable to enable',
          'Without API key, a configuration message is shown',
          'Contact your admin if the feature is not available',
        ],
      },
    ],
    shortcuts: [
      { key: 'Enter', action: 'Send message' },
    ],
  },

  '/dashboard/sources': {
    title: 'Log Sources',
    overview:
      'Configure and manage log collection sources. Only admins can add, modify, or delete sources.',
    sections: [
      {
        title: 'Source Cards',
        description:
          'Each source displays its configuration, event count, and last activity.',
        tips: [
          'Active/Disabled badge shows current status',
          'Type shows API Pull, File Watch, or API Push',
          'Parser shows which format parser is used',
          'Events shows total count; Last Event shows recency',
        ],
      },
      {
        title: 'Source Types',
        description:
          'Different methods for collecting logs.',
        tips: [
          'API Pull: NetGuardian polls an external API on an interval',
          'File Watch: Monitors a log file for new entries',
          'API Push: External systems send logs to NetGuardian',
        ],
      },
      {
        title: 'API Push Sources',
        description:
          'API Push sources generate an API key for authentication.',
        tips: [
          'API key is displayed in the source card',
          'Click the copy icon to copy the key to clipboard',
          'Use this key when configuring external log senders',
        ],
      },
      {
        title: 'Source Management',
        description:
          'Add, enable/disable, or delete sources (Admin only).',
        tips: [
          'Click Add Source to create a new log source',
          'Click Enable/Disable to toggle collection',
          'Click Delete to remove a source (cannot be undone)',
          'Error messages appear if source has collection issues',
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
          'SSO users show "External" badge and their identity provider',
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
          'SSO users get roles from Authentik group membership',
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
      {
        title: 'Authentik SSO Integration',
        description:
          'Enable Single Sign-On via Authentik identity provider for centralized authentication.',
        tips: [
          'Set AUTHENTIK_ENABLED=true in backend .env file',
          'Configure AUTHENTIK_ISSUER_URL with your Authentik server',
          'Set AUTHENTIK_CLIENT_ID and AUTHENTIK_CLIENT_SECRET from Authentik',
          'Map Authentik groups to roles via AUTHENTIK_GROUP_MAPPINGS',
          'Auto-create mode: Set AUTHENTIK_AUTO_CREATE_USERS=true to create users on first SSO login',
          'Pre-create mode: Set AUTHENTIK_AUTO_CREATE_USERS=false, then create users here first',
          'Pre-created users link to Authentik by email match on first SSO login',
          'See docs/deployment-guide.md for full setup instructions',
        ],
      },
    ],
  },

  '/dashboard/settings': {
    title: 'Settings',
    overview:
      'Configure your account settings across four tabs: General, Notifications, Security, and Data Retention (admin only).',
    sections: [
      {
        title: 'General Tab',
        description:
          'View account information and real-time connection status.',
        tips: [
          'Shows your username and role',
          'Connection status indicates if real-time updates are active',
          'Green dot means connected, gray means disconnected',
        ],
      },
      {
        title: 'Notifications Tab',
        description:
          'Configure email and ntfy.sh push notification preferences.',
        tips: [
          'Email requires SMTP configuration in environment variables',
          'Toggle severity levels to control which alerts notify you',
          'Toggle event types (Anomalies, Quarantine Actions)',
          'Use Send Test buttons to verify configuration',
        ],
      },
      {
        title: 'Security Tab',
        description:
          'Manage Two-Factor Authentication (2FA) for your account.',
        tips: [
          'Click Set Up 2FA to enable authenticator app protection',
          'Scan the QR code with Google Authenticator or Authy',
          'Save backup codes in a secure location',
          'View/regenerate backup codes after enabling',
        ],
      },
      {
        title: 'Data Retention Tab (Admin)',
        description:
          'Configure how long data is kept before automatic cleanup.',
        tips: [
          'Only visible to administrators',
          'Storage Overview shows table sizes and row counts',
          'Edit retention days for each data type (0 = keep forever)',
          'Preview Cleanup to see what would be deleted',
          'Run Cleanup to permanently delete old data',
        ],
      },
    ],
  },

  '/dashboard/topology': {
    title: 'Network Topology',
    overview:
      'Visual map of your network devices and connections. Interactive canvas with force-directed layout.',
    sections: [
      {
        title: 'Stats Overview',
        description:
          'Summary cards showing device and event counts.',
        tips: [
          'Total Devices shows all discovered devices',
          'Active shows recently seen devices',
          'Quarantined shows isolated devices',
          'Events shows total for selected time range',
        ],
      },
      {
        title: 'Network Map',
        description:
          'Interactive canvas visualization of your network topology.',
        tips: [
          'Internet node at top, router in center, devices around it',
          'Node colors indicate device type (see legend)',
          'Red nodes are quarantined devices',
          'Line thickness indicates traffic volume',
          'Red dashed lines indicate blocked connections',
        ],
      },
      {
        title: 'Controls',
        description:
          'Time range, zoom, and pan controls.',
        tips: [
          'Select time range (1h, 6h, 24h, 3d, 7d) for event data',
          'Toggle "Inactive" to include offline devices',
          'Use zoom +/- buttons or mouse wheel to zoom',
          'Click and drag empty space to pan the view',
          'Click Reset button to restore default view',
        ],
      },
      {
        title: 'Node Interaction',
        description:
          'Click and drag nodes to view details.',
        tips: [
          'Click a node to select it and view details panel',
          'Drag a node to reposition it (releases when dropped)',
          'Details panel shows IP, MAC, manufacturer, status, tags',
          'Click "View Device Details" to go to device page',
        ],
      },
    ],
  },

  '/dashboard/patterns': {
    title: 'Log Patterns',
    overview:
      'View and manage learned log patterns from semantic analysis. Control which patterns trigger irregular log detection.',
    sections: [
      {
        title: 'Stats Overview',
        description:
          'Summary cards show total patterns, irregular logs detected, and last analysis time.',
        tips: [
          'Total Patterns shows all learned log templates',
          'Irregular Detected shows logs flagged for review',
          'Last Analysis shows when semantic analysis last ran',
        ],
      },
      {
        title: 'Filtering and Search',
        description:
          'Filter patterns by source, ignored status, and rarity.',
        tips: [
          'Filter by source to focus on specific log sources',
          'Active Only shows patterns that trigger analysis',
          'Ignored Only shows patterns you have excluded',
          'Check "Rare patterns only" to see uncommon patterns',
          'Search by pattern text to find specific templates',
        ],
      },
      {
        title: 'Pattern Table',
        description:
          'View pattern details including occurrences and timestamps.',
        tips: [
          'Click a row to expand and see full pattern details',
          'Yellow badge with warning icon indicates rare patterns (<3 occurrences)',
          'Green badge indicates common, normal patterns',
          'Copy button lets you copy the normalized pattern',
        ],
      },
      {
        title: 'Ignore/Unignore',
        description:
          'Control whether a pattern triggers irregular log detection.',
        tips: [
          'Click Ignore to exclude a pattern from semantic analysis',
          'Ignored patterns show "Ignored" status and appear dimmed',
          'Click Unignore to re-enable analysis for a pattern',
          'Use ignore for known-benign rare patterns (e.g., startup messages)',
        ],
      },
    ],
  },

  '/dashboard/semantic-review': {
    title: 'Semantic Review',
    overview:
      'Review irregular log patterns detected by semantic analysis. AI provides severity scores and analysis to help prioritize investigation.',
    sections: [
      {
        title: 'Stats Overview',
        description:
          'Summary cards show total patterns, irregular logs, pending review count, and high severity count.',
        tips: [
          'Pending Review shows items needing your attention',
          'High Severity highlights critical issues (score 0.8+)',
          'Use these stats to prioritize your review workflow',
        ],
      },
      {
        title: 'Filtering',
        description:
          'Filter irregular logs by source, review status, and severity.',
        tips: [
          'Source dropdown filters by log source',
          'Status: Unreviewed (default), Reviewed, or All',
          'Severity: Critical (0.8+), High (0.6+), Medium (0.4+), or All',
        ],
      },
      {
        title: 'Irregular Log Table',
        description:
          'Table showing timestamp, source, severity, reason, LLM analysis, and status.',
        tips: [
          'Click a row to expand and see full details',
          'Severity shows percentage score with label (Critical/High/Medium/Low)',
          '"Pending analysis" means LLM has not yet processed this log',
        ],
      },
      {
        title: 'Review Actions',
        description:
          'Mark logs as reviewed and research issues.',
        tips: [
          'Click "Mark Reviewed" to acknowledge you investigated the log',
          'Click "Research this issue" to open a Google search with AI-generated query',
          'Reviewed logs show green checkmark with review timestamp',
        ],
      },
    ],
  },

  '/dashboard/suggested-rules': {
    title: 'Suggested Rules',
    overview:
      'Review and approve AI-suggested detection rules. The system proposes rules based on patterns detected in your logs.',
    sections: [
      {
        title: 'Pending vs All Rules Tabs',
        description:
          'Switch between pending rules needing review and complete history.',
        tips: [
          'Pending Review shows rules awaiting your decision',
          'Badge shows count of pending rules',
          'All Rules tab shows complete history with filters',
        ],
      },
      {
        title: 'Rule Cards',
        description:
          'Each rule shows name, status, type, description, and reasoning.',
        tips: [
          'Status badges: Pending (yellow), Approved (blue), Implemented (green), Rejected (red)',
          'Rule types: Pattern Match, Threshold, Sequence',
          '"Why suggested" explains the AI reasoning',
          '"Security benefit" describes what the rule protects against',
        ],
      },
      {
        title: 'Approval Workflow',
        description:
          'Review and approve rules to add them to detection.',
        tips: [
          'Click Review to expand the approval panel',
          'Check "Enable rule immediately" to activate on approval',
          'Click Approve to add the rule to Detection Rules',
          'Approved rules appear on the Rules page',
        ],
      },
      {
        title: 'Rejection Workflow',
        description:
          'Reject rules that are not applicable.',
        tips: [
          'Enter a rejection reason in the text area',
          'Click Reject to decline the suggested rule',
          'Rejection reason is saved for reference',
          'Rejected rules can be viewed in All Rules tab',
        ],
      },
      {
        title: 'Filtering (All Rules Tab)',
        description:
          'Filter the complete rule history.',
        tips: [
          'Filter by source to see rules from specific log sources',
          'Filter by status to see Pending, Approved, Implemented, or Rejected',
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
