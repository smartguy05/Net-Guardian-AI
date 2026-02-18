import { useParams, Link } from 'react-router-dom';
import {
  ArrowLeft,
  Target,
  Play,
  Square,
  Clock,
  AlertTriangle,
  Activity,
  Terminal,
  Globe,
  Database,
  Server,
  User,
  Brain,
} from 'lucide-react';
import { useHoneypot, useHoneypotInteractions, useStopHoneypot, useHoneypotTemplates, useTriggerHoneypotAnalysis } from '../api/hooks';
import type { HoneypotStatus, HoneypotType } from '../types';

const statusConfig: Record<HoneypotStatus, { icon: React.ReactNode; color: string; label: string }> = {
  pending: { icon: <Clock className="h-5 w-5" />, color: 'text-gray-500 bg-gray-100 dark:bg-gray-700', label: 'Pending' },
  starting: { icon: <Clock className="h-5 w-5" />, color: 'text-blue-500 bg-blue-100 dark:bg-blue-900', label: 'Starting' },
  running: { icon: <Play className="h-5 w-5" />, color: 'text-green-500 bg-green-100 dark:bg-green-900', label: 'Running' },
  stopping: { icon: <Clock className="h-5 w-5" />, color: 'text-yellow-500 bg-yellow-100 dark:bg-yellow-900', label: 'Stopping' },
  stopped: { icon: <Square className="h-5 w-5" />, color: 'text-gray-500 bg-gray-100 dark:bg-gray-700', label: 'Stopped' },
  failed: { icon: <AlertTriangle className="h-5 w-5" />, color: 'text-red-500 bg-red-100 dark:bg-red-900', label: 'Failed' },
};

const typeIcons: Partial<Record<HoneypotType, React.ReactNode>> = {
  ssh: <Terminal className="h-6 w-6" />,
  http: <Globe className="h-6 w-6" />,
  https: <Globe className="h-6 w-6" />,
  smb: <Server className="h-6 w-6" />,
  ftp: <Server className="h-6 w-6" />,
  telnet: <Terminal className="h-6 w-6" />,
  mysql: <Database className="h-6 w-6" />,
  postgresql: <Database className="h-6 w-6" />,
  rdp: <Server className="h-6 w-6" />,
  redis: <Database className="h-6 w-6" />,
};

export default function HoneypotDetailPage() {
  const { id } = useParams<{ id: string }>();
  const { data: honeypot, isLoading } = useHoneypot(id!);
  const { data: interactions } = useHoneypotInteractions(id!, { limit: 100 });
  const { data: templates } = useHoneypotTemplates();
  const stopHoneypot = useStopHoneypot();
  const triggerAnalysis = useTriggerHoneypotAnalysis();

  // Get honeypot type from template
  const template = templates?.find(t => t.id === honeypot?.template_id);
  const honeypotType = template?.honeypot_type;

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600" />
      </div>
    );
  }

  if (!honeypot) {
    return (
      <div className="text-center py-12">
        <p className="text-gray-500 dark:text-gray-400">Honeypot not found.</p>
        <Link to="/dashboard/honeypots" className="text-blue-600 hover:text-blue-800 mt-2 inline-block">
          Back to Honeypots
        </Link>
      </div>
    );
  }

  const config = statusConfig[honeypot.status];
  const uniqueAttackers = [...new Set(interactions?.map(i => i.source_ip) || [])];

  const handleStop = async () => {
    if (confirm('Are you sure you want to stop this honeypot?')) {
      await stopHoneypot.mutateAsync(id!);
    }
  };

  const handleAnalyze = async () => {
    await triggerAnalysis.mutateAsync(id!);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-4">
        <Link
          to="/dashboard/honeypots"
          className="p-2 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
        >
          <ArrowLeft className="h-5 w-5 text-gray-500" />
        </Link>
        <div className="flex items-center gap-3">
          <div className="p-3 bg-gray-100 dark:bg-gray-700 rounded-lg">
            {honeypotType && typeIcons[honeypotType] ? typeIcons[honeypotType] : <Target className="h-6 w-6" />}
          </div>
          <div>
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
              {honeypot.container_name}
            </h1>
            <p className="text-sm text-gray-500 dark:text-gray-400">
              {honeypot.host_ip}:{Object.values(honeypot.port_mappings || {})[0] || 'N/A'}
            </p>
          </div>
        </div>
        <span className={`ml-auto inline-flex items-center gap-2 px-3 py-1.5 rounded-full text-sm font-medium ${config.color}`}>
          {config.icon}
          {config.label}
        </span>
        {honeypot.status === 'running' && (
          <button
            onClick={handleStop}
            disabled={stopHoneypot.isPending}
            className="flex items-center gap-2 px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors disabled:opacity-50"
          >
            <Square className="h-4 w-4" />
            {stopHoneypot.isPending ? 'Stopping...' : 'Stop'}
          </button>
        )}
      </div>

      {/* Info Grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-4">
          <p className="text-sm text-gray-500 dark:text-gray-400">Type</p>
          <p className="text-xl font-bold text-gray-900 dark:text-white uppercase">
            {honeypotType || 'unknown'}
          </p>
        </div>
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-4">
          <p className="text-sm text-gray-500 dark:text-gray-400">Interactions</p>
          <p className="text-xl font-bold text-gray-900 dark:text-white">
            {honeypot.interaction_count}
          </p>
        </div>
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-4">
          <p className="text-sm text-gray-500 dark:text-gray-400">Unique Attackers</p>
          <p className="text-xl font-bold text-gray-900 dark:text-white">
            {uniqueAttackers.length}
          </p>
        </div>
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-4">
          <p className="text-sm text-gray-500 dark:text-gray-400">Expires</p>
          <p className="text-sm font-medium text-gray-900 dark:text-white">
            {new Date(honeypot.expires_at).toLocaleString()}
          </p>
        </div>
      </div>

      {/* LLM Profile */}
      {honeypot.llm_profile && Object.keys(honeypot.llm_profile).length > 0 && (
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <div className="flex items-center gap-2 mb-4">
            <Brain className="h-5 w-5 text-purple-500" />
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">AI Analysis</h2>
          </div>
          <pre className="p-4 bg-gray-50 dark:bg-gray-900 rounded text-sm overflow-x-auto">
            {JSON.stringify(honeypot.llm_profile, null, 2)}
          </pre>
        </div>
      )}

      {/* Unique Attackers */}
      {uniqueAttackers.length > 0 && (
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Attackers</h2>
            <button
              onClick={handleAnalyze}
              disabled={triggerAnalysis.isPending}
              className="flex items-center gap-2 px-3 py-1.5 bg-purple-600 text-white rounded-lg hover:bg-purple-700 transition-colors text-sm disabled:opacity-50"
            >
              <Brain className="h-4 w-4" />
              {triggerAnalysis.isPending ? 'Analyzing...' : 'Analyze All'}
            </button>
          </div>
          <div className="flex flex-wrap gap-2">
            {uniqueAttackers.map((ip) => (
              <div key={ip} className="flex items-center gap-2 px-3 py-2 bg-gray-100 dark:bg-gray-700 rounded-lg">
                <User className="h-4 w-4 text-gray-500" />
                <span className="text-sm font-mono text-gray-900 dark:text-white">{ip}</span>
                <Link
                  to={`/dashboard/attackers?ip=${ip}`}
                  className="p-1 hover:bg-gray-200 dark:hover:bg-gray-600 rounded"
                  title="View profile"
                >
                  <Activity className="h-4 w-4 text-blue-500" />
                </Link>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Interactions Timeline */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
        <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
          Interaction Timeline
        </h2>

        {interactions && interactions.length > 0 ? (
          <div className="space-y-4 max-h-[600px] overflow-y-auto">
            {interactions.map((interaction, index) => (
              <div key={interaction.id} className="relative">
                {index < interactions.length - 1 && (
                  <div className="absolute left-4 top-10 w-0.5 h-full bg-gray-200 dark:bg-gray-700" />
                )}
                <div className="flex gap-4">
                  <div className="flex-shrink-0 w-8 h-8 rounded-full bg-red-100 dark:bg-red-900 flex items-center justify-center">
                    <AlertTriangle className="h-4 w-4 text-red-600" />
                  </div>
                  <div className="flex-1 pb-4">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="font-medium text-gray-900 dark:text-white capitalize">
                          {interaction.interaction_type.replace(/_/g, ' ')}
                        </span>
                        <span className="text-sm text-gray-500 dark:text-gray-400 font-mono">
                          {interaction.source_ip}:{interaction.source_port || 'N/A'}
                        </span>
                      </div>
                      <span className="text-xs text-gray-500 dark:text-gray-400">
                        {new Date(interaction.timestamp).toLocaleString()}
                      </span>
                    </div>

                    {/* Raw Data */}
                    {interaction.raw_data && (
                      <div className="mt-2 p-3 bg-gray-900 dark:bg-black rounded font-mono text-xs text-green-400 overflow-x-auto">
                        <pre>{interaction.raw_data}</pre>
                      </div>
                    )}

                    {/* Parsed Data */}
                    {interaction.parsed_data && Object.keys(interaction.parsed_data).length > 0 && (
                      <details className="mt-2">
                        <summary className="text-sm text-blue-600 dark:text-blue-400 cursor-pointer hover:underline">
                          View parsed data
                        </summary>
                        <pre className="mt-2 p-3 bg-gray-50 dark:bg-gray-900 rounded text-xs overflow-x-auto">
                          {JSON.stringify(interaction.parsed_data, null, 2)}
                        </pre>
                      </details>
                    )}

                    {/* Threat Indicators */}
                    {interaction.threat_indicators && Object.keys(interaction.threat_indicators).length > 0 && (
                      <div className="mt-2 flex flex-wrap gap-2">
                        {Object.entries(interaction.threat_indicators).map(([key, value]) => (
                          <span
                            key={key}
                            className="px-2 py-1 bg-red-100 dark:bg-red-900 text-red-700 dark:text-red-300 text-xs rounded"
                          >
                            {key}: {String(value)}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-center py-12">
            <Activity className="h-12 w-12 text-gray-300 dark:text-gray-600 mx-auto mb-4" />
            <p className="text-gray-500 dark:text-gray-400">No interactions recorded yet.</p>
            <p className="text-sm text-gray-400 dark:text-gray-500">
              Waiting for attackers to connect...
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
