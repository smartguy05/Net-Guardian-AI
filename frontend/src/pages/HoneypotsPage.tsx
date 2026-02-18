import { useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Target,
  Play,
  Square,
  Clock,
  AlertTriangle,
  Activity,
  Plus,
  ChevronRight,
  Server,
  Globe,
  Database,
  Terminal,
} from 'lucide-react';
import { useHoneypots, useHoneypotTemplates, useSpawnHoneypot, useStopHoneypot, useHoneypotStats } from '../api/hooks';
import type { HoneypotStatus, HoneypotType, HoneypotInstance } from '../types';

const statusConfig: Record<HoneypotStatus, { icon: React.ReactNode; color: string; label: string }> = {
  pending: { icon: <Clock className="h-4 w-4" />, color: 'text-gray-500 bg-gray-100 dark:bg-gray-700', label: 'Pending' },
  starting: { icon: <Clock className="h-4 w-4" />, color: 'text-blue-500 bg-blue-100 dark:bg-blue-900', label: 'Starting' },
  running: { icon: <Play className="h-4 w-4" />, color: 'text-green-500 bg-green-100 dark:bg-green-900', label: 'Running' },
  stopping: { icon: <Clock className="h-4 w-4" />, color: 'text-yellow-500 bg-yellow-100 dark:bg-yellow-900', label: 'Stopping' },
  stopped: { icon: <Square className="h-4 w-4" />, color: 'text-gray-500 bg-gray-100 dark:bg-gray-700', label: 'Stopped' },
  failed: { icon: <AlertTriangle className="h-4 w-4" />, color: 'text-red-500 bg-red-100 dark:bg-red-900', label: 'Failed' },
};

const typeIcons: Partial<Record<HoneypotType, React.ReactNode>> = {
  ssh: <Terminal className="h-5 w-5" />,
  http: <Globe className="h-5 w-5" />,
  https: <Globe className="h-5 w-5" />,
  smb: <Server className="h-5 w-5" />,
  ftp: <Server className="h-5 w-5" />,
  telnet: <Terminal className="h-5 w-5" />,
  mysql: <Database className="h-5 w-5" />,
  postgresql: <Database className="h-5 w-5" />,
  rdp: <Server className="h-5 w-5" />,
  redis: <Database className="h-5 w-5" />,
};

export default function HoneypotsPage() {
  const [showSpawnModal, setShowSpawnModal] = useState(false);
  const [selectedTemplate, setSelectedTemplate] = useState<string>('');
  const [timeout, setTimeout] = useState(60);

  const { data: honeypots, isLoading } = useHoneypots({ status: 'running' });
  const { data: allHoneypots } = useHoneypots({ limit: 100 });
  const { data: templates } = useHoneypotTemplates();
  const { data: stats } = useHoneypotStats();
  const spawnHoneypot = useSpawnHoneypot();
  const stopHoneypot = useStopHoneypot();

  // Create a map from template_id to template for looking up honeypot types
  const templateMap = templates?.reduce((acc, t) => {
    acc[t.id] = t;
    return acc;
  }, {} as Record<string, typeof templates[0]>) || {};

  const getHoneypotType = (honeypot: HoneypotInstance): HoneypotType | null => {
    if (honeypot.template_id && templateMap[honeypot.template_id]) {
      return templateMap[honeypot.template_id].honeypot_type;
    }
    return null;
  };

  const handleSpawn = async () => {
    if (!selectedTemplate) return;
    try {
      await spawnHoneypot.mutateAsync({
        template_id: selectedTemplate,
        timeout_minutes: timeout,
      });
      setShowSpawnModal(false);
      setSelectedTemplate('');
    } catch (error) {
      console.error('Failed to spawn honeypot:', error);
    }
  };

  const handleStop = async (id: string) => {
    if (confirm('Are you sure you want to stop this honeypot?')) {
      await stopHoneypot.mutateAsync(id);
    }
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Honeypots</h1>
        <button
          onClick={() => setShowSpawnModal(true)}
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
        >
          <Plus className="h-4 w-4" />
          Deploy Honeypot
        </button>
      </div>

      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-4">
            <div className="flex items-center gap-2">
              <Activity className="h-5 w-5 text-green-500" />
              <span className="text-sm text-gray-500 dark:text-gray-400">Active</span>
            </div>
            <p className="text-2xl font-bold text-gray-900 dark:text-white mt-1">
              {stats.by_status?.running || 0}
            </p>
          </div>
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-4">
            <div className="flex items-center gap-2">
              <Target className="h-5 w-5 text-blue-500" />
              <span className="text-sm text-gray-500 dark:text-gray-400">Total Deployed</span>
            </div>
            <p className="text-2xl font-bold text-gray-900 dark:text-white mt-1">
              {Object.values(stats.by_status || {}).reduce((a, b) => a + b, 0)}
            </p>
          </div>
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-4">
            <div className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-orange-500" />
              <span className="text-sm text-gray-500 dark:text-gray-400">Total Interactions</span>
            </div>
            <p className="text-2xl font-bold text-gray-900 dark:text-white mt-1">
              {stats.total_interactions}
            </p>
          </div>
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-4">
            <div className="flex items-center gap-2">
              <Globe className="h-5 w-5 text-red-500" />
              <span className="text-sm text-gray-500 dark:text-gray-400">Unique Attackers</span>
            </div>
            <p className="text-2xl font-bold text-gray-900 dark:text-white mt-1">
              {stats.unique_attackers}
            </p>
          </div>
        </div>
      )}

      {/* Active Honeypots */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow">
        <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Active Honeypots</h2>
        </div>

        {honeypots?.items && honeypots.items.length > 0 ? (
          <div className="divide-y divide-gray-200 dark:divide-gray-700">
            {honeypots.items.map((honeypot) => {
              const config = statusConfig[honeypot.status];
              const honeypotType = getHoneypotType(honeypot);
              return (
                <div key={honeypot.id} className="p-4 hover:bg-gray-50 dark:hover:bg-gray-700/50">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-4">
                      <div className="p-2 bg-gray-100 dark:bg-gray-700 rounded-lg">
                        {honeypotType && typeIcons[honeypotType] ? typeIcons[honeypotType] : <Target className="h-5 w-5" />}
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <h3 className="font-medium text-gray-900 dark:text-white">
                            {honeypot.container_name}
                          </h3>
                          <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium ${config.color}`}>
                            {config.icon}
                            {config.label}
                          </span>
                        </div>
                        <p className="text-sm text-gray-500 dark:text-gray-400">
                          {honeypot.host_ip}:{Object.values(honeypot.port_mappings || {})[0] || 'N/A'}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-4">
                      <div className="text-right">
                        <p className="text-sm font-medium text-gray-900 dark:text-white">
                          {honeypot.interaction_count} interactions
                        </p>
                        <p className="text-xs text-gray-500 dark:text-gray-400">
                          Expires: {new Date(honeypot.expires_at).toLocaleString()}
                        </p>
                      </div>
                      <div className="flex items-center gap-2">
                        {honeypot.status === 'running' && (
                          <button
                            onClick={() => handleStop(honeypot.id)}
                            disabled={stopHoneypot.isPending}
                            className="p-2 text-red-600 hover:bg-red-100 dark:hover:bg-red-900/30 rounded-lg transition-colors"
                            title="Stop honeypot"
                          >
                            <Square className="h-4 w-4" />
                          </button>
                        )}
                        <Link
                          to={`/dashboard/honeypots/${honeypot.id}`}
                          className="p-2 text-blue-600 hover:bg-blue-100 dark:hover:bg-blue-900/30 rounded-lg transition-colors"
                        >
                          <ChevronRight className="h-4 w-4" />
                        </Link>
                      </div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        ) : (
          <div className="text-center py-12">
            <Target className="h-12 w-12 text-gray-300 dark:text-gray-600 mx-auto mb-4" />
            <p className="text-gray-500 dark:text-gray-400">No active honeypots.</p>
            <p className="text-sm text-gray-400 dark:text-gray-500">
              Deploy a honeypot to start capturing attacker activity.
            </p>
          </div>
        )}
      </div>

      {/* Recent Honeypots */}
      {allHoneypots?.items && allHoneypots.items.length > 0 && (
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow">
          <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Recent Honeypots</h2>
          </div>
          <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
            <thead className="bg-gray-50 dark:bg-gray-900">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Honeypot
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Type
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Status
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Interactions
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Created
                </th>
                <th className="px-6 py-3"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
              {allHoneypots.items.slice(0, 10).map((honeypot) => {
                const config = statusConfig[honeypot.status];
                const honeypotType = getHoneypotType(honeypot);
                return (
                  <tr key={honeypot.id} className="hover:bg-gray-50 dark:hover:bg-gray-700/50">
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className="text-sm font-medium text-gray-900 dark:text-white">
                        {honeypot.container_name}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center gap-2">
                        {honeypotType && typeIcons[honeypotType] ? typeIcons[honeypotType] : <Target className="h-4 w-4" />}
                        <span className="text-sm text-gray-600 dark:text-gray-400 uppercase">
                          {honeypotType || 'unknown'}
                        </span>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium ${config.color}`}>
                        {config.icon}
                        {config.label}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-600 dark:text-gray-400">
                      {honeypot.interaction_count}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                      {new Date(honeypot.created_at).toLocaleString()}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-right">
                      <Link
                        to={`/dashboard/honeypots/${honeypot.id}`}
                        className="text-blue-600 dark:text-blue-400 hover:text-blue-800"
                      >
                        <ChevronRight className="h-5 w-5" />
                      </Link>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Spawn Modal */}
      {showSpawnModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl p-6 max-w-lg w-full mx-4">
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
              Deploy Honeypot
            </h2>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Template
                </label>
                <div className="grid grid-cols-2 gap-2">
                  {templates?.map((template) => (
                    <button
                      key={template.id}
                      onClick={() => setSelectedTemplate(template.id)}
                      className={`p-3 rounded-lg border text-left transition-colors ${
                        selectedTemplate === template.id
                          ? 'border-blue-500 bg-blue-50 dark:bg-blue-900/30'
                          : 'border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700'
                      }`}
                    >
                      <div className="flex items-center gap-2">
                        {typeIcons[template.honeypot_type] || <Target className="h-4 w-4" />}
                        <span className="font-medium text-gray-900 dark:text-white">
                          {template.name}
                        </span>
                      </div>
                      <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                        {template.honeypot_type.toUpperCase()} - Port {template.exposed_ports?.[0]}
                      </p>
                    </button>
                  ))}
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Timeout (minutes)
                </label>
                <input
                  type="number"
                  value={timeout}
                  onChange={(e) => setTimeout(parseInt(e.target.value) || 60)}
                  min={10}
                  max={1440}
                  className="w-full rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-900 px-3 py-2"
                />
              </div>
            </div>

            <div className="flex justify-end gap-3 mt-6">
              <button
                onClick={() => setShowSpawnModal(false)}
                className="px-4 py-2 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleSpawn}
                disabled={!selectedTemplate || spawnHoneypot.isPending}
                className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors disabled:opacity-50"
              >
                {spawnHoneypot.isPending ? 'Deploying...' : 'Deploy'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
