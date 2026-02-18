import { useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Search,
  Clock,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Play,
  Pause,
  ChevronRight,
  Filter,
  Plus,
} from 'lucide-react';
import { useInvestigations, useCreateInvestigation } from '../api/hooks';
import type { InvestigationStatus } from '../types';

const statusConfig: Record<InvestigationStatus, { icon: React.ReactNode; color: string; label: string }> = {
  pending: { icon: <Clock className="h-4 w-4" />, color: 'text-gray-500 bg-gray-100 dark:bg-gray-700', label: 'Pending' },
  running: { icon: <Play className="h-4 w-4" />, color: 'text-blue-500 bg-blue-100 dark:bg-blue-900', label: 'Running' },
  awaiting_approval: { icon: <Pause className="h-4 w-4" />, color: 'text-yellow-500 bg-yellow-100 dark:bg-yellow-900', label: 'Awaiting Approval' },
  completed: { icon: <CheckCircle className="h-4 w-4" />, color: 'text-green-500 bg-green-100 dark:bg-green-900', label: 'Completed' },
  failed: { icon: <XCircle className="h-4 w-4" />, color: 'text-red-500 bg-red-100 dark:bg-red-900', label: 'Failed' },
  cancelled: { icon: <XCircle className="h-4 w-4" />, color: 'text-gray-500 bg-gray-100 dark:bg-gray-700', label: 'Cancelled' },
};

const priorityColors: Record<number, string> = {
  1: 'text-gray-500',
  2: 'text-blue-500',
  3: 'text-yellow-500',
  4: 'text-orange-500',
  5: 'text-red-500',
};

export default function InvestigationsPage() {
  const [statusFilter, setStatusFilter] = useState<InvestigationStatus | undefined>();
  const [showCreateModal, setShowCreateModal] = useState(false);

  const { data: investigations, isLoading } = useInvestigations({ status: statusFilter, limit: 50 });
  const createInvestigation = useCreateInvestigation();

  const handleCreateManual = async () => {
    try {
      await createInvestigation.mutateAsync({
        priority: 3,
        auto_run: true,
      });
      setShowCreateModal(false);
    } catch (error) {
      console.error('Failed to create investigation:', error);
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
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Investigations</h1>
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <Filter className="h-4 w-4 text-gray-400" />
            <select
              value={statusFilter || ''}
              onChange={(e) => setStatusFilter(e.target.value as InvestigationStatus || undefined)}
              className="rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-3 py-1.5 text-sm"
            >
              <option value="">All Status</option>
              <option value="pending">Pending</option>
              <option value="running">Running</option>
              <option value="awaiting_approval">Awaiting Approval</option>
              <option value="completed">Completed</option>
              <option value="failed">Failed</option>
            </select>
          </div>
          <button
            onClick={() => setShowCreateModal(true)}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
          >
            <Plus className="h-4 w-4" />
            New Investigation
          </button>
        </div>
      </div>

      {/* Stats Summary */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        {(['pending', 'running', 'awaiting_approval', 'completed', 'failed'] as InvestigationStatus[]).map((status) => {
          const config = statusConfig[status];
          const count = investigations?.items.filter(i => i.status === status).length || 0;
          return (
            <button
              key={status}
              onClick={() => setStatusFilter(statusFilter === status ? undefined : status)}
              className={`p-4 rounded-lg border transition-colors ${
                statusFilter === status
                  ? 'border-blue-500 bg-blue-50 dark:bg-blue-900/20'
                  : 'border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 hover:bg-gray-50 dark:hover:bg-gray-700'
              }`}
            >
              <div className="flex items-center gap-2">
                <span className={config.color}>{config.icon}</span>
                <span className="text-sm font-medium text-gray-600 dark:text-gray-400">{config.label}</span>
              </div>
              <p className="text-2xl font-bold text-gray-900 dark:text-white mt-1">{count}</p>
            </button>
          );
        })}
      </div>

      {/* Investigations List */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow overflow-hidden">
        <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
          <thead className="bg-gray-50 dark:bg-gray-900">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                Investigation
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                Status
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                Priority
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                Trigger
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                Started
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                Actions
              </th>
              <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">

              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
            {investigations?.items.map((investigation) => {
              const config = statusConfig[investigation.status];
              return (
                <tr key={investigation.id} className="hover:bg-gray-50 dark:hover:bg-gray-700/50">
                  <td className="px-6 py-4">
                    <div>
                      <p className="text-sm font-medium text-gray-900 dark:text-white">
                        {investigation.id.slice(0, 8)}...
                      </p>
                      {investigation.summary && (
                        <p className="text-sm text-gray-500 dark:text-gray-400 truncate max-w-xs">
                          {investigation.summary}
                        </p>
                      )}
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium ${config.color}`}>
                      {config.icon}
                      {config.label}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className={`font-medium ${priorityColors[investigation.priority]}`}>
                      P{investigation.priority}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className="text-sm text-gray-600 dark:text-gray-400 capitalize">
                      {investigation.trigger_source}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                    {investigation.started_at
                      ? new Date(investigation.started_at).toLocaleString()
                      : '-'}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    {investigation.requires_approval && investigation.status === 'awaiting_approval' && (
                      <span className="inline-flex items-center gap-1 text-yellow-600 dark:text-yellow-400 text-sm">
                        <AlertTriangle className="h-4 w-4" />
                        Needs Approval
                      </span>
                    )}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-right">
                    <Link
                      to={`/dashboard/investigations/${investigation.id}`}
                      className="text-blue-600 dark:text-blue-400 hover:text-blue-800 dark:hover:text-blue-300"
                    >
                      <ChevronRight className="h-5 w-5" />
                    </Link>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>

        {(!investigations?.items || investigations.items.length === 0) && (
          <div className="text-center py-12">
            <Search className="h-12 w-12 text-gray-300 dark:text-gray-600 mx-auto mb-4" />
            <p className="text-gray-500 dark:text-gray-400">No investigations found.</p>
            <p className="text-sm text-gray-400 dark:text-gray-500">
              Investigations are automatically created for high-severity alerts.
            </p>
          </div>
        )}
      </div>

      {/* Create Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl p-6 max-w-md w-full mx-4">
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
              Create Manual Investigation
            </h2>
            <p className="text-sm text-gray-600 dark:text-gray-400 mb-6">
              Start a new investigation to analyze recent activity and potential threats.
              The AI agent will gather context, correlate events, and provide recommendations.
            </p>
            <div className="flex justify-end gap-3">
              <button
                onClick={() => setShowCreateModal(false)}
                className="px-4 py-2 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleCreateManual}
                disabled={createInvestigation.isPending}
                className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors disabled:opacity-50"
              >
                {createInvestigation.isPending ? 'Creating...' : 'Create Investigation'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
