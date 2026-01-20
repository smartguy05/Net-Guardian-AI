import { useState } from 'react';
import {
  Shield,
  Search,
  Plus,
  ToggleLeft,
  ToggleRight,
  Trash2,
  Edit2,
  AlertTriangle,
  Info,
  RefreshCw,
  ChevronDown,
  ChevronUp,
  Play,
} from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';
import clsx from 'clsx';
import {
  useRules,
  useEnableRule,
  useDisableRule,
  useDeleteRule,
} from '../api/hooks';
import { useAuthStore } from '../stores/auth';
import Pagination from '../components/Pagination';
import CreateRuleModal from '../components/CreateRuleModal';
import EditRuleModal from '../components/EditRuleModal';
import TestRuleModal from '../components/TestRuleModal';
import type { DetectionRule, AlertSeverity } from '../types';

const severityConfig: Record<AlertSeverity, { label: string; class: string }> = {
  critical: { label: 'Critical', class: 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300' },
  high: { label: 'High', class: 'bg-orange-100 dark:bg-orange-900/30 text-orange-700 dark:text-orange-300' },
  medium: { label: 'Medium', class: 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-700 dark:text-yellow-300' },
  low: { label: 'Low', class: 'bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300' },
};

function RuleCard({ rule, onEdit, onTest }: { rule: DetectionRule; onEdit: () => void; onTest: () => void }) {
  const user = useAuthStore((state) => state.user);
  const canManage = user?.role === 'admin';
  const [expanded, setExpanded] = useState(false);

  const enableRule = useEnableRule();
  const disableRule = useDisableRule();
  const deleteRule = useDeleteRule();

  const severityStyle = severityConfig[rule.severity] || severityConfig.medium;

  const handleToggle = () => {
    if (rule.enabled) {
      disableRule.mutate(rule.id);
    } else {
      enableRule.mutate(rule.id);
    }
  };

  const handleDelete = () => {
    if (confirm(`Delete rule "${rule.name}"? This action cannot be undone.`)) {
      deleteRule.mutate(rule.id);
    }
  };

  const conditionCount = rule.conditions?.conditions?.length || 0;
  const actionCount = rule.response_actions?.length || 0;

  return (
    <div className="card p-4">
      <div className="flex items-start justify-between gap-4">
        <div className="flex items-start gap-3 min-w-0">
          <div className={clsx(
            'p-2 rounded-lg flex-shrink-0',
            rule.enabled
              ? 'bg-primary-100 dark:bg-primary-900/30'
              : 'bg-gray-100 dark:bg-zinc-700'
          )}>
            <Shield className={clsx(
              'w-5 h-5',
              rule.enabled
                ? 'text-primary-600 dark:text-primary-400'
                : 'text-gray-400 dark:text-gray-500'
            )} />
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <h3 className="text-sm font-medium text-gray-900 dark:text-white">
                {rule.name}
              </h3>
              <span className={clsx('text-xs px-2 py-0.5 rounded-full', severityStyle.class)}>
                {severityStyle.label}
              </span>
              {!rule.enabled && (
                <span className="text-xs px-2 py-0.5 rounded-full bg-gray-100 dark:bg-zinc-700 text-gray-500 dark:text-gray-400">
                  Disabled
                </span>
              )}
            </div>
            <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
              ID: {rule.id}
            </p>
            {rule.description && (
              <p className="text-sm text-gray-600 dark:text-gray-300 mt-1 line-clamp-2">
                {rule.description}
              </p>
            )}
            <div className="flex items-center gap-4 mt-2 text-xs text-gray-500 dark:text-gray-400">
              <span>{conditionCount} condition{conditionCount !== 1 ? 's' : ''}</span>
              <span>{actionCount} action{actionCount !== 1 ? 's' : ''}</span>
              <span>{rule.cooldown_minutes}min cooldown</span>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2 flex-shrink-0">
          {canManage && (
            <>
              <button
                onClick={onTest}
                className="p-2 text-gray-400 hover:text-primary-600 dark:hover:text-primary-400 rounded-lg hover:bg-gray-100 dark:hover:bg-zinc-700"
                title="Test rule"
              >
                <Play className="w-4 h-4" />
              </button>
              <button
                onClick={onEdit}
                className="p-2 text-gray-400 hover:text-primary-600 dark:hover:text-primary-400 rounded-lg hover:bg-gray-100 dark:hover:bg-zinc-700"
                title="Edit rule"
              >
                <Edit2 className="w-4 h-4" />
              </button>
              <button
                onClick={handleToggle}
                disabled={enableRule.isPending || disableRule.isPending}
                className={clsx(
                  'p-2 rounded-lg transition-colors',
                  rule.enabled
                    ? 'text-success-600 dark:text-success-400 hover:bg-success-50 dark:hover:bg-success-900/30'
                    : 'text-gray-400 hover:bg-gray-100 dark:hover:bg-zinc-700'
                )}
                title={rule.enabled ? 'Disable rule' : 'Enable rule'}
              >
                {rule.enabled ? (
                  <ToggleRight className="w-5 h-5" />
                ) : (
                  <ToggleLeft className="w-5 h-5" />
                )}
              </button>
              <button
                onClick={handleDelete}
                disabled={deleteRule.isPending}
                className="p-2 text-gray-400 hover:text-danger-600 dark:hover:text-danger-400 rounded-lg hover:bg-danger-50 dark:hover:bg-danger-900/30"
                title="Delete rule"
              >
                <Trash2 className="w-4 h-4" />
              </button>
            </>
          )}
          <button
            onClick={() => setExpanded(!expanded)}
            className="p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 rounded-lg hover:bg-gray-100 dark:hover:bg-zinc-700"
          >
            {expanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </button>
        </div>
      </div>

      {/* Expanded Details */}
      {expanded && (
        <div className="mt-4 pt-4 border-t border-gray-200 dark:border-zinc-700 space-y-4">
          {/* Conditions */}
          <div>
            <h4 className="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase mb-2">
              Conditions ({rule.conditions.logic.toUpperCase()})
            </h4>
            <div className="space-y-2">
              {rule.conditions.conditions.map((cond, idx) => (
                <div
                  key={idx}
                  className="flex items-center gap-2 text-sm bg-gray-50 dark:bg-zinc-700/50 rounded px-3 py-2"
                >
                  <code className="text-primary-600 dark:text-primary-400">{cond.field}</code>
                  <span className="text-gray-500 dark:text-gray-400">{cond.operator}</span>
                  <code className="text-gray-900 dark:text-white">
                    {typeof cond.value === 'object' ? JSON.stringify(cond.value) : String(cond.value)}
                  </code>
                </div>
              ))}
            </div>
          </div>

          {/* Actions */}
          {rule.response_actions.length > 0 && (
            <div>
              <h4 className="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase mb-2">
                Actions
              </h4>
              <div className="space-y-2">
                {rule.response_actions.map((action, idx) => (
                  <div
                    key={idx}
                    className="flex items-center gap-2 text-sm bg-gray-50 dark:bg-zinc-700/50 rounded px-3 py-2"
                  >
                    <span className="font-medium text-gray-900 dark:text-white">{action.type}</span>
                    {Object.keys(action.config).length > 0 && (
                      <span className="text-gray-500 dark:text-gray-400">
                        ({Object.entries(action.config).map(([k, v]) => `${k}: ${v}`).join(', ')})
                      </span>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Metadata */}
          <div className="text-xs text-gray-500 dark:text-gray-400">
            Created {formatDistanceToNow(new Date(rule.created_at), { addSuffix: true })}
            {rule.updated_at !== rule.created_at && (
              <> &bull; Updated {formatDistanceToNow(new Date(rule.updated_at), { addSuffix: true })}</>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default function RulesPage() {
  const [search, setSearch] = useState('');
  const [enabledFilter, setEnabledFilter] = useState<string>('');
  const [severityFilter, setSeverityFilter] = useState<string>('');
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [editingRule, setEditingRule] = useState<DetectionRule | null>(null);
  const [testingRule, setTestingRule] = useState<DetectionRule | null>(null);

  const user = useAuthStore((state) => state.user);
  const canManage = user?.role === 'admin';

  const { data, isLoading, refetch, isFetching } = useRules({
    enabled: enabledFilter === '' ? undefined : enabledFilter === 'true',
    severity: severityFilter || undefined,
    search: search || undefined,
    page,
    page_size: pageSize,
  });

  const totalPages = data ? Math.ceil(data.total / pageSize) : 0;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Detection Rules</h1>
          <p className="text-gray-500 dark:text-gray-400">
            {data?.total || 0} rules configured
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => refetch()}
            disabled={isFetching}
            className="btn-secondary"
          >
            <RefreshCw className={clsx('w-4 h-4 mr-2', isFetching && 'animate-spin')} />
            Refresh
          </button>
          {canManage && (
            <button
              onClick={() => setShowCreateModal(true)}
              className="btn-primary"
            >
              <Plus className="w-4 h-4 mr-2" />
              Create Rule
            </button>
          )}
        </div>
      </div>

      {/* Info Banner */}
      <div className="flex items-start gap-3 p-4 bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg">
        <Info className="w-5 h-5 text-blue-600 dark:text-blue-400 flex-shrink-0 mt-0.5" />
        <div className="text-sm text-blue-700 dark:text-blue-300">
          <p className="font-medium">Detection rules trigger alerts when events match specified conditions.</p>
          <p className="mt-1">Rules can be configured to create alerts, quarantine devices, send notifications, and more.</p>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-4">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
          <input
            type="text"
            placeholder="Search rules..."
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setPage(1);
            }}
            className="input pl-10"
          />
        </div>
        <select
          value={enabledFilter}
          onChange={(e) => {
            setEnabledFilter(e.target.value);
            setPage(1);
          }}
          className="input w-full sm:w-40"
        >
          <option value="">All status</option>
          <option value="true">Enabled</option>
          <option value="false">Disabled</option>
        </select>
        <select
          value={severityFilter}
          onChange={(e) => {
            setSeverityFilter(e.target.value);
            setPage(1);
          }}
          className="input w-full sm:w-40"
        >
          <option value="">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
      </div>

      {/* Rules List */}
      {isLoading ? (
        <div className="space-y-4">
          {[...Array(3)].map((_, i) => (
            <div key={i} className="card p-4">
              <div className="animate-pulse space-y-3">
                <div className="h-5 bg-gray-200 dark:bg-zinc-700 rounded w-1/4" />
                <div className="h-4 bg-gray-200 dark:bg-zinc-700 rounded w-3/4" />
                <div className="h-4 bg-gray-200 dark:bg-zinc-700 rounded w-1/2" />
              </div>
            </div>
          ))}
        </div>
      ) : data?.items.length ? (
        <div className="space-y-4">
          {data.items.map((rule) => (
            <RuleCard
              key={rule.id}
              rule={rule}
              onEdit={() => setEditingRule(rule)}
              onTest={() => setTestingRule(rule)}
            />
          ))}
        </div>
      ) : (
        <div className="card p-12 text-center">
          <AlertTriangle className="w-12 h-12 text-gray-400 dark:text-gray-500 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
            No rules found
          </h3>
          <p className="text-gray-500 dark:text-gray-400 mb-4">
            {search || enabledFilter || severityFilter
              ? 'Try adjusting your filters'
              : 'Create your first detection rule to start monitoring'}
          </p>
          {canManage && !search && !enabledFilter && !severityFilter && (
            <button
              onClick={() => setShowCreateModal(true)}
              className="btn-primary inline-flex items-center gap-2"
            >
              <Plus className="w-4 h-4" />
              Create Rule
            </button>
          )}
        </div>
      )}

      {/* Pagination */}
      {data && data.total > 0 && (
        <Pagination
          currentPage={page}
          totalPages={totalPages}
          totalItems={data.total}
          pageSize={pageSize}
          onPageChange={setPage}
          onPageSizeChange={(size) => {
            setPageSize(size);
            setPage(1);
          }}
          pageSizeOptions={[10, 25, 50]}
        />
      )}

      {/* Modals */}
      {showCreateModal && (
        <CreateRuleModal
          onClose={() => setShowCreateModal(false)}
        />
      )}
      {editingRule && (
        <EditRuleModal
          rule={editingRule}
          onClose={() => setEditingRule(null)}
        />
      )}
      {testingRule && (
        <TestRuleModal
          rule={testingRule}
          onClose={() => setTestingRule(null)}
        />
      )}
    </div>
  );
}
