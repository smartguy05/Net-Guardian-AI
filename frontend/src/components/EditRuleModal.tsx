import { useState } from 'react';
import { X, Plus, Trash2, Loader2 } from 'lucide-react';
import { useUpdateRule, useRuleFields } from '../api/hooks';
import type { DetectionRule, RuleCondition, RuleAction, AlertSeverity } from '../types';

const OPERATORS = [
  { value: 'eq', label: 'equals' },
  { value: 'ne', label: 'not equals' },
  { value: 'gt', label: 'greater than' },
  { value: 'lt', label: 'less than' },
  { value: 'gte', label: 'greater or equal' },
  { value: 'lte', label: 'less or equal' },
  { value: 'contains', label: 'contains' },
  { value: 'starts_with', label: 'starts with' },
  { value: 'ends_with', label: 'ends with' },
  { value: 'regex', label: 'matches regex' },
  { value: 'in', label: 'in list' },
  { value: 'not_in', label: 'not in list' },
];

const ACTION_TYPES = [
  { value: 'create_alert', label: 'Create Alert', description: 'Generate an alert when triggered' },
  { value: 'quarantine_device', label: 'Quarantine Device', description: 'Isolate the device from network' },
  { value: 'tag_device', label: 'Tag Device', description: 'Add a tag to the device' },
  { value: 'send_notification', label: 'Send Notification', description: 'Send email/ntfy notification' },
  { value: 'execute_webhook', label: 'Execute Webhook', description: 'Call external webhook URL' },
  { value: 'log_event', label: 'Log Event', description: 'Write to audit log' },
];

interface EditRuleModalProps {
  rule: DetectionRule;
  onClose: () => void;
}

export default function EditRuleModal({ rule, onClose }: EditRuleModalProps) {
  const [name, setName] = useState(rule.name);
  const [description, setDescription] = useState(rule.description || '');
  const [severity, setSeverity] = useState<AlertSeverity>(rule.severity);
  const [cooldownMinutes, setCooldownMinutes] = useState(rule.cooldown_minutes);
  const [logic, setLogic] = useState<'and' | 'or'>(rule.conditions.logic);
  const [conditions, setConditions] = useState<RuleCondition[]>(rule.conditions.conditions);
  const [actions, setActions] = useState<RuleAction[]>(rule.response_actions);

  const { data: fieldsData } = useRuleFields();
  const updateRule = useUpdateRule();

  const fields = fieldsData || [];

  const addCondition = () => {
    setConditions([...conditions, { field: 'event_type', operator: 'eq', value: '' }]);
  };

  const removeCondition = (index: number) => {
    setConditions(conditions.filter((_, i) => i !== index));
  };

  const updateCondition = (index: number, updates: Partial<RuleCondition>) => {
    setConditions(
      conditions.map((c, i) => (i === index ? { ...c, ...updates } : c))
    );
  };

  const addAction = () => {
    setActions([...actions, { type: 'create_alert', config: {} }]);
  };

  const removeAction = (index: number) => {
    setActions(actions.filter((_, i) => i !== index));
  };

  const updateAction = (index: number, updates: Partial<RuleAction>) => {
    setActions(
      actions.map((a, i) => (i === index ? { ...a, ...updates } : a))
    );
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await updateRule.mutateAsync({
        ruleId: rule.id,
        name,
        description: description || undefined,
        severity,
        conditions: { logic, conditions },
        response_actions: actions,
        cooldown_minutes: cooldownMinutes,
      });
      onClose();
    } catch (error) {
      console.error('Failed to update rule:', error);
    }
  };

  const isValid = name.trim() && conditions.length > 0 && conditions.every((c) => c.field && c.operator && c.value !== '') && actions.length > 0;

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto">
      <div className="fixed inset-0 bg-black/50 dark:bg-black/70" onClick={onClose} />

      <div className="flex min-h-full items-center justify-center p-4">
        <div className="relative w-full max-w-2xl bg-white dark:bg-zinc-800 rounded-xl shadow-xl">
          {/* Header */}
          <div className="flex items-center justify-between p-4 border-b border-gray-200 dark:border-zinc-700">
            <div>
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                Edit Rule
              </h3>
              <p className="text-sm text-gray-500 dark:text-gray-400">
                {rule.id}
              </p>
            </div>
            <button
              onClick={onClose}
              className="p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 rounded-lg hover:bg-gray-100 dark:hover:bg-zinc-700"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Content */}
          <form onSubmit={handleSubmit}>
            <div className="p-4 space-y-6 max-h-[60vh] overflow-y-auto">
              {/* Basic Info */}
              <div className="space-y-4">
                <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300">Basic Information</h4>

                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Name <span className="text-danger-500">*</span>
                  </label>
                  <input
                    type="text"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    className="input w-full"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Description
                  </label>
                  <textarea
                    value={description}
                    onChange={(e) => setDescription(e.target.value)}
                    className="input w-full"
                    rows={2}
                  />
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Severity
                    </label>
                    <select
                      value={severity}
                      onChange={(e) => setSeverity(e.target.value as AlertSeverity)}
                      className="input w-full"
                    >
                      <option value="critical">Critical</option>
                      <option value="high">High</option>
                      <option value="medium">Medium</option>
                      <option value="low">Low</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Cooldown (minutes)
                    </label>
                    <input
                      type="number"
                      value={cooldownMinutes}
                      onChange={(e) => setCooldownMinutes(parseInt(e.target.value) || 0)}
                      min={0}
                      max={10080}
                      className="input w-full"
                    />
                  </div>
                </div>
              </div>

              {/* Conditions */}
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300">Conditions</h4>
                  <div className="flex items-center gap-2">
                    <span className="text-sm text-gray-500 dark:text-gray-400">Match</span>
                    <select
                      value={logic}
                      onChange={(e) => setLogic(e.target.value as 'and' | 'or')}
                      className="input py-1 px-2 text-sm w-20"
                    >
                      <option value="and">ALL</option>
                      <option value="or">ANY</option>
                    </select>
                  </div>
                </div>

                {conditions.map((condition, index) => (
                  <div
                    key={index}
                    className="flex items-center gap-2 p-3 bg-gray-50 dark:bg-zinc-700/50 rounded-lg"
                  >
                    <select
                      value={condition.field}
                      onChange={(e) => updateCondition(index, { field: e.target.value })}
                      className="input py-1.5 text-sm flex-1"
                    >
                      <option value="">Select field...</option>
                      {fields.map((f) => (
                        <option key={f.name} value={f.name}>
                          {f.name}
                        </option>
                      ))}
                    </select>

                    <select
                      value={condition.operator}
                      onChange={(e) => updateCondition(index, { operator: e.target.value })}
                      className="input py-1.5 text-sm w-36"
                    >
                      {OPERATORS.map((op) => (
                        <option key={op.value} value={op.value}>
                          {op.label}
                        </option>
                      ))}
                    </select>

                    <input
                      type="text"
                      value={String(condition.value)}
                      onChange={(e) => updateCondition(index, { value: e.target.value })}
                      placeholder="Value..."
                      className="input py-1.5 text-sm flex-1"
                    />

                    <button
                      type="button"
                      onClick={() => removeCondition(index)}
                      disabled={conditions.length === 1}
                      className="p-1.5 text-gray-400 hover:text-danger-600 dark:hover:text-danger-400 disabled:opacity-50"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                ))}

                <button
                  type="button"
                  onClick={addCondition}
                  className="btn-secondary text-sm inline-flex items-center gap-1"
                >
                  <Plus className="w-4 h-4" />
                  Add Condition
                </button>
              </div>

              {/* Actions */}
              <div className="space-y-3">
                <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300">Actions</h4>

                {actions.map((action, index) => (
                  <div
                    key={index}
                    className="p-3 bg-gray-50 dark:bg-zinc-700/50 rounded-lg"
                  >
                    <div className="flex items-center gap-2 mb-2">
                      <select
                        value={action.type}
                        onChange={(e) => updateAction(index, { type: e.target.value, config: {} })}
                        className="input py-1.5 text-sm flex-1"
                      >
                        {ACTION_TYPES.map((at) => (
                          <option key={at.value} value={at.value}>
                            {at.label}
                          </option>
                        ))}
                      </select>

                      <button
                        type="button"
                        onClick={() => removeAction(index)}
                        disabled={actions.length === 1}
                        className="p-1.5 text-gray-400 hover:text-danger-600 dark:hover:text-danger-400 disabled:opacity-50"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>

                    {action.type === 'tag_device' && (
                      <input
                        type="text"
                        value={(action.config.tag as string) || ''}
                        onChange={(e) =>
                          updateAction(index, { config: { ...action.config, tag: e.target.value } })
                        }
                        placeholder="Tag to add..."
                        className="input py-1.5 text-sm w-full"
                      />
                    )}

                    {action.type === 'execute_webhook' && (
                      <input
                        type="url"
                        value={(action.config.url as string) || ''}
                        onChange={(e) =>
                          updateAction(index, { config: { ...action.config, url: e.target.value } })
                        }
                        placeholder="https://..."
                        className="input py-1.5 text-sm w-full"
                      />
                    )}
                  </div>
                ))}

                <button
                  type="button"
                  onClick={addAction}
                  className="btn-secondary text-sm inline-flex items-center gap-1"
                >
                  <Plus className="w-4 h-4" />
                  Add Action
                </button>
              </div>
            </div>

            {/* Footer */}
            <div className="flex items-center justify-end gap-3 p-4 border-t border-gray-200 dark:border-zinc-700">
              <button type="button" onClick={onClose} className="btn-secondary">
                Cancel
              </button>
              <button
                type="submit"
                disabled={!isValid || updateRule.isPending}
                className="btn-primary disabled:opacity-50 inline-flex items-center gap-2"
              >
                {updateRule.isPending && <Loader2 className="w-4 h-4 animate-spin" />}
                Save Changes
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
}
