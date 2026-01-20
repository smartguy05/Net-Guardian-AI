import { useState } from 'react';
import { X, Plus, Trash2, Loader2, Info } from 'lucide-react';
import clsx from 'clsx';
import { useCreateRule, useRuleFields } from '../api/hooks';
import type { RuleCondition, RuleAction, AlertSeverity } from '../types';

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

interface CreateRuleModalProps {
  onClose: () => void;
}

export default function CreateRuleModal({ onClose }: CreateRuleModalProps) {
  const [step, setStep] = useState(1);
  const [id, setId] = useState('');
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [severity, setSeverity] = useState<AlertSeverity>('medium');
  const [cooldownMinutes, setCooldownMinutes] = useState(60);
  const [logic, setLogic] = useState<'and' | 'or'>('and');
  const [conditions, setConditions] = useState<RuleCondition[]>([
    { field: 'event_type', operator: 'eq', value: '' },
  ]);
  const [actions, setActions] = useState<RuleAction[]>([
    { type: 'create_alert', config: {} },
  ]);

  const { data: fieldsData } = useRuleFields();
  const createRule = useCreateRule();

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

  const handleSubmit = async () => {
    try {
      await createRule.mutateAsync({
        id,
        name,
        description: description || undefined,
        severity,
        enabled: true,
        conditions: { logic, conditions },
        response_actions: actions,
        cooldown_minutes: cooldownMinutes,
      });
      onClose();
    } catch (error) {
      console.error('Failed to create rule:', error);
    }
  };

  const isStep1Valid = id.trim() && name.trim() && /^[a-z0-9][a-z0-9_-]*$/.test(id);
  const isStep2Valid = conditions.length > 0 && conditions.every((c) => c.field && c.operator && c.value !== '');
  const isStep3Valid = actions.length > 0;

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto">
      <div className="fixed inset-0 bg-black/50 dark:bg-black/70" onClick={onClose} />

      <div className="flex min-h-full items-center justify-center p-4">
        <div className="relative w-full max-w-2xl bg-white dark:bg-zinc-800 rounded-xl shadow-xl">
          {/* Header */}
          <div className="flex items-center justify-between p-4 border-b border-gray-200 dark:border-zinc-700">
            <div>
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                Create Detection Rule
              </h3>
              <p className="text-sm text-gray-500 dark:text-gray-400">
                Step {step} of 3
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
          <div className="p-4 space-y-4 max-h-[60vh] overflow-y-auto">
            {step === 1 && (
              <>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Rule ID <span className="text-danger-500">*</span>
                  </label>
                  <input
                    type="text"
                    value={id}
                    onChange={(e) => setId(e.target.value.toLowerCase().replace(/[^a-z0-9_-]/g, ''))}
                    placeholder="e.g., suspicious-dns-query"
                    className="input w-full"
                  />
                  <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                    Lowercase letters, numbers, underscores, and hyphens only
                  </p>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Name <span className="text-danger-500">*</span>
                  </label>
                  <input
                    type="text"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="e.g., Suspicious DNS Query"
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
                    placeholder="Describe what this rule detects..."
                    className="input w-full"
                    rows={3}
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
                    <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                      Minimum time between alerts for same device
                    </p>
                  </div>
                </div>
              </>
            )}

            {step === 2 && (
              <>
                <div className="flex items-center justify-between">
                  <div>
                    <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300">
                      Conditions
                    </h4>
                    <p className="text-xs text-gray-500 dark:text-gray-400">
                      Define when this rule should trigger
                    </p>
                  </div>
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

                <div className="space-y-3">
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
                        onClick={() => removeCondition(index)}
                        disabled={conditions.length === 1}
                        className="p-1.5 text-gray-400 hover:text-danger-600 dark:hover:text-danger-400 disabled:opacity-50"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  ))}
                </div>

                <button
                  onClick={addCondition}
                  className="btn-secondary text-sm inline-flex items-center gap-1"
                >
                  <Plus className="w-4 h-4" />
                  Add Condition
                </button>

                {/* Field help */}
                {fields.length > 0 && (
                  <div className="mt-4 p-3 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
                    <div className="flex items-start gap-2">
                      <Info className="w-4 h-4 text-blue-600 dark:text-blue-400 mt-0.5" />
                      <div className="text-xs text-blue-700 dark:text-blue-300">
                        <p className="font-medium mb-1">Available fields:</p>
                        <div className="flex flex-wrap gap-1">
                          {fields.slice(0, 8).map((f) => (
                            <code key={f.name} className="px-1 py-0.5 bg-blue-100 dark:bg-blue-800/50 rounded">
                              {f.name}
                            </code>
                          ))}
                          {fields.length > 8 && (
                            <span>+{fields.length - 8} more</span>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>
                )}
              </>
            )}

            {step === 3 && (
              <>
                <div>
                  <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300">
                    Actions
                  </h4>
                  <p className="text-xs text-gray-500 dark:text-gray-400">
                    What should happen when this rule triggers
                  </p>
                </div>

                <div className="space-y-3">
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
                          onClick={() => removeAction(index)}
                          disabled={actions.length === 1}
                          className="p-1.5 text-gray-400 hover:text-danger-600 dark:hover:text-danger-400 disabled:opacity-50"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>

                      <p className="text-xs text-gray-500 dark:text-gray-400">
                        {ACTION_TYPES.find((at) => at.value === action.type)?.description}
                      </p>

                      {/* Action-specific config */}
                      {action.type === 'tag_device' && (
                        <div className="mt-2">
                          <input
                            type="text"
                            value={(action.config.tag as string) || ''}
                            onChange={(e) =>
                              updateAction(index, { config: { ...action.config, tag: e.target.value } })
                            }
                            placeholder="Tag to add..."
                            className="input py-1.5 text-sm w-full"
                          />
                        </div>
                      )}

                      {action.type === 'execute_webhook' && (
                        <div className="mt-2">
                          <input
                            type="url"
                            value={(action.config.url as string) || ''}
                            onChange={(e) =>
                              updateAction(index, { config: { ...action.config, url: e.target.value } })
                            }
                            placeholder="https://..."
                            className="input py-1.5 text-sm w-full"
                          />
                        </div>
                      )}
                    </div>
                  ))}
                </div>

                <button
                  onClick={addAction}
                  className="btn-secondary text-sm inline-flex items-center gap-1"
                >
                  <Plus className="w-4 h-4" />
                  Add Action
                </button>
              </>
            )}
          </div>

          {/* Footer */}
          <div className="flex items-center justify-between p-4 border-t border-gray-200 dark:border-zinc-700">
            <button
              onClick={() => setStep(step - 1)}
              disabled={step === 1}
              className="btn-secondary disabled:opacity-50"
            >
              Back
            </button>

            <div className="flex items-center gap-2">
              {[1, 2, 3].map((s) => (
                <div
                  key={s}
                  className={clsx(
                    'w-2 h-2 rounded-full',
                    s === step
                      ? 'bg-primary-500'
                      : s < step
                      ? 'bg-primary-300 dark:bg-primary-700'
                      : 'bg-gray-300 dark:bg-zinc-600'
                  )}
                />
              ))}
            </div>

            {step < 3 ? (
              <button
                onClick={() => setStep(step + 1)}
                disabled={step === 1 ? !isStep1Valid : !isStep2Valid}
                className="btn-primary disabled:opacity-50"
              >
                Next
              </button>
            ) : (
              <button
                onClick={handleSubmit}
                disabled={!isStep3Valid || createRule.isPending}
                className="btn-primary disabled:opacity-50 inline-flex items-center gap-2"
              >
                {createRule.isPending && <Loader2 className="w-4 h-4 animate-spin" />}
                Create Rule
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
