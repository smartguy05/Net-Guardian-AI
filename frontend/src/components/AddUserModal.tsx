import { useState } from 'react';
import { X, Shield, UserCog, Eye, Copy, Check } from 'lucide-react';
import { useCreateUser } from '../api/hooks';
import type { UserRole } from '../types';
import clsx from 'clsx';

interface AddUserModalProps {
  isOpen: boolean;
  onClose: () => void;
}

const roleOptions: { value: UserRole; label: string; description: string; icon: typeof Shield }[] = [
  {
    value: 'admin',
    label: 'Administrator',
    description: 'Full system access including user management',
    icon: Shield,
  },
  {
    value: 'operator',
    label: 'Operator',
    description: 'Manage devices, alerts, and sources',
    icon: UserCog,
  },
  {
    value: 'viewer',
    label: 'Viewer',
    description: 'Read-only access to dashboard and events',
    icon: Eye,
  },
];

export default function AddUserModal({ isOpen, onClose }: AddUserModalProps) {
  const createUser = useCreateUser();

  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [role, setRole] = useState<UserRole>('viewer');
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [createdUser, setCreatedUser] = useState<{ username: string; tempPassword: string } | null>(null);
  const [copied, setCopied] = useState(false);

  const resetForm = () => {
    setUsername('');
    setEmail('');
    setRole('viewer');
    setErrors({});
    setCreatedUser(null);
    setCopied(false);
  };

  const handleClose = () => {
    resetForm();
    onClose();
  };

  const validate = () => {
    const newErrors: Record<string, string> = {};
    if (!username.trim()) {
      newErrors.username = 'Username is required';
    } else if (!/^[a-z0-9_-]+$/.test(username)) {
      newErrors.username = 'Username must be lowercase letters, numbers, underscores, and hyphens only';
    } else if (username.length < 3) {
      newErrors.username = 'Username must be at least 3 characters';
    }
    if (!email.trim()) {
      newErrors.email = 'Email is required';
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      newErrors.email = 'Invalid email address';
    }
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!validate()) return;

    try {
      await createUser.mutateAsync({
        username: username.toLowerCase(),
        email: email.toLowerCase(),
        role,
      });
      // Note: The backend returns the user but not the temp password in the response
      // In a real app, you'd want the backend to return the temp password or send an email
      setCreatedUser({
        username: username.toLowerCase(),
        tempPassword: 'Check backend logs for temporary password',
      });
    } catch (error: unknown) {
      const err = error as { response?: { data?: { detail?: string } } };
      setErrors({
        submit: err.response?.data?.detail || 'Failed to create user',
      });
    }
  };

  const copyPassword = () => {
    if (createdUser?.tempPassword) {
      navigator.clipboard.writeText(createdUser.tempPassword);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto">
      <div className="flex min-h-full items-center justify-center p-4">
        <div
          className="fixed inset-0 bg-gray-900/50 transition-opacity"
          onClick={handleClose}
        />

        <div className="relative w-full max-w-md bg-white rounded-xl shadow-xl">
          <div className="flex items-center justify-between p-4 border-b border-gray-200">
            <h2 className="text-lg font-semibold text-gray-900">
              {createdUser ? 'User Created' : 'Add New User'}
            </h2>
            <button
              onClick={handleClose}
              className="p-2 text-gray-400 hover:text-gray-600 rounded-lg hover:bg-gray-100"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {createdUser ? (
            <div className="p-6">
              <div className="text-center mb-6">
                <div className="mx-auto w-12 h-12 bg-success-100 rounded-full flex items-center justify-center mb-3">
                  <Check className="w-6 h-6 text-success-600" />
                </div>
                <h3 className="text-lg font-medium text-gray-900">
                  User "{createdUser.username}" created successfully
                </h3>
              </div>

              <div className="bg-warning-50 border border-warning-200 rounded-lg p-4">
                <p className="text-sm font-medium text-warning-800 mb-2">
                  Temporary Password
                </p>
                <div className="flex items-center gap-2">
                  <code className="flex-1 bg-white px-3 py-2 rounded border border-warning-200 text-sm font-mono">
                    {createdUser.tempPassword}
                  </code>
                  <button
                    onClick={copyPassword}
                    className="p-2 text-warning-600 hover:text-warning-800 hover:bg-warning-100 rounded-lg"
                  >
                    {copied ? (
                      <Check className="w-5 h-5 text-success-600" />
                    ) : (
                      <Copy className="w-5 h-5" />
                    )}
                  </button>
                </div>
                <p className="text-xs text-warning-600 mt-2">
                  The user must change this password on first login.
                  Check backend logs for the actual temporary password.
                </p>
              </div>

              <button
                onClick={handleClose}
                className="w-full mt-6 btn-primary"
              >
                Done
              </button>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="p-6 space-y-4">
              {errors.submit && (
                <div className="p-3 bg-danger-50 border border-danger-200 rounded-lg">
                  <p className="text-sm text-danger-700">{errors.submit}</p>
                </div>
              )}

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Username
                </label>
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value.toLowerCase())}
                  className={clsx('input w-full', errors.username && 'border-danger-500')}
                  placeholder="johndoe"
                />
                {errors.username && (
                  <p className="mt-1 text-xs text-danger-600">{errors.username}</p>
                )}
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Email
                </label>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className={clsx('input w-full', errors.email && 'border-danger-500')}
                  placeholder="john@example.com"
                />
                {errors.email && (
                  <p className="mt-1 text-xs text-danger-600">{errors.email}</p>
                )}
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Role
                </label>
                <div className="space-y-2">
                  {roleOptions.map((option) => {
                    const Icon = option.icon;
                    return (
                      <label
                        key={option.value}
                        className={clsx(
                          'flex items-center gap-3 p-3 border rounded-lg cursor-pointer transition-colors',
                          role === option.value
                            ? 'border-primary-500 bg-primary-50'
                            : 'border-gray-200 hover:border-gray-300'
                        )}
                      >
                        <input
                          type="radio"
                          name="role"
                          value={option.value}
                          checked={role === option.value}
                          onChange={(e) => setRole(e.target.value as UserRole)}
                          className="sr-only"
                        />
                        <Icon
                          className={clsx(
                            'w-5 h-5',
                            role === option.value ? 'text-primary-600' : 'text-gray-400'
                          )}
                        />
                        <div>
                          <p
                            className={clsx(
                              'font-medium',
                              role === option.value ? 'text-primary-900' : 'text-gray-900'
                            )}
                          >
                            {option.label}
                          </p>
                          <p className="text-xs text-gray-500">{option.description}</p>
                        </div>
                      </label>
                    );
                  })}
                </div>
              </div>

              <div className="flex gap-3 pt-4">
                <button
                  type="button"
                  onClick={handleClose}
                  className="flex-1 btn-secondary"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={createUser.isPending}
                  className="flex-1 btn-primary"
                >
                  {createUser.isPending ? 'Creating...' : 'Create User'}
                </button>
              </div>
            </form>
          )}
        </div>
      </div>
    </div>
  );
}
