import { useState, useEffect } from 'react';
import { X, Shield, UserCog, Eye } from 'lucide-react';
import { useUpdateUser } from '../api/hooks';
import type { User, UserRole } from '../types';
import clsx from 'clsx';

interface EditUserModalProps {
  user: User | null;
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

export default function EditUserModal({ user, isOpen, onClose }: EditUserModalProps) {
  const updateUser = useUpdateUser();

  const [email, setEmail] = useState('');
  const [role, setRole] = useState<UserRole>('viewer');
  const [isActive, setIsActive] = useState(true);
  const [errors, setErrors] = useState<Record<string, string>>({});

  // Populate form when user changes
  useEffect(() => {
    if (user) {
      setEmail(user.email);
      setRole(user.role);
      setIsActive(user.is_active);
      setErrors({});
    }
  }, [user]);

  const handleClose = () => {
    setErrors({});
    onClose();
  };

  const validate = () => {
    const newErrors: Record<string, string> = {};
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
    if (!user || !validate()) return;

    try {
      await updateUser.mutateAsync({
        id: user.id,
        email: email.toLowerCase(),
        role,
        is_active: isActive,
      });
      handleClose();
    } catch (error: unknown) {
      const err = error as { response?: { data?: { detail?: string } } };
      setErrors({
        submit: err.response?.data?.detail || 'Failed to update user',
      });
    }
  };

  if (!isOpen || !user) return null;

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
              Edit User: {user.username}
            </h2>
            <button
              onClick={handleClose}
              className="p-2 text-gray-400 hover:text-gray-600 rounded-lg hover:bg-gray-100"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

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
                value={user.username}
                disabled
                className="input w-full bg-gray-50 text-gray-500 cursor-not-allowed"
              />
              <p className="mt-1 text-xs text-gray-500">Username cannot be changed</p>
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

            <div>
              <label className="flex items-center gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={isActive}
                  onChange={(e) => setIsActive(e.target.checked)}
                  className="w-4 h-4 rounded border-gray-300 text-primary-600 focus:ring-primary-500"
                />
                <div>
                  <span className="font-medium text-gray-900">Active</span>
                  <p className="text-xs text-gray-500">
                    Inactive users cannot log in
                  </p>
                </div>
              </label>
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
                disabled={updateUser.isPending}
                className="flex-1 btn-primary"
              >
                {updateUser.isPending ? 'Saving...' : 'Save Changes'}
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
}
