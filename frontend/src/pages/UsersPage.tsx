import { useState } from 'react';
import {
  Users,
  Plus,
  RefreshCw,
  Shield,
  UserCog,
  Eye,
  MoreVertical,
  KeyRound,
  UserX,
  Pencil,
} from 'lucide-react';
import {
  useUsers,
  useDeactivateUser,
  useResetUserPassword,
  useUpdateUser,
} from '../api/hooks';
import { useAuthStore } from '../stores/auth';
import { formatDistanceToNow } from 'date-fns';
import clsx from 'clsx';
import type { User, UserRole } from '../types';
import AddUserModal from '../components/AddUserModal';
import EditUserModal from '../components/EditUserModal';

const roleIcons: Record<UserRole, typeof Shield> = {
  admin: Shield,
  operator: UserCog,
  viewer: Eye,
};

const roleColors: Record<UserRole, string> = {
  admin: 'bg-danger-100 text-danger-700',
  operator: 'bg-primary-100 text-primary-700',
  viewer: 'bg-gray-100 text-gray-700',
};

function UserCard({
  user,
  currentUserId,
  onEdit,
}: {
  user: User;
  currentUserId: string;
  onEdit: (user: User) => void;
}) {
  const [showMenu, setShowMenu] = useState(false);
  const [showTempPassword, setShowTempPassword] = useState<string | null>(null);
  const deactivateUser = useDeactivateUser();
  const resetPassword = useResetUserPassword();
  const updateUser = useUpdateUser();
  const isCurrentUser = user.id === currentUserId;

  const RoleIcon = roleIcons[user.role];

  const handleDeactivate = () => {
    if (confirm(`Deactivate user "${user.username}"? They will no longer be able to log in.`)) {
      deactivateUser.mutate(user.id);
    }
    setShowMenu(false);
  };

  const handleReactivate = () => {
    updateUser.mutate({ id: user.id, is_active: true });
    setShowMenu(false);
  };

  const handleResetPassword = async () => {
    if (confirm(`Reset password for "${user.username}"? A new temporary password will be generated.`)) {
      const result = await resetPassword.mutateAsync(user.id);
      setShowTempPassword(result.temporary_password);
    }
    setShowMenu(false);
  };

  return (
    <div className={clsx('card p-4', !user.is_active && 'opacity-60')}>
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-4 flex-1 min-w-0">
          <div
            className={clsx(
              'flex h-10 w-10 items-center justify-center rounded-full',
              roleColors[user.role]
            )}
          >
            <RoleIcon className="w-5 h-5" />
          </div>

          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2">
              <h3 className="font-semibold text-gray-900">{user.username}</h3>
              {isCurrentUser && (
                <span className="text-xs bg-primary-100 text-primary-700 px-2 py-0.5 rounded">
                  You
                </span>
              )}
              {!user.is_active && (
                <span className="text-xs bg-gray-100 text-gray-500 px-2 py-0.5 rounded">
                  Inactive
                </span>
              )}
              {user.must_change_password && (
                <span className="text-xs bg-warning-100 text-warning-700 px-2 py-0.5 rounded">
                  Must change password
                </span>
              )}
            </div>
            <p className="text-sm text-gray-500 truncate">{user.email}</p>
          </div>
        </div>

        <div className="flex items-center gap-4">
          <div className="text-right hidden sm:block">
            <span
              className={clsx('badge capitalize', roleColors[user.role])}
            >
              {user.role}
            </span>
            <p className="text-xs text-gray-400 mt-1">
              Created {formatDistanceToNow(new Date(user.created_at), { addSuffix: true })}
            </p>
          </div>

          {!isCurrentUser && (
            <div className="relative">
              <button
                onClick={() => setShowMenu(!showMenu)}
                className="p-2 text-gray-400 hover:text-gray-600 hover:bg-gray-100 rounded-lg"
              >
                <MoreVertical className="w-5 h-5" />
              </button>

              {showMenu && (
                <>
                  <div
                    className="fixed inset-0 z-10"
                    onClick={() => setShowMenu(false)}
                  />
                  <div className="absolute right-0 mt-1 w-48 bg-white rounded-lg shadow-lg border border-gray-200 z-20">
                    <button
                      onClick={() => {
                        onEdit(user);
                        setShowMenu(false);
                      }}
                      className="w-full flex items-center gap-2 px-4 py-2 text-sm text-gray-700 hover:bg-gray-50"
                    >
                      <Pencil className="w-4 h-4" />
                      Edit User
                    </button>
                    <button
                      onClick={handleResetPassword}
                      disabled={resetPassword.isPending}
                      className="w-full flex items-center gap-2 px-4 py-2 text-sm text-gray-700 hover:bg-gray-50"
                    >
                      <KeyRound className="w-4 h-4" />
                      Reset Password
                    </button>
                    <hr className="my-1" />
                    {user.is_active ? (
                      <button
                        onClick={handleDeactivate}
                        disabled={deactivateUser.isPending}
                        className="w-full flex items-center gap-2 px-4 py-2 text-sm text-danger-600 hover:bg-danger-50"
                      >
                        <UserX className="w-4 h-4" />
                        Deactivate
                      </button>
                    ) : (
                      <button
                        onClick={handleReactivate}
                        disabled={updateUser.isPending}
                        className="w-full flex items-center gap-2 px-4 py-2 text-sm text-success-600 hover:bg-success-50"
                      >
                        <UserCog className="w-4 h-4" />
                        Reactivate
                      </button>
                    )}
                  </div>
                </>
              )}
            </div>
          )}
        </div>
      </div>

      {showTempPassword && (
        <div className="mt-4 p-3 bg-warning-50 border border-warning-200 rounded-lg">
          <p className="text-sm text-warning-800 font-medium">Temporary Password</p>
          <p className="font-mono text-lg text-warning-900 mt-1">{showTempPassword}</p>
          <p className="text-xs text-warning-600 mt-2">
            Share this password securely with the user. They must change it on next login.
          </p>
          <button
            onClick={() => setShowTempPassword(null)}
            className="mt-2 text-xs text-warning-700 hover:text-warning-900"
          >
            Dismiss
          </button>
        </div>
      )}
    </div>
  );
}

export default function UsersPage() {
  const currentUser = useAuthStore((state) => state.user);
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [editingUser, setEditingUser] = useState<User | null>(null);

  const { data, isLoading, refetch, isFetching } = useUsers();

  const activeCount = data?.items.filter((u) => u.is_active).length || 0;

  if (currentUser?.role !== 'admin') {
    return (
      <div className="space-y-6">
        <h1 className="text-2xl font-bold text-gray-900">User Management</h1>
        <div className="card p-12 text-center">
          <Shield className="w-12 h-12 mx-auto mb-3 text-gray-300" />
          <p className="text-gray-500">Administrator access required</p>
          <p className="text-sm text-gray-400 mt-2">
            Only administrators can manage users
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">User Management</h1>
          <p className="text-gray-500">
            {activeCount} of {data?.total || 0} users active
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => refetch()}
            disabled={isFetching}
            className="btn-secondary"
          >
            <RefreshCw
              className={clsx('w-4 h-4 mr-2', isFetching && 'animate-spin')}
            />
            Refresh
          </button>
          <button
            className="btn-primary"
            onClick={() => setIsAddModalOpen(true)}
          >
            <Plus className="w-4 h-4 mr-2" />
            Add User
          </button>
        </div>
      </div>

      {/* Role legend */}
      <div className="flex gap-4 text-sm">
        <div className="flex items-center gap-2">
          <Shield className="w-4 h-4 text-danger-600" />
          <span className="text-gray-600">Admin - Full access</span>
        </div>
        <div className="flex items-center gap-2">
          <UserCog className="w-4 h-4 text-primary-600" />
          <span className="text-gray-600">Operator - Manage devices & alerts</span>
        </div>
        <div className="flex items-center gap-2">
          <Eye className="w-4 h-4 text-gray-600" />
          <span className="text-gray-600">Viewer - Read only</span>
        </div>
      </div>

      {/* User cards */}
      <div className="space-y-3">
        {isLoading ? (
          [...Array(3)].map((_, i) => (
            <div key={i} className="card p-4">
              <div className="animate-pulse flex items-center gap-4">
                <div className="h-10 w-10 bg-gray-100 rounded-full" />
                <div className="flex-1 space-y-2">
                  <div className="h-4 bg-gray-100 rounded w-1/4" />
                  <div className="h-3 bg-gray-100 rounded w-1/3" />
                </div>
              </div>
            </div>
          ))
        ) : data?.items.length ? (
          data.items.map((user) => (
            <UserCard
              key={user.id}
              user={user}
              currentUserId={currentUser?.id || ''}
              onEdit={setEditingUser}
            />
          ))
        ) : (
          <div className="card p-12 text-center">
            <Users className="w-12 h-12 mx-auto mb-3 text-gray-300" />
            <p className="text-gray-500">No users found</p>
          </div>
        )}
      </div>

      {/* Add User Modal */}
      <AddUserModal
        isOpen={isAddModalOpen}
        onClose={() => setIsAddModalOpen(false)}
      />

      {/* Edit User Modal */}
      <EditUserModal
        user={editingUser}
        isOpen={!!editingUser}
        onClose={() => setEditingUser(null)}
      />
    </div>
  );
}
