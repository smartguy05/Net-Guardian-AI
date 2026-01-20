import { createContext, useContext, useCallback, ReactNode, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import {
  useWebSocket,
  WebSocketMessage,
  AlertCreatedData,
  AlertUpdatedData,
  DeviceStatusChangedData,
  AnomalyDetectedData,
  SystemNotificationData,
} from '../hooks/useWebSocket';

export interface Toast {
  id: string;
  type: 'info' | 'success' | 'warning' | 'error';
  title: string;
  message: string;
  duration?: number;
}

interface RealtimeContextValue {
  isConnected: boolean;
  toasts: Toast[];
  addToast: (toast: Omit<Toast, 'id'>) => void;
  removeToast: (id: string) => void;
}

const RealtimeContext = createContext<RealtimeContextValue | null>(null);

export function useRealtime() {
  const context = useContext(RealtimeContext);
  if (!context) {
    throw new Error('useRealtime must be used within a RealtimeProvider');
  }
  return context;
}

interface RealtimeProviderProps {
  children: ReactNode;
}

export function RealtimeProvider({ children }: RealtimeProviderProps) {
  const queryClient = useQueryClient();
  const [toasts, setToasts] = useState<Toast[]>([]);

  const addToast = useCallback((toast: Omit<Toast, 'id'>) => {
    const id = `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    const newToast = { ...toast, id };
    setToasts((prev) => [...prev, newToast]);

    // Auto-remove toast after duration
    const duration = toast.duration ?? 5000;
    if (duration > 0) {
      setTimeout(() => {
        setToasts((prev) => prev.filter((t) => t.id !== id));
      }, duration);
    }
  }, []);

  const removeToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const handleMessage = useCallback(
    (message: WebSocketMessage) => {
      switch (message.type) {
        case 'alert_created': {
          const data = message.data as AlertCreatedData;
          queryClient.invalidateQueries({ queryKey: ['alerts'] });
          queryClient.invalidateQueries({ queryKey: ['stats'] });
          addToast({
            type: data.severity === 'critical' || data.severity === 'high' ? 'error' : 'warning',
            title: 'New Alert',
            message: data.title,
          });
          break;
        }

        case 'alert_updated': {
          const data = message.data as AlertUpdatedData;
          queryClient.invalidateQueries({ queryKey: ['alerts'] });
          queryClient.invalidateQueries({ queryKey: ['alert', data.alert_id] });
          break;
        }

        case 'device_status_changed': {
          const data = message.data as DeviceStatusChangedData;
          queryClient.invalidateQueries({ queryKey: ['devices'] });
          queryClient.invalidateQueries({ queryKey: ['device', data.device_id] });

          const statusMessages: Record<string, string> = {
            quarantined: 'has been quarantined',
            active: 'is now active',
            inactive: 'is now inactive',
          };
          const statusMsg = statusMessages[data.new_status] || `status changed to ${data.new_status}`;
          const deviceName = data.hostname || data.device_id;

          addToast({
            type: data.new_status === 'quarantined' ? 'warning' : 'info',
            title: 'Device Status Changed',
            message: `${deviceName} ${statusMsg}`,
          });
          break;
        }

        case 'anomaly_detected': {
          const data = message.data as AnomalyDetectedData;
          queryClient.invalidateQueries({ queryKey: ['anomalies'] });
          queryClient.invalidateQueries({ queryKey: ['stats'] });
          addToast({
            type: 'warning',
            title: 'Anomaly Detected',
            message: data.description,
          });
          break;
        }

        case 'system_notification': {
          const data = message.data as SystemNotificationData;
          addToast({
            type: data.severity,
            title: data.title,
            message: data.message,
          });
          break;
        }

        default:
          // Ignore heartbeat, pong, connection_info messages
          break;
      }
    },
    [queryClient, addToast]
  );

  const { isConnected } = useWebSocket({
    onMessage: handleMessage,
    onConnect: () => {
      console.log('WebSocket connected');
    },
    onDisconnect: () => {
      console.log('WebSocket disconnected');
    },
  });

  return (
    <RealtimeContext.Provider value={{ isConnected, toasts, addToast, removeToast }}>
      {children}
      <ToastContainer toasts={toasts} onRemove={removeToast} />
    </RealtimeContext.Provider>
  );
}

interface ToastContainerProps {
  toasts: Toast[];
  onRemove: (id: string) => void;
}

function ToastContainer({ toasts, onRemove }: ToastContainerProps) {
  if (toasts.length === 0) return null;

  return (
    <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 max-w-sm">
      {toasts.map((toast) => (
        <ToastItem key={toast.id} toast={toast} onRemove={onRemove} />
      ))}
    </div>
  );
}

interface ToastItemProps {
  toast: Toast;
  onRemove: (id: string) => void;
}

function ToastItem({ toast, onRemove }: ToastItemProps) {
  const [isExiting, setIsExiting] = useState(false);

  const handleRemove = () => {
    setIsExiting(true);
    setTimeout(() => onRemove(toast.id), 150);
  };

  const typeStyles = {
    info: 'bg-primary-50 dark:bg-primary-900/30 border-primary-500 text-primary-800 dark:text-primary-200',
    success: 'bg-success-50 dark:bg-success-900/30 border-success-500 text-success-800 dark:text-success-200',
    warning: 'bg-warning-50 dark:bg-warning-900/30 border-warning-500 text-warning-800 dark:text-warning-200',
    error: 'bg-danger-50 dark:bg-danger-900/30 border-danger-500 text-danger-800 dark:text-danger-200',
  };

  return (
    <div
      className={`
        ${typeStyles[toast.type]}
        border-l-4 rounded-lg shadow-lg p-4
        transform transition-all duration-150
        ${isExiting ? 'opacity-0 translate-x-4' : 'opacity-100 translate-x-0'}
      `}
      role="alert"
    >
      <div className="flex items-start gap-3">
        <div className="flex-1 min-w-0">
          <p className="font-medium text-sm">{toast.title}</p>
          <p className="text-sm opacity-90 mt-0.5">{toast.message}</p>
        </div>
        <button
          onClick={handleRemove}
          className="flex-shrink-0 p-1 hover:bg-black/10 dark:hover:bg-white/10 rounded"
          aria-label="Dismiss"
        >
          <svg
            className="w-4 h-4"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M6 18L18 6M6 6l12 12"
            />
          </svg>
        </button>
      </div>
    </div>
  );
}
