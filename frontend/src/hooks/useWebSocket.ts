import { useEffect, useRef, useState, useCallback } from 'react';
import { useAuthStore } from '../stores/auth';

export type WebSocketMessageType =
  | 'connection_info'
  | 'heartbeat'
  | 'pong'
  | 'alert_created'
  | 'alert_updated'
  | 'device_status_changed'
  | 'anomaly_detected'
  | 'system_notification';

export interface WebSocketMessage<T = unknown> {
  type: WebSocketMessageType;
  data: T;
  timestamp: string;
}

export interface ConnectionInfo {
  status: 'connected' | 'disconnected';
  client_id?: string;
  timestamp?: string;
}

export interface AlertCreatedData {
  id: string;
  title: string;
  description: string;
  severity: string;
  status: string;
}

export interface AlertUpdatedData {
  alert_id: string;
  status?: string;
  [key: string]: unknown;
}

export interface DeviceStatusChangedData {
  device_id: string;
  new_status: string;
  hostname?: string;
  [key: string]: unknown;
}

export interface AnomalyDetectedData {
  id: string;
  device_id: string;
  anomaly_type: string;
  description: string;
  severity: string;
}

export interface SystemNotificationData {
  title: string;
  message: string;
  severity: 'info' | 'warning' | 'error' | 'success';
}

type MessageHandler = (message: WebSocketMessage) => void;

interface UseWebSocketOptions {
  onMessage?: MessageHandler;
  onConnect?: () => void;
  onDisconnect?: () => void;
  onError?: (error: Event) => void;
  reconnectAttempts?: number;
  reconnectInterval?: number;
}

interface UseWebSocketReturn {
  isConnected: boolean;
  connectionInfo: ConnectionInfo | null;
  lastMessage: WebSocketMessage | null;
  sendMessage: (message: string) => void;
  reconnect: () => void;
}

export function useWebSocket(options: UseWebSocketOptions = {}): UseWebSocketReturn {
  const {
    onMessage,
    onConnect,
    onDisconnect,
    onError,
    reconnectAttempts = 5,
    reconnectInterval = 3000,
  } = options;

  const accessToken = useAuthStore((state) => state.accessToken);
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated);

  const [isConnected, setIsConnected] = useState(false);
  const [connectionInfo, setConnectionInfo] = useState<ConnectionInfo | null>(null);
  const [lastMessage, setLastMessage] = useState<WebSocketMessage | null>(null);

  const wsRef = useRef<WebSocket | null>(null);
  const reconnectAttemptsRef = useRef(0);
  const reconnectTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const pingIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const hasLoggedErrorRef = useRef(false);
  const maxRetriesExhaustedRef = useRef(false);

  // Store callbacks in refs to avoid re-creating connect function
  const onMessageRef = useRef(onMessage);
  const onConnectRef = useRef(onConnect);
  const onDisconnectRef = useRef(onDisconnect);
  const onErrorRef = useRef(onError);

  // Update refs when callbacks change
  onMessageRef.current = onMessage;
  onConnectRef.current = onConnect;
  onDisconnectRef.current = onDisconnect;
  onErrorRef.current = onError;

  const clearTimers = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }
    if (pingIntervalRef.current) {
      clearInterval(pingIntervalRef.current);
      pingIntervalRef.current = null;
    }
  }, []);

  const connect = useCallback(() => {
    if (!accessToken || !isAuthenticated) {
      return;
    }

    // Don't attempt to reconnect if max retries exhausted
    if (maxRetriesExhaustedRef.current) {
      return;
    }

    // Don't connect if already connected or connecting
    if (wsRef.current && (wsRef.current.readyState === WebSocket.OPEN || wsRef.current.readyState === WebSocket.CONNECTING)) {
      return;
    }

    // Construct WebSocket URL
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host;
    const wsUrl = `${protocol}//${host}/api/v1/ws?token=${encodeURIComponent(accessToken)}`;

    try {
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        setIsConnected(true);
        reconnectAttemptsRef.current = 0;
        hasLoggedErrorRef.current = false;
        maxRetriesExhaustedRef.current = false;
        onConnectRef.current?.();

        // Set up ping interval to keep connection alive
        pingIntervalRef.current = setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send('ping');
          }
        }, 25000);
      };

      ws.onmessage = (event) => {
        try {
          const message: WebSocketMessage = JSON.parse(event.data);
          setLastMessage(message);

          // Handle connection info
          if (message.type === 'connection_info') {
            setConnectionInfo(message.data as ConnectionInfo);
          }

          onMessageRef.current?.(message);
        } catch (error) {
          console.error('Failed to parse WebSocket message:', error);
        }
      };

      ws.onclose = () => {
        setIsConnected(false);
        setConnectionInfo({ status: 'disconnected' });
        clearTimers();
        onDisconnectRef.current?.();

        // Attempt reconnection with exponential backoff
        if (reconnectAttemptsRef.current < reconnectAttempts && isAuthenticated) {
          reconnectAttemptsRef.current += 1;
          // Exponential backoff: 3s, 6s, 12s, 24s, 48s
          const backoffDelay = reconnectInterval * Math.pow(2, reconnectAttemptsRef.current - 1);
          reconnectTimeoutRef.current = setTimeout(() => {
            connect();
          }, backoffDelay);
        } else if (reconnectAttemptsRef.current >= reconnectAttempts) {
          maxRetriesExhaustedRef.current = true;
          if (!hasLoggedErrorRef.current) {
            console.warn('WebSocket: Max reconnection attempts reached. Call reconnect() to try again.');
          }
        }
      };

      ws.onerror = (error) => {
        // Only log the first error to prevent console spam
        if (!hasLoggedErrorRef.current) {
          console.warn('WebSocket connection failed. Backend may be unavailable.', error);
          hasLoggedErrorRef.current = true;
        }
        onErrorRef.current?.(error);
      };
    } catch (error) {
      if (!hasLoggedErrorRef.current) {
        console.warn('Failed to create WebSocket connection:', error);
        hasLoggedErrorRef.current = true;
      }
    }
  }, [
    accessToken,
    isAuthenticated,
    reconnectAttempts,
    reconnectInterval,
    clearTimers,
  ]);

  const disconnect = useCallback(() => {
    clearTimers();
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    setIsConnected(false);
    setConnectionInfo(null);
  }, [clearTimers]);

  const reconnect = useCallback(() => {
    disconnect();
    reconnectAttemptsRef.current = 0;
    hasLoggedErrorRef.current = false;
    maxRetriesExhaustedRef.current = false;
    connect();
  }, [connect, disconnect]);

  const sendMessage = useCallback((message: string) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(message);
    }
  }, []);

  // Connect when authenticated, disconnect when logged out
  // Only depend on auth state, not on connect/disconnect functions
  useEffect(() => {
    if (isAuthenticated && accessToken) {
      // Reset state on new auth session
      hasLoggedErrorRef.current = false;
      maxRetriesExhaustedRef.current = false;
      reconnectAttemptsRef.current = 0;
      connect();
    } else {
      disconnect();
    }

    return () => {
      disconnect();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isAuthenticated, accessToken]);

  return {
    isConnected,
    connectionInfo,
    lastMessage,
    sendMessage,
    reconnect,
  };
}
