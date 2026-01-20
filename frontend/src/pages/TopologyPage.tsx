import { useState, useRef, useEffect, useCallback } from 'react';
import {
  Network,
  RefreshCw,
  ZoomIn,
  ZoomOut,
  Maximize2,
  Monitor,
  Wifi,
  Globe,
  Server,
  Smartphone,
  HelpCircle,
  AlertTriangle,
} from 'lucide-react';
import clsx from 'clsx';
import { useTopology } from '../api/hooks';

interface Node {
  id: string;
  label: string;
  type: string;
  status: string;
  ip_address?: string;
  mac_address?: string;
  manufacturer?: string;
  device_type?: string;
  event_count_24h: number;
  tags: string[];
  is_quarantined: boolean;
  // Simulation properties
  x: number;
  y: number;
  vx: number;
  vy: number;
  fx?: number;
  fy?: number;
}

interface Link {
  source: string;
  target: string;
  traffic_volume: number;
  link_type: string;
}

const NODE_COLORS: Record<string, string> = {
  router: '#3B82F6',
  internet: '#10B981',
  device: '#6366F1',
  server: '#8B5CF6',
  computer: '#06B6D4',
  mobile: '#F59E0B',
  iot: '#EC4899',
  unknown: '#6B7280',
};

const NODE_ICONS: Record<string, typeof Monitor> = {
  router: Wifi,
  internet: Globe,
  device: Monitor,
  server: Server,
  computer: Monitor,
  mobile: Smartphone,
  iot: Monitor,
  unknown: HelpCircle,
};

function getNodeRadius(node: Node): number {
  if (node.type === 'internet' || node.type === 'router') return 30;
  const base = 20;
  const eventBonus = Math.min(10, Math.log10(node.event_count_24h + 1) * 3);
  return base + eventBonus;
}

export default function TopologyPage() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [hours, setHours] = useState(24);
  const [includeInactive, setIncludeInactive] = useState(false);
  const [selectedNode, setSelectedNode] = useState<Node | null>(null);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
  const [nodes, setNodes] = useState<Node[]>([]);
  const [links, setLinks] = useState<Link[]>([]);
  const animationRef = useRef<number>();
  const draggedNodeRef = useRef<Node | null>(null);

  const { data, isLoading, refetch, isFetching } = useTopology({ hours, include_inactive: includeInactive });

  // Initialize nodes with positions when data changes
  useEffect(() => {
    if (!data) return;

    const canvas = canvasRef.current;
    if (!canvas) return;

    const centerX = canvas.width / 2;
    const centerY = canvas.height / 2;

    // Position nodes in a circular layout initially
    const newNodes: Node[] = data.nodes.map((node) => {
      let x, y;

      if (node.id === 'internet') {
        x = centerX;
        y = 80;
      } else if (node.id === 'router') {
        x = centerX;
        y = centerY - 50;
      } else {
        // Arrange devices in a circle around the router
        const deviceNodes = data.nodes.filter(n => n.id !== 'internet' && n.id !== 'router');
        const deviceIndex = deviceNodes.findIndex(n => n.id === node.id);
        const angle = (deviceIndex / deviceNodes.length) * 2 * Math.PI - Math.PI / 2;
        const radius = 180;
        x = centerX + Math.cos(angle) * radius;
        y = centerY + Math.sin(angle) * radius + 50;
      }

      return {
        ...node,
        x,
        y,
        vx: 0,
        vy: 0,
      };
    });

    setNodes(newNodes);
    setLinks(data.links);
  }, [data]);

  // Force simulation
  useEffect(() => {
    if (nodes.length === 0) return;

    const simulate = () => {
      setNodes(prevNodes => {
        const newNodes = [...prevNodes];

        // Apply forces
        for (let i = 0; i < newNodes.length; i++) {
          const node = newNodes[i];

          // Skip fixed nodes
          if (node.fx !== undefined) {
            node.x = node.fx;
            node.y = node.fy!;
            continue;
          }

          // Repulsion between nodes
          for (let j = 0; j < newNodes.length; j++) {
            if (i === j) continue;
            const other = newNodes[j];
            const dx = node.x - other.x;
            const dy = node.y - other.y;
            const dist = Math.sqrt(dx * dx + dy * dy) || 1;
            const force = 500 / (dist * dist);
            node.vx += (dx / dist) * force * 0.1;
            node.vy += (dy / dist) * force * 0.1;
          }

          // Attraction along links
          links.forEach(link => {
            let other: Node | undefined;
            if (link.source === node.id) {
              other = newNodes.find(n => n.id === link.target);
            } else if (link.target === node.id) {
              other = newNodes.find(n => n.id === link.source);
            }

            if (other) {
              const dx = other.x - node.x;
              const dy = other.y - node.y;
              const dist = Math.sqrt(dx * dx + dy * dy) || 1;
              const targetDist = 150;
              const force = (dist - targetDist) * 0.01;
              node.vx += (dx / dist) * force;
              node.vy += (dy / dist) * force;
            }
          });

          // Center gravity
          const canvas = canvasRef.current;
          if (canvas) {
            const centerX = canvas.width / 2;
            const centerY = canvas.height / 2;
            node.vx += (centerX - node.x) * 0.001;
            node.vy += (centerY - node.y) * 0.001;
          }

          // Apply velocity with damping
          node.vx *= 0.9;
          node.vy *= 0.9;
          node.x += node.vx;
          node.y += node.vy;
        }

        return newNodes;
      });

      animationRef.current = requestAnimationFrame(simulate);
    };

    animationRef.current = requestAnimationFrame(simulate);

    return () => {
      if (animationRef.current) {
        cancelAnimationFrame(animationRef.current);
      }
    };
  }, [links, nodes.length]);

  // Draw canvas
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const draw = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      ctx.save();
      ctx.translate(pan.x, pan.y);
      ctx.scale(zoom, zoom);

      // Draw links
      links.forEach(link => {
        const sourceNode = nodes.find(n => n.id === link.source);
        const targetNode = nodes.find(n => n.id === link.target);
        if (!sourceNode || !targetNode) return;

        ctx.beginPath();
        ctx.moveTo(sourceNode.x, sourceNode.y);
        ctx.lineTo(targetNode.x, targetNode.y);

        if (link.link_type === 'blocked') {
          ctx.strokeStyle = '#EF4444';
          ctx.setLineDash([5, 5]);
        } else {
          const alpha = Math.min(0.8, 0.2 + (link.traffic_volume / 1000) * 0.6);
          ctx.strokeStyle = `rgba(156, 163, 175, ${alpha})`;
          ctx.setLineDash([]);
        }

        ctx.lineWidth = Math.min(4, 1 + Math.log10(link.traffic_volume + 1));
        ctx.stroke();
        ctx.setLineDash([]);
      });

      // Draw nodes
      nodes.forEach(node => {
        const radius = getNodeRadius(node);
        const color = node.is_quarantined ? '#EF4444' : (NODE_COLORS[node.type] || NODE_COLORS.unknown);

        // Node circle
        ctx.beginPath();
        ctx.arc(node.x, node.y, radius, 0, 2 * Math.PI);
        ctx.fillStyle = color;
        ctx.fill();

        if (selectedNode?.id === node.id) {
          ctx.strokeStyle = '#FCD34D';
          ctx.lineWidth = 3;
          ctx.stroke();
        }

        // Node label
        ctx.fillStyle = '#FFFFFF';
        ctx.font = '10px sans-serif';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';

        const label = node.label.length > 12 ? node.label.substring(0, 12) + '...' : node.label;
        ctx.fillText(label, node.x, node.y + radius + 12);
      });

      ctx.restore();
      requestAnimationFrame(draw);
    };

    draw();
  }, [nodes, links, selectedNode, zoom, pan]);

  // Handle canvas resize
  useEffect(() => {
    const handleResize = () => {
      const canvas = canvasRef.current;
      const container = containerRef.current;
      if (!canvas || !container) return;

      canvas.width = container.clientWidth;
      canvas.height = container.clientHeight;
    };

    handleResize();
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  // Mouse handlers
  const getMousePos = useCallback((e: React.MouseEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current;
    if (!canvas) return { x: 0, y: 0 };

    const rect = canvas.getBoundingClientRect();
    return {
      x: (e.clientX - rect.left - pan.x) / zoom,
      y: (e.clientY - rect.top - pan.y) / zoom,
    };
  }, [pan, zoom]);

  const findNodeAtPosition = useCallback((x: number, y: number): Node | null => {
    for (const node of nodes) {
      const radius = getNodeRadius(node);
      const dx = x - node.x;
      const dy = y - node.y;
      if (dx * dx + dy * dy < radius * radius) {
        return node;
      }
    }
    return null;
  }, [nodes]);

  const handleMouseDown = useCallback((e: React.MouseEvent<HTMLCanvasElement>) => {
    const pos = getMousePos(e);
    const node = findNodeAtPosition(pos.x, pos.y);

    if (node) {
      draggedNodeRef.current = node;
      setNodes(prev => prev.map(n =>
        n.id === node.id ? { ...n, fx: n.x, fy: n.y } : n
      ));
    } else {
      setIsDragging(true);
      setDragStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
    }
  }, [getMousePos, findNodeAtPosition, pan]);

  const handleMouseMove = useCallback((e: React.MouseEvent<HTMLCanvasElement>) => {
    if (draggedNodeRef.current) {
      const pos = getMousePos(e);
      setNodes(prev => prev.map(n =>
        n.id === draggedNodeRef.current?.id
          ? { ...n, x: pos.x, y: pos.y, fx: pos.x, fy: pos.y }
          : n
      ));
    } else if (isDragging) {
      setPan({
        x: e.clientX - dragStart.x,
        y: e.clientY - dragStart.y,
      });
    }
  }, [getMousePos, isDragging, dragStart]);

  const handleMouseUp = useCallback(() => {
    if (draggedNodeRef.current) {
      setNodes(prev => prev.map(n =>
        n.id === draggedNodeRef.current?.id
          ? { ...n, fx: undefined, fy: undefined }
          : n
      ));
      draggedNodeRef.current = null;
    }
    setIsDragging(false);
  }, []);

  const handleClick = useCallback((e: React.MouseEvent<HTMLCanvasElement>) => {
    const pos = getMousePos(e);
    const node = findNodeAtPosition(pos.x, pos.y);
    setSelectedNode(node);
  }, [getMousePos, findNodeAtPosition]);

  const handleWheel = useCallback((e: React.WheelEvent<HTMLCanvasElement>) => {
    e.preventDefault();
    const delta = e.deltaY > 0 ? 0.9 : 1.1;
    setZoom(prev => Math.max(0.3, Math.min(3, prev * delta)));
  }, []);

  const resetView = useCallback(() => {
    setZoom(1);
    setPan({ x: 0, y: 0 });
  }, []);

  const NodeIcon = selectedNode ? (NODE_ICONS[selectedNode.type] || Monitor) : Monitor;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
            Network Topology
          </h1>
          <p className="text-gray-500 dark:text-gray-400">
            Visual map of your network devices and connections
          </p>
        </div>
        <div className="flex items-center gap-3">
          <select
            value={hours}
            onChange={(e) => setHours(Number(e.target.value))}
            className="input w-32"
          >
            <option value={1}>1 hour</option>
            <option value={6}>6 hours</option>
            <option value={24}>24 hours</option>
            <option value={72}>3 days</option>
            <option value={168}>7 days</option>
          </select>
          <label className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-400">
            <input
              type="checkbox"
              checked={includeInactive}
              onChange={(e) => setIncludeInactive(e.target.checked)}
              className="rounded"
            />
            Inactive
          </label>
          <button
            onClick={() => refetch()}
            disabled={isFetching}
            className="btn-secondary"
          >
            <RefreshCw className={clsx('w-4 h-4', isFetching && 'animate-spin')} />
          </button>
        </div>
      </div>

      {/* Stats */}
      {data?.stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="card p-4">
            <div className="text-2xl font-bold text-gray-900 dark:text-white">
              {data.stats.total_devices}
            </div>
            <div className="text-sm text-gray-500 dark:text-gray-400">Total Devices</div>
          </div>
          <div className="card p-4">
            <div className="text-2xl font-bold text-green-600 dark:text-green-400">
              {data.stats.active_devices}
            </div>
            <div className="text-sm text-gray-500 dark:text-gray-400">Active</div>
          </div>
          <div className="card p-4">
            <div className="text-2xl font-bold text-red-600 dark:text-red-400">
              {data.stats.quarantined_devices}
            </div>
            <div className="text-sm text-gray-500 dark:text-gray-400">Quarantined</div>
          </div>
          <div className="card p-4">
            <div className="text-2xl font-bold text-primary-600 dark:text-primary-400">
              {data.stats.total_events.toLocaleString()}
            </div>
            <div className="text-sm text-gray-500 dark:text-gray-400">Events ({hours}h)</div>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Canvas */}
        <div className="lg:col-span-3 card overflow-hidden">
          <div className="flex items-center justify-between p-4 border-b border-gray-200 dark:border-zinc-700">
            <h3 className="font-semibold text-gray-900 dark:text-white flex items-center gap-2">
              <Network className="w-5 h-5" />
              Network Map
            </h3>
            <div className="flex items-center gap-2">
              <button onClick={() => setZoom(z => Math.min(3, z * 1.2))} className="p-1.5 hover:bg-gray-100 dark:hover:bg-zinc-700 rounded">
                <ZoomIn className="w-4 h-4" />
              </button>
              <button onClick={() => setZoom(z => Math.max(0.3, z / 1.2))} className="p-1.5 hover:bg-gray-100 dark:hover:bg-zinc-700 rounded">
                <ZoomOut className="w-4 h-4" />
              </button>
              <button onClick={resetView} className="p-1.5 hover:bg-gray-100 dark:hover:bg-zinc-700 rounded">
                <Maximize2 className="w-4 h-4" />
              </button>
            </div>
          </div>
          <div ref={containerRef} className="relative h-[500px] bg-gray-50 dark:bg-zinc-900">
            {isLoading ? (
              <div className="absolute inset-0 flex items-center justify-center">
                <RefreshCw className="w-8 h-8 animate-spin text-gray-400" />
              </div>
            ) : (
              <canvas
                ref={canvasRef}
                onMouseDown={handleMouseDown}
                onMouseMove={handleMouseMove}
                onMouseUp={handleMouseUp}
                onMouseLeave={handleMouseUp}
                onClick={handleClick}
                onWheel={handleWheel}
                className="cursor-grab active:cursor-grabbing"
              />
            )}
          </div>
          {/* Legend */}
          <div className="p-4 border-t border-gray-200 dark:border-zinc-700 flex flex-wrap gap-4 text-xs">
            {Object.entries(NODE_COLORS).slice(0, 6).map(([type, color]) => (
              <div key={type} className="flex items-center gap-1.5">
                <div className="w-3 h-3 rounded-full" style={{ backgroundColor: color }} />
                <span className="text-gray-600 dark:text-gray-400 capitalize">{type}</span>
              </div>
            ))}
            <div className="flex items-center gap-1.5">
              <div className="w-3 h-3 rounded-full bg-red-500" />
              <span className="text-gray-600 dark:text-gray-400">Quarantined</span>
            </div>
          </div>
        </div>

        {/* Details Panel */}
        <div className="card p-4">
          <h3 className="font-semibold text-gray-900 dark:text-white mb-4">
            {selectedNode ? 'Device Details' : 'Select a Device'}
          </h3>
          {selectedNode ? (
            <div className="space-y-4">
              <div className="flex items-center gap-3">
                <div
                  className="p-3 rounded-lg"
                  style={{ backgroundColor: NODE_COLORS[selectedNode.type] || NODE_COLORS.unknown }}
                >
                  <NodeIcon className="w-6 h-6 text-white" />
                </div>
                <div>
                  <div className="font-medium text-gray-900 dark:text-white">
                    {selectedNode.label}
                  </div>
                  <div className="text-sm text-gray-500 dark:text-gray-400 capitalize">
                    {selectedNode.type}
                  </div>
                </div>
              </div>

              {selectedNode.is_quarantined && (
                <div className="flex items-center gap-2 p-2 bg-red-50 dark:bg-red-900/20 rounded text-red-600 dark:text-red-400 text-sm">
                  <AlertTriangle className="w-4 h-4" />
                  Quarantined
                </div>
              )}

              <div className="space-y-2 text-sm">
                {selectedNode.ip_address && (
                  <div className="flex justify-between">
                    <span className="text-gray-500 dark:text-gray-400">IP Address</span>
                    <span className="text-gray-900 dark:text-white font-mono">
                      {selectedNode.ip_address}
                    </span>
                  </div>
                )}
                {selectedNode.mac_address && (
                  <div className="flex justify-between">
                    <span className="text-gray-500 dark:text-gray-400">MAC</span>
                    <span className="text-gray-900 dark:text-white font-mono text-xs">
                      {selectedNode.mac_address}
                    </span>
                  </div>
                )}
                {selectedNode.manufacturer && (
                  <div className="flex justify-between">
                    <span className="text-gray-500 dark:text-gray-400">Manufacturer</span>
                    <span className="text-gray-900 dark:text-white">
                      {selectedNode.manufacturer}
                    </span>
                  </div>
                )}
                <div className="flex justify-between">
                  <span className="text-gray-500 dark:text-gray-400">Status</span>
                  <span className={clsx(
                    'capitalize',
                    selectedNode.status === 'active' && 'text-green-600 dark:text-green-400',
                    selectedNode.status === 'quarantined' && 'text-red-600 dark:text-red-400',
                    selectedNode.status === 'inactive' && 'text-gray-600 dark:text-gray-400'
                  )}>
                    {selectedNode.status}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500 dark:text-gray-400">Events ({hours}h)</span>
                  <span className="text-gray-900 dark:text-white">
                    {selectedNode.event_count_24h.toLocaleString()}
                  </span>
                </div>
              </div>

              {selectedNode.tags.length > 0 && (
                <div>
                  <div className="text-sm text-gray-500 dark:text-gray-400 mb-2">Tags</div>
                  <div className="flex flex-wrap gap-1">
                    {selectedNode.tags.map(tag => (
                      <span
                        key={tag}
                        className="px-2 py-0.5 bg-gray-100 dark:bg-zinc-700 rounded text-xs"
                      >
                        {tag}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {selectedNode.id !== 'internet' && selectedNode.id !== 'router' && (
                <a
                  href={`/devices/${selectedNode.id}`}
                  className="btn-primary w-full text-center"
                >
                  View Device Details
                </a>
              )}
            </div>
          ) : (
            <p className="text-sm text-gray-500 dark:text-gray-400">
              Click on a node in the network map to view its details.
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
