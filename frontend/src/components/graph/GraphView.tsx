// Renders ONLY nodes and edges returned by the backend. No client-side inference of relationships.
import dagre from "@dagrejs/dagre";
import {
  Background,
  Controls,
  type Edge,
  Handle,
  MarkerType,
  MiniMap,
  type Node,
  type NodeProps,
  Position,
  ReactFlow,
  ReactFlowProvider,
} from "@xyflow/react";
import clsx from "clsx";
import { memo, useMemo } from "react";

import type { GraphEdge, GraphNode, GraphPayload } from "../../types/api";
import { labelStyle } from "./graphStyle";

const NODE_W = 196;
const NODE_H = 54;

type GNodeData = { node: GraphNode; dimmed: boolean; onPath: boolean; isTarget: boolean; selected: boolean };

const EntityNode = memo(function EntityNode({ data }: NodeProps<Node<GNodeData>>) {
  const { node, dimmed, onPath, isTarget, selected } = data;
  const st = labelStyle(node.label);
  const Icon = st.icon;
  const historical = node.properties.status === "retired";
  return (
    <div
      className={clsx(
        "flex w-[196px] items-center gap-2 rounded-lg border bg-[#0d1422] px-2 py-1.5 text-left shadow transition-opacity",
        dimmed ? "opacity-25" : "opacity-100",
        selected ? "ring-2 ring-sky-300" : onPath ? "ring-1 ring-sky-400/70" : "",
        isTarget ? "border-rose-400/80" : "border-[#2a3b5c]",
      )}
      title={`${node.label} · ${node.id}`}
    >
      <Handle type="target" position={Position.Left} className="!size-1.5 !border-0 !bg-slate-500" />
      <span className="grid size-7 shrink-0 place-items-center rounded-md" style={{ background: `${st.color}22`, color: st.color }}>
        <Icon className="size-4" aria-hidden />
      </span>
      <span className="min-w-0">
        <span className="block truncate text-[11px] font-medium text-slate-100">{node.display_name}</span>
        <span className="block truncate font-mono text-[10px] text-slate-400">
          {node.label} · {node.id}
          {historical ? " · retired" : ""}
        </span>
      </span>
      <Handle type="source" position={Position.Right} className="!size-1.5 !border-0 !bg-slate-500" />
    </div>
  );
});

const nodeTypes = { entity: EntityNode };

function layout(nodes: GraphNode[], edges: GraphEdge[]): Map<string, { x: number; y: number }> {
  const g = new dagre.graphlib.Graph();
  g.setGraph({ rankdir: "LR", nodesep: 18, ranksep: 70, marginx: 20, marginy: 20 });
  g.setDefaultEdgeLabel(() => ({}));
  nodes.forEach((n) => g.setNode(n.id, { width: NODE_W, height: NODE_H }));
  edges.forEach((e) => {
    if (g.hasNode(e.source) && g.hasNode(e.target)) g.setEdge(e.source, e.target);
  });
  dagre.layout(g);
  const out = new Map<string, { x: number; y: number }>();
  nodes.forEach((n) => {
    const p = g.node(n.id);
    out.set(n.id, { x: (p?.x ?? 0) - NODE_W / 2, y: (p?.y ?? 0) - NODE_H / 2 });
  });
  return out;
}

export interface GraphViewProps {
  payload: GraphPayload;
  targetId?: string;
  highlightPathId?: string | null;
  selectedNodeId?: string | null;
  onSelectNode?: (id: string | null) => void;
  hideLabels?: string[];
  /** Render only the highlighted path's nodes and edges (still exactly as returned by the backend). */
  pathOnly?: boolean;
  className?: string;
}

function Inner({ payload, targetId, highlightPathId, selectedNodeId, onSelectNode, hideLabels = [], pathOnly = false, className }: GraphViewProps) {
  const path = payload.paths.find((p) => p.id === highlightPathId) ?? null;
  const onlyPath = pathOnly && !!path;
  const visibleNodes = useMemo(
    () => payload.nodes.filter((n) => !hideLabels.includes(n.label) && (!onlyPath || path!.node_ids.includes(n.id))),
    [payload.nodes, hideLabels, onlyPath, path],
  );
  const visibleIds = useMemo(() => new Set(visibleNodes.map((n) => n.id)), [visibleNodes]);
  const visibleEdges = useMemo(
    () =>
      payload.edges.filter(
        (e) => visibleIds.has(e.source) && visibleIds.has(e.target) && (!onlyPath || path!.edge_ids.includes(e.id)),
      ),
    [payload.edges, visibleIds, onlyPath, path],
  );
  const pathNodes = useMemo(() => new Set(path?.node_ids ?? []), [path]);
  const pathEdges = useMemo(() => new Set(path?.edge_ids ?? []), [path]);
  const positions = useMemo(() => layout(visibleNodes, visibleEdges), [visibleNodes, visibleEdges]);

  const rfNodes: Node<GNodeData>[] = visibleNodes.map((n) => ({
    id: n.id,
    type: "entity",
    position: positions.get(n.id) ?? { x: 0, y: 0 },
    data: {
      node: n,
      dimmed: !!path && !pathNodes.has(n.id),
      onPath: pathNodes.has(n.id),
      isTarget: n.id === targetId,
      selected: n.id === selectedNodeId,
    },
    draggable: true,
  }));

  const rfEdges: Edge[] = visibleEdges.map((e) => {
    const onPath = pathEdges.has(e.id);
    const historical = e.temporal_status === "historical";
    const evidenceEdge = e.type === "SUPPORTS" || e.type === "CONTRADICTS";
    const color = onPath ? "#38bdf8" : e.type === "CONTRADICTS" ? "#fbbf24" : historical ? "#475569" : evidenceEdge ? "#64748b" : "#3b4d6e";
    return {
      id: e.id,
      source: e.source,
      target: e.target,
      label: historical ? `${e.type} (historical)` : e.type,
      animated: onPath,
      style: {
        stroke: color,
        strokeWidth: onPath ? 2.2 : 1.2,
        strokeDasharray: historical ? "5 4" : evidenceEdge ? "2 3" : undefined,
        opacity: path && !onPath ? 0.2 : 1,
      },
      labelStyle: { fontSize: 9, fill: onPath ? "#bae6fd" : "#8ea0bd" },
      labelBgStyle: { fill: "#0d1422" },
      markerEnd: { type: MarkerType.ArrowClosed, color, width: 14, height: 14 },
    };
  });

  // Focus the highlighted path (readable chain); otherwise fit the whole graph. React Flow applies
  // fitViewOptions once nodes are measured; the component is re-keyed when the focus changes.
  const focus = useMemo(
    () => (path ? path.node_ids.filter((id) => visibleIds.has(id)).map((id) => ({ id })) : undefined),
    [path, visibleIds],
  );
  const viewKey = `${path?.id ?? "all"}:${visibleNodes.length}:${onlyPath}`;

  return (
    <div className={clsx("relative h-full w-full", className)} data-testid="graph-view">
      <ReactFlow
        key={viewKey}
        fitView
        fitViewOptions={{ padding: 0.2, nodes: focus, maxZoom: 1.1 }}
        nodes={rfNodes}
        edges={rfEdges}
        nodeTypes={nodeTypes}
        onNodeClick={(_, n) => onSelectNode?.(n.id)}
        onPaneClick={() => onSelectNode?.(null)}
        minZoom={0.15}
        maxZoom={2}
        proOptions={{ hideAttribution: true }}
        colorMode="dark"
        nodesConnectable={false}
      >
        <Background gap={22} size={1} color="#1d2a42" />
        <Controls showInteractive={false} />
        <MiniMap
          pannable
          zoomable
          style={{ width: 140, height: 90, background: "#0d1422", border: "1px solid #1d2a42" }}
          nodeColor={(n) => labelStyle((n.data as GNodeData).node.label).color}
          maskColor="rgba(7,11,20,0.55)"
        />
      </ReactFlow>
      <p className="pointer-events-none absolute bottom-2 left-14 text-[10px] text-faint">
        {visibleNodes.length} nodes · {visibleEdges.length} relationships from the backend
        {payload.truncation.truncated ? " · truncated by server limits" : ""}
      </p>
    </div>
  );
}

export function GraphView(props: GraphViewProps) {
  return (
    <ReactFlowProvider>
      <Inner {...props} />
    </ReactFlowProvider>
  );
}

export function GraphLegend({ labels }: { labels: string[] }) {
  return (
    <div className="flex flex-wrap gap-x-3 gap-y-1 text-[11px] text-muted">
      {labels.map((l) => {
        const st = labelStyle(l);
        const Icon = st.icon;
        return (
          <span key={l} className="flex items-center gap-1">
            <Icon className="size-3" style={{ color: st.color }} aria-hidden /> {l}
          </span>
        );
      })}
      <span className="flex items-center gap-1"><span className="inline-block w-5 border-t border-dashed border-slate-500" /> historical</span>
      <span className="flex items-center gap-1"><span className="inline-block w-5 border-t-2 border-sky-400" /> highlighted path</span>
    </div>
  );
}
