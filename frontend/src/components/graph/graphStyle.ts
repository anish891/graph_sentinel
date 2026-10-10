import {
  AlertTriangle,
  Bug,
  Building2,
  Cpu,
  FileText,
  Fingerprint,
  Flag,
  Globe,
  KeyRound,
  type LucideIcon,
  Server,
  Shield,
  Swords,
  User,
  Zap,
} from "lucide-react";

export const LABEL_STYLE: Record<string, { color: string; icon: LucideIcon }> = {
  SecurityAlert: { color: "#f43f5e", icon: AlertTriangle },
  Person: { color: "#a78bfa", icon: User },
  Identity: { color: "#c084fc", icon: KeyRound },
  IP: { color: "#38bdf8", icon: Globe },
  Device: { color: "#22d3ee", icon: Cpu },
  Service: { color: "#34d399", icon: Server },
  Vulnerability: { color: "#fb923c", icon: Bug },
  Incident: { color: "#f472b6", icon: Flag },
  Indicator: { color: "#facc15", icon: Fingerprint },
  Technique: { color: "#94a3b8", icon: Swords },
  Team: { color: "#64748b", icon: Building2 },
  Evidence: { color: "#cbd5e1", icon: FileText },
  ResponseAction: { color: "#10b981", icon: Zap },
  Investigation: { color: "#0ea5e9", icon: Shield },
};

export function labelStyle(label: string) {
  return LABEL_STYLE[label] ?? { color: "#94a3b8", icon: Shield };
}
