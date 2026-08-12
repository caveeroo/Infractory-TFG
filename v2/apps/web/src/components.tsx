import { type ReactNode, useEffect, useMemo, useState } from "react";
import * as Dialog from "@radix-ui/react-dialog";
import * as Tabs from "@radix-ui/react-tabs";
import {
  Activity, AlertCircle, AlertTriangle, ArrowLeft, Check, CheckCircle2, ChevronDown,
  ChevronRight, Circle, CircleDot, Cloud, Command, Copy, Database, ExternalLink,
  FileDiff, Info, Laptop, LoaderCircle, Menu, Moon, Network, Package,
  PanelLeftClose, PanelLeftOpen, Plus, RefreshCw, Search, Server, Settings,
  ShieldCheck, Sun, TerminalSquare, X, Zap
} from "lucide-react";
import { Link, NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import { demoEnvironments, type StatusTone } from "./data";
import { demoMode } from "./transport";
import { getEnvironment, listEnvironments } from "./transport";
import type { Environment } from "@infractory/contracts";
import { useQuery } from "@tanstack/react-query";

export const iconByTone = {
  success: CheckCircle2,
  warning: AlertTriangle,
  danger: AlertCircle,
  info: CircleDot,
  neutral: Circle
};

export function StatusBadge({ tone = "neutral", children }: { tone?: StatusTone; children: ReactNode }) {
  const Icon = iconByTone[tone];
  return <span className={`status status--${tone}`}><Icon aria-hidden="true" />{children}</span>;
}

export function Button({ children, variant = "primary", icon: Icon, className = "", ...props }: React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "secondary" | "quiet" | "danger"; icon?: typeof Plus }) {
  return <button className={`button button--${variant} ${className}`} {...props}>{Icon ? <Icon aria-hidden="true" /> : null}{children}</button>;
}

export function ButtonLink({ to, children, variant = "primary", icon: Icon }: { to: string; children: ReactNode; variant?: "primary" | "secondary" | "quiet" | "danger"; icon?: typeof Plus }) {
  return <Link className={`button button--${variant}`} to={to}>{Icon ? <Icon aria-hidden="true" /> : null}{children}</Link>;
}

export function PageHeader({ eyebrow, title, description, action }: { eyebrow?: string; title: string; description?: string; action?: ReactNode }) {
  return <header className="page-header">
    <div>{eyebrow ? <p className="eyebrow">{eyebrow}</p> : null}<h1>{title}</h1>{description ? <p className="page-description">{description}</p> : null}</div>
    {action ? <div className="page-actions">{action}</div> : null}
  </header>;
}

export function IssueBanner({ tone = "warning", title, children, actions }: { tone?: "warning" | "danger" | "info"; title: string; children: ReactNode; actions?: ReactNode }) {
  const Icon = tone === "danger" ? AlertCircle : tone === "warning" ? AlertTriangle : Info;
  return <section className={`issue-banner issue-banner--${tone}`} role={tone === "danger" ? "alert" : "status"}>
    <Icon aria-hidden="true" />
    <div className="issue-banner__content"><strong>{title}</strong><p>{children}</p></div>
    {actions ? <div className="issue-banner__actions">{actions}</div> : null}
  </section>;
}

export function EmptyState({ icon: Icon = Package, title, detail, action }: { icon?: typeof Package; title: string; detail: string; action?: ReactNode }) {
  return <div className="empty-state"><span className="empty-state__icon"><Icon aria-hidden="true" /></span><h2>{title}</h2><p>{detail}</p>{action}</div>;
}

export function Skeleton({ rows = 4 }: { rows?: number }) {
  return <div className="skeleton" aria-label="Loading content">{Array.from({ length: rows }, (_, i) => <span key={i} style={{ width: `${94 - i * 7}%` }} />)}</div>;
}

type ThemePreference = "system" | "light" | "dark";
function applyTheme(preference: ThemePreference) {
  const isDark = preference === "dark" || (preference === "system" && matchMedia("(prefers-color-scheme: dark)").matches);
  document.documentElement.dataset.theme = isDark ? "dark" : "light";
  document.documentElement.style.colorScheme = isDark ? "dark" : "light";
}

export function ThemeControl({ compact = false }: { compact?: boolean }) {
  const [theme, setTheme] = useState<ThemePreference>(() => (localStorage.getItem("infractory-theme") as ThemePreference) || "system");
  useEffect(() => {
    applyTheme(theme);
    localStorage.setItem("infractory-theme", theme);
    const media = matchMedia("(prefers-color-scheme: dark)");
    const listener = () => theme === "system" && applyTheme(theme);
    media.addEventListener("change", listener);
    return () => media.removeEventListener("change", listener);
  }, [theme]);
  useEffect(() => {
    const listener = (event: Event) => setTheme((event as CustomEvent<ThemePreference>).detail);
    addEventListener("infractory-theme-change", listener);
    return () => removeEventListener("infractory-theme-change", listener);
  }, []);
  const next = () => setTheme(theme === "system" ? "light" : theme === "light" ? "dark" : "system");
  return <button className="icon-button theme-button" onClick={next} aria-label={`Theme: ${theme}. Change theme`} title={`Theme: ${theme}`}>
    {theme === "light" ? <Sun /> : theme === "dark" ? <Moon /> : <Laptop />}
    {!compact ? <span>{theme[0].toUpperCase() + theme.slice(1)}</span> : null}
  </button>;
}

const nav = [
  { to: "/environments", label: "Environments", icon: Network },
  { to: "/workloads", label: "Workloads", icon: Package },
  { to: "/connections", label: "Connections", icon: Cloud },
  { to: "/activity", label: "Activity", icon: Activity },
  { to: "/settings", label: "Settings", icon: Settings }
];

export function AppShell() {
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [commandOpen, setCommandOpen] = useState(false);
  const location = useLocation();
  useEffect(() => setMobileOpen(false), [location.pathname]);
  return <div className={`app-shell ${collapsed ? "app-shell--collapsed" : ""}`}>
    <a className="skip-link" href="#main-content">Skip to content</a>
    <aside className={`sidebar ${mobileOpen ? "sidebar--open" : ""}`} aria-label="Primary navigation">
      <div className="brand"><span className="brand-mark"><Zap /></span>{!collapsed ? <span>Infractory</span> : null}</div>
      <nav className="main-nav">
        {nav.map(({ to, label, icon: Icon }) => <NavLink key={to} to={to} className={({ isActive }) => `nav-link ${isActive ? "nav-link--active" : ""}`} title={collapsed ? label : undefined}>
          <Icon aria-hidden="true" />{!collapsed ? <span>{label}</span> : null}
        </NavLink>)}
      </nav>
      <div className="sidebar-footer">
        <div className="control-status"><span className={demoMode ? "live-dot" : "state-dot state-dot--unknown"} />{!collapsed ? <span><strong>Control plane</strong><small>{demoMode ? "Simulated" : "Status not checked"}</small></span> : null}</div>
        <button className="collapse-button" onClick={() => setCollapsed(!collapsed)} aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}>
          {collapsed ? <PanelLeftOpen /> : <PanelLeftClose />}{!collapsed ? <span>Collapse</span> : null}
        </button>
      </div>
    </aside>
    {mobileOpen ? <button className="sidebar-scrim" aria-label="Close navigation" onClick={() => setMobileOpen(false)} /> : null}
    <div className="app-frame">
      <header className="topbar">
        <button className="icon-button mobile-menu" onClick={() => setMobileOpen(true)} aria-label="Open navigation"><Menu /></button>
        <EnvironmentSelector />
        {demoMode ? <StatusBadge tone="info">Simulated</StatusBadge> : null}
        <div className="topbar-actions">
          <button className="command-trigger" onClick={() => setCommandOpen(true)}><Search /><span>Search or go to…</span><kbd>⌘ K</kbd></button>
          <ThemeControl compact />
        </div>
      </header>
      <main id="main-content" className="main-content" tabIndex={-1}><Outlet /></main>
    </div>
    <CommandMenu open={commandOpen} onOpenChange={setCommandOpen} />
  </div>;
}

function EnvironmentSelector() {
  const navigate = useNavigate();
  const location = useLocation();
  const query = useQuery({ queryKey: ["environment-selector"], queryFn: listEnvironments, enabled: !demoMode });
  const environments = demoMode ? demoEnvironments : query.data ?? [];
  const current = environments.find((environment) => location.pathname.includes(environment.id));
  return <label className="environment-select"><span className="sr-only">Current environment</span><Network aria-hidden="true" />
    <select value={current?.id ?? ""} onChange={(e) => e.target.value && navigate(`/environments/${e.target.value}`)}>
      <option value="">{query.isLoading ? "Loading environments…" : query.error ? "Environments unavailable" : "All environments"}</option>
      {environments.map((environment) => <option key={environment.id} value={environment.id}>{environment.name}</option>)}
    </select><ChevronDown aria-hidden="true" />
  </label>;
}

function CommandMenu({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const [search, setSearch] = useState("");
  const navigate = useNavigate();
  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") { event.preventDefault(); onOpenChange(!open); }
    };
    addEventListener("keydown", handler); return () => removeEventListener("keydown", handler);
  }, [open, onOpenChange]);
  const items = useMemo(() => [...nav.map(({ to, label, icon }) => ({ to, label, meta: "Navigate", icon })), ...(demoMode ? demoEnvironments.map((env) => ({ to: `/environments/${env.id}`, label: env.name, meta: env.region, icon: Network })) : [])].filter((item) => `${item.label} ${item.meta}`.toLowerCase().includes(search.toLowerCase())), [search]);
  return <Dialog.Root open={open} onOpenChange={onOpenChange}>
    <Dialog.Portal><Dialog.Overlay className="dialog-overlay" /><Dialog.Content className="command-dialog" aria-describedby={undefined}>
      <Dialog.Title className="sr-only">Search and navigate</Dialog.Title>
      <div className="command-search"><Search /><input autoFocus value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search environments and pages" /></div>
      <div className="command-results">{items.map(({ to, label, meta, icon: Icon }) => <button key={to} onClick={() => { navigate(to); onOpenChange(false); }}><Icon /><span>{label}<small>{meta}</small></span><ChevronRight /></button>)}</div>
      <footer><span><kbd>↑</kbd><kbd>↓</kbd> navigate</span><span><kbd>esc</kbd> close</span></footer>
    </Dialog.Content></Dialog.Portal>
  </Dialog.Root>;
}

export function EnvironmentLayout() {
  const location = useLocation();
  const id = location.pathname.split("/")[2] || "env-aurora";
  const query = useQuery({ queryKey: ["environment", id], queryFn: () => getEnvironment(id) });
  const tabs = [
    ["", "Overview"], ["nodes", "Nodes"], ["workloads", "Workloads"], ["activity", "Activity"], ["settings", "Settings"]
  ];
  if (query.isLoading) return <div className="page"><Skeleton rows={7} /></div>;
  if (query.error || !query.data) return <div className="page"><IssueBanner tone="danger" title="Environment could not be loaded">{query.error instanceof Error ? query.error.message : "The environment is unavailable."}</IssueBanner></div>;
  const environment = query.data;
  const description = environment.spec.nodes.flatMap((node) => node.roles).join(" · ") || "Draft environment";
  return <div>
    <div className="context-heading">
      <Link to="/environments" className="back-link"><ArrowLeft /> Environments</Link>
      <div className="context-heading__title"><h1>{environment.name}</h1><StatusBadge tone={environment.health === "healthy" ? "success" : environment.health === "degraded" ? "warning" : "neutral"}>{environment.health}</StatusBadge></div>
      <p>{description}</p>
    </div>
    <nav className="tab-nav" aria-label="Environment sections">{tabs.map(([path, label]) => <NavLink key={label} to={`/environments/${id}${path ? `/${path}` : ""}`} end={!path}>{label}</NavLink>)}</nav>
    <Outlet context={{ environment }} />
  </div>;
}

export type EnvironmentOutletContext = { environment: Environment };

export function Inspector({ open, title, onClose, details, raw, activity }: { open: boolean; title: string; onClose: () => void; details: [string, ReactNode][]; raw: unknown; activity: string }) {
  return <aside className={`inspector ${open ? "inspector--open" : ""}`} aria-hidden={!open} aria-label={`${title} details`}>
    <header><div><p className="eyebrow">Node details</p><h2>{title}</h2></div><button className="icon-button" onClick={onClose} aria-label="Close details"><X /></button></header>
    <Tabs.Root defaultValue="summary">
      <Tabs.List className="inspector-tabs"><Tabs.Trigger value="summary">Summary</Tabs.Trigger><Tabs.Trigger value="relations">Relationships</Tabs.Trigger><Tabs.Trigger value="activity">Activity</Tabs.Trigger><Tabs.Trigger value="raw">Raw</Tabs.Trigger></Tabs.List>
      <Tabs.Content value="summary" className="inspector-content"><DefinitionList items={details} /><IssueBanner tone="info" title="Persisted node state">This view reports only data returned by the control plane. Capabilities and addresses remain unknown until their observation endpoints expose them.</IssueBanner></Tabs.Content>
      <Tabs.Content value="relations" className="inspector-content"><EmptyState icon={Network} title="Relationships unavailable" detail="The node inventory endpoint does not currently return network or deployment relationships." /></Tabs.Content>
      <Tabs.Content value="activity" className="inspector-content"><p className="muted">{activity}</p></Tabs.Content>
      <Tabs.Content value="raw" className="inspector-content"><pre className="code-block">{JSON.stringify(raw, null, 2)}</pre></Tabs.Content>
    </Tabs.Root>
  </aside>;
}

export function DefinitionList({ items }: { items: [string, ReactNode][] }) {
  return <dl className="definition-list">{items.map(([term, value]) => <div key={term}><dt>{term}</dt><dd>{value}</dd></div>)}</dl>;
}

export function ResourceLink({ icon: Icon, title, detail }: { icon: typeof Server; title: string; detail: string }) {
  return <button className="resource-link"><span><Icon /></span><span><strong>{title}</strong><small>{detail}</small></span><ChevronRight /></button>;
}

export function ProgressBar({ value }: { value: number }) { return <div className="progress" aria-label={`${value}% complete`}><span style={{ width: `${value}%` }} /></div>; }

export function DialogShell({ trigger, title, description, children }: { trigger: ReactNode; title: string; description: string; children: ReactNode }) {
  return <Dialog.Root><Dialog.Trigger asChild>{trigger}</Dialog.Trigger><Dialog.Portal><Dialog.Overlay className="dialog-overlay" /><Dialog.Content className="dialog-content"><Dialog.Title>{title}</Dialog.Title><Dialog.Description>{description}</Dialog.Description>{children}<Dialog.Close className="dialog-close"><X /><span className="sr-only">Close</span></Dialog.Close></Dialog.Content></Dialog.Portal></Dialog.Root>;
}

export const Icons = { Activity, AlertCircle, AlertTriangle, Check, CheckCircle2, ChevronRight, Cloud, Command, Copy, Database, ExternalLink, FileDiff, Info, LoaderCircle, Network, Package, Plus, RefreshCw, Server, Settings, ShieldCheck, TerminalSquare, X };
