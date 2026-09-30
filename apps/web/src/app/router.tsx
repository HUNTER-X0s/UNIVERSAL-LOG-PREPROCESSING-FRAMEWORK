import React, { lazy, Suspense } from 'react';
import { createBrowserRouter, Navigate } from 'react-router-dom';
import { ProtectedRoute } from '../auth/ProtectedRoute';
import { RoleGuard } from '../auth/RoleGuard';

// Auth pages — eagerly loaded (small, needed immediately on first paint)
import { LoginPage } from '../pages/auth/LoginPage';
import { AccessDeniedPage } from '../pages/auth/AccessDeniedPage';

// AppShell — eagerly loaded (shared chrome, always needed for protected pages)
import { AppShell } from '../components/layout/AppShell';

// ---------------------------------------------------------------------------
// Lazy page imports — each becomes its own JS chunk downloaded on-demand.
// The login page now loads only a fraction of the original bundle size.
// ---------------------------------------------------------------------------

const CommandCenter         = lazy(() => import('../pages/CommandCenter').then(m => ({ default: m.CommandCenter })));
const LogIntake             = lazy(() => import('../pages/LogIntake').then(m => ({ default: m.LogIntake })));
const ParserRegistry        = lazy(() => import('../pages/ParserRegistry').then(m => ({ default: m.ParserRegistry })));
const UceTransformation     = lazy(() => import('../pages/UceTransformation').then(m => ({ default: m.UceTransformation })));
const StandardsInterop      = lazy(() => import('../pages/StandardsInterop').then(m => ({ default: m.StandardsInterop })));
const UniversalConverter    = lazy(() => import('../pages/UniversalConverter').then(m => ({ default: m.UniversalConverter })));
const SchemaDrift           = lazy(() => import('../pages/SchemaDrift').then(m => ({ default: m.SchemaDrift })));
const ThreatDetection       = lazy(() => import('../pages/ThreatDetection').then(m => ({ default: m.ThreatDetection })));
const ThreatIntelligence    = lazy(() => import('../pages/ThreatIntelligence').then(m => ({ default: m.ThreatIntelligence })));
const Investigation         = lazy(() => import('../pages/Investigation').then(m => ({ default: m.Investigation })));
const ForensicEvidence      = lazy(() => import('../pages/ForensicEvidence').then(m => ({ default: m.ForensicEvidence })));
const ResponsePlaybooks     = lazy(() => import('../pages/ResponsePlaybooks').then(m => ({ default: m.ResponsePlaybooks })));
const SystemHealth          = lazy(() => import('../pages/SystemHealth').then(m => ({ default: m.SystemHealth })));

const LiveLogs              = lazy(() => import('../pages/LiveLogs').then(m => ({ default: m.LiveLogs })));
const AlertsDetection       = lazy(() => import('../pages/AlertsDetection').then(m => ({ default: m.AlertsDetection })));
const ParserWorkbench       = lazy(() => import('../pages/ParserWorkbench').then(m => ({ default: m.ParserWorkbench })));
const SchemasExport         = lazy(() => import('../pages/SchemasExport').then(m => ({ default: m.SchemasExport })));

const SiemCostOptimizer     = lazy(() => import('../pages/SiemCostOptimizer').then(m => ({ default: m.SiemCostOptimizer })));
const PipelineRoutingReplay = lazy(() => import('../pages/PipelineRoutingReplay').then(m => ({ default: m.PipelineRoutingReplay })));
const TelemetrySimulator    = lazy(() => import('../pages/TelemetrySimulator').then(m => ({ default: m.TelemetrySimulator })));
const DataPrivacyShield     = lazy(() => import('../pages/DataPrivacyShield').then(m => ({ default: m.DataPrivacyShield })));
const ChronosTimestamp      = lazy(() => import('../pages/ChronosTimestamp').then(m => ({ default: m.ChronosTimestamp })));
const LogQualityScorecard   = lazy(() => import('../pages/LogQualityScorecard').then(m => ({ default: m.LogQualityScorecard })));

const BlockchainExplorer    = lazy(() => import('../pages/BlockchainExplorer').then(m => ({ default: m.BlockchainExplorer })));
const AgentExporter         = lazy(() => import('../pages/AgentExporter').then(m => ({ default: m.AgentExporter })));
const ParserSynthesizer     = lazy(() => import('../pages/ParserSynthesizer').then(m => ({ default: m.ParserSynthesizer })));
const ReDosDebugger         = lazy(() => import('../pages/ReDosDebugger').then(m => ({ default: m.ReDosDebugger })));
const QueryTranslator       = lazy(() => import('../pages/QueryTranslator').then(m => ({ default: m.QueryTranslator })));
const AiCopilot             = lazy(() => import('../pages/AiCopilot').then(m => ({ default: m.AiCopilot })));

const ProfilePage           = lazy(() => import('../pages/profile/ProfilePage').then(m => ({ default: m.ProfilePage })));
const UsersPage             = lazy(() => import('../pages/admin/UsersPage').then(m => ({ default: m.UsersPage })));
const RolesPage             = lazy(() => import('../pages/admin/RolesPage').then(m => ({ default: m.RolesPage })));
const AuthAuditPage         = lazy(() => import('../pages/admin/AuthAuditPage').then(m => ({ default: m.AuthAuditPage })));
const MitreAttack           = lazy(() => import('../pages/MitreAttack').then(m => ({ default: m.MitreAttack })));
const IndiaCompliance       = lazy(() => import('../pages/IndiaCompliance').then(m => ({ default: m.IndiaCompliance })));

// ---------------------------------------------------------------------------
// Minimal page-level loading fallback — shows inside AppShell content area
// ---------------------------------------------------------------------------
const PageLoader: React.FC = () => (
  <div className="flex items-center justify-center h-full min-h-[60vh]">
    <div className="flex flex-col items-center gap-3">
      <div className="w-7 h-7 border-2 border-gov-blue border-t-transparent rounded-full animate-spin" />
      <span className="text-xs text-slate-400 font-mono tracking-wide">Loading module…</span>
    </div>
  </div>
);

export const router = createBrowserRouter([
  // -------------------------------------------------------------------------
  // Public routes (no auth required)
  // -------------------------------------------------------------------------
  { path: '/login', element: <LoginPage /> },
  { path: '/access-denied', element: <AccessDeniedPage /> },

  // -------------------------------------------------------------------------
  // Protected routes — require authentication
  // -------------------------------------------------------------------------
  {
    element: <ProtectedRoute />,
    children: [
      {
        path: '/',
        element: <AppShell />,
        children: [
          { index: true, element: <Navigate to="/command-center" replace /> },

          // General — all authenticated users
          { path: 'command-center',      element: <Suspense fallback={<PageLoader />}><CommandCenter /></Suspense> },
          { path: 'ai-copilot',          element: <Suspense fallback={<PageLoader />}><AiCopilot /></Suspense> },
          { path: 'live-logs',           element: <Suspense fallback={<PageLoader />}><LiveLogs /></Suspense> },
          { path: 'log-intake',          element: <Suspense fallback={<PageLoader />}><LogIntake /></Suspense> },
          { path: 'parsers',             element: <Suspense fallback={<PageLoader />}><ParserRegistry /></Suspense> },
          { path: 'parser-workbench',    element: <Suspense fallback={<PageLoader />}><ParserWorkbench /></Suspense> },
          { path: 'parser-synthesizer',  element: <Suspense fallback={<PageLoader />}><ParserSynthesizer /></Suspense> },
          { path: 'redos-debugger',      element: <Suspense fallback={<PageLoader />}><ReDosDebugger /></Suspense> },
          { path: 'cost-optimizer',      element: <Suspense fallback={<PageLoader />}><SiemCostOptimizer /></Suspense> },
          { path: 'pipeline-routing',    element: <Suspense fallback={<PageLoader />}><PipelineRoutingReplay /></Suspense> },
          { path: 'agent-exporter',      element: <Suspense fallback={<PageLoader />}><AgentExporter /></Suspense> },
          { path: 'telemetry-simulator', element: <Suspense fallback={<PageLoader />}><TelemetrySimulator /></Suspense> },
          { path: 'uce',                 element: <Suspense fallback={<PageLoader />}><UceTransformation /></Suspense> },
          { path: 'data-privacy',        element: <Suspense fallback={<PageLoader />}><DataPrivacyShield /></Suspense> },
          { path: 'timestamp-chronos',   element: <Suspense fallback={<PageLoader />}><ChronosTimestamp /></Suspense> },
          { path: 'log-quality',         element: <Suspense fallback={<PageLoader />}><LogQualityScorecard /></Suspense> },
          { path: 'standards',           element: <Suspense fallback={<PageLoader />}><StandardsInterop /></Suspense> },
          { path: 'universal-converter', element: <Suspense fallback={<PageLoader />}><UniversalConverter /></Suspense> },
          { path: 'transpiler',          element: <Navigate to="/universal-converter" replace /> },
          { path: 'query-translator',    element: <Suspense fallback={<PageLoader />}><QueryTranslator /></Suspense> },
          { path: 'schemas-export',      element: <Suspense fallback={<PageLoader />}><SchemasExport /></Suspense> },
          { path: 'onboarding',          element: <Suspense fallback={<PageLoader />}><SchemaDrift /></Suspense> },
          { path: 'health',              element: <Suspense fallback={<PageLoader />}><SystemHealth /></Suspense> },
          { path: 'blockchain',          element: <Suspense fallback={<PageLoader />}><BlockchainExplorer /></Suspense> },
          { path: 'india-compliance',    element: <Suspense fallback={<PageLoader />}><IndiaCompliance /></Suspense> },
          { path: 'traceability',        element: <Navigate to="/command-center" replace /> },
          { path: 'competitive-proof',   element: <Navigate to="/command-center" replace /> },
          { path: 'judge-mode',          element: <Navigate to="/command-center" replace /> },


          // Intelligence — requires intelligence.read
          {
            element: <RoleGuard requiredPermission="intelligence.read" />,
            children: [
              { path: 'alerts',              element: <Suspense fallback={<PageLoader />}><AlertsDetection /></Suspense> },
              { path: 'threat-detection',    element: <Suspense fallback={<PageLoader />}><ThreatDetection /></Suspense> },
              { path: 'threat-intelligence', element: <Suspense fallback={<PageLoader />}><ThreatIntelligence /></Suspense> },
              { path: 'playbooks',           element: <Suspense fallback={<PageLoader />}><ResponsePlaybooks /></Suspense> },
              { path: 'response-playbooks',  element: <Suspense fallback={<PageLoader />}><ResponsePlaybooks /></Suspense> },
              { path: 'mitre-attack',        element: <Suspense fallback={<PageLoader />}><MitreAttack /></Suspense> },
            ],
          },


          // Investigation — requires intelligence.investigate
          {
            element: <RoleGuard requiredPermission="intelligence.investigate" />,
            children: [
              { path: 'investigation', element: <Suspense fallback={<PageLoader />}><Investigation /></Suspense> },
              { path: 'forensics',     element: <Suspense fallback={<PageLoader />}><ForensicEvidence /></Suspense> },
            ],
          },

          // Profile — any authenticated user
          { path: 'profile', element: <Suspense fallback={<PageLoader />}><ProfilePage /></Suspense> },

          // Admin — requires admin.manage
          {
            element: <RoleGuard requiredPermission="admin.manage" />,
            children: [
              { path: 'admin/users',  element: <Suspense fallback={<PageLoader />}><UsersPage /></Suspense> },
              { path: 'admin/roles',  element: <Suspense fallback={<PageLoader />}><RolesPage /></Suspense> },
              { path: 'admin/audit',  element: <Suspense fallback={<PageLoader />}><AuthAuditPage /></Suspense> },
            ],
          },

          { path: '*', element: <Navigate to="/command-center" replace /> },
        ],
      },
    ],
  },
]);


