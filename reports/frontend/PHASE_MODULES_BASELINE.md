# ULPF Phase Modules — Baseline Report

**Date:** 2026-09-13  
**Commit:** `ecd437a ULPF`  
**Backend Test Count:** 680 passed, 2 warnings, 19 subtests  
**Frontend Build:** ✓ 1666 modules, clean (27.07s)

## Current Frontend Architecture

- React 18 + TypeScript + Vite 5
- Tailwind CSS v3 + shadcn/ui + Radix UI
- React Router v6 (`createBrowserRouter`)
- Lucide React icons
- Recharts (CommandCenter)
- TanStack Table (ThreatDetection)
- Design: white/navy institutional, no glassmorphism

## Existing Routes (17 pages)

command-center, log-intake, parsers, uce, standards, onboarding,
health, traceability, competitive-proof, judge-mode, threat-detection,
threat-intelligence, investigation, forensics, playbooks,
admin/users, admin/roles, admin/audit

## APIs Discovered

Platform: events/ingest, events/raw/{id}, uce/{id}, semantic/{id}, 
          search, dlq, replay, metrics, health
Intelligence: detections, detections/evaluate, correlations, anomalies,
              hunting/query, cases, rules, graph/{id}, advisor/summary
Advanced-Intelligence: ti/indicators, ti/match, triage, dedup, flood
Mission: health, posture, early-warning, fusion, coverage, scenarios,
         playbooks/dry-run, copilot/summary, pipeline/run, simulation/run

## Parser Registry: 20 parsers

Tier A: JSON, NDJSON, CSV, KV, RFC3164, RFC5424, CEF, LEEF, W3C, XML
Tier B: PaloAlto, FortiGate, Cisco, Suricata, OPNsense, Snort, WebAccess, Zeek
Tier C: CloudAudit, LinuxAuditd

## Missing APIs (to be added)

- GET /parsers — expose parser registry via REST
- GET /parsers/{id}/detail — parser metadata
- POST /parsers/test — parse a sample payload
- GET /schemas/{schema} — UCE/OCSF/OTel field definitions

## Implementation Plan

Phase A: /live-logs — TanStack Table, polling, event detail drawer (9 tabs)
Phase B: /alerts — detections API, ATT&CK, investigation linkage
Phase C: /parser-workbench — parser registry, mapping, drift, replay
Phase D: /schemas-export — schema catalog, export preview
Phase E: Sidebar restructure + cross-module deep links
