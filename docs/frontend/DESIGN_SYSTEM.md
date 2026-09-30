# ULPF Institutional Design System v2.0
**Universal Log Pre-processing Framework — Security Telemetry Processing Platform**

---

## 1. Design Philosophy & Architectural Directive

The ULPF design system provides an authoritative, institutional, government-grade visual identity for national security telemetry operations. It deliberately avoids the visual tropes of generic AI dashboards, startup SaaS templates, or neon cyberpunk gaming consoles.

### Core Principles:
- **Restraint & Authority**: Quiet, conservative color palette dominated by institutional white, slate, and deep navy.
- **High Information Density**: Structured information panels and dense operational tables rather than oversized floating cards.
- **Human-Designed Editorial Quality**: Stable typography, formal terminology, and clear semantic hierarchies.
- **Printable Layouts**: Every core screen maintains visual coherence and hierarchy when exported or printed.
- **Strict Air-Gap Sovereignty**: Zero runtime external network requests, zero Google Fonts or external CDN stylesheets, robust system font fallbacks.

---

## 2. Color Palette & Semantic Design Tokens

### Primary Surfaces & Backgrounds
- **Page Canvas**: `#F8FAFC` (Slate 50)
- **Surface**: `#FFFFFF` (Pure White)
- **Surface Muted / Alt**: `#F1F5F9` (Slate 100)
- **Surface Hover**: `#EEF2F7`

### Institutional Text & Headings
- **Navy 900 (Primary Headings & Text)**: `#0F2747` / `#172033`
- **Navy 800 (Secondary Headings)**: `#163A63`
- **Slate 600 (Secondary Body)**: `#475569`
- **Slate 500 (Muted / Labels)**: `#64748B`

### Administrative Actions & Accents
- **Government Blue (Primary Action)**: `#1455A0`
- **Government Dark (Hover)**: `#0F4080`
- **Government Light (Active Selection Background)**: `#EFF6FF`
- **Government Border (Active Selection Ring)**: `#BFDBFE`

### Operational Status Indicators
- **Operational / OK**: Text `#167A45` | Background `#F0FDF4` | Border `#BBF7D0`
- **Attention / Pending**: Text `#A85D00` | Background `#FFFBEB` | Border `#FDE68A`
- **Alert / Danger**: Text `#B42318` | Background `#FEF2F2` | Border `#FECACA`

---

## 3. Typography & Monospace Rules

- **Primary UI Sans-Serif**: `Inter`, `-apple-system`, `BlinkMacSystemFont`, `Segoe UI`, `Roboto`, `sans-serif`
- **Technical Monospace**: `JetBrains Mono`, `Consolas`, `Courier New`, `monospace`

> [!NOTE]
> Monospace font is strictly reserved for machine identifiers, hashes, parser IDs, raw log payloads, network IP/ports, and JSON structures. Normal labels and titles remain human-readable sans-serif.

---

## 4. Component Standards

### Header
Clean administrative layout featuring the original ULPF geometric vector emblem, product title, global search bar (`Ctrl+K`), documentation, notifications, and user profile role. Development and test telemetry are excluded.

### Sidebar
White background with `#CBD5E1` border, monochrome 16px icons, and a restrained blue active indicator (`border-l-2 border-gov-blue text-navy-900 bg-gov-light`).

### Structured Tables
Dense, compact tables with subtle header borders, consistent cell padding (`py-2 px-3`), and explicit column alignment (numeric right-aligned, text left-aligned).

### Footer
Mature institutional copyright notice (`© Universal Log Pre-processing Framework`) and standard support links (`Privacy | Accessibility | Documentation | Help`).
