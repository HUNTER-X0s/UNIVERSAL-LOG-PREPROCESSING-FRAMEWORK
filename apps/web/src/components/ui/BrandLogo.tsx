import React from 'react';

interface BrandLogoProps {
  className?: string;
  size?: number;
}

/**
 * ULPF Modern Telemetry Nexus Logo
 * A multi-dimensional cyber emblem featuring:
 * - Hexagonal precision perimeter with tactical dash array
 * - Interlocking geometric energy ribbons in cyan, cobalt, and indigo
 * - Converging tri-node telemetry ingestion vectors
 * - Crystalline central normalization diamond core with luminous glow
 */
export const BrandLogo: React.FC<BrandLogoProps> = ({ className = '', size = 26 }) => {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 40 40"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
      aria-label="Universal Log Pre-processing Framework Logo"
    >
      <defs>
        {/* Ambient neon bloom */}
        <filter id="ulpf-neon-glow" x="-30%" y="-30%" width="160%" height="160%">
          <feGaussianBlur stdDeviation="1.5" result="blur" />
          <feComposite in="SourceGraphic" in2="blur" operator="over" />
        </filter>

        {/* Dynamic Gradient Ribbons */}
        <linearGradient id="ulpf-ribbon-cyan" x1="6" y1="4" x2="34" y2="36" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#38BDF8" />
          <stop offset="50%" stopColor="#2563EB" />
          <stop offset="100%" stopColor="#0F172A" />
        </linearGradient>

        <linearGradient id="ulpf-ribbon-indigo" x1="34" y1="4" x2="6" y2="36" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#A855F7" />
          <stop offset="45%" stopColor="#6366F1" />
          <stop offset="100%" stopColor="#0284C7" />
        </linearGradient>

        <linearGradient id="ulpf-vector-grad" x1="20" y1="6" x2="20" y2="34" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#00F2FE" />
          <stop offset="50%" stopColor="#38BDF8" />
          <stop offset="100%" stopColor="#60A5FA" />
        </linearGradient>

        <radialGradient id="ulpf-core-glow" cx="50%" cy="50%" r="50%">
          <stop offset="0%" stopColor="#FFFFFF" />
          <stop offset="35%" stopColor="#67E8F9" />
          <stop offset="75%" stopColor="#0284C7" />
          <stop offset="100%" stopColor="#0284C7" stopOpacity="0" />
        </radialGradient>

        <linearGradient id="ulpf-perimeter-grad" x1="4" y1="20" x2="36" y2="20" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#38BDF8" stopOpacity="0.9" />
          <stop offset="50%" stopColor="#6366F1" stopOpacity="0.4" />
          <stop offset="100%" stopColor="#38BDF8" stopOpacity="0.9" />
        </linearGradient>
      </defs>

      {/* Hexagonal Cyber Perimeter */}
      <polygon
        points="20,2.5 35.5,11.5 35.5,28.5 20,37.5 4.5,28.5 4.5,11.5"
        stroke="url(#ulpf-perimeter-grad)"
        strokeWidth="1.25"
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeDasharray="4 2.5"
        fill="#070E1B"
      />

      {/* Inner Dimensional Depth Shield */}
      <polygon
        points="20,5.5 32.5,12.8 32.5,27.2 20,34.5 7.5,27.2 7.5,12.8"
        fill="#0B1527"
        fillOpacity="0.95"
        stroke="#1E293B"
        strokeWidth="0.75"
      />

      {/* Facet 1: North-East Kinetic Ribbon */}
      <path
        d="M20 5.5L32.5 12.8V21C32.5 21 26.5 17.5 20 19.5C14.5 21.2 9.5 16.5 9.5 16.5L20 5.5Z"
        fill="url(#ulpf-ribbon-cyan)"
        fillOpacity="0.85"
      />

      {/* Facet 2: South-West Counter Kinetic Ribbon */}
      <path
        d="M20 34.5L7.5 27.2V19C7.5 19 13.5 22.5 20 20.5C25.5 18.8 30.5 23.5 30.5 23.5L20 34.5Z"
        fill="url(#ulpf-ribbon-indigo)"
        fillOpacity="0.85"
      />

      {/* Tri-Node Converging Telemetry Ingestion Streams */}
      <path
        d="M20 8.5V20M20 20L30 25.8M20 20L10 25.8"
        stroke="url(#ulpf-vector-grad)"
        strokeWidth="2.2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />

      {/* Telemetry Endpoint Nodes */}
      <circle cx="20" cy="8.5" r="2.2" fill="#00F2FE" filter="url(#ulpf-neon-glow)" />
      <circle cx="30" cy="25.8" r="2.2" fill="#A855F7" filter="url(#ulpf-neon-glow)" />
      <circle cx="10" cy="25.8" r="2.2" fill="#38BDF8" filter="url(#ulpf-neon-glow)" />

      {/* Central Telemetry Core Glow */}
      <circle cx="20" cy="20" r="6" fill="url(#ulpf-core-glow)" />

      {/* Precision Normalization Nexus Diamond */}
      <polygon
        points="20,15.5 24,20 20,24.5 16,20"
        fill="#FFFFFF"
        filter="url(#ulpf-neon-glow)"
      />
      <circle cx="20" cy="20" r="1.3" fill="#0284C7" />
    </svg>
  );
};
