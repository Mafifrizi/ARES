/**
 * ARES Tactical Visualizer - Animated Firewall Flames
 * Organic, continuous looping flame animation and ember particles
 * for the PERIMETER INGRESS node, preserving authentic boundary semantics.
 */

import React, { memo } from "react";

export const AnimatedFirewallFlames = memo(function AnimatedFirewallFlames() {
  return (
    <g className="ares-firewall-flame-group">
      <defs>
        {/* Core Multi-Stop Fiery Gradient */}
        <linearGradient id="aresFireGradientMain" x1="40" y1="0" x2="40" y2="36" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#fef08a" stopOpacity="0.95" />
          <stop offset="25%" stopColor="#f59e0b" stopOpacity="0.9" />
          <stop offset="60%" stopColor="#f97316" stopOpacity="0.95" />
          <stop offset="100%" stopColor="#dc2626" stopOpacity="1" />
        </linearGradient>

        {/* Outer Deep Crimson Fire Gradient */}
        <linearGradient id="aresFireGradientOuter" x1="40" y1="4" x2="40" y2="36" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#f97316" stopOpacity="0.8" />
          <stop offset="40%" stopColor="#dc2626" stopOpacity="0.85" />
          <stop offset="100%" stopColor="#991b1b" stopOpacity="0.95" />
        </linearGradient>

        {/* Hot Incandescent Core Gradient */}
        <linearGradient id="aresFireGradientCore" x1="40" y1="8" x2="40" y2="34" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#ffffff" stopOpacity="0.95" />
          <stop offset="40%" stopColor="#fef08a" stopOpacity="0.9" />
          <stop offset="100%" stopColor="#f59e0b" stopOpacity="0.8" />
        </linearGradient>
      </defs>

      {/* Layer 1: Ambient Fire Aura (breathing back glow) */}
      <ellipse
        cx="40"
        cy="22"
        rx="32"
        ry="18"
        fill="url(#aresFireGradientOuter)"
        className="ares-flame-ambient-aura"
      />

      {/* Layer 2: Outer Billowing Flames (Back layer, deep red/orange) */}
      <path
        d="M10 36 C6 26 12 14 18 8 C22 18 26 20 28 12 C32 4 40 1 48 8 C54 16 56 10 62 4 C68 12 72 24 66 36 Z"
        fill="url(#aresFireGradientOuter)"
        className="ares-flame-layer-back"
      />

      {/* Layer 3: Main Dynamic Flame Tongues (Staggered rhythmic flicker) */}
      {/* Left Leaping Tongue */}
      <path
        d="M14 36 C10 27 16 16 22 10 C25 18 29 20 31 16 C33 24 24 32 20 36 Z"
        fill="url(#aresFireGradientMain)"
        className="ares-flame-tongue ares-flame-tongue-left"
      />

      {/* Center Roaring Plume */}
      <path
        d="M26 36 C28 22 34 8 40 2 C46 8 52 22 54 36 C46 34 34 34 26 36 Z"
        fill="url(#aresFireGradientMain)"
        className="ares-flame-tongue ares-flame-tongue-center"
      />

      {/* Right Leaping Tongue */}
      <path
        d="M44 36 C48 28 54 18 60 6 C64 14 66 22 62 36 Z"
        fill="url(#aresFireGradientMain)"
        className="ares-flame-tongue ares-flame-tongue-right"
      />

      {/* Layer 4: Intense White-Hot Inner Cores */}
      <path
        d="M32 36 C34 26 38 16 40 10 C42 16 46 26 48 36 Z"
        fill="url(#aresFireGradientCore)"
        className="ares-flame-core"
      />

      {/* Layer 5: Floating Ember Sparks */}
      <circle cx="22" cy="14" r="1.2" fill="#fef08a" className="ares-ember ares-ember-1" />
      <circle cx="38" cy="6" r="1.5" fill="#fde047" className="ares-ember ares-ember-2" />
      <circle cx="50" cy="10" r="1.0" fill="#f97316" className="ares-ember ares-ember-3" />
      <circle cx="30" cy="8" r="1.2" fill="#ffffff" className="ares-ember ares-ember-4" />
      <circle cx="58" cy="12" r="1.0" fill="#fbbf24" className="ares-ember ares-ember-5" />
    </g>
  );
});
