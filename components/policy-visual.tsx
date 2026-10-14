"use client";
import { useEffect, useRef } from 'react';

/** Decorative illustration; it represents the workflow, never a live verdict. */
export function PolicyVisual() {
  const figure = useRef<HTMLElement>(null);
  useEffect(() => {
    const element = figure.current;
    if (!element) return;
    const motion = window.matchMedia('(prefers-reduced-motion: reduce)');
    let frame = 0;
    const update = () => {
      frame = 0;
      const offset = motion.matches ? 0 : Math.min(window.scrollY, 1000);
      element.style.setProperty('--policy-rise', `${offset * 0.085}px`);
      element.style.setProperty('--policy-turn', `${offset * 0.025}deg`);
      element.style.setProperty('--policy-drift', `${offset * -0.045}px`);
    };
    const schedule = () => { if (!frame) frame = requestAnimationFrame(update); };
    update();
    window.addEventListener('scroll', schedule, { passive: true });
    motion.addEventListener('change', schedule);
    return () => {
      window.removeEventListener('scroll', schedule);
      motion.removeEventListener('change', schedule);
      cancelAnimationFrame(frame);
    };
  }, []);
  return <figure className="policy-visual" ref={figure} aria-label="Animated illustration of a policy document, evidence connections, and a protective shield">
    <div className="policy-glow" aria-hidden="true" />
    <svg className="policy-art" viewBox="0 0 440 340" fill="none" aria-hidden="true">
      <defs>
        <linearGradient id="pp-paper" x1="128" y1="55" x2="310" y2="290" gradientUnits="userSpaceOnUse"><stop stopColor="white"/><stop offset="1" stopColor="#dae5ff"/></linearGradient>
        <linearGradient id="pp-shield" x1="220" y1="120" x2="350" y2="280" gradientUnits="userSpaceOnUse"><stop stopColor="#5c8cff"/><stop offset="1" stopColor="#173abc"/></linearGradient>
        <linearGradient id="pp-edge" x1="190" y1="100" x2="335" y2="267" gradientUnits="userSpaceOnUse"><stop stopColor="#b5ccff"/><stop offset="1" stopColor="#7196f1"/></linearGradient>
        <filter id="pp-shadow" x="-40%" y="-40%" width="180%" height="200%"><feDropShadow dx="0" dy="16" stdDeviation="14" floodColor="#244fe4" floodOpacity=".16"/></filter>
      </defs>
      <g className="policy-orbit">
        <ellipse cx="220" cy="175" rx="190" ry="119" stroke="#c6d5f4" strokeDasharray="4 8"/>
        <ellipse cx="220" cy="175" rx="165" ry="92" transform="rotate(-25 220 175)" stroke="#d2def4"/>
      </g>
      <path className="policy-flow" d="M58 206C109 267 323 292 386 125" stroke="#799df5" strokeWidth="2" strokeDasharray="5 12"/>
      <g className="policy-document" filter="url(#pp-shadow)">
        <path d="M142 58L254 41L298 75L325 248Q327 260 313 264L170 285Q157 286 155 273L128 77Q126 62 142 58Z" fill="#b9cdfb"/>
        <path d="M136 49L248 32L292 66L319 239Q321 251 307 255L164 276Q151 277 149 264L122 68Q120 53 136 49Z" fill="url(#pp-paper)" stroke="white" strokeWidth="2"/>
        <path d="M248 32L253 70L292 66" fill="#c2d4ff" stroke="#aac4f9"/>
        <rect x="145" y="84" width="47" height="8" rx="4" transform="rotate(-8 145 84)" fill="#244fe4"/>
        <path d="M149 116L260 100M153 139L252 125M160 189L265 174M164 212L236 202" stroke="#afc2e8" strokeWidth="7" strokeLinecap="round"/>
        <path d="M157 163L207 155" stroke="#7095f1" strokeWidth="7" strokeLinecap="round"/>
        <circle cx="182" cy="242" r="13" fill="#cceee3"/>
        <path d="M176 242L181 246L188 237" stroke="#21866c" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"/>
      </g>
      <g className="policy-shield" filter="url(#pp-shadow)">
        <path d="M273 124L336 146L339 200C341 242 313 270 291 279C267 275 232 253 224 212L213 159Z" fill="url(#pp-edge)" stroke="#b7ccff" strokeWidth="2"/>
        <path d="M273 131L330 152L332 201C334 237 311 261 290 271C268 265 239 247 232 210L221 163Z" fill="url(#pp-shield)"/>
        <path d="M252 203L277 222L310 176" stroke="white" strokeWidth="9" strokeLinecap="round" strokeLinejoin="round"/>
        <path d="M232 166L275 143L321 159" stroke="#9ebdff" strokeWidth="2" strokeLinecap="round" opacity=".7"/>
      </g>
      <g className="policy-node node-one"><rect x="40" y="91" width="64" height="62" rx="17" fill="white" stroke="#d8e2f5"/><path d="M60 109H81M60 118H75M60 127H80" stroke="#6286e7" strokeWidth="3" strokeLinecap="round"/><circle cx="94" cy="97" r="7" fill="#51baa0" stroke="#f3f6fb" strokeWidth="3"/></g>
      <g className="policy-node node-two"><rect x="345" y="64" width="57" height="57" rx="17" fill="#244fe4"/><path d="M361 92L371 102L388 82" stroke="white" strokeWidth="4" strokeLinecap="round" strokeLinejoin="round"/></g>
      <g className="policy-node node-three"><rect x="72" y="247" width="49" height="49" rx="15" fill="white" stroke="#d8e2f5"/><path d="M88 269L95 262L102 269L95 276Z" stroke="#6286e7" strokeWidth="2"/><path d="M88 277L95 284L102 277" stroke="#6286e7" strokeWidth="2" strokeLinecap="round"/></g>
      <circle className="policy-spark" cx="351" cy="260" r="5" fill="#51baa0"/><circle cx="115" cy="38" r="3" fill="#8faef6"/><circle cx="406" cy="190" r="3" fill="#8faef6"/>
    </svg>
    <figcaption><span className="visual-kicker">A PROMISE, WITH A PAPER TRAIL</span><strong>Policy. Evidence. Accountability.</strong></figcaption>
  </figure>;
}
