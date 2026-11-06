# Guidelines & Standing Rules for Antigravity & AI Agents

## Mandatory Frontend Design Engineering & UI Craft Standard

Whenever creating, updating, or reviewing any webpage, modal, dashboard, card, or UI component in this project, **YOU MUST ALWAYS** apply the principles of:
1. **Impeccable (`.agents/skills/impeccable`)** — Award-winning design director craft, zero generic AI clichés, rigorous typography hierarchy, optical alignment, and deep attention to UX ergonomics.
2. **Emil Kowalski Design Engineering (`.agents/skills/emil-design-eng`, `animate`, `choreograph`, `animation-performance`)** — Micro-interactions, physics-based motion, compounding invisible details, and fluid interactive responsiveness.

---

### Key Design & Motion Engineering Rules

1. **Composite-Only Transitions**:
   - NEVER use `transition: all`.
   - Explicitly define transitions on `transform` and `opacity` only:
     ```css
     transition: transform 200ms cubic-bezier(0.16, 1, 0.3, 1), opacity 200ms ease;
     ```
2. **Realistic Entrances & Exits**:
   - Never pop elements in from `scale(0)`. Elements enter from `scale(0.95)` with `opacity: 0` or subtle `translateY(6px)` / `translateY(8px)`.
3. **Tactile Interaction & Active States**:
   - All interactive buttons, chips, and clickable cards must have tactile `:active` feedback:
     ```css
     button:active, .interactive-card:active {
       transform: scale(0.975);
     }
     ```
4. **Natural Physics Easing**:
   - Avoid linear or generic ease-in for entering UI. Use snappy ease-out (`cubic-bezier(0.16, 1, 0.3, 1)` or spring-like curves) so interfaces feel instantaneous yet smooth.
5. **Dark Luxury Aesthetic (Santander Real Estate standard)**:
   - Backgrounds: Deep obsidian (`#070708` to `#0d0e12`).
   - Cards & Surfaces: Bento glassmorphic elevated panels (`rgba(20, 21, 26, 0.75)` with `backdrop-filter: blur(20px)` and hairline borders `rgba(255, 255, 255, 0.08)`).
   - Accents: Subtle emerald glow (`#10b981`), warm champagnes/golds, and pure white typography hierarchy.
6. **Accessibility & Reduced Motion**:
   - Always wrap continuous or complex motion in `@media (prefers-reduced-motion: no-preference)` or provide graceful static alternatives when reduced motion is requested.

---

### Installed Skills in Workspace

- `.agents/skills/impeccable`
- `.agents/skills/emil-design-eng`
- `.agents/skills/animate`
- `.agents/skills/choreograph`
- `.agents/skills/animation-performance`
- `.agents/skills/animation-vocabulary`
- `.agents/skills/apple-design`
- `.agents/skills/break-ui`
- `.agents/skills/find-animation-opportunities`
- `.agents/skills/improve-animations`
- `.agents/skills/review-animations`
- `.agents/skills/prototype`
