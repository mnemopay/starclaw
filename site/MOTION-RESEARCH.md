# StarClaw motion direction — research, 18 November 2026

The current page has credible product proof but reads like a static document. Keep the warm paper, ink and vermilion identity; introduce scale, depth and a continuous narrative through the actual recorded task.

## Repositories evaluated

| Repository | What it contributes | Decision |
| --- | --- | --- |
| https://github.com/greensock/GSAP | Timelines, ScrollTrigger, coordinated SVG and typography animation | Primary motion engine. Self-host pinned core and ScrollTrigger. Uses GSAP standard license, not MIT. |
| https://github.com/darkroomengineering/lenis | Smooth scrolling with GSAP integration | Optional desktop enhancement after native-scroll prototype; keep native touch scrolling and keyboard behavior. MIT. |
| https://github.com/codrops/OnScrollTypographyAnimations | Concrete experiments in scroll-driven type composition | Reference for oversized editorial type, restrained word reveals and transitions. MIT code; verify separate assets before reuse. |
| https://github.com/codrops/TextClipScroll | SVG clipping experiments for typography | Reference for the transition from agent intent to an approval boundary. MIT code. |
| https://github.com/14islands/r3f-scroll-rig | Synchronizes DOM elements and Three.js meshes through scrolling | Strong reference for spatial continuity. Defer dependency: current site is static HTML, and adopting it requires React/R3F infrastructure. MIT. |
| https://github.com/pmndrs/react-three-fiber | Declarative Three.js rendering in React | Only adopt if a custom 3D scene proves worth the additional stack and rendering cost. MIT. |
| https://github.com/pmndrs/drei | R3F scene helpers | Companion to R3F rather than a reason to migrate. MIT. |

Repository identities, archive status and license metadata checked through GitHub API. All were unarchived at research time. GSAP's README links its own standard license; the other listed repos report MIT. Preserve notices with any code reuse. No third-party demo imagery or complete layouts have been copied.

## Art direction: a task becomes a record

1. Opening: asymmetrical oversized typography, generous paper space and an original spatial composition of source notes, proposed file and receipt. Short entrance choreography settles quickly; primary navigation and install remain immediately usable. The objects are labeled as a recorded example.
2. Task journey: a desktop scroll sequence carries the same document through read, propose and policy check. Layer position, typography and a connecting line create continuity instead of unrelated reveal animations. On mobile, show sequential normal-flow panels.
3. Approval: the motion stops at the boundary. The existing approval/denial replay remains an explicit user action; scrolling never presses it. The branch changes only after a choice, and the exact proposed content stays inspectable.
4. Receipt: layers align into the actual signed record. Verification remains real Web Crypto verification; visual animation does not imply validation has passed. Tampering visibly breaks the connecting line only after the verifier reports failure.
5. Capabilities: large editorial rows for research, code changes and scheduled checks. Hover/focus reveals concise supporting detail without hiding essential content. Avoid endless marquees, fabricated activity and dashboard filler.
6. Closing: an oversized StarClaw wordmark and clear installation command; quiet final composition after the more active middle.

## Implementation choice

Use the existing static site, GSAP core and ScrollTrigger, original SVG/CSS document geometry, and Codrops as an animation reference. Avoid a React migration for decorative effects. Prototype with native scrolling first. Add Lenis only if visual testing shows a clear improvement.

Render readable content before animation initializes. Reduced-motion users receive the complete static composition. Do not pin tall content on small screens. Pause any ambient animation offscreen and when the document is hidden. No custom cursor, loading gate or autoplay audio. Self-host dependencies with version and license records; no remote runtime scripts.

## Acceptance checks

Desktop and 320/390/768px layouts; keyboard navigation; prefers-reduced-motion; no-JavaScript readability; viewport resize; signed example download; real approved/denied verification and tamper detection; no horizontal overflow or console errors. Inspect screenshots at the opening, approval boundary and receipt before production deployment.

This is a researched design and implementation brief, not a newly deployed version.
