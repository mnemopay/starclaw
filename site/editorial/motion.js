(() => {
  const { gsap, ScrollTrigger } = window;
  if (!gsap || !ScrollTrigger) return;
  gsap.registerPlugin(ScrollTrigger);
  gsap.matchMedia().add('(prefers-reduced-motion: no-preference)', () => {
    const leaves = gsap.utils.toArray('.leaf');
    const replay = document.querySelector('#refold');
    // Keep the engraved page legible while the sheets behind it unfold.
    const opening = gsap.timeline();
    leaves.forEach((leaf, index) => {
      const angle = -66 + index * 2.75;
      opening.fromTo(leaf, { attr: { transform: 'rotate(22 220 322)' } }, {
        attr: { transform: 'rotate(' + angle + ' 220 322)' },
        duration: 1.16,
        ease: 'power3.inOut'
      }, index * 0.008);
    });
    opening.from('.cover h1 span', { y: 18, duration: 0.68, stagger: 0.1, ease: 'power3.out' }, 0);
    const restart = () => opening.restart();
    replay.hidden = false;
    replay.addEventListener('click', restart);
    // Scroll the fan closed at the proposed write. Only replay controls choose an outcome.
    const desktop = gsap.matchMedia();
    desktop.add('(min-width:901px) and (min-height:620px)', () => {
      // Parent rotations compose with the independent entrance animation on each leaf.
      const wrappers = leaves.map(leaf => {
        const wrapper = document.createElementNS('http://www.w3.org/2000/svg', 'g');
        leaf.before(wrapper);
        wrapper.append(leaf);
        return wrapper;
      });
      gsap.to(wrappers, {
        rotation: index => 66 - index * 2.75,
        svgOrigin: '220 322', ease: 'power2.inOut',
        scrollTrigger: { trigger: '.cover-chapter', start: 'top 80%', end: 'center 52%', scrub: true }
      });
      return () => wrappers.forEach(wrapper => wrapper.replaceWith(wrapper.firstElementChild));
    });
    for (const selector of ['.run-intro h2', '.section-heading h2', '.ownership-copy h2', '.manifesto h2', '.press-signature']) {
      gsap.from(selector, {
        y: 20, duration: 0.72, ease: 'power3.out',
        scrollTrigger: { trigger: selector, start: 'top 97%', once: true }
      });
    }
    return () => {
      desktop.revert();
      replay.hidden = true;
      replay.removeEventListener('click', restart);
      leaves.forEach((leaf, index) => leaf.setAttribute('transform', 'rotate(' + (-66 + index * 2.75) + ' 220 322)'));
    };
  });
})();
