(() => {
  const player = document.querySelector('.cinema');
  const films = [...player.querySelectorAll('video')];
  const links = [...player.querySelectorAll('[data-film]')];
  const preference = matchMedia('(prefers-reduced-motion: reduce)');
  let started = false;
  let selected = 0;
  function play(video) { video.play().catch(() => {}); }
  function pauseAll() { films.forEach(video => video.pause()); }
  links.forEach((link, index) => link.addEventListener('click', event => {
    if (event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
    event.preventDefault();
    started = true;
    selected = index;
    pauseAll();
    films.forEach((video, i) => { video.hidden = i !== index; });
    links.forEach((item, i) => {
      if (i === index) item.setAttribute('aria-current', 'true');
      else item.removeAttribute('aria-current');
    });
    films[index].currentTime = 0;
    play(films[index]);
  }));
  const observer = new IntersectionObserver(entries => {
    const visible = entries[0].intersectionRatio >= 0.45;
    if (!visible) pauseAll();
    else if (!started && !preference.matches && !document.hidden) {
      started = true;
      play(films[selected]);
    }
  }, { threshold: [0, 0.45] });
  observer.observe(player);
  document.addEventListener('visibilitychange', () => { if (document.hidden) pauseAll(); });
  preference.addEventListener('change', () => { if (preference.matches) pauseAll(); });
})();
