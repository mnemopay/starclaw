const film=document.querySelector('#reel');
const play=document.querySelector('#play');
const seek=document.querySelector('#seek');
function sync(){play.textContent=film.paused?'Play film':'Pause film';seek.value=film.currentTime;document.querySelector('#clock').textContent='0:'+String(Math.floor(film.currentTime)).padStart(2,'0')+' / 0:12';}
for(const event of ['timeupdate','play','pause','ended'])film.addEventListener(event,sync);
play.disabled=false;
play.onclick=()=>film.paused?film.play().catch(sync):film.pause();
seek.oninput=()=>{film.currentTime=Number(seek.value)};
document.querySelectorAll('[data-cue]').forEach(b=>b.onclick=()=>{film.currentTime=Number(b.dataset.cue);film.scrollIntoView({block:'center'});film.play().catch(sync)});
const reduce=matchMedia('(prefers-reduced-motion:reduce)');
let first=true;
new IntersectionObserver(([entry])=>{if(!entry.isIntersecting)film.pause();else if(first&&!reduce.matches&&!document.hidden){first=false;film.play().catch(sync)}},{threshold:.3}).observe(film);
document.addEventListener('visibilitychange',()=>{if(document.hidden)film.pause()});
reduce.addEventListener('change',()=>{if(reduce.matches)film.pause()});
