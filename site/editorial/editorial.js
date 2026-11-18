'use strict';
const canvas=document.querySelector('#copper-sculpture');
if(canvas){
 const ctx=canvas.getContext('2d');
 if(ctx){
  const reduced=matchMedia('(prefers-reduced-motion:reduce)').matches;
  const points=[];const rows=innerWidth<620?90:125,columns=innerWidth<620?70:100;
  for(let i=0;i<rows;i++)for(let j=0;j<columns;j++){
   const u=(i+.5)/rows*Math.PI,v=j/columns*Math.PI*2;
   const ripple=1+.08*Math.sin(11*u+3*v);
   const x=Math.sin(u)*Math.cos(v)*ripple;
   const y=Math.cos(u)*1.18;
   const z=Math.sin(u)*Math.sin(v)*ripple;
   points.push([x,y,z]);
  }
  let width=0,height=0,time=.45,frame=0,visible=true,last=0;
  function resize(){const r=canvas.getBoundingClientRect();width=r.width;height=r.height;const dpr=Math.min(devicePixelRatio||1,1.5);canvas.width=width*dpr;canvas.height=height*dpr;ctx.setTransform(dpr,0,0,dpr,0,0)}
  function draw(now=0){
   frame=0;if(!visible||document.hidden)return;
   if(now-last<33&&!reduced){frame=requestAnimationFrame(draw);return}last=now;
   time+=reduced?0:.002;
   ctx.clearRect(0,0,width,height);
   const a=.25,b=time,ca=Math.cos(a),sa=Math.sin(a),cb=Math.cos(b),sb=Math.sin(b);
   const scale=height*.35;
   const projected=[];
   for(const p of points){const x=p[0]*cb+p[2]*sb,z=-p[0]*sb+p[2]*cb,y=p[1]*ca-z*sa;projected.push([x,y,p[1]*sa+z*ca]);}
   projected.sort((a,b)=>b[2]-a[2]);
   for(const[x,y,z]of projected){const front=(1.3-z)/2.6,light=Math.max(0,Math.min(1,.5-x*.25-y*.18+front*.2));const perspective=4.8/(4.8+z);const r=147+Math.round(light*83),g=53+Math.round(light*83),blue=18+Math.round(light*40);ctx.fillStyle=`rgba(${r},${g},${blue},${.1+front*.65})`;const size=(.55+front*.3)*perspective;ctx.fillRect(width*.5+x*scale*perspective,height*.48+y*scale*perspective,size,size);}
   if(!reduced)frame=requestAnimationFrame(draw);
  }
  resize();draw();
  new IntersectionObserver(entries=>{visible=entries[0].isIntersecting;if(visible&&!frame)draw();if(!visible){cancelAnimationFrame(frame);frame=0}}).observe(canvas);
  document.addEventListener('visibilitychange',()=>{if(document.hidden){cancelAnimationFrame(frame);frame=0}else if(visible&&!frame)draw()});
  addEventListener('resize',()=>{resize();if(reduced)draw()});
 }
}
