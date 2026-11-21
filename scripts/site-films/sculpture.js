// Offline studio lighting and turntable for three machined, six-lobed plates.
const ctx = document.querySelector('canvas').getContext('2d');
const tau = Math.PI * 2;
const clamp = x => Math.min(1, Math.max(0, x));
const ease = x => (1 - Math.cos(Math.PI * clamp(x))) / 2;
const chapters = [['Read.', 'launch-notes.txt'], ['Ask.', 'fs.write'], ['Record.', 'decision.result']];
const surfaces = [];
for (let ring = 0; ring < 3; ring++) {
  const rows = [];
  for (let i = 0; i < 144; i++) {
    const a = i * tau / 144;
    const lobe = (1 + Math.cos(a * 6)) / 2;
    const outer = 130 + 85 * Math.pow(lobe, 2.1);
    const inner = 69 + 8 * lobe;
    const sections = [[inner+6,10],[outer-9,10],[outer-3,8],[outer,3],[outer,-6],[outer-5,-10],[inner+5,-10],[inner,-6],[inner,4]];
    rows.push(sections.map(([r,h])=>[r*Math.cos(a),h,r*Math.sin(a)]));
  }
  surfaces.push(rows);
}
function draw(t) {
  const chapter = Math.min(2, Math.floor(t/4));
  const beat = t - chapter*4;
  const pale = chapter===1;
  const bg = ctx.createRadialGradient(492,270,60,564,340,820);
  bg.addColorStop(0,pale?'#f8ebcd':'#713d2c');
  bg.addColorStop(.6,pale?'#ddc9a8':'#342a26');
  bg.addColorStop(1,pale?'#b49d7d':'#181b18');
  ctx.fillStyle=bg;ctx.fillRect(0,0,1152,720);
  document.querySelector('main').style.color=pale?'#30251e':'#fff2dc';
  document.querySelector('#verb').textContent=chapters[chapter][0];
  document.querySelector('#detail').textContent=chapters[chapter][1];
  const spread = [28+46*ease(beat/3), 77-36*ease(beat/2), 41-18*ease(beat/3)][chapter];
  const tilt = [.48,.28,.79][chapter]+.045*Math.sin(t*.5);
  const roll = [-.36,.25,-.48][chapter];
  const zoom = [1.26,1.56,1.24][chapter]+.06*ease(beat/3);
  const faces=[];
  for(let ring=0;ring<3;ring++){
    const spin=t*.20+ring*.16;
    const verts=surfaces[ring].map(row=>row.map(([x,y,z])=>{
      const X=x*Math.cos(spin)-z*Math.sin(spin), Z=x*Math.sin(spin)+z*Math.cos(spin);
      const H=y+(1-ring)*spread, Y=Z*Math.sin(tilt)-H*Math.cos(tilt);
      return [X*Math.cos(roll)-Y*Math.sin(roll),X*Math.sin(roll)+Y*Math.cos(roll),Z*Math.cos(tilt)+H*Math.sin(tilt)];
    }));
    for(let i=0;i<verts.length;i++) for(let j=0;j<9;j++){
      const next=verts[(i+1)%verts.length], k=(j+1)%9;
      const poly=[verts[i][j],next[j],next[k],verts[i][k]];
      const a=poly[0],b=poly[1],c=poly[3],u=b.map((v,k)=>v-a[k]),v=c.map((n,k)=>n-a[k]);
      const n=[u[1]*v[2]-u[2]*v[1],u[2]*v[0]-u[0]*v[2],u[0]*v[1]-u[1]*v[0]];
      const len=Math.hypot(...n)||1;
      const gleam=Math.pow(Math.abs((n[0]*.44-n[1]*.71+n[2]*.53)/len),6);
      const streak=.5+.5*Math.cos(i*tau/144*2+spin*2);
      let intensity=.20+.44*Math.abs(n[1])/len+.23*streak+.68*gleam;
      if(j===0) intensity+=.22;
      const base=ring===1?[249,97,48]:[247,228,194];
      faces.push({poly,z:poly.reduce((s,p)=>s+p[2],0),color:'rgb('+base.map(c=>Math.min(255,Math.round(c*intensity))).join(',')+')'});
    }
  }
  faces.sort((a,b)=>a.z-b.z);
  for(const {poly,color} of faces){
    ctx.beginPath();poly.forEach(([x,y,z],i)=>{const scale=zoom*1100/(1100-z);ctx[i?'lineTo':'moveTo'](578+x*scale,341+y*scale)});
    ctx.closePath();ctx.fillStyle=ctx.strokeStyle=color;ctx.lineWidth=.65;ctx.fill();ctx.stroke();
  }
  // The edit rides a physical shutter between camera angles.
  if(chapter && beat<.24){ctx.fillStyle='#cf4728';ctx.fillRect(0,0,1152*(1-ease(beat/.24)),720);}
}

