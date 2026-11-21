const slider=document.querySelector('#event'),branch=document.querySelector('#branch'),play=document.querySelector('#scan');
const canvas=document.querySelector('canvas'),ctx=canvas.getContext('2d');
let runs,records=[],timer=null;
function stop(){clearInterval(timer);timer=null;play.textContent='Play sequence'}
function paint(){
 if(!records.length)return;
 const width=canvas.clientWidth,height=canvas.clientHeight,dpr=Math.min(devicePixelRatio,2);
 canvas.width=width*dpr;canvas.height=height*dpr;ctx.scale(dpr,dpr);
 const gap=width/records.length,selected=Number(slider.value);
 // Each column represents one signed record. The motif uses its first 12 hash bytes.
 records.forEach((r,i)=>{
   const x=(i+.5)*gap;ctx.fillStyle=i===selected?'#e1fa65':i<selected?'#8cae78':'#4a6245';
   for(let j=0;j<12;j++){
     const v=parseInt(r.hash.slice(j*2,j*2+2),16)/255,h=(.07+.76*v)*height*.42;
     ctx.fillRect(x+(j-6)*gap/15,height/2-h,Math.max(1,gap/19),2*h);
   }
   if(i===selected){ctx.strokeStyle='#e1fa65';ctx.strokeRect(i*gap+1,2,gap-2,height-4)}
 });
}
function display(){
 const i=Number(slider.value),r=records[i];
 document.querySelector('#position').textContent=(i+1)+' / '+records.length;
 document.querySelector('#type').textContent=r.type;
 document.querySelector('#detail').textContent=[r.data.class,r.data.allowed===true?'Allowed':r.data.allowed===false?'Denied':'',r.data.kind].filter(Boolean).join(' · ');
 document.querySelector('#digest').textContent=r.hash;paint();
}
const sources={real:document.querySelector('#source')?.innerHTML,scripted:'Scripted example · real engine, scripted model and approver · <a href="/editorial/#recorded-run">Walkthrough ↗</a> · <a href="/editorial/example-run.json">Source data ↗</a>'};
function choose(){
 stop();const src=document.querySelector('#source');if(src)src.innerHTML=branch.value==='real'?sources.real:sources.scripted;records=runs[branch.value].records;slider.max=records.length-1;
 slider.value=Math.max(0,records.findIndex(r=>r.type==='decision.result'&&r.data.class==='fs.write'));display();
}
const load=u=>fetch(u).then(r=>{if(!r.ok)throw Error();return r.json()});
Promise.all([load('/editorial/real-run.json'),load('/editorial/example-run.json')]).then(([real,example])=>{
 runs={real:real.runs.real,approve:example.runs.approve,deny:example.runs.deny};choose();slider.disabled=play.disabled=false;
 branch.onchange=choose;slider.oninput=()=>{stop();display()};
 play.onclick=()=>{if(timer){stop();return}slider.value=0;display();play.textContent='Pause';timer=setInterval(()=>{slider.value=Number(slider.value)+1;display();if(Number(slider.value)>=records.length-1)stop()},550)};
 canvas.onclick=e=>{stop();slider.value=Math.min(records.length-1,Math.floor(e.offsetX/canvas.clientWidth*records.length));display()};
 new ResizeObserver(paint).observe(canvas);
 document.addEventListener('visibilitychange',()=>{if(document.hidden)stop()});
}).catch(()=>{document.querySelector('#type').textContent='Could not load this run';branch.disabled=true});
