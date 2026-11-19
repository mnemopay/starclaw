const sheets=document.querySelectorAll('[data-sheet]');
const page=document.querySelector('.page');
async function loadDocuments(){
 const response=await fetch('/editorial/example-run.json');
 if(!response.ok)throw Error();
 const run=await response.json();
 const approved=run.runs.approve;
 const decision=approved.records.find(r=>r.type==='decision.result'&&r.data.decisionId===approved.approval.id);
 const docs={input:['launch-notes.txt','Source notes',run.input.split('\n').filter(l=>l.startsWith('- ')).map(l=>l.slice(2)).join('\n\n')],draft:['launch-brief.md','The draft',approved.output],decision:['decision.result','Recorded approval','The scripted approver allowed the file write.\n\nAction: '+decision.data.class+'\nRecord: '+decision.seq+'\nHash: '+decision.hash]};
 sheets.forEach(b=>b.onclick=()=>{
   sheets.forEach(x=>x.setAttribute('aria-pressed',String(x===b)));
   const [name,title,body]=docs[b.dataset.sheet];
   document.querySelector('#filename').textContent=name;
   document.querySelector('#doc-title').textContent=title;
   const pre=document.createElement('pre');pre.textContent=body;document.querySelector('#document').replaceChildren(pre);
   if(!matchMedia('(prefers-reduced-motion:reduce)').matches)page.animate([{transform:'perspective(900px) rotateY(-7deg)',opacity:.65},{transform:'none',opacity:1}],{duration:360,easing:'ease-out'});
 });
}
loadDocuments().catch(()=>{document.querySelector('.pager').hidden=true;});
