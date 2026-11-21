// Usage: NODE_PATH must resolve playwright. Set CHROMIUM_PATH to your browser executable.
const {chromium} = require('playwright');
const {spawn} = require('node:child_process');
const {once} = require('node:events');
const path = require('node:path');
const {pathToFileURL} = require('node:url');
const fs = require('node:fs');
const media = path.resolve(__dirname, '../../site/assets/films');
const film = process.argv[2];
(async()=>{
 const browser=await chromium.launch({executablePath:process.env.CHROMIUM_PATH});
 try {
  const page=await browser.newPage({viewport:{width:1152,height:720},deviceScaleFactor:1});
  await page.goto(pathToFileURL(path.join(__dirname, film+'.html')).href);
  await page.evaluate(()=>document.fonts.ready);
  const duration=Number(await page.locator('main').getAttribute('data-duration'));
  const fps=24;
  const encoder=spawn('ffmpeg',['-hide_banner','-loglevel','error','-y','-f','image2pipe','-framerate',String(fps),'-i','pipe:0','-an','-c:v','libx264','-preset','fast','-crf','20','-pix_fmt','yuv420p','-movflags','+faststart',path.join(media,film+'.mp4')],{stdio:['pipe','inherit','inherit']});
  const finished=once(encoder,'close');
  for(let frame=0;frame<duration*fps;frame++){
   await page.evaluate(({film,t})=>{window.__timelines[film].time(t);},{film,t:frame/fps});
   const pixels=await page.screenshot({type:'jpeg',quality:94});
   if(frame===fps) fs.writeFileSync(path.join(media,film+'.jpg'),pixels);
   if(!encoder.stdin.write(pixels)) await once(encoder.stdin,'drain');
  }
  encoder.stdin.end();
  if((await finished)[0]!==0)throw Error('Video encoder failed');
 } finally {await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
