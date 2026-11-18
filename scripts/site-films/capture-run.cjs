// Capture the real browser verifier. Start the static site and set SITE_URL, NODE_PATH and CHROMIUM_PATH.
const {chromium}=require('playwright');
const path=require('node:path');
const os=require('node:os');
const {execFileSync}=require('node:child_process');
(async()=>{
 const browser=await chromium.launch({executablePath:process.env.CHROMIUM_PATH});
 const media=path.resolve(__dirname,'../../site/assets/films');
 try {
  const page=await browser.newPage({viewport:{width:1152,height:720},recordVideo:{dir:os.tmpdir(),size:{width:1152,height:720}}});
  await page.goto((process.env.SITE_URL||'http://127.0.0.1:4173')+'/editorial/',{waitUntil:'networkidle'});
  await page.locator('[data-decision=approve]:enabled').waitFor();
  await page.addStyleTag({content:`
    html {scroll-behavior:auto} body {overflow:hidden}
    .masthead,.skip,main>section:not(.run-example),footer,.run-intro,.example-provenance,.honest-note {display:none}
    .run-example {width:100%;margin:0;padding:0 30px}
    .run-panels {min-height:610px;padding:28px}.run-book {box-shadow:none}
    .run-layout {grid-template-columns:185px 1fr}
    .run-steps {padding:16px 8px}.run-steps button {padding:12px 6px}
    .run-example::before {content:'StarClaw  /  Recorded engine run';display:block;padding:18px 0;font:500 20px "Space Grotesk",sans-serif}
    button:focus-visible {outline:3px solid #cf4728}
  `});
  const video=page.video();

  const t0=Date.now();
  async function hold(ms){await page.waitForTimeout(ms);}
  async function select(selector){const target=page.locator(selector);await target.focus();await hold(500);await target.press('Enter');}
  await hold(2300);
  await select('[data-decision=approve]');
  await hold(2100);
  await select('#verify-log');
  await page.locator('[data-result=verified]').waitFor();
  await hold(2600);
  await select('#test-tamper');
  await page.locator('[data-result=rejected]').waitFor();
  await hold(2800);
  await page.close();
  const raw=await video.path();
  const elapsed=(Date.now()-t0)/1000;
  const metadata=JSON.parse(execFileSync('ffprobe',['-v','quiet','-show_format','-of','json',raw]));
  const skip=Math.max(0,Number(metadata.format.duration)-elapsed);
  execFileSync('ffmpeg',['-loglevel','error','-y','-ss',String(skip),'-i',raw,'-an','-c:v','libx264','-crf','17','-pix_fmt','yuv420p','-movflags','+faststart',path.join(media,'run.mp4')]);
  execFileSync('ffmpeg',['-loglevel','error','-y','-ss','1','-i',path.join(media,'run.mp4'),'-frames:v','1',path.join(media,'run.jpg')]);
  await video.delete();
 } finally {await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
