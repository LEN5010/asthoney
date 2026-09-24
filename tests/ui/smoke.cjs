/* Checks a running rehearsal instance; never purges its data. */
const { chromium } = require('playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const base = process.env.BASE_URL || 'http://127.0.0.1:8765';
const out = path.resolve(process.env.UI_OUTPUT || 'docs/evidence/ssh-demo/ui');
fs.mkdirSync(out, {recursive:true});
const results = [];
const record = (name, detail={}) => { results.push({name, passed:true, ...detail}); console.log('PASS ' + name); };
(async()=>{
 const browser = await chromium.launch({headless:true});
 const context = await browser.newContext({viewport:{width:1366,height:768}, reducedMotion:'reduce'});
 const page = await context.newPage();
 const errors = [];
 page.on('pageerror', error => errors.push(error.message));
 await page.addInitScript(() => {
   localStorage.setItem('theme','dark');
   const Native = window.WebSocket; window.testSockets = [];
   window.WebSocket = class extends Native {constructor(...args) {super(...args); window.testSockets.push(this);}};
 });
 let runId;
 if (!process.env.UI_LAYOUT_ONLY) {
 await page.goto(base);
 await page.waitForFunction(()=>document.documentElement.dataset.stream === 'connected');
 await page.waitForFunction(()=>document.querySelectorAll('#graphCanvas g[data-tip]').length>0);
 assert.equal(await page.locator('[data-pref-theme]').count(),0);
 assert.equal(await page.evaluate(()=>getComputedStyle(document.documentElement).colorScheme),'light');
 record('默认浅色且无旧主题影响');
 assert.equal(await page.locator('input[type=password]').count(),0);
 const { execFileSync } = require('node:child_process');
 const python = fs.existsSync('.venv/bin/python') ? '.venv/bin/python' : 'venv/bin/python';
 execFileSync(python,['-c', `import asyncio,asyncssh
async def run():
 async with asyncssh.connect('127.0.0.1',2222,username='svc-backup',client_keys=[],agent_path=None,known_hosts=None) as c:
  await c.run('whoami',check=True)
  await c.run('echo browser-live-probe',check=True)
asyncio.run(run())`]);
 await page.waitForFunction(()=>document.querySelector('#liveTerminal').textContent.includes('browser-live-probe'));
 record('真实 SSH 输出实时出现在总览，无登录弹窗');
 const firstRun=JSON.parse(fs.readFileSync('docs/evidence/ssh-demo/ssh-results.json','utf8'));
 runId=firstRun.session_id;
 await page.locator('#liveSessionSelect').selectOption(runId);
 await page.waitForFunction(()=>document.querySelector('#liveTerminal').textContent.includes('vmstat 1 1'));
 await page.locator('#refreshBtn').click();
 assert.equal(await page.locator('#liveSessionSelect').inputValue(),runId);
 record('选择真实会话并在刷新后保持');
 await page.evaluate(()=>window.testSockets.at(-1).close());
 await page.waitForFunction(()=>document.documentElement.dataset.stream==='reconnecting');
 await page.waitForFunction(()=>document.documentElement.dataset.stream==='connected');
 record('WebSocket 断线重连');
 await page.route('**/alerts', route=>route.fulfill({status:503,contentType:'application/json',body:'{"detail":"test outage"}'}));
 await page.locator('#refreshBtn').click();
 await page.waitForSelector('.alerts-panel > .error-bar');
 assert((await page.locator('#graphCanvas g[data-tip]').count())>0);
 await page.unroute('**/alerts');
 await page.locator('#refreshBtn').click();
 await page.waitForSelector('.alerts-panel > .error-bar',{state:'detached'});
 record('局部接口失败不影响拓扑且可恢复');
 await page.goto(base+'/sessions/view');
 await page.waitForSelector('#sessionRows .table-row');
 const rows=await page.locator('#sessionRows .table-row').count();
 await page.locator('#sessionSearch').fill('no-matching-session-zz');
 await page.waitForSelector('#sessionRows .empty-state');
 await page.locator('#sessionSearch').fill('');
 assert.equal(await page.locator('#sessionRows .table-row').count(),rows);
 await page.locator('#sessionSort').selectOption('commands');
 const counts=await page.locator('#sessionRows [data-label="命令数"]').allTextContents();
 assert.deepEqual(counts.map(Number),counts.map(Number).sort((a,b)=>b-a));
 await page.locator('.danger-zone summary').click();
 await page.locator('#purgeHistoryBtn').click();
 await page.locator('dialog button[value=cancel]').click();
 assert.equal(await page.locator('#sessionRows .table-row').count(),rows);
 record('会话搜索、排序和清理取消');
 if (!runId) {
   const href=await page.locator('#sessionRows a').first().getAttribute('href');
   runId=new URL(href,base).searchParams.get('session_id');
 }
 await page.goto(base+'/session/view?session_id='+encodeURIComponent(runId));
 await page.waitForFunction(()=>document.querySelector('#replayMeta').textContent !== '0/0 事件');
 await page.locator('#stepBtn').click();
 await page.locator('#tab-2').click();
 await page.waitForSelector('#decisionList .is-active');
 await page.locator('#playBtn').click();
 await page.waitForTimeout(900);
 await page.locator('#pauseBtn').click();
 const paused=await page.locator('#replayMeta').textContent();
 await page.waitForTimeout(800);
 assert.equal(await page.locator('#replayMeta').textContent(),paused);
 await page.locator('#resetBtn').click();
 assert((await page.locator('#replayMeta').textContent()).startsWith('0/'));
 await page.locator('#tab-0').click();
 await page.keyboard.press('ArrowRight');
 assert.equal(await page.locator('#tab-1').getAttribute('aria-selected'),'true');
 record('回放播放、暂停、重置、决策同步与键盘标签');
 await page.goto(base+'/attack/view');
 await page.waitForSelector('[data-technique]');
 await page.locator('[data-technique]').first().click();
 const technique=await page.locator('[data-technique][aria-pressed=true]').getAttribute('data-technique');
 assert((await page.locator('#evidenceMeta').textContent()).includes(technique));
 await page.locator('#clearTechnique').click();
 assert.equal(await page.locator('[data-technique][aria-pressed=true]').count(),0);
 record('攻击矩阵点击与全部证据恢复');
 await page.goto(base+'/profiles/view');
 await page.waitForSelector('[data-select]');
 await page.locator('[data-select]').last().click();
 const ip=await page.locator('[data-select][aria-pressed=true]').getAttribute('data-select');
 await page.locator('#refreshBtn').click();
 await page.waitForTimeout(500);
 assert.equal(await page.locator('[data-select][aria-pressed=true]').getAttribute('data-select'),ip);
 record('画像选择在刷新后保持');
 } else {
   runId=JSON.parse(fs.readFileSync('docs/evidence/ssh-demo/ssh-results.json','utf8')).session_id;
 }
 const routes=[['overview','/'],['sessions','/sessions/view'],['replay','/session/view?session_id='+encodeURIComponent(runId)],['attack','/attack/view'],['profiles','/profiles/view']];
 for(const size of [{width:1366,height:768},{width:1920,height:1080}]) {
   await page.setViewportSize(size);
   for(const [name,route] of routes) {
     await page.goto(base+route);
     await page.waitForTimeout(1200);
     if(name==='replay') {
       await page.locator('[data-speed="350"]').click();
       await page.locator('#playBtn').click();
       await page.waitForTimeout(4300);
       await page.locator('#pauseBtn').click();
     }
     const width=await page.evaluate(()=>document.documentElement.scrollWidth);
     assert(width<=size.width,name+': horizontal overflow '+width);
     if(name==='overview') {
       const graph=await page.locator('.topology-panel').boundingBox();
       const roles=await page.locator('#theaterRoles').boundingBox();
       assert(graph.y+graph.height<=size.height+5,'topology must fit first screen');
       assert(roles.y+roles.height<=size.height+5,'decision steps must fit first screen');
     }
     await page.screenshot({path:path.join(out,name+'-'+size.width+'.png'),fullPage:false});
     record('布局与截图 '+name+' '+size.width+'×'+size.height);
   }
 }
 await page.goto(base+'/session/view?session_id=does-not-exist');
 await page.waitForFunction(()=>document.querySelector('#sessionMeta').textContent.includes('加载失败'));
 assert(await page.locator('#playBtn').isDisabled());
 record('未知会话错误态');
 await page.route('**/sessions', route=>route.fulfill({json:{sessions:[]}}));
 await page.goto(base+'/sessions/view');
 await page.waitForSelector('#sessionRows .empty-state');
 record('空数据状态');
 await page.unroute('**/sessions');
 await page.route('**/sessions', route=>route.fulfill({json:{sessions:[{session_id:'<img src=x>',source_ip:'<script>bad</script>',last_payload:'<img src=x>',command_count:1}]}}));
 await page.reload();
 await page.waitForSelector('#sessionRows .table-row');
 assert.equal(await page.locator('#sessionRows img').count(),0);
 record('不可信会话内容按纯文本渲染');
 assert.deepEqual(errors,[], 'browser page errors');
 record('全部页面无 JavaScript 异常');
 await browser.close();
 fs.writeFileSync(path.join(out,'results.json'),JSON.stringify({checked_at:new Date().toISOString(),base,results},null,2));
 console.log('Completed '+results.length+' checks.');
})().catch(error=>{ console.error(error); fs.writeFileSync(path.join(out,'failure.txt'),String(error.stack)); process.exit(1); });
