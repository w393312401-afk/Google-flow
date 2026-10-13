"""Unified refresh controls verified with synthetic API responses only."""
import os
from pathlib import Path
import shutil
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which("node"), "Node.js required for UI checks")
class RefreshControlsUITests(unittest.TestCase):
    def run_js(self, code):
        result = subprocess.run(
            [shutil.which("node"), "-"], input=code, text=True, cwd=ROOT,
            env={**os.environ, "TZ": "Asia/Shanghai"}, capture_output=True, timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_single_control_markup_and_script_syntax(self):
        self.run_js(r"""
const fs=require('fs'),vm=require('vm'),assert=require('assert');
const html=fs.readFileSync('static/manage.html','utf8');
assert.doesNotMatch(html,/atAutoRefreshToggle|toggleATAutoRefresh|onclick="refreshTokens\(\)"/);
assert.equal((html.match(/id="refreshAllBtn"/g)||[]).length,1);
assert.match(html,/id="refreshAllLabel"[^>]*>刷新<\/span>/);
assert.match(html,/id="tokenRefreshSettingsBtn"/);
assert.match(html,/max="525600"/);
assert.match(html,/关闭页面后仍会执行/);
assert.match(html,/支持定时校验且已配置登录凭据/);
[...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g)].forEach(match=>new vm.Script(match[1]));
""")

    def test_read_save_cancel_scope_errors_and_manual_deduplication(self):
        self.run_js(r"""
const fs=require('fs'),vm=require('vm'),assert=require('assert');
const html=fs.readFileSync('static/manage.html','utf8');
const source=[...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g)].at(-1)[1];
const nodes=new Map(),requests=[];
function node(id){if(!nodes.has(id)){const classes=new Set();nodes.set(id,{value:'',checked:false,disabled:false,innerHTML:'',textContent:'',className:'',style:{},classList:{add:(...names)=>names.forEach(name=>classes.add(name)),remove:(...names)=>names.forEach(name=>classes.delete(name)),contains:name=>classes.has(name),toggle:(name,on)=>on?classes.add(name):classes.delete(name)}})}return nodes.get(id)}
let response=async()=>({ok:true,status:200,json:async()=>({success:true,config:{at_auto_refresh_enabled:true,protocol_refresh_enabled:false,refresh_interval_minutes:120}})});
const ctx={console,URLSearchParams,document:{hidden:false,getElementById:node,addEventListener(){},createElement:()=>node('toast'),body:{appendChild(){},removeChild(){}}},location:{},setTimeout(){},setInterval(){return 1},clearInterval(){},fetch:async(url,opts={})=>{requests.push({url,method:opts.method||'GET',body:opts.body});return response(url,opts)}};
ctx.window=ctx;ctx.addEventListener=()=>{};vm.createContext(ctx);vm.runInContext(source,ctx);
const run=code=>vm.runInContext(code,ctx),postCount=()=>requests.filter(item=>item.method==='POST').length;
(async()=>{
 await run('loadATAutoRefreshConfig()');assert.equal(postCount(),0);
 assert.equal(node('tokenRefreshSummary').textContent,'定时关闭');
 node('tokenRefreshSettingsModal').classList.remove('hidden');await run('loadATAutoRefreshConfig({populate:true})');
 assert.equal(node('tokenRefreshEnabled').checked,false);assert.equal(node('tokenRefreshInterval').value,'120');assert.equal(postCount(),0);
 node('tokenRefreshEnabled').checked=true;node('tokenRefreshInterval').value='23';run('closeTokenRefreshSettings()');assert.equal(postCount(),0);assert.equal(node('tokenRefreshSettingsModal').classList.contains('hidden'),true);
 response=async()=>({ok:false,status:503});node('tokenRefreshSettingsModal').classList.remove('hidden');await run('loadATAutoRefreshConfig({populate:true})');
 assert.equal(node('tokenRefreshSaveBtn').disabled,true);await run('saveTokenRefreshSettings()');assert.equal(postCount(),0);assert.match(node('tokenRefreshConfigNotice').textContent,/无法读取/);
 response=async()=>({ok:true,status:200,json:async()=>({success:true,config:{at_auto_refresh_enabled:true,protocol_refresh_enabled:false,refresh_interval_minutes:120}})});await run('loadATAutoRefreshConfig({populate:true})');
 node('tokenRefreshEnabled').checked=true;run('updateTokenRefreshDraft()');assert.equal(node('tokenRefreshInterval').disabled,false);
 for(const invalid of ['0','1.5','525601','','1e2']){node('tokenRefreshInterval').value=invalid;await run('saveTokenRefreshSettings()')};assert.equal(postCount(),0);
 node('tokenRefreshInterval').value='23';response=async()=>({ok:false,status:503});await run('saveTokenRefreshSettings()');assert.equal(postCount(),1);assert.equal(node('tokenRefreshInterval').value,'23');assert.equal(node('tokenRefreshEnabled').checked,true);assert.equal(node('tokenRefreshSettingsModal').classList.contains('hidden'),false);assert.match(node('tokenRefreshConfigNotice').textContent,/保存未能确认/);assert.equal(run('tokenRefreshState.config.protocol_refresh_enabled'),false);
 response=async(url,opts)=>({ok:true,status:200,json:async()=>url==='/api/token-refresh/config'?{success:true,config:{protocol_refresh_enabled:JSON.parse(opts.body).enabled,refresh_interval_minutes:JSON.parse(opts.body).refresh_interval_minutes}}:url==='/api/tokens'?[{id:2,email:'synthetic@example.test',is_active:true,protocol_mode:'protocol',google_cookies:'SYNTHETIC',auto_refresh_enabled:true,refresh_interval_minutes:23}]:{}});
 await run('saveTokenRefreshSettings()');const saved=requests.filter(item=>item.method==='POST').at(-1);assert.equal(saved.url,'/api/token-refresh/config');assert.deepEqual(JSON.parse(saved.body),{enabled:true,refresh_interval_minutes:23,apply_to_active_tokens:true});assert.doesNotMatch(saved.body,/SYNTHETIC|cookie/);assert.equal(node('tokenRefreshSettingsModal').classList.contains('hidden'),true);assert.equal(node('tokenRefreshSummary').textContent,'每 23 分钟');
 run("allTokens.push({id:3,is_active:true,protocol_mode:'protocol',google_cookies:'SYNTHETIC',auto_refresh_enabled:false,refresh_interval_minutes:120});renderTokenRefreshSummary()");assert.equal(node('tokenRefreshSummary').textContent,'定时已开启');assert.match(node('tokenRefreshScope').textContent,/其中 1 个参与/);
 run("allTokens=allTokens.filter(token=>token.id===2);allTokens.push({id:4,is_active:true,protocol_mode:'session',google_cookies:'SYNTHETIC',auto_refresh_enabled:true},{id:5,is_active:true,protocol_mode:'protocol',google_cookies:'',auto_refresh_enabled:true},{id:6,is_active:false,protocol_mode:'protocol',google_cookies:'SYNTHETIC',auto_refresh_enabled:true});renderTokenRefreshSummary()");assert.equal(node('tokenRefreshSummary').textContent,'每 23 分钟');assert.match(node('tokenRefreshScope').textContent,/1 个支持定时/);
 let finishManual,manualCalls=0;
 response=(url)=>url==='/api/tokens/refresh-all'?(manualCalls++,new Promise(resolve=>{finishManual=resolve})):Promise.resolve({ok:true,status:200,json:async()=>url==='/api/tokens'?[]:{}});
 const first=run('refreshAllTokenAT()');const second=run('refreshAllTokenAT()');await second;assert.equal(manualCalls,1);assert.equal(node('refreshAllBtn').disabled,true);
 finishManual({ok:true,status:200,json:async()=>({success:true,total:1,failed:1,succeeded:0,results:[{id:2,email:'synthetic@example.test',success:false,error:'credentials rejected',disabled:true}]})});await first;
 assert.equal(node('refreshAllBtn').disabled,false);assert.equal(node('refreshAllLabel').textContent,'刷新');assert.equal(node('refreshAllModal').classList.contains('hidden'),false);assert.match(node('refreshAllList').innerHTML,/已失效|重新登录|失败/);
 const manualIndex=requests.findIndex(item=>item.url==='/api/tokens/refresh-all');assert(requests.slice(manualIndex+1).some(item=>item.url==='/api/tokens'));assert(requests.slice(manualIndex+1).some(item=>item.url==='/api/stats'));
})().catch(error=>{console.error(error);process.exitCode=1});
""")


if __name__ == "__main__":
    unittest.main()
