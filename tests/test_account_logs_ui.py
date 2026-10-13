"""Offline audit UI checks: no service, account, or browser operations."""
import os
from pathlib import Path
import shutil
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which("node"), "Node.js required for inline JavaScript checks")
class AccountLogsUITests(unittest.TestCase):
    def run_js(self, script):
        result = subprocess.run(
            [shutil.which("node"), "-"], input=script, text=True,
            cwd=ROOT, env={**os.environ, "TZ": "Asia/Shanghai"},
            capture_output=True, timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_all_inline_scripts_parse(self):
        self.run_js(r"""
const fs=require('fs'), vm=require('vm');
const html=fs.readFileSync('static/manage.html','utf8');
const scripts=[...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g)].map(match=>match[1]).filter(Boolean);
if(scripts.length<2)throw new Error('Inline scripts missing');
scripts.forEach((source,index)=>new vm.Script(source,{filename:`manage-${index}.js`}));
""")

    def test_filter_safety_dates_pagination_races_and_refresh(self):
        self.run_js(r"""
const fs=require('fs'),vm=require('vm'),assert=require('assert');
const html=fs.readFileSync('static/manage.html','utf8');
const source=[...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g)].at(-1)[1];
const elements=new Map(), timers=new Map();let timerId=0;
function element(id){if(!elements.has(id)){const classes=new Set();elements.set(id,{value:'',checked:true,innerHTML:'',textContent:'',disabled:false,className:'',get options(){return [...this.innerHTML.matchAll(/<option value="([^"]*)"/g)].map(match=>({value:match[1]}))},classList:{contains:name=>classes.has(name),toggle:(name,on)=>on?classes.add(name):classes.delete(name),add:name=>classes.add(name),remove:name=>classes.delete(name)}})}return elements.get(id)}
const context={console,URLSearchParams,Date,Number,JSON,Math,Set,Array,Object,String,document:{hidden:false,getElementById:element,addEventListener(){}},location:{},fetch:async()=>{throw Error('No live API calls allowed')},setInterval:fn=>{timers.set(++timerId,fn);return timerId},clearInterval:id=>timers.delete(id),setTimeout(){}};
context.window=context;context.addEventListener=()=>{};
vm.createContext(context);vm.runInContext(source,context);
const run=code=>vm.runInContext(code,context);
element('accountLogsPageSize').value='50';
assert.equal(run("accountLogDate('2026-10-06 08:11:35')"),run("accountLogDate('2026-10-06T08:11:35Z')"));
assert.match(run("accountLogDate('2026-10-06 08:11:35')"),/16:11:35/);
assert.equal(run("accountLogDate('PRIVATE_VALUE')"),'-');
assert.match(run("accountLogReason('frontend_probe_passed')"),/尚未完成完整凭证校验/);
assert.match(run("accountLogReason('browser_session_refreshed')"),/尚需完整凭证校验/);
assert.match(run("accountLogReason('session_token_unchanged')"),/与原值相同/);
assert.match(run("accountLogReason('browser_context_ambiguous')"),/无法唯一确定/);
assert.match(run("accountLogReason('invalid_sync_result')"),/同步返回结果无法确认/);
assert.match(run("accountLogReason('imported_enabled')"),/启用/);
assert.match(run("accountLogReason('batch_partial_failed')"),/部分账号未成功/);
assert.match(run("accountLogReason('pool_lock_unavailable')"),/号池同步锁/);
assert.match(run("accountLogReason('private_file_permissions')"),/权限/);
assert.match(run("accountLogReason('account_selection_failed')"),/不代表账号永久失效/);
assert.match(run("accountLogReason('login_binding_mismatch')"),/绑定复核不一致/);
assert.match(run("accountLogReason('login_wrong_password')"),/密码/);
assert.match(run("accountLogLabel('state_recheck',accountLogStages)"),/复核同步状态/);
assert.match(run("accountLogLabel('identity_verify',accountLogStages)"),/身份及额度/);
assert.match(run("accountLogLabel('editor_readiness',accountLogStages)"),/等待编辑器/);
assert.match(run("accountLogDetailHtml({setting:'ads_serial',cookie_source:'live'})"),/ADS 序号/);
assert.match(run("accountLogDetailHtml({setting:'token_refresh'})"),/登录态自动校验/);
assert.equal(run("accountLogDetailHtml({setting:'<script>',category:'constructor'})"),'');
assert.equal(run("accountLogDetailHtml({google_cookies:'COOKIE_SECRET',password:'PASSWORD_SECRET',proxy_url:'http://SECRET',count:'<script>'})"),'');
const detail=run("accountLogDetailHtml(JSON.stringify({count:2,identity_verified:true,category:'auth',google_cookies:'COOKIE_SECRET'}))");
assert.match(detail,/身份已验证/);assert.match(detail,/认证/);assert.doesNotMatch(detail,/COOKIE_SECRET/);
run(`renderAccountLogs([{token_id:2,token_email:'<img src=x onerror=alert(1)>',operation:'refresh_at',stage:'AT_REFRESH',status:'failed',reason:'credentials_rejected',source:'admin',created_at:'2026-10-06 08:11:35',details:{password:'PASSWORD_SECRET',count:1}}])`);
assert.match(element('accountLogsTableBody').innerHTML,/&lt;img/);
assert.doesNotMatch(element('accountLogsTableBody').innerHTML,/<img|PASSWORD_SECRET/);
element('accountLogsQuery').value='user+tag@example.test & status=success';element('accountLogsSource').value='admin';
let query=new URLSearchParams(run('accountLogQuery()'));assert.equal(query.get('q'),element('accountLogsQuery').value);assert.equal(query.get('source'),'admin');assert.equal(query.get('status'),null);
run('accountLogState.total=101;accountLogState.page=2;renderAccountLogPagination()');
assert.equal(element('accountLogsPrev').disabled,false);assert.equal(element('accountLogsNext').disabled,false);
run('accountLogState.page=3;renderAccountLogPagination()');assert.equal(element('accountLogsNext').disabled,true);
element('accountLogsQuery').value='';element('accountLogsSource').value='';
(async()=>{
 let resolveOld;
 context.fetch=()=>new Promise(resolve=>{resolveOld=resolve});
 const old=run('loadAccountLogs()');
 context.fetch=async()=>({ok:true,status:200,json:async()=>({items:[{token_email:'new@example.test',operation:'refresh_at',status:'success',reason:'credentials_validated'}],total:51,page:2,operations:['refresh_at'],sources:['admin']})});
 await run('accountLogState.page=2;loadAccountLogs()');
 resolveOld({ok:true,status:200,json:async()=>({items:[{token_email:'old@example.test'}],total:1,page:1})});await old;
 assert.match(element('accountLogsTableBody').innerHTML,/new@example.test/);assert.doesNotMatch(element('accountLogsTableBody').innerHTML,/old@example.test/);assert.equal(run('accountLogState.page'),2);
 context.fetch=async()=>({ok:false,status:500,json:async()=>({detail:'COOKIE_SECRET'})});await run('loadAccountLogs()');
 assert.match(element('accountLogsNotice').textContent,/加载失败/);assert.doesNotMatch(element('accountLogsTableBody').innerHTML,/COOKIE_SECRET/);assert.equal(run('accountLogState.loading'),false);
 context.fetch=async()=>({ok:true,status:200,json:async()=>({items:[],total:0,page:1,operations:[],sources:[]})});await run('loadAccountLogs()');assert.match(element('accountLogsTableBody').innerHTML,/没有符合筛选条件/);
 run('updateAccountLogsAutoRefresh()');assert.equal(timers.size,1);
 context.document.hidden=true;run('updateAccountLogsAutoRefresh()');assert.equal(timers.size,0);
 context.document.hidden=false;element('accountLogsAutoRefresh').checked=false;run('updateAccountLogsAutoRefresh()');assert.equal(timers.size,0);
 assert.match(element('accountLogsNotice').textContent,/自动刷新已关闭/);
 element('accountLogsAutoRefresh').checked=true;element('panelAccountLogs').classList.add('hidden');run('updateAccountLogsAutoRefresh()');assert.equal(timers.size,0);
 run("allTokens=[{id:2,email:'demo@example.test',adspower_serial:7}];rememberAccountLogAccounts([{token_id:99,token_email:'deleted@example.test',token_serial:88}])");
 assert.match(element('accountLogsToken').innerHTML,/deleted@example.test.*历史/);
 element('accountLogsToken').value='99';run('renderAccountLogTokenFilter()');assert.equal(element('accountLogsToken').value,'99');
 element('accountLogsOperation').value='refresh_at';element('accountLogsStatus').value='failed';element('accountLogsSource').value='admin';element('accountLogsQuery').value='previous search';
 run('loadAccountLogs=async()=>{};accountLogState.page=3;openAccountLogs(99)');
 assert.equal(element('accountLogsToken').value,'99');assert.equal(run('accountLogState.page'),1);
 ['accountLogsOperation','accountLogsStatus','accountLogsSource','accountLogsQuery'].forEach(id=>assert.equal(element(id).value,''));
 query=new URLSearchParams(run('accountLogQuery()'));assert.equal(query.get('token_id'),'99');assert.equal(query.get('q'),null);assert.equal(query.get('operation'),null);
 run("renderAccountLogs([{token_id:99,token_email:'deleted@example.test',status:'success'}])");assert.match(element('accountLogsTableBody').innerHTML,/openAccountLogs\(99\)/);
 run('stopAccountLogsAutoRefresh()');
 let downloaded=0,auditRequest;
 context.URL={createObjectURL:()=> 'blob:synthetic',revokeObjectURL(){}};context.Blob=class {};
 context.document.createElement=()=>({click(){downloaded++},style:{}});context.document.body={appendChild(){},removeChild(){}};
 context.fetch=async(url,options)=>{auditRequest={url,options};throw Error('Synthetic audit unavailable')};
 run("allTokens=[{id:2,email:'demo@example.test',google_cookies:'SYNTHETIC_COOKIE'}];exportTokens()");
 await Promise.resolve();assert.equal(downloaded,1);assert.equal(auditRequest.url,'/api/account-logs/events');
 assert.equal(auditRequest.options.method,'POST');assert.deepEqual(JSON.parse(auditRequest.options.body),{operation:'export',status:'success',reason:'export_complete',details:{count:1}});assert.doesNotMatch(auditRequest.options.body,/SYNTHETIC_COOKIE/);
})().catch(error=>{console.error(error);process.exitCode=1});
""")


if __name__ == "__main__":
    unittest.main()
