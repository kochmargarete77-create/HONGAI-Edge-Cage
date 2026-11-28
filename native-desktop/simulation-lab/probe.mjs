// Independent local test consumer. It receives no profile or expected values.
import {createInterface} from 'node:readline';
import {createHash} from 'node:crypto';

const allowed = new Set(['network','regional','platform','hardware','rendering','state','tools']);
const fault = process.argv[2] || 'none';
const send = value => process.stdout.write(JSON.stringify(value)+'\n');
const digest = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
let start, index = 0, pending, observed = {};
const input = createInterface({input:process.stdin, crlfDelay:Infinity});
function requestNext() {
  if (index === start.surfaces.length) {
    if (fault === 'mutate') observed.regional = {unexpected:'LOCAL_FAULT_FIXTURE'};
    send({type:'complete',version:1,runId:start.runId,challenge:start.challenge,observed,observedDigest:digest(observed)});
    input.close();process.stdin.destroy();return;
  }
  pending = {requestId:'r'+index, surface:start.surfaces[index]};
  send({type:'read',version:1,runId:start.runId,challenge:fault==='stale'?'stale-challenge':start.challenge,...pending});
}
input.on('line', line => {
  if (Buffer.byteLength(line)>32768) {process.exitCode=2;input.close();process.stdin.destroy();return;}
  let message;try{message=JSON.parse(line);}catch{process.exit(2);}
  if (!start) {
    if (message.type!=='start'||message.version!==1||!Array.isArray(message.surfaces)||message.surfaces.length!==7||new Set(message.surfaces).size!==7||message.surfaces.some(x=>!allowed.has(x)))process.exit(2);
    start=message;
    if(fault==='silent')return;
    if(fault==='oversized'){process.stdout.write('X'.repeat(40000));return;}
    requestNext();return;
  }
  if (message.type!=='value'||message.version!==1||message.runId!==start.runId||message.challenge!==start.challenge||message.requestId!==pending.requestId||message.surface!==pending.surface)process.exit(2);
  observed[pending.surface]=message.value;index++;requestNext();
});
