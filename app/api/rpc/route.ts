import deployment from '@/lib/deployment.json';
import {validateSignedWrite} from '@/lib/rpc-policy';
const allowed=new Set(['gen_call','gen_getContractSchema','gen_getContractCode','eth_chainId','eth_gasPrice','eth_estimateGas','eth_getTransactionCount','eth_sendRawTransaction','eth_getTransactionByHash','eth_getTransactionReceipt']);
export async function POST(request:Request){
 const fail=(message:string,status=400)=>Response.json({jsonrpc:'2.0',id:null,error:{code:-32600,message}},{status});
 try{
  const text=await request.text();if(text.length>100000)return fail('Request too large',413);
  const p=JSON.parse(text);
  if(!p||!allowed.has(p.method)||!Array.isArray(p.params)||p.params.length>4)return fail('Unsupported RPC method');
  if(p.method==='gen_call'&&(p.params[0]?.to?.toLowerCase()!==deployment.address.toLowerCase()||p.params[0]?.type!=='read'))return fail('Only PolicyProof reads are supported');
  if(p.method==='eth_sendRawTransaction'){
   try{await validateSignedWrite(p.params[0],deployment.address,deployment.chainId)}catch(e){return fail(e instanceof Error?e.message:'Invalid signed transaction')}
  }
  const r=await fetch(deployment.rpc,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(p),signal:AbortSignal.timeout(25000)});
  if(!r.ok)return fail('Studionet is unavailable',502);
  return new Response(await r.text(),{headers:{'Content-Type':'application/json','Cache-Control':'no-store'}});
 }catch{return fail('Studionet request failed',502)}
}
