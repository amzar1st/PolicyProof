import {decodeFunctionData,parseTransaction,recoverTransactionAddress,type Hex,type TransactionSerialized} from 'viem';
import {studionet} from 'genlayer-js/chains';
export async function validateSignedWrite(serialized:Hex,address:string,chainId:number){
 const tx=parseTransaction(serialized);
 if(Number(tx.chainId)!==chainId)throw Error('Wrong signing chain');
 const sender=await recoverTransactionAddress({serializedTransaction:serialized as TransactionSerialized});
 if(tx.to?.toLowerCase()!==studionet.consensusMainContract?.address.toLowerCase()||BigInt(tx.value||0)!==0n)throw Error('Only zero-value PolicyProof Studio transactions are supported');
 if(!tx.data)throw Error('Missing transaction data');
 const decoded=decodeFunctionData({abi:studionet.consensusMainContract!.abi,data:tx.data});
 const args=decoded.args as any[];
 if(decoded.functionName!=='addTransaction'||args[0]?.toLowerCase()!==sender.toLowerCase()||args[1]?.toLowerCase()!==address.toLowerCase())throw Error('Signed sender and PolicyProof target must match');
 return sender;
}
