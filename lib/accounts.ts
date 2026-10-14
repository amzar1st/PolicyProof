import {generatePrivateKey,privateKeyToAccount} from 'viem/accounts';
import type {PrivateKeyAccount} from 'viem';
// Ephemeral browser-memory keys. Never persisted, logged, or sent to the server.
const signers=new Map<string,PrivateKeyAccount>();
let walletAddress='';
export function generateDemoAccount(){const a=privateKeyToAccount(generatePrivateKey());signers.set(a.address.toLowerCase(),a);return a.address.toLowerCase()}
export function signingAccount(address:string){const a=signers.get(address.toLowerCase());if(a)return a;if(walletAddress===address.toLowerCase())return address as `0x${string}`;throw Error('This address is read-only. Connect its wallet or generate a signed demo account. Selecting an address does not authorize its use.')}
export function isWalletAccount(address:string){return walletAddress===address.toLowerCase()}
export async function connectWallet(){const provider=(globalThis as any).ethereum;if(!provider)throw Error('No wallet extension found. Generate a signed demo account instead.');const accounts=await provider.request({method:'eth_requestAccounts'});const chain=await provider.request({method:'eth_chainId'});if(BigInt(chain)!==61999n)throw Error('Switch your wallet to StudioNet, chain 61999, then connect again.');walletAddress=accounts[0].toLowerCase();return walletAddress}
export async function walletRequest(method:string,params:unknown[]){const provider=(globalThis as any).ethereum;const accounts=await provider.request({method:'eth_accounts'});if(accounts[0]?.toLowerCase()!==walletAddress)throw Error('Wallet account changed; reconnect.');if(BigInt(await provider.request({method:'eth_chainId'}))!==61999n)throw Error('Wallet network changed; reconnect to StudioNet.');return provider.request({method,params})}
