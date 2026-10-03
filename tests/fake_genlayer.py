"""Behavioral harness, not a GenVM, storage, or network-consensus emulator."""
import types
bigint=int
class TreeMap(dict):pass
class UserError(Exception):pass
class Return:
 def __init__(self,calldata):self.calldata=calldata
class Contract:
 def __new__(cls,*args):
  obj=super().__new__(cls)
  for name,typ in cls.__annotations__.items():
   if getattr(typ,'__origin__',None) is TreeMap:setattr(obj,name,TreeMap())
  return obj
class Runtime:
 def __init__(self):self.pages={};self.answers=[];self.fetches=[]
 def render(self,url,mode):
  self.fetches.append(url);v=self.pages[url]
  if isinstance(v,Exception):raise v
  return v
 def prompt(self,prompt):return self.answers.pop(0)
runtime=Runtime()
def nondet(leader,validator):
 answer=leader()
 if not validator(Return(answer)):raise UserError('Validator disagreement')
 return answer
identity=lambda f:f
gl=types.SimpleNamespace(Contract=Contract,public=types.SimpleNamespace(write=identity,view=identity),message=types.SimpleNamespace(sender_address='owner'),vm=types.SimpleNamespace(UserError=UserError,Return=Return,run_nondet_unsafe=nondet),nondet=types.SimpleNamespace(web=types.SimpleNamespace(render=runtime.render),exec_prompt=runtime.prompt))
