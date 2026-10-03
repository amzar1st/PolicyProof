import unittest,sys,json,hashlib,importlib.util
from pathlib import Path
import fake_genlayer
sys.modules['genlayer']=fake_genlayer
s=importlib.util.spec_from_file_location('policyproof',Path(__file__).parents[1]/'contracts/policyproof.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
gl=fake_genlayer.gl;r=fake_genlayer.runtime;A='https://example.org/incident';B='https://example.org/response'
class Tests(unittest.TestCase):
 def setUp(self):
  self.t=1000;m.now=lambda:self.t;gl.message.sender_address='owner';r.pages={A:'Incident report, public postmortem and remediation timeline.',B:'Response evidence containing supporting remediation details.'};r.answers=[];r.fetches=[]
  self.c=m.PolicyProof(60,60,1000);self.o=self.c.create_organization('Demo','https://example.org');self.p=self.c.publish_policy(self.o,'Disclosure v1','Disclose within 72 hours; include postmortem and remediation.','https://example.org/policy');gl.message.sender_address='requester';self.k=self.c.open_compliance_check(self.p,'Synthetic incident')
 def state(self):return json.loads(self.c.get_check(self.k))
 def add(self,u=A,h=''):self.c.submit_evidence(self.k,u,'Relevant incident evidence',h)
 def answer(self,v='COMPLIANT',cite=None):return json.dumps({'verdict':v,'reasoning':'The fetched evidence supports the stated policy criteria.','citations':[A] if cite is None else cite})
 def review(self,v='COMPLIANT'):
  self.t=1060;r.answers=[self.answer(v),self.answer(v)];self.c.validator_review(self.k)
 def rejects(self,fn,*args):
  with self.assertRaises(Exception):fn(*args)
 def test_compliant_full_workflow(self):
  self.add();gl.message.sender_address='owner';self.c.submit_response(self.k,'Public response',B,'');self.review();self.assertEqual(r.fetches.count(A),2);self.assertEqual(r.fetches.count(B),2);self.t=1120;self.c.finalize(self.k);self.assertIsNotNone(self.state()['attestation']);self.assertEqual(self.state()['record_type'],'ATTESTATION')
 def test_non_compliance_records_violation(self):
  self.add();self.review('NON_COMPLIANT');self.t=1120;self.c.finalize(self.k);self.assertEqual(self.state()['record_type'],'VIOLATION');self.assertIsNone(self.state()['attestation'])
 def test_partial_compliance_records_violation(self):
  self.add();self.review('PARTIALLY_COMPLIANT');self.t=1120;self.c.finalize(self.k);self.assertEqual(self.state()['record_type'],'VIOLATION')
 def test_ambiguous_no_attestation(self):
  self.add();self.review('POLICY_AMBIGUOUS');self.t=1120;self.c.finalize(self.k);self.assertIsNone(self.state()['attestation'])
 def test_insufficient_no_attestation(self):
  self.add();self.review('INSUFFICIENT_EVIDENCE');self.t=1120;self.c.finalize(self.k);self.assertIsNone(self.state()['attestation'])
 def test_only_owner_publishes(self):self.rejects(self.c.publish_policy,self.o,'Forged','Changed','https://example.org/policy')
 def test_policy_versions_immutable(self):
  old=self.c.get_policy(self.p);gl.message.sender_address='owner';self.c.publish_policy(self.o,'v2','Disclose in 24 hours','https://example.org/policy');self.assertEqual(old,self.c.get_policy(self.p));self.assertEqual(self.state()['policy_id'],self.p)
 def test_outsider_submission_rejected(self):gl.message.sender_address='outsider';self.rejects(self.add)
 def test_requester_response_rejected(self):self.rejects(self.c.submit_response,self.k,'Forged',B,'')
 def test_evidence_deadline_enforced(self):self.t=1060;self.rejects(self.add)
 def test_review_deadline_enforced(self):self.add();self.rejects(self.c.validator_review,self.k)
 def test_finalization_deadline_enforced(self):self.add();self.review();self.rejects(self.c.finalize,self.k)
 def test_capacity_reserved_per_side(self):
  for i in range(4):self.add('https://example.org/e'+str(i))
  self.rejects(self.add);gl.message.sender_address='owner';self.c.submit_response(self.k,'Response',B,'');self.assertEqual(len(self.state()['evidence']['organization']),1)
 def test_duplicate_evidence_rejected(self):self.add();self.rejects(self.add)
 def test_malformed_hash_rejected(self):self.rejects(self.add,A,'bad')
 def test_malicious_hash_never_attests(self):
  self.add(h='0'*64);self.t=1060;self.c.validator_review(self.k);self.assertEqual(self.state()['status'],'EVIDENCE_REVIEW');self.t=1120;self.c.finalize(self.k);self.assertIsNone(self.state()['attestation'])
 def test_matching_hash_accepted(self):self.add(h=hashlib.sha256(r.pages[A].encode()).hexdigest());self.review();self.assertEqual(self.state()['review']['verdict'],'COMPLIANT')
 def test_failed_fetch_blocks_attestation(self):
  self.add();r.pages[A]=RuntimeError('unavailable');self.t=1060;self.c.validator_review(self.k);self.assertEqual(self.state()['review']['failed_urls'],[A]);self.assertEqual(self.state()['review']['verdict'],'INSUFFICIENT_EVIDENCE')
 def test_failed_fetch_retry_recovers(self):
  self.add();r.pages[A]=RuntimeError();self.t=1060;self.c.validator_review(self.k);r.pages[A]='Evidence recovered with adequate remediation information.';r.answers=[self.answer(),self.answer()];self.t=1061;self.c.validator_review(self.k);self.assertEqual(self.state()['status'],'REVIEWED')
 def test_absent_evidence_unresolved(self):self.t=1060;self.c.validator_review(self.k);self.assertEqual(self.state()['review']['verdict'],'INSUFFICIENT_EVIDENCE')
 def test_empty_page_unresolved(self):self.add();r.pages[A]='';self.t=1060;self.c.validator_review(self.k);self.assertEqual(self.state()['status'],'EVIDENCE_REVIEW')
 def test_unfetched_citation_rejected(self):self.add();self.t=1060;r.answers=[self.answer(cite=[B])];self.rejects(self.c.validator_review,self.k);self.assertEqual(self.state()['status'],'EVIDENCE_OPEN')
 def test_missing_citations_rejected(self):self.add();self.t=1060;r.answers=[self.answer(cite=[])];self.rejects(self.c.validator_review,self.k)
 def test_independent_validator_disagreement(self):self.add();self.t=1060;r.answers=[self.answer(),self.answer('NON_COMPLIANT')];self.rejects(self.c.validator_review,self.k);self.assertEqual(self.state()['status'],'EVIDENCE_OPEN')
 def test_challenge_and_counter_evidence(self):
  self.add();self.review();self.t=1061;self.c.challenge(self.k,'New evidence',B,'');deadline=self.state()['challenge_deadline'];gl.message.sender_address='owner';self.c.submit_counter_evidence(self.k,'https://example.org/counter','Counter evidence','');self.assertEqual(deadline,self.state()['challenge_deadline']);self.rejects(self.c.finalize,self.k)
 def test_outsider_challenge_rejected(self):self.add();self.review();gl.message.sender_address='outsider';self.rejects(self.c.challenge,self.k,'Reason',B,'')
 def test_late_challenge_rejected(self):self.add();self.review();self.t=1120;self.rejects(self.c.challenge,self.k,'Reason',B,'')
 def test_only_one_challenge_round(self):
  self.add();self.review();self.t=1061;self.c.challenge(self.k,'Reason',B,'');self.t=1120;r.answers=[self.answer(),self.answer()];self.c.validator_review(self.k);self.rejects(self.c.challenge,self.k,'Again','https://example.org/again','');self.t=1180;self.c.finalize(self.k);self.assertEqual(len(self.state()['history']),2)
 def test_timeout_open(self):self.t=2000;self.c.resolve_timeout(self.k);self.assertEqual(self.state()['status'],'EXPIRED');self.assertIsNone(self.state()['attestation'])
 def test_timeout_challenged(self):self.add();self.review();self.t=1061;self.c.challenge(self.k,'Reason',B,'');self.t=2000;self.c.resolve_timeout(self.k);self.assertEqual(self.state()['status'],'EXPIRED')
 def test_early_timeout_rejected(self):self.rejects(self.c.resolve_timeout,self.k)
 def test_terminal_state_immutable(self):self.add();self.review();self.t=1120;self.c.finalize(self.k);self.rejects(self.c.validator_review,self.k);self.rejects(self.c.resolve_timeout,self.k)
 def test_unsafe_urls_rejected(self):
  for u in ['http://example.org/a','https://localhost/a','https://127.0.0.1/a','https://user:pass@example.org/a','https://example.local/a','https://example.org:8443/a']:
   with self.subTest(url=u):self.rejects(self.add,u)
 def test_empty_scope_rejected(self):self.rejects(self.c.open_compliance_check,self.p,' ')
 def test_registry_counts(self):self.assertEqual(json.loads(self.c.get_registry())['counts'],{'checks':1,'organizations':1,'policies':1})
 def test_self_declared_identity(self):self.assertEqual(json.loads(self.c.get_organization(self.o))['identity'],'SELF_DECLARED')
 def test_invalid_window_configuration(self):
  for args in [(0,60,1000),(60,0,1000),(60,60,120),(60,60,2592001)]:self.rejects(m.PolicyProof,*args)
if __name__=='__main__':unittest.main()
