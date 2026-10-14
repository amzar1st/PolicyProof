import unittest,sys,json,hashlib,importlib.util
from pathlib import Path
import fake_genlayer
sys.modules['genlayer']=fake_genlayer
s=importlib.util.spec_from_file_location('policyproof',Path(__file__).parents[1]/'contracts/policyproof.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
gl=fake_genlayer.gl;r=fake_genlayer.runtime;A='https://example.org/incident';B='https://example.org/response'
class Tests(unittest.TestCase):
 def setUp(self):
  self.t=1000;m.now=lambda:self.t;gl.message.sender_address='owner';r.pages={A:'Incident report, public postmortem and remediation timeline.',B:'Response evidence containing supporting remediation details.'};r.answers=[];r.fetches=[];r.candidate_supported=True
  self.c=m.PolicyProof(60,60,1000);self.o=self.c.create_organization('Demo','https://example.org');self.p=self.c.publish_policy(self.o,'Disclosure v1','Disclose within 72 hours; include postmortem and remediation.','https://example.org/policy');gl.message.sender_address='requester';self.k=self.c.open_compliance_check(self.p,'Synthetic incident')
 def state(self):return json.loads(self.c.get_check(self.k))
 def add(self,u=A,h=''):self.c.submit_evidence(self.k,u,'Relevant incident evidence',h)
 def answer(self,v='COMPLIANT',cite=None,quote=None,statuses=None,supported=True):
  statuses=statuses or {'COMPLIANT':['SATISFIED','SATISFIED'],'NON_COMPLIANT':['VIOLATED','VIOLATED'],'PARTIALLY_COMPLIANT':['SATISFIED','VIOLATED'],'POLICY_AMBIGUOUS':['AMBIGUOUS','AMBIGUOUS'],'INSUFFICIENT_EVIDENCE':['UNKNOWN','UNKNOWN']}[v]
  observations=[] if cite==[] else [{'source_id':'requester-0' if cite is None or cite==[A] else 'organization-0','quote':quote or r.pages.get(A,'')}]
  rows=[{'id':'R'+str(i+1),'status':status,'explanation':'These facts establish this specific requirement.','observations':observations if status in ('SATISFIED','VIOLATED') else []} for i,status in enumerate(statuses)]
  return [json.dumps({'reasoning':'The complete evidence supports the policy assessment.','requirements':rows}),json.dumps([{'id':x['id'],'supported':supported} for x in rows])]
 def review(self,v='COMPLIANT'):
  self.t=1060;r.answers=self.answer(v)+self.answer(v);self.c.validator_review(self.k)
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
 def test_failed_fetch_recovers_through_bounded_challenge(self):
  self.add();r.pages[A]=RuntimeError();self.t=1060;self.c.validator_review(self.k);r.pages[A]='Evidence recovered with adequate remediation information.';self.t=1061;self.c.challenge(self.k,'Recovered evidence',B,'');r.answers=self.answer()+self.answer();self.t=1121;self.c.validator_review(self.k);self.assertEqual(self.state()['status'],'REVIEWED')
 def test_absent_evidence_unresolved(self):self.t=1060;self.c.validator_review(self.k);self.assertEqual(self.state()['review']['verdict'],'INSUFFICIENT_EVIDENCE')
 def test_empty_page_unresolved(self):self.add();r.pages[A]='';self.t=1060;self.c.validator_review(self.k);self.assertEqual(self.state()['status'],'EVIDENCE_REVIEW')
 def test_unfetched_citation_rejected(self):self.add();self.t=1060;r.answers=self.answer(cite=[B]);self.rejects(self.c.validator_review,self.k);self.assertEqual(self.state()['status'],'EVIDENCE_OPEN')
 def test_missing_citations_rejected(self):self.add();self.t=1060;r.answers=self.answer(cite=[]);self.rejects(self.c.validator_review,self.k)
 def test_independent_validator_disagreement(self):self.add();self.t=1060;r.answers=self.answer()+self.answer('NON_COMPLIANT');self.rejects(self.c.validator_review,self.k);self.assertEqual(self.state()['status'],'EVIDENCE_OPEN')
 def test_challenge_and_counter_evidence(self):
  self.add();self.review();self.t=1061;self.c.challenge(self.k,'New evidence',B,'');deadline=self.state()['challenge_deadline'];gl.message.sender_address='owner';self.c.submit_counter_evidence(self.k,'https://example.org/counter','Counter evidence','');self.assertEqual(deadline,self.state()['challenge_deadline']);self.rejects(self.c.finalize,self.k)
 def test_outsider_challenge_rejected(self):self.add();self.review();gl.message.sender_address='outsider';self.rejects(self.c.challenge,self.k,'Reason',B,'')
 def test_late_challenge_rejected(self):self.add();self.review();self.t=1120;self.rejects(self.c.challenge,self.k,'Reason',B,'')
 def test_only_one_challenge_round(self):
  self.add();self.review();self.t=1061;self.c.challenge(self.k,'Reason',B,'');self.t=1121;r.answers=self.answer()+self.answer();self.c.validator_review(self.k);self.rejects(self.c.challenge,self.k,'Again','https://example.org/again','');self.t=1180;self.c.finalize(self.k);self.assertEqual(len(self.state()['history']),2)
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

 def test_invalid_organization_evidence_cannot_veto_violation(self):
  self.add();gl.message.sender_address='owner';self.c.submit_response(self.k,'Disputed reply',B,'0'*64);self.review('NON_COMPLIANT');self.assertEqual(self.state()['review']['verdict'],'NON_COMPLIANT');self.assertEqual(self.state()['review']['sources'][1]['status'],'HASH_MISMATCH');self.t=1120;self.c.finalize(self.k);self.assertEqual(self.state()['record_type'],'VIOLATION')
 def test_invalid_requester_evidence_cannot_veto_organization(self):
  self.add(h='0'*64);gl.message.sender_address='owner';self.c.submit_response(self.k,'Valid response',B,'');self.t=1060
  rows=json.loads(self.answer()[0]);
  for row in rows['requirements']:row['observations']=[{'source_id':'organization-0','quote':r.pages[B]}]
  r.answers=[json.dumps(rows),self.answer()[1]]*2;self.c.validator_review(self.k);self.t=1120;self.c.finalize(self.k);self.assertIsNotNone(self.state()['attestation'])
 def test_unavailable_optional_source_does_not_block(self):
  self.add();gl.message.sender_address='owner';self.c.submit_response(self.k,'Unavailable reply',B,'');r.pages[B]=RuntimeError();self.review('NON_COMPLIANT');self.assertEqual(self.state()['review']['verdict'],'NON_COMPLIANT')
 def test_unsupported_verbatim_quote_rejected(self):
  self.add();self.t=1060;r.answers=self.answer(quote='This sentence never appeared in the fetched document.');self.rejects(self.c.validator_review,self.k)
 def test_topical_but_non_entailing_quotes_become_unknown(self):
  self.add();self.t=1060;r.answers=self.answer(supported=False)*2;self.c.validator_review(self.k);self.assertEqual(self.state()['review']['verdict'],'INSUFFICIENT_EVIDENCE')
 def test_missing_requirement_rejected(self):
  self.add();self.t=1060;answer=json.loads(self.answer()[0]);answer['requirements'].pop();r.answers=[json.dumps(answer)];self.rejects(self.c.validator_review,self.k)
 def test_duplicate_requirement_rejected(self):
  self.add();self.t=1060;answer=json.loads(self.answer()[0]);answer['requirements'][1]['id']='R1';r.answers=[json.dumps(answer)];self.rejects(self.c.validator_review,self.k)
 def test_multipart_unknown_prevents_compliance(self):
  self.add();self.t=1060;r.answers=self.answer(statuses=['SATISFIED','UNKNOWN'])*2;self.c.validator_review(self.k);self.assertEqual(self.state()['review']['verdict'],'INSUFFICIENT_EVIDENCE')
 def test_affirmative_violation_survives_other_unknown(self):
  self.add();self.t=1060;r.answers=self.answer(statuses=['VIOLATED','UNKNOWN'])*2;self.c.validator_review(self.k);self.assertEqual(self.state()['review']['verdict'],'NON_COMPLIANT')
 def test_conflicting_source_fingerprints_disagree(self):
  self.add();self.t=1060;r.answers=self.answer()*2;original=r.render;count=[0]
  def changing(u,mode):
   count[0]+=1
   return original(u,mode)+(' New contradictory source version.' if count[0]>1 else '')
  gl.nondet.web.render=changing
  try:self.rejects(self.c.validator_review,self.k)
  finally:gl.nondet.web.render=original
  self.assertEqual(self.state()['status'],'EVIDENCE_OPEN')
 def test_same_verdict_different_requirement_outcomes_disagree(self):
  self.add();self.t=1060;r.answers=self.answer(statuses=['VIOLATED','UNKNOWN'])+self.answer(statuses=['UNKNOWN','VIOLATED']);self.rejects(self.c.validator_review,self.k)
 def test_long_page_tail_is_passed_to_both_semantic_passes(self):
  self.add();r.pages[A]='Public facts. '*1400+'QUALIFICATION: disclosure was late and remediation is missing.';self.t=1060;prompts=[];original=gl.nondet.exec_prompt
  def prompt(p,**kwargs):prompts.append(p);return original(p,**kwargs)
  gl.nondet.exec_prompt=prompt;r.answers=self.answer('NON_COMPLIANT',quote=r.pages[A][-60:])*2
  try:self.c.validator_review(self.k)
  finally:gl.nondet.exec_prompt=original
  self.assertEqual(len(prompts),5);self.assertTrue(all('QUALIFICATION: disclosure was late' in p for p in prompts))
 def test_overlimit_page_is_never_evaluated_as_prefix(self):
  self.add();r.pages[A]='x'*64001;self.t=1060;self.c.validator_review(self.k);self.assertEqual(self.state()['review']['sources'][0]['status'],'TOO_LARGE');self.assertEqual(self.state()['review']['verdict'],'INSUFFICIENT_EVIDENCE')
 def test_last_second_challenge_has_full_response_period(self):
  self.add();self.review();self.t=1119;self.c.challenge(self.k,'Last second challenge',B,'');self.assertEqual(self.state()['challenge_deadline'],1120);self.assertEqual(self.state()['response_deadline'],1179);self.t=1120;self.rejects(self.c.validator_review,self.k);gl.message.sender_address='owner';self.c.submit_counter_evidence(self.k,'https://example.org/counter','Counter facts','');self.t=1178;self.rejects(self.c.validator_review,self.k);self.t=1179;r.answers=self.answer()+self.answer();self.c.validator_review(self.k);self.c.finalize(self.k);self.assertEqual(self.state()['status'],'FINALIZED')
 def test_challenger_cannot_append_late_evidence(self):
  self.add();self.review();self.t=1061;self.c.challenge(self.k,'Challenge',B,'');self.rejects(self.c.submit_counter_evidence,self.k,'https://example.org/late','Late facts','')
 def test_counter_submission_does_not_extend_response_deadline(self):
  self.add();self.review();self.t=1119;self.c.challenge(self.k,'Challenge',B,'');deadline=self.state()['response_deadline'];gl.message.sender_address='owner';self.t=1178;self.c.submit_counter_evidence(self.k,'https://example.org/counter','Reply','');self.assertEqual(self.state()['response_deadline'],deadline);self.t=1179;self.rejects(self.c.submit_counter_evidence,self.k,'https://example.org/late','Late reply','')
 def test_development_sender_is_impersonable_and_not_verified(self):
  # The harness models Studio's arbitrary sender selection, not signature security.
  gl.message.sender_address='owner';p=self.c.publish_policy(self.o,'Impersonated sender','A demo requirement','https://example.org/forged');self.assertTrue(p);self.assertEqual(json.loads(self.c.get_organization(self.o))['identity'],'SELF_DECLARED')
 def test_review_retry_cannot_move_filing_deadline(self):
  self.t=1060;self.c.validator_review(self.k);deadline=self.state()['challenge_deadline'];self.t=1061;self.rejects(self.c.validator_review,self.k);self.assertEqual(self.state()['challenge_deadline'],deadline)

 def test_leader_support_is_independently_audited(self):
  self.add();self.t=1060;r.candidate_supported=False;r.answers=self.answer()*2;self.rejects(self.c.validator_review,self.k)
 def test_different_valid_quote_spans_can_agree(self):
  self.add();r.pages[A]='Disclosure was late, so the timing requirement was violated. Remediation was absent after the deadline.';self.t=1060;r.answers=self.answer('NON_COMPLIANT',quote=r.pages[A][:59])+self.answer('NON_COMPLIANT',quote=r.pages[A]);self.c.validator_review(self.k);self.assertEqual(self.state()['review']['verdict'],'NON_COMPLIANT')
 def test_invalid_source_version_changes_cannot_veto_valid_evidence(self):
  self.add();gl.message.sender_address='owner';self.c.submit_response(self.k,'Bad commitment',B,'0'*64);self.t=1060;r.answers=self.answer('NON_COMPLIANT')*2;original=gl.nondet.web.render;count=[0]
  def changing(u,mode):
   if u==B:count[0]+=1;return original(u,mode)+(' Different invalid page version.' if count[0]>1 else '')
   return original(u,mode)
  gl.nondet.web.render=changing
  try:self.c.validator_review(self.k)
  finally:gl.nondet.web.render=original
  self.assertEqual(self.state()['review']['verdict'],'NON_COMPLIANT')

 def test_fenced_json_is_safely_decoded(self):
  r.answers=['```json\n{"requirements": []}\n```'];self.assertEqual(m.llm_json('Test'),{'requirements':[]})
 def test_non_json_model_output_cannot_become_verdict(self):
  self.add();self.t=1060;r.answers=['not a JSON assessment'];self.rejects(self.c.validator_review,self.k);self.assertEqual(self.state()['status'],'EVIDENCE_OPEN')

if __name__=='__main__':unittest.main()
