from conftest import CONTRACT

def setup(vm,deploy,alice,bob,charlie):
 vm.warp('2035-01-01T00:00:00+00:00');vm.sender=alice;c=deploy(CONTRACT);c.open_replay('inc-44','0x'+bob.hex(),'0x'+charlie.hex(),'https://trace.example/run-44','https://runbook.example/v3',600,600);return c
def replay_mocks(vm):
 vm.mock_web(r'trace\.example',{'status':200,'body':'0 boot ok\n1 load config ok\n2 publish with stale key\n3 authorization denied'});vm.mock_web(r'runbook\.example',{'status':200,'body':'0 boot\n1 load current config\n2 publish with active key\n3 confirm'});vm.mock_llm(r'.*CausalReplay first-divergence reconstruction.*','{"event_count":4,"first_divergence":2,"cause_class":"CONFIG","rationale":"Event 2 uses a stale key instead of the active key."}')

def test_replay_and_permissionless_confirmation(direct_vm,direct_deploy,direct_alice,direct_bob,direct_charlie):
 c=setup(direct_vm,direct_deploy,direct_alice,direct_bob,direct_charlie);direct_vm.sender=direct_bob;replay_mocks(direct_vm);c.reconstruct('inc-44');r=c.get_replay('inc-44');assert r['first_divergence']==2 and r['state']=='REPLAYED';direct_vm.warp('2035-01-01T00:11:00+00:00');direct_vm.sender=direct_alice;c.finalize('inc-44');assert c.get_replay('inc-44')['state']=='CONFIRMED'

def test_auditor_can_reopen_with_material_correction(direct_vm,direct_deploy,direct_alice,direct_bob,direct_charlie):
 c=setup(direct_vm,direct_deploy,direct_alice,direct_bob,direct_charlie);direct_vm.sender=direct_bob;replay_mocks(direct_vm);c.reconstruct('inc-44');direct_vm.clear_mocks();direct_vm.sender=direct_charlie;direct_vm.mock_web(r'audit\.example',{'status':200,'body':'Event 1 loaded an unauthorized configuration snapshot.'});direct_vm.mock_llm(r'.*CausalReplay audit challenge.*','{"material":true,"corrected_index":1,"corrected_class":"PERMISSION","reason":"The first unauthorized operation is event 1."}');c.challenge('inc-44','https://audit.example/finding');direct_vm.warp('2035-01-01T00:11:00+00:00');direct_vm.sender=direct_alice;c.finalize('inc-44');assert c.get_replay('inc-44')['state']=='REOPENED' and c.get_replay('inc-44')['challenge_digest']

def test_only_analyst_can_reconstruct(direct_vm,direct_deploy,direct_alice,direct_bob,direct_charlie):
 c=setup(direct_vm,direct_deploy,direct_alice,direct_bob,direct_charlie);replay_mocks(direct_vm)
 with direct_vm.expect_revert('nominated analyst'):c.reconstruct('inc-44')

def test_validator_rejects_later_symptom(direct_vm,direct_deploy,direct_alice,direct_bob,direct_charlie):
 c=setup(direct_vm,direct_deploy,direct_alice,direct_bob,direct_charlie);replay_mocks(direct_vm);x=c.replays['INC-44'];result=c._reconstruct(x);assert direct_vm.run_validator(leader_result=result) is True;forged=dict(result);forged['first_divergence']=3;assert direct_vm.run_validator(leader_result=forged) is False

def test_permissionless_open_expiry(direct_vm,direct_deploy,direct_alice,direct_bob,direct_charlie):
 c=setup(direct_vm,direct_deploy,direct_alice,direct_bob,direct_charlie);direct_vm.warp('2035-01-01T00:11:00+00:00');direct_vm.sender=direct_charlie;c.expire_open('inc-44');assert c.get_replay('inc-44')['state']=='EXPIRED_UNREPLAYED'
