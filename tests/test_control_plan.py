from copy import deepcopy
from control_plan import prepare_draft, invalidate_draft, selected_plan, priorities, priority_value
from local_llm import context_fingerprint
from core import score


def component(ref,impact=3,exposure=1,selected=()):
    return {'id':ref,'name':ref,'version':'1','assessment':score({'factors':{'archived':exposure}},[impact]*3,selected)}


def test_only_checked_current_controls_group_exact_component_assignments():
    components=[component('a'),component('b'),component('c',selected=['review'])]
    measure={'title':'Test recovery','actions':['Run the recovery exercise.'],'selected':True}
    payload={'components':components,'generated_control_measures':{
        'a':{'controls':[measure,{'title':'UNSELECTED','actions':[],'selected':False}]},
        'b':{'controls':[deepcopy(measure)]}}}
    plan=selected_plan(payload)
    assert len(plan)==2 and plan[0]['component_ids']==['a','b'] and plan[1]['component_ids']==['c']
    payload['generated_control_measures']['b']['stale']=True
    assert selected_plan(payload)[0]['component_ids']==['a']


def test_plain_text_cards_identity_selection_and_staleness():
    draft={'generated_at':'time','context_fingerprint':'fingerprint','controls':[],
           'text':'Intro\n1. First action\n  With a continuation.\n2. Second action'}
    cards=prepare_draft(draft)
    assert len(cards)==2 and not any(c['selected'] for c in cards)
    assert cards[0]['actions']==['First action\nWith a continuation.']
    identity=cards[0]['selection_id'];cards[0]['selected']=True
    assert prepare_draft(draft)[0]['selection_id']==identity and cards[0]['selected']
    invalidate_draft(draft,True)
    assert not any(c['selected'] for c in cards)
    invalidate_draft(draft,False)
    assert draft['stale']  # Returning to old inputs does not reapprove a stale generation.
    replacement={**draft,'generated_at':'new time','generation_id':'new-generation','action_cards':[]}
    assert prepare_draft(replacement)==[]


def test_ranking_unknowns_ties_and_baseline():
    a=component('a',5,.5);b=component('b',3,1);c=component('c',5,.5)
    unknown=component('unknown');unknown['assessment']=score({},[5]*3)
    assert [c['id'] for c in priorities({'components':[unknown,c,a,b]})]==['b','a','c']
    assert priority_value(b['assessment'])==60 and priority_value(unknown['assessment']) is None


def test_selection_does_not_invalidate_generated_proposals():
    before={'assessment':score({'factors':{'review':1}},[3]*3)}
    after={'assessment':score({'factors':{'review':1}},[3]*3,['review'])}
    assert context_fingerprint(before)==context_fingerprint(after)
    after['assessment']['impact_inputs']=[4,3,3]
    assert context_fingerprint(before)!=context_fingerprint(after)


def test_empty_edited_controls_cannot_enter_report():
    payload={'components':[component('a')], 'generated_control_measures':{'a':{'action_cards':[
        {'title':'','actions':['Do something'],'selected':True},
        {'title':'Incomplete','actions':['  '],'selected':True}]}}}
    assert selected_plan(payload)==[]
