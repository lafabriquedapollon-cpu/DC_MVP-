import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readSteinerProtocolProjection} from '../frontend/src/features/ortho/cephaloSteinerProtocol.ts';
import {readTweedMerrifieldProtocolProjection} from '../frontend/src/features/ortho/cephaloTweedMerrifieldProtocol.ts';
import {steinerIds,tweedIds,protocolMethods} from '../frontend/src/features/ortho/cephaloProtocolGuard.ts';
for(const [key,id,ids,read] of [
 ['steiner','STEINER_STATIC_PROTOCOL_PROFILE_V1',steinerIds,readSteinerProtocolProjection],
 ['tweed_merrifield','TWEED_MERRIFIELD_DC_PROTOCOL_PROFILE_V1',tweedIds,readTweedMerrifieldProtocolProjection]
] as const) {
 test(key,()=>{
 const make=()=>({scientific_read_path:{authority:'EVIDENCE_GRAPH_V1',active_chain:'VERIFIED',protocol_profiles:{[key]:{protocol_profile_id:id,final_gate:{gate:'ORTHO_ANALYSIS_PROTOCOLS_VERIFIED',status:'OPEN'},rows:ids.map(cid=>({canonical_measurement_id:cid,classification_authority:false,availability_status:'AVAILABLE',value:12,unit:cid.includes('_MM_')?'mm':'deg',measurement_refs:['synthetic-ref'],value_authority_method_id:protocolMethods[cid]}))}}}});
 assert.ok(read(make()));
 for(const mutate of [
 (p:any)=>p.rows[0].canonical_measurement_id='FOREIGN',
 (p:any)=>p.rows.reverse(),
 (p:any)=>p.rows.pop(),
 (p:any)=>p.rows[0].classification_authority=true,
 (p:any)=>delete p.rows[0].classification_authority,
 (p:any)=>p.final_gate.status='SATISFIED',
 (p:any)=>p.rows[0].value=NaN,
 (p:any)=>p.rows[0].value='12',
 (p:any)=>p.rows[0].unit='bad',
 (p:any)=>p.rows[0].value_authority_method_id='wrong',
 (p:any)=>p.rows[0].measurement_refs=[],
 (p:any)=>p.rows[0].measurement_refs=['a','a'],
 (p:any)=>p.rows[0].availability_status='NOT_COMPUTABLE',
 ]) {const x=make();mutate(x.scientific_read_path.protocol_profiles[key]);assert.equal(read(x),null);}
 const x=make();Object.assign(x.scientific_read_path.protocol_profiles[key].rows[0],{value:null,availability_status:'NOT_COMPUTABLE',measurement_refs:[],value_authority_method_id:null});assert.ok(read(x));
 });
}
