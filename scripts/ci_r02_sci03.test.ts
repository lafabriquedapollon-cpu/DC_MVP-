import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readSteinerProtocolProjection } from '../frontend/src/features/ortho/cephaloSteinerProtocol.ts';
import { readTweedMerrifieldProtocolProjection } from '../frontend/src/features/ortho/cephaloTweedMerrifieldProtocol.ts';
for (const [key,id,count,read] of [
 ['steiner','STEINER_STATIC_PROTOCOL_PROFILE_V1',15,readSteinerProtocolProjection],
 ['tweed_merrifield','TWEED_MERRIFIELD_DC_PROTOCOL_PROFILE_V1',4,readTweedMerrifieldProtocolProjection],
] as const) {
 test(key + ' synthetic reader guard', () => {
  const make = () => ({scientific_read_path:{authority:'EVIDENCE_GRAPH_V1',active_chain:'VERIFIED',protocol_profiles:{[key]:{
   protocol_profile_id:id,final_gate:{gate:'ORTHO_ANALYSIS_PROTOCOLS_VERIFIED',status:'OPEN'},
   rows:Array.from({length:count},(_,i)=>({canonical_measurement_id:'FIXTURE_'+i,classification_authority:false,availability_status:'NOT_COMPUTABLE',value:null}))
  }}}});
  const good=make(); assert.ok(read(good));
  const mutations = [
   (p:any)=>p.rows[0].classification_authority=true,
   (p:any)=>delete p.rows[0].classification_authority,
   (p:any)=>p.rows[0].classification_authority='false',
   (p:any)=>p.final_gate.status='SATISFIED',
   (p:any)=>p.rows.pop(),
   (p:any)=>p.rows[1].canonical_measurement_id=p.rows[0].canonical_measurement_id,
   (p:any)=>p.rows[0].value=12,
   (p:any)=>{p.rows[0].availability_status='AVAILABLE';p.rows[0].value=NaN},
   (p:any)=>{p.rows[0].availability_status='AVAILABLE';p.rows[0].value='12'},
   (p:any)=>p.rows[0]=null,
  ];
  for (const mutate of mutations) {const x=make(); mutate(x.scientific_read_path.protocol_profiles[key]); assert.equal(read(x),null);}
  const available=make(); const row=available.scientific_read_path.protocol_profiles[key].rows[0]; row.availability_status='AVAILABLE'; Object.assign(row,{value:12}); assert.ok(read(available));
  const chain=make();chain.scientific_read_path.active_chain='INVALID';assert.equal(read(chain),null);
 });
}
