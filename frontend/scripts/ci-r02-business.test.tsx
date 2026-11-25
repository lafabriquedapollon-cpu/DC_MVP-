import React from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { PendingRequestCard } from '../src/features/agenda/PendingRequestCard';
import { PatientCompanionEmergencyPhoto } from '../src/features/patient-companion/PatientCompanionEmergencyPhoto';
import { DrugRow } from '../src/features/admin/DocumentStudio/Forms/DrugRowV1';

const mocks=vi.hoisted(()=>({post:vi.fn(),get:vi.fn(),upload:vi.fn(),load:vi.fn(),saveQueue:vi.fn(),readBytes:vi.fn(),deleteBytes:vi.fn(),prepare:vi.fn()}));
vi.mock('../src/services/api',()=>({api:{post:mocks.post,get:mocks.get}}));
vi.mock('../src/features/patient-companion/PatientCompanionEmergencyPhotoTransport',()=>({uploadEmergencyPhoto:mocks.upload}));
vi.mock('../src/features/patient-companion/PatientCompanionEmergencyPhotoPrep',()=>({prepareEmergencyPhoto:mocks.prepare}));
vi.mock('../src/features/patient-companion/PatientCompanionStorage',()=>({PatientCompanionStorage:{
  load:mocks.load,saveEmergencyPhotoQueue:mocks.saveQueue,readEmergencyPhotoBytes:mocks.readBytes,deleteEmergencyPhotoBytes:mocks.deleteBytes
}}));
const deferred=()=>{let resolve!:()=>void,reject!:(e:Error)=>void;const promise=new Promise<void>((a,b)=>{resolve=a;reject=b});return{promise,resolve,reject}};
beforeEach(()=>{vi.resetAllMocks();vi.spyOn(window,'alert').mockImplementation(()=>{});});
afterEach(()=>{cleanup();vi.restoreAllMocks();vi.unstubAllGlobals();});
const request={id:17,patient_name:'CI SYNTHETIC',datetime_start:'2030-01-01T09:00:00Z',duration_minutes:30,status:'EN_ATTENTE_DEMANDE',created_at:'2030-01-01T08:00:00Z'};
describe('agenda — UI boundary, mocked API',()=>{
 it('waits for successful request-confirmation before updating UI',async()=>{
  const d=deferred(),onAction=vi.fn();mocks.post.mockReturnValue(d.promise);
  render(<PendingRequestCard request={request} onAction={onAction}/>);
  const button=screen.getByRole('button',{name:'Demander confirmation'});
  fireEvent.click(button);
  expect(mocks.post).toHaveBeenCalledExactlyOnceWith('/appointments/17/request-confirmation');
  expect(onAction).not.toHaveBeenCalled();expect((button as HTMLButtonElement).disabled).toBe(true);
  await act(async()=>d.resolve());
  await waitFor(()=>expect(onAction).toHaveBeenCalledTimes(1));
 });
 it('does not announce success on failure or allow masked identity request',async()=>{
  const onAction=vi.fn();mocks.post.mockRejectedValue(new Error('synthetic refusal'));
  const view=render(<PendingRequestCard request={request} onAction={onAction}/>);
  fireEvent.click(screen.getByRole('button',{name:'Demander confirmation'}));
  await waitFor(()=>expect(window.alert).toHaveBeenCalled());
  expect(onAction).not.toHaveBeenCalled();expect(screen.queryByText(/Message template copié/)).toBeNull();
  view.rerender(<PendingRequestCard request={{...request,patient_name:null}} onAction={onAction}/>);
  expect((screen.getByRole('button',{name:'Demander confirmation'}) as HTMLButtonElement).disabled).toBe(true);
 });
});
const timestamp='2030-01-01T08:00:00Z';
const pairing={accessToken:'synthetic-not-auth',context:{access_id:'ci-context',relationship_type:'SELF',patient:{display_name:'CI SYNTHETIC'}},pairedAt:timestamp,expiresAt:'2030-01-02T08:00:00Z'};
const bytes=new Uint8Array([10,20,30]);
function photoFixture(){
 let queue=[{uploadId:'ci-photo',state:'local_pending',byteSize:3,capturedAt:timestamp,createdAt:timestamp,updatedAt:timestamp}];
 mocks.load.mockImplementation(async()=>({cache:{'ci-context':{emergencyPhotos:queue}}}));
 mocks.saveQueue.mockImplementation(async(_access:string,next:typeof queue)=>{queue=next});
 mocks.readBytes.mockResolvedValue(bytes);mocks.deleteBytes.mockResolvedValue(undefined);
 vi.stubGlobal('URL',class extends URL{static createObjectURL(){return 'blob:synthetic-photo'}static revokeObjectURL(){}});
 return ()=>queue;
}
describe('photo — UI boundary, mocked transport/storage',()=>{
 it('requires acknowledgement before receipt and local byte deletion',async()=>{
  const queue=photoFixture(),d=deferred();mocks.upload.mockReturnValue(d.promise);
  render(<PatientCompanionEmergencyPhoto pairing={pairing} enabled/>);
  fireEvent.click(await screen.findByRole('button',{name:'Envoyer au cabinet'}));
  await waitFor(()=>expect(mocks.upload).toHaveBeenCalledTimes(1));
  expect(queue()[0].state).toBe('remote_uploading');expect(mocks.deleteBytes).not.toHaveBeenCalled();
  expect(screen.queryByText('Photo reçue par le cabinet.')).toBeNull();
  await act(async()=>d.resolve());
  await screen.findByText('Photo reçue par le cabinet.');
  expect(queue()[0].state).toBe('received');expect(mocks.deleteBytes).toHaveBeenCalledExactlyOnceWith('ci-photo');
 });
 it('retains bytes and pending state when acknowledgement is absent',async()=>{
  const queue=photoFixture();mocks.upload.mockRejectedValue(Object.assign(new Error('synthetic pending'),{remotePending:true}));
  render(<PatientCompanionEmergencyPhoto pairing={pairing} enabled/>);
  fireEvent.click(await screen.findByRole('button',{name:'Envoyer au cabinet'}));
  await screen.findByText(/aucune réception cabinet/);
  expect(queue()[0].state).toBe('remote_pending_ack');expect(mocks.deleteBytes).not.toHaveBeenCalled();
  expect(screen.queryByText('Photo reçue par le cabinet.')).toBeNull();
 });
});
describe('prescription — active DrugRow V1, no clinical recommendation',()=>{
 it('changes form, clears stale presentation provenance, preserves authored dose and posology',async()=>{
  const updates=vi.fn();const noop=()=>{};
  const initial={id:1,name:'SYNTHETIC',dosage:'DOSE TEST',forme:'COMPRIMÉS',posologie:'TEXTE TEST',type:'MEDICAMENT' as const,catalogPresentationId:'synthetic-presentation',catalogDci:'SYNTHETIC DCI',catalogSourceId:'synthetic-source'};
  function Harness(){const [drug,setDrug]=React.useState(initial);return <><DrugRow drug={drug} idx={0} drugsCount={1} assessment={null} validationErrors={[]} forcedDrugs={[]} activeSearchId={null} suggestions={{medications:[],dosages:[],posologies:[]}} highlightedIdx={-1} medChecks={{}} onUpdateDrug={(id,field,val)=>{updates(id,field,val);setDrug(d=>({...d,[field]:val}))}} onRemoveDrug={noop} onMove={noop} onSearch={noop} onKeyDown={noop} onApplySuggestion={noop} onForceAllergy={noop} onToggleType={noop} disableCatalogLookup/><output data-testid="state">{JSON.stringify(drug)}</output></>}
  render(<Harness/>);
  fireEvent.click(screen.getByRole('button',{name:'Forme',exact:true}));
  fireEvent.click(await screen.findByRole('menuitem',{name:'SACHETS',exact:true}));
  const state=JSON.parse(screen.getByTestId('state').textContent||'{}');
  expect(state.forme).toBe('SACHETS');expect(state.catalogPresentationId).toBeUndefined();
  expect(state.catalogSourceId).toBeUndefined();expect(state.catalogDci).toBe('SYNTHETIC DCI');
  expect(state.dosage).toBe('DOSE TEST');expect(state.posologie).toBe('TEXTE TEST');
  expect(mocks.get).not.toHaveBeenCalled();
 });
});
