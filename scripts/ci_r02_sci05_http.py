"""Synthetic route integration: actual router, SQLAlchemy, graph and projections.
Identity dependency is overridden with fixture users; not a login/Station test.
No scientific historical profile bytes, real patients, media, or keys.
"""
import copy
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import types
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

def main(out):
    with tempfile.TemporaryDirectory(prefix="sci05-") as tmp:
        scratch=Path(tmp)
        envfile=scratch/"fixture.env"
        envfile.touch()
        os.environ.update(ENVIRONMENT="sci05_rehearsal",
                          DATABASE_URL="sqlite:///:memory:",
                          DIGITALCROWN_ENV_FILE=str(envfile),
                          APPDATA=str(scratch),LOCALAPPDATA=str(scratch),
                          USERPROFILE=str(scratch),HOME=str(scratch))
        # Isolate the exact target router, not unrelated imaging/AI route bootstrap.
        import backend
        pkg=types.ModuleType("backend.routers")
        pkg.__path__=[str(ROOT/"backend/routers")]
        sys.modules["backend.routers"]=pkg
        from backend import models, database
        from backend.routers import auth, cephalo_analysis_read as route
        from backend.services import cephalo_protocol_projection as p
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        from sqlalchemy.pool import StaticPool
        engine=create_engine("sqlite://",poolclass=StaticPool,connect_args={"check_same_thread":False})
        models.Base.metadata.create_all(engine)
        Session=sessionmaker(bind=engine,expire_on_commit=False)
        now=dt.datetime(2000,1,1)
        with Session() as db:
            db.add_all([models.User(id=1,email="fixture1@example.invalid",hashed_password="NOT_A_LOGIN",role=models.UserRole.DENTISTE),
                        models.User(id=2,email="fixture2@example.invalid",hashed_password="NOT_A_LOGIN",role=models.UserRole.DENTISTE)])
            db.add(models.Patient(id=1,nom="SYNTHETIC",prenom="FIXTURE",date_naissance=now,sexe="M",employer_id=1))
            db.commit()
        def dep_db():
            with Session() as db:
                yield db
        selected=[1]
        def dep_user():
            with Session() as db:
                return db.get(models.User,selected[0])
        app=FastAPI()
        app.include_router(route.router)
        app.dependency_overrides[database.get_db]=dep_db
        app.dependency_overrides[auth.get_current_user]=dep_user

        ids=list(p._PROTOCOL_METHODS)
        gate=lambda identity: {"gate":"ORTHO_ANALYSIS_PROTOCOLS_SOURCE_LOCKED","scope":identity,"status":"SATISFIED"}
        def profile(identity):
            return {"schema_version":"ORTHO_ANALYSIS_PROTOCOL_PROFILE_V1","protocol_profile_id":identity,
                    "scientific_authority":"LOT06_CANONICAL_MEASUREMENT_REGISTRY","status":"SOURCE_LOCKED",
                    "pre_code_gate":gate(identity),"final_gate":{"status":"SATISFIED"},
                    "scope_resolutions":{"AUTONOMOUS_TREATMENT":"FORBIDDEN","EXTRACTION_NON_EXTRACTION":"CLINICIAN_ONLY"}}
        steiner=profile("STEINER_STATIC_PROTOCOL_PROFILE_V1")
        steiner.update(layers={"STEINER_1953_BASE":{"required_measurement_ids":ids[:11]},
                               "STEINER_1959_EXTENSION":{"required_measurement_ids":ids[11:15]}},
                       norm_sets=[{"classification_authority":False,"authority":"REFERENCE_DISPLAY_ONLY",
                                  "norm_set_id":"SYNTHETIC","population":"SYNTHETIC","applicability":"NONE",
                                  "out_of_domain_behavior":"DISPLAY_ONLY","values":{}}],
                       explicit_manual_or_constructed_identities={})
        tweed=profile("TWEED_MERRIFIELD_DC_PROTOCOL_PROFILE_V1")
        tweed.update(profiles={"SYNTHETIC_TRIANGLE":{"required_measurement_ids":ids[15:18]},
                               "SYNTHETIC_Z":{"required_measurement_ids":ids[18:]}},
                     reference_contexts=[{"classification_authority":False,"runtime_delta_authority":False}],
                     historical_geometry_resolution={})
        sp=scratch/"s.json";tp=scratch/"t.json"
        for file,obj in [(sp,steiner),(tp,tweed)]:file.write_bytes(json.dumps(obj).encode())
        pin=lambda file:hashlib.sha256(file.read_bytes()).hexdigest()
        source={"evidence_id":"source-fixture","patient_id":1,"kind":"image","source_record_id":"fixture",
                "recorded_at":"2000-01-01T00:00:00Z","metadata":{"case_id":"fixture-case"}}
        landmark={"evidence_id":"landmark-fixture","landmark_id":"S","x":1,"y":2,
                  "source_image_ref":"source-fixture","origin":"MANUAL","evidence_refs":["source-fixture"],
                  "evidence_status":"OBSERVED"}
        def measure(method,index,unit="deg"):
            return {"measurement_id":f"fixture-{index}","analysis_id":"SYNTHETIC","method_id":method,
                    "method_version":"fixture","value":12.0,"unit":unit,"landmark_refs":["landmark-fixture"],
                    "evidence_refs":["source-fixture"],"availability_status":"AVAILABLE"}
        mandatory=["CRANIOM_SITUATION_A_MM_V1","CRANIOM_SITUATION_B_MM_V1","CRANIOM_AB_PRIME_MM_V1","CRANIOM_FACIAL_DEPTH_MM_V1"]
        graph={"schema_version":"CEPHALO_EVIDENCE_V1","case_id":"fixture-case","revision":1,
               "sources":[source],"landmarks":[landmark],"current_landmark_refs":["landmark-fixture"],
               "measurements":[measure(method,i,"mm") for i,method in enumerate(mandatory)]+
                 [measure(p._PROTOCOL_METHODS[cid],i+4,"mm" if "_MM_" in cid else "deg") for i,cid in enumerate(ids)]}
        def persist(payload):
            with Session() as db:
                row=db.get(models.CephaloAnalysis,1)
                if row is None:
                    row=models.CephaloAnalysis(id=1,patient_id=1,image_original_path="SYNTHETIC-NO-IMAGE",angles_data=payload)
                    db.add(row)
                else:row.angles_data=payload
                db.commit()
        payload={"_evidence_graph_v1":graph}
        persist(payload)
        with patch.multiple(p,_PROFILE_PATH=sp,_TWEED_MERRIFIELD_PROFILE_PATH=tp,_STEINER_PIN=pin(sp),_TWEED_PIN=pin(tp)),TestClient(app) as client:
            response=client.get("/analyses/1")
            assert response.status_code==200, (response.status_code,response.text[:300])
            result=response.json()["angles_data"]
            profiles=result["scientific_read_path"]["protocol_profiles"]
            assert all(len(profiles[key]["rows"])==count and profiles[key]["final_gate"]["status"]=="OPEN" for key,count in [("steiner",15),("tweed_merrifield",4)])
            assert all(row["value"]==12 and row["classification_authority"] is False for profile in profiles.values() for row in profile["rows"])
            out.write_text(json.dumps(result),encoding="utf-8")
            selected[0]=2
            assert client.get("/analyses/1").status_code==403
            selected[0]=1
            bad=copy.deepcopy(payload);bad["_evidence_graph_v1"]["sources"][0]["patient_id"]=2
            persist(bad)
            assert client.get("/analyses/1").status_code==409
            persist({"scientific_read_path":result["scientific_read_path"]})
            legacy=client.get("/analyses/1")
            assert legacy.status_code==200 and "scientific_read_path" not in legacy.json()["angles_data"]
            persist(payload)
            sp.write_bytes(b"tampered")
            assert client.get("/analyses/1").status_code==409
        engine.dispose()
        print("SCI05_HTTP_PASS 19 rows; DB roundtrip; cross-tenant 403; graph and profile 409; legacy spoof suppressed; auth fixture only")
if __name__=="__main__":
    main(Path(sys.argv[1]))
