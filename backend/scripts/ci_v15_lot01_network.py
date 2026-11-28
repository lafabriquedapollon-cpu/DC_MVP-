"""Synthetic topology contract; real TLS loopback handshake, no external routes."""
import json, os, socket, ssl, subprocess, tempfile, threading
from pathlib import Path
from backend.core.cabinet_topology import resolve_cabinet_network, TOPOLOGY_ROLES
assert os.environ.get("GITHUB_ACTIONS") == "true"
rows=[]
def check(label, func):
    try:
        func()
        rows.append(dict(label=label,passed=True))
    except Exception as exc:
        rows.append(dict(label=label,passed=False,error=type(exc).__name__))
    print(json.dumps(rows[-1]),flush=True)
def denied(env):
    try:
        resolve_cabinet_network(env)
    except RuntimeError:
        return
    raise AssertionError("unsafe configuration admitted")
def loopback():
    c=resolve_cabinet_network({"ENVIRONMENT":"production","CABINET_HOST":"127.0.0.1"})
    assert c.connection_url is None and c.diagnostics()["remediation"]=="LAN_DISABLED_LOOPBACK_ONLY"
def tls():
    with tempfile.TemporaryDirectory() as d:
        cert,key=Path(d)/"cert.pem",Path(d)/"key.pem"
        subprocess.run(["openssl","req","-x509","-newkey","rsa:2048","-nodes","-days","1","-subj","/CN=localhost","-addext","subjectAltName=DNS:localhost","-keyout",str(key),"-out",str(cert)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        env={"ENVIRONMENT":"production","CABINET_HOST":"192.0.2.10","CABINET_PORT":"8005","DIGITALCROWN_ENABLE_HTTPS":"true","DIGITALCROWN_TLS_CERT_FILE":str(cert),"DIGITALCROWN_TLS_KEY_FILE":str(key)}
        c=resolve_cabinet_network(env)
        assert c.connection_url=="https://192.0.2.10:8005" and c.tls_ready and c.diagnostics()["remediation"] is None
        srv=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        srv.load_cert_chain(cert,key)
        cli=ssl.create_default_context(cafile=str(cert))
        with socket.socket() as listener:
            listener.bind(("127.0.0.1",0)); listener.listen(); listener.settimeout(5)
            port=listener.getsockname()[1]; errors=[]
            def serve():
                try:
                    conn,_=listener.accept()
                    with srv.wrap_socket(conn,server_side=True) as s:
                        s.settimeout(5); assert s.recv(4)==b"ping"; s.sendall(b"pong")
                except Exception as e:
                    errors.append(type(e).__name__)
            t=threading.Thread(target=serve);t.start()
            try:
                with socket.create_connection(("127.0.0.1",port),timeout=5) as raw:
                    with cli.wrap_socket(raw,server_hostname="localhost") as s:
                        s.sendall(b"ping"); assert s.recv(4)==b"pong"
            finally:
                t.join(6)
            assert not t.is_alive() and not errors
        denied({**env,"CABINET_PORT":"8006"})
        cert.unlink(); denied(env)
def roles():
    assert tuple(TOPOLOGY_ROLES)==("server","workstation","reception","connected_device")
try:
    check("production loopback not published",loopback)
    for env in ("cabinet","production"):
        for host in ("0.0.0.0","192.0.2.10","::"):
            check(env+" plaintext refused "+host,lambda e=env,h=host:denied({"ENVIRONMENT":e,"CABINET_HOST":h}))
    for p in ("0","65536","nope"):
        check("invalid port refused "+p,lambda p=p:denied({"CABINET_PORT":p}))
    check("TLS missing material denied",lambda:denied({"DIGITALCROWN_ENABLE_HTTPS":"true"}))
    check("real synthetic TLS handshake and missing/wrong config",tls)
    check("descriptive topology contract",roles)
finally:
    Path(os.environ["DC_EVIDENCE"],"network.json").write_text(json.dumps(rows,indent=2))
assert all(r["passed"] for r in rows)
