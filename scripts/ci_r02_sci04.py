import importlib.util
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[1]
def load(name):
    import sys
    spec=importlib.util.spec_from_file_location(name,ROOT/"backend/services"/(name+".py"))
    m=importlib.util.module_from_spec(spec)
    sys.modules[name]=m
    spec.loader.exec_module(m)
    return m
p=load("cephalo_protocol_projection")
b=load("cephalo_canonical_method_bridge")
class Guard(unittest.TestCase):
    def test_all_identities(self):
        self.assertEqual(len(p._PROTOCOL_METHODS),19)
        for cid,method in p._PROTOCOL_METHODS.items():
            self.assertEqual(b.canonical_measurement_id_for_method(method),cid)
            item={"canonical_measurement_id":cid,"availability_status":"AVAILABLE","value":12,
                  "unit":"mm" if "_MM_" in cid else "deg","measurement_refs":["synthetic-ref"],"value_authority_method_id":method}
            self.assertEqual(p._safe_protocol_row(item,cid),item)
            for key,value in [("value",float("nan")),("value",True),("unit","wrong"),("measurement_refs",[]),("measurement_refs",["x","x"]),("value_authority_method_id","wrong"),("availability_status","MISSING")]:
                invalid=p._safe_protocol_row({**item,key:value},cid)
                self.assertIsNone(invalid["value"])
                self.assertEqual(invalid["measurement_refs"],[])
            with self.assertRaises(ValueError):
                p._protocol_inputs([item,item])
if __name__=="__main__":
    unittest.main(verbosity=2)
