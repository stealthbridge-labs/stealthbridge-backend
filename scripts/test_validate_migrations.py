import copy
import sys
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from validate_migrations import validate_sources
FILES=[(p.name,p.read_text()) for p in sorted((ROOT/"migrations").glob("*.sql"))]
SERVER=(ROOT/"src/server.rs").read_text()

class MigrationSafetyTests(unittest.TestCase):
 def test_migrations_and_readiness_have_exact_parity(self):
    self.assertEqual(validate_sources(FILES,SERVER),12)
 def test_missing_migration_is_rejected(self):
    with self.assertRaisesRegex(ValueError,"readiness migration manifest"):
     validate_sources(FILES[:-1],SERVER)
 def test_new_unreviewed_drop_is_rejected(self):
    rows=copy.deepcopy(FILES)
    index=next(i for i,(name,_) in enumerate(rows) if name.startswith("202610130002"))
    name,sql=rows[index]
    rows[index]=(name,sql+"\nDROP TABLE organizations;\n")
    with self.assertRaisesRegex(ValueError,"destructive"):
     validate_sources(rows,SERVER)
 def test_unreviewed_grants_and_update_are_rejected(self):
    for injected in ["GRANT ALL ON organizations TO public;", "UPDATE organizations SET status='active';"]:
     rows=copy.deepcopy(FILES)
     i=next(i for i,(name,_) in enumerate(rows) if name.startswith("202610130001"))
     rows[i]=(rows[i][0],rows[i][1]+"\n"+injected)
     with self.subTest(injected=injected),self.assertRaisesRegex(ValueError,"permission|destructive"):
      validate_sources(rows,SERVER)
 def test_missing_readiness_relation_is_rejected(self):
    with self.assertRaisesRegex(ValueError,"missing stellar_contract_event_journal"):
     validate_sources(FILES,SERVER.replace("to_regclass('stellar_contract_event_journal')","to_regclass('other')"))
 def test_missing_version_marker_is_rejected(self):
    with self.assertRaisesRegex(ValueError,"readiness migration manifest"):
     validate_sources(FILES,SERVER.replace("202610130002,","202610130099,"))
if __name__=="__main__":unittest.main()
