#!/usr/bin/env python3
"""Fail-closed source/ready consistency for audited SQLx migrations.

This is a read-only repository check; it never connects to Neon or runs DDL.
"""
import re
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
VERSION_RE=re.compile(r"^(\d{12})_[a-z0-9_]+\.sql$")
SCHEMA_RE=re.compile(r"const REQUIRED_SCHEMA_VERSIONS: \[i64; (\d+)\] = \[([\s\S]*?)\];")
# The private draft vault is opt-in and is not part of the existing
# production readiness contract until the protected migration is applied.
# Do not block unrelated network and catalog reads on an unreleased vault.
OPTIONAL_MIGRATIONS=(202611040001,202611120001)
ADDITIVE_ONLY=(202610130001,202610130002,202610150001,202610210001,202610270001,*OPTIONAL_MIGRATIONS)
REQUIRED_TABLES=(
    "organization_invitations",
    "customer_profiles",
    "customer_profile_update_receipts",
    "business_review_requests",
    "business_review_records",
    "organization_login_challenges",
    "stellar_contract_event_cursors",
    "stellar_contract_event_journal",
)
def require(condition,reason):
    if not condition: raise ValueError(reason)

def validate_sources(files,server):
    match=SCHEMA_RE.search(server)
    require(match is not None,"server.rs must declare schema migration versions")
    requested_count=int(match.group(1))
    server_versions=[int(v) for v in re.findall(r"\b\d{12}\b",match.group(2))]
    file_versions=[]
    for name,source in files:
        parsed=VERSION_RE.fullmatch(name)
        require(parsed is not None,f"invalid migration filename {name}")
        version=int(parsed.group(1))
        file_versions.append(version)
        require(bool(source.strip()),f"migration {version} is empty")
        if version == 202611040001:
            expected=(
                "customer_ciphertext_drafts", "customer_ciphertext_draft_receipts",
                "PRIMARY KEY(account_address,draft_id)", "nonce UUID PRIMARY KEY",
                "octet_length(envelope::text)<=4096", "revision BETWEEN 1 AND 1000000",
                "account_address VARCHAR(56) NOT NULL",
            )
            for item in expected:
                require(item in source, f"ciphertext vault migration missing bound: {item}")
        if version == 202611120001:
            for item in ("customer_payment_instructions", "customer_payment_instruction_events", "customer_payment_instruction_receipts",
                         "PRIMARY KEY(account_address,id)", "nonce UUID PRIMARY KEY", "octet_length(envelope::text)<=4096",
                         "expires_at_unix-created_at_unix BETWEEN 300 AND 86400"):
                require(item in source, f"payment instruction migration missing bound: {item}")
        if version in ADDITIVE_ONLY:
            require("CREATE TABLE IF NOT EXISTS" in source,
                    f"additive migration {version} must create tables safely")
            stripped=re.sub(r"--[^\n]*","",source)
            # An FK ON DELETE RESTRICT protects parent records; it is not
            # a DELETE DML statement and must not trip the destructive guard.
            stripped=re.sub(r"\bON\s+DELETE\s+RESTRICT\b","",stripped,flags=re.I)
            # SQL enum/check string literals are data, not DELETE DML.
            stripped=re.sub(r"'(?:''|[^'])*'","''",stripped)
            require(not re.search(r"\b(DROP|TRUNCATE|DELETE|UPDATE|GRANT|REVOKE)\b",
                                  stripped,re.I),
                    f"migration {version} performs unreviewed destructive or permission SQL")
    require(file_versions==sorted(file_versions) and
            len(file_versions)==len(set(file_versions)),"SQLx migration filenames must be unique and sorted")
    require(set(OPTIONAL_MIGRATIONS).issubset(file_versions),"optional ciphertext vault migration is missing")
    required=[version for version in file_versions if version not in OPTIONAL_MIGRATIONS]
    require(server_versions==required and len(required)==requested_count,
            "backend readiness migration manifest drifts from SQLx files")
    query=server.split("async fn database_schema_ready",1)[1]
    require(f"COUNT(*) = {requested_count}" in query,
            "backend readiness count differs from migration set")
    for table in REQUIRED_TABLES:
        require(f"to_regclass('{table}')" in query,
                f"backend readiness missing {table}")
    return requested_count

def main():
    files=[(p.name,p.read_text()) for p in sorted((ROOT/"migrations").glob("*.sql"))]
    count=validate_sources(files,(ROOT/"src/server.rs").read_text())
    print(f"PASS: {count} SQLx migrations align with backend readiness; new migrations additive-only")

if __name__=="__main__":main()
