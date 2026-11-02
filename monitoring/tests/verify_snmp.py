#!/usr/bin/env python3
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from modules.snmp import devices, verify_snmp, verify_trap_ingestion
items=devices()
verify_snmp(items)
verify_trap_ingestion(items)
