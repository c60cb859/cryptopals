#!/usr/bin/env python3
from crypto_tools import ByteAtATimeECBSimple
from crypto_tools import BreakECBEncryption

backend = ByteAtATimeECBSimple()

break_ecb = BreakECBEncryption(backend)
if break_ecb.verify_ecb_mode():
    print(break_ecb.break_ecb())
