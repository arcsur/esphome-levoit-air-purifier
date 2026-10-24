#!/usr/bin/env python3
"""
Levoit Core 300S Onboarding & Firmware Wizard Entrypoint
=======================================================
Friendly alias pointing to `levoit_ble_provision.py`.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from levoit_ble_provision import main

if __name__ == "__main__":
    main()
