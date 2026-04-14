# This file mirrors Surge/tools/sync_engine.py
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'tools'))
from sync_engine import main

if __name__ == '__main__':
    main()
