# See Surge/tools/sync_engine.py for canonical implementation.
# This mirrored implementation exists so Clash workflow can execute standalone.
from pathlib import Path
import runpy

runpy.run_path(str(Path(__file__).with_name('sync_engine.py')), run_name='__main__')
