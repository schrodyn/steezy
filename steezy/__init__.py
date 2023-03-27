'''Initialise Steezy package.

Steezy can be imported by: import Steezy.

Initialisation will check first if the rizin or radare2 binaries are
available in the current environment PATH.
'''

import logging
from shutil import which

logging.basicConfig(
    format='[%(asctime)s] %(module)s:%(funcName)s %(levelname)s: %(message)s'
)
logger = logging.getLogger(__name__)

R2Z_CMD = ''

for cmd in ['rizin', 'radare2']:
    if which(cmd) is not None:
        R2Z_CMD = cmd

if R2Z_CMD == 'rizin':
    import rzpipe as r_pipe
elif R2Z_CMD == 'radare2':
    import r2pipe as r_pipe
else:
    raise FileNotFoundError('Unable to locate either rizin or radare2 commands in current PATH.')

from .steezy import Steezy
