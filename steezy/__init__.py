# -*- coding: utf-8 -*-
import sys
import logging
from shutil import which

logging.basicConfig(
    format='[%(asctime)s] %(module)s:%(funcName)s %(levelname)s: %(message)s'
)
logger = logging.getLogger(__name__)

cmd_found = ''

for cmd in ['rizin', 'radare2']:
    if which(cmd) is not None:
        cmd_found = cmd
        logger.debug('cmd (%s) installed.', cmd)

if not cmd_found:
    logger.error('Could not find rizin or radare2!')
    sys.exit(1)

try:
    if cmd_found == 'rizin':
        import rzpipe as r_pipe
    elif cmd_found == 'radare2':
        import r2pipe as r_pipe
except ImportError:
    raise ImportError("Cannot find rzpipe or r2pipe")

from .steezy import Steezy
