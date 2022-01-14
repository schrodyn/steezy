# -*- coding: utf-8 -*-
import sys
import logging
from shutil import which

logging.basicConfig(
    format='[%(asctime)s] %(module)s:%(funcName)s %(levelname)s: %(message)s'
)
logger = logging.getLogger(__name__)

r2z_installed = False

for cmd in ['rizin', 'r2', 'radare2']:
    if which(cmd) is not None:
        r2z_installed = True

if r2z_installed == False:
    logger.error('Could not find rizin or radare2!')
    sys.exit(1)

try:
    import rzpipe as r_pipe
except ImportError:
    try:
        import r2pipe as r_pipe
    except ImportError:
        raise ImportError("Cannot find rzpipe or r2pipe")

from .steezy import Steezy
