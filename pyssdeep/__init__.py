"""The Python wrapper for ssdeep.

This package is a Python wrapper for ssdeep by Jesse Kornblum, which is a
library for computing Context Triggered Piecewise Hashes (CTPH).
"""

__title__ = 'pyssdeep'
__version__ = '1.0.0'
__author__ = 'Evgeny Drobotun'
__author_email__ = 'drobotun@xakep.ru'
__license__ = 'MIT'
__copyright__ = 'Copyright (C) 2020 Evgeny Drobotun'

from sys import version_info
from sys import exit as sys_exit

if version_info.major < 3:
    print('Use python version 3.0 and higher')
    sys_exit()

from .ssdeep_wrapper import (
    FUZZY_FLAG_ELIMSEQ,
    FUZZY_FLAG_NOTRUNC,
    fuzzy_state,
    fuzzy_new,
    fuzzy_clone,
    fuzzy_update,
    fuzzy_digest,
    fuzzy_compare,
    fuzzy_free,
    fuzzy_hash_buf,
    fuzzy_hash_filename,
    fuzzy_set_total_input_length,
    FuzzyHashError,
)

from .ssdeep_pep_452 import(
    new,
    FuzzyHash,
    compare,
    get_hash_file,
    get_hash_buffer,
)
