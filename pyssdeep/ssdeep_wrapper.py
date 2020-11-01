"""The Python wrapper for ssdeep.

This module is a Python wrapper for ssdeep's library (fuzzy.dll or fuzzy.so).
"""
import os
import sys
import ctypes

FUZZY_FLAG_ELIMSEQ = 0x1 #Flag indicating to eliminate sequences of more than
                         #three identical characters.
FUZZY_FLAG_NOTRUNC = 0x2 #Flag indicating not to truncate the second part to
                         #_SPAMSUM_LENGTH/2 characters.
_ROLLING_WINDOW = 7
_SPAMSUM_LENGTH = 64
_FUZZY_MAX_RESULT = (2 * _SPAMSUM_LENGTH + 20)
_NUM_BLOCKHASHES = 31

package_path = os.path.split(__file__)[0]

if sys.platform == 'win32':
    if sys.maxsize > 2**32:
        lib_path = os.path.join(package_path, r'bin/windows/fuzzy_64.dll')
    else:
        lib_path = os.path.join(package_path, r'bin/windows/fuzzy.dll')
elif sys.platform == 'linux':
    if sys.maxsize > 2**32:
        lib_path = os.path.join(package_path, r'bin/linux/fuzzy_64.so')
    else:
        lib_path = os.path.join(package_path, r'bin/linux/fuzzy.so')
else:
    print('Unsupported operation sysytem')
    sys.exit(0)
try:
    fuzzy_lib = ctypes.cdll.LoadLibrary(lib_path)
except FileNotFoundError:
    print('The library fuzzy.dll or fuzzy.so not found')
    sys.exit(0)

# pylint: disable=invalid-name
# pylint: disable=too-few-public-methods

class _blockhash_context(ctypes.Structure):
    """The wrapper for 'blockhash_context' structure.

    This class is a wrapper for the 'blockhash_context' structure from the
    library 'fuzzy.dll' or 'fuzzy.so'.
    """

    _fields_ = [
        ('dindex', ctypes.c_uint),
        ('digest', ctypes.c_char * _SPAMSUM_LENGTH),
        ('halfdigest', ctypes.c_char),
        ('h', ctypes.c_char),
        ('halfh', ctypes.c_char),
    ]

class _roll_state(ctypes.Structure):
    """The wrapper for 'roll_state' structure.


    This class is a wrapper for the 'roll_state' structure from the library
    'fuzzy.dll' or 'fuzzy_64.dll'.
    """

    _fields_ = [
        ('window', ctypes.c_char * _ROLLING_WINDOW),
        ('h1', ctypes.c_ulong),
        ('h2', ctypes.c_ulong),
        ('h3', ctypes.c_ulong),
        ('n', ctypes.c_ulong),
    ]

class fuzzy_state(ctypes.Structure):
    """The wrapper for 'fuzzy_context' structure.

    This class is a wrapper for the 'fuzzy_context' structure from the library
    'fuzzy.dll' or 'fuzzy.so'.
    """

    _fields_ = [
        ('total_size', ctypes.c_ulonglong),
        ('fixed_size', ctypes.c_ulonglong),
        ('reduce_border', ctypes.c_ulonglong),
        ('bhstart', ctypes.c_uint),
        ('bhend', ctypes.c_uint),
        ('bhendlimit', ctypes.c_uint),
        ('flags', ctypes.c_uint),
        ('rollmask', ctypes.c_ulong),
        ('bh', _blockhash_context * _NUM_BLOCKHASHES),
        ('roll', _roll_state),
        ('lasth',ctypes.c_ubyte),
    ]
# pylint: enable=invalid-name
# pylint: enable=too-few-public-methods

class FuzzyHashError(Exception):
    """The exception class."""
    pass

def fuzzy_new():
    """Construct an instance of the 'fuzzy_state' class.

    This function is a wrapper for the 'fuzzy_new' function from the library
    'fuzzy.dll' or 'fuzzy.so'. To use it call 'fuzzy_update' and
    'fuzzy_digest' on it. It must be disposed with 'fuzzy_free'.

    Returns:
      The instance of the 'fuzzy_state' class.

    Raises:
      FuzzyHashError: If a function execution error occurred.
    """
    fuzzy_lib.fuzzy_new.restype = ctypes.POINTER(fuzzy_state)
    result = fuzzy_lib.fuzzy_new()
    if result is None:
        raise FuzzyHashError(-1)
    return result

def fuzzy_clone(state):
    """Create a copy of a 'fuzzy_state' object.

    This function is a wrapper for the 'fuzzy_clone' function from the library
    'fuzzy.dll' or 'fuzzy.so'. The copy of a 'fuzzy_state' object can be
    used with 'fuzzy_update' and 'fuzzy_digest' independently of the original.
    It must be disposed with 'fuzzy_free' like the original has to be cleared in
    this way.

    Args:
      state: The 'fuzzy_state' object.

    Returns:
      The copy of a 'fuzzy_state' object.

    Raises:
      FuzzyHashError: If a function execution error occurred.
    """
    fuzzy_lib.fuzzy_clone.restype = ctypes.POINTER(fuzzy_state)
    result = fuzzy_lib.fuzzy_clone(state)
    if result is None:
        raise FuzzyHashError(-1)
    return result

def fuzzy_update(state, buffer, buffer_size):
    """Feed the data contained in the given 'buffer' to the 'state'.

    This function is a wrapper for the 'fuzzy_update' function from the library
    'fuzzy.dll' or 'fuzzy.so'. When an error occurs, the 'state' is
    undefined. In that case it must not be passed to any function besides
    'fuzzy_free'.

    Args:
      state: The 'fuzzy_state' object.
      buffer: The data to be hashed (at a byte format).
      buffer_size: The length of the given 'buffer'.

    Raises:
      FuzzyHashError: If a function execution error occurred.
    """
    buffer = ctypes.create_string_buffer(buffer)
    result = fuzzy_lib.fuzzy_update(state, buffer, buffer_size)
    if result != 0:
        raise FuzzyHashError(result)

def fuzzy_digest(state, flag):
    """Obtain the fuzzy hash from the 'state'.

    This function is a wrapper for the 'fuzzy_digest' function from the library
    'fuzzy.dll' or 'fuzzy.so'. This function does not change the 'state'
    at all. It reports the hash for the concatenation of the data previously
    fed using 'fuzzy_update' function.

    Args:
      state: The 'fuzzy_state' object.
      flag: Is a bitwise or of 'FUZZY_FLAG_ELIMSEQ' and 'FUZZY_FLAG_NOTRUNC'
        value. The absence of flags is represented by a zero.

    Returns:
      The fuzzy hash value (at a string format).
    Raises:
      FuzzyHashError: If a function execution error occurred.
    """
    digest = ctypes.create_string_buffer(_FUZZY_MAX_RESULT)
    result = fuzzy_lib.fuzzy_digest(state, digest, flag)
    if result != 0:
        raise FuzzyHashError(result)
    return digest.value.decode('ascii')

def fuzzy_compare(signature_1, signature_2):
    """Compute the match score between two fuzzy hash signatures.

    This function is a wrapper for the 'fuzzy_compare' function from the library
    'fuzzy.dll' or 'fuzzy.so'.

    Args:
      signature_1: The first fuzzy hash signature (at a string format).
      signature_2: The second fuzzy hash signature (at a string format).

    Returns:
      The value from zero to 100 indicating the match score of the two
      signatures. A match score of zero indicates the signatures did not match.

    Rises:
      FuzzyHashError: If a function execution error occurred.
    """
    signature_1 = ctypes.create_string_buffer(signature_1.encode('utf-8'))
    signature_2 = ctypes.create_string_buffer(signature_2.encode('utf-8'))
    result = fuzzy_lib.fuzzy_compare(signature_1, signature_2)
    if result < 0:
        raise FuzzyHashError(result)
    return result

def fuzzy_free(state):
    """Dispose a 'fuzzy_state' object.

    This function is a wrapper for the 'fuzzy_free' function from the library
    'fuzzy.dll' or 'fuzzy.so'.

    Args:
      state: The 'fuzzy_state' object.
    """
    fuzzy_lib.fuzzy_free(state)

def fuzzy_hash_buf(buf, buf_len):
    """Compute the fuzzy hash of a buffer.

    This function is a wrapper for the 'fuzzy_hash_buf' function from the
    library 'fuzzy.dll' or 'fuzzy.so'. The computes the fuzzy hash of the
    first 'buf_len' bytes of the 'buf'.

    Args:
      buf: The data to be fuzzy hashed (at a byte format).
      buf_len: The length of the given 'buffer'.

    Returns:
      The fuzzy hash of the 'buffer' (at a string format).

    Raises:
      FuzzyHashError: If a function execution error occurred.
    """
    buf = ctypes.create_string_buffer(buf)
    hash_result = ctypes.create_string_buffer(_FUZZY_MAX_RESULT)
    result = fuzzy_lib.fuzzy_hash_buf(buf, buf_len, hash_result)
    if result != 0:
        raise FuzzyHashError(result)
    return hash_result.value.decode('ascii')

def fuzzy_hash_filename(filename):
    """Compute the fuzzy hash of a file.

    This function is a wrapper for the 'fuzzy_hash_filename' function from the
    library 'fuzzy.dll' or 'fuzzy.so'. Opens, reads, and hashes the contents
    of the file 'filename'.

    Args:
      filename: The file to be hashed.

    Returns:
      The fuzzy hash of the file (at a string format).

    Raises:
      FuzzyHashError: If a function execution error occurred.
    """
    filename =  ctypes.create_string_buffer(filename.encode('utf-8'))
    hash_result = ctypes.create_string_buffer(_FUZZY_MAX_RESULT)
    result = fuzzy_lib.fuzzy_hash_filename(filename, hash_result)
    if result != 0:
        raise FuzzyHashError(result)
    return hash_result.value.decode('ascii')

def fuzzy_set_total_input_length(state, total_fixed_length):
    """Set fixed length of input.

    This function is a wrapper for the 'fuzzy_set_total_input_length' function
    from the library 'fuzzy.dll' or 'fuzzy.so'. If we know the file size to
    compute fuzzy digest, we can boost computation by restricting range of
    blocksize.

    Args:
      state: The 'fuzzy_state' object.
      total_fixed_length: Total length of the data to generate digest.

    Raises:
      FuzzyHashError: If a function execution error occurred.
    """
    result = fuzzy_lib.fuzzy_set_total_input_length(state, total_fixed_length)
    if result != 0:
        raise FuzzyHashError(result)

