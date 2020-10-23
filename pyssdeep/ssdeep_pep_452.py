"""
"""
import os
import six
from copy import deepcopy

from pyssdeep.ssdeep_wrapper import fuzzy_state
from pyssdeep.ssdeep_wrapper import fuzzy_new
from pyssdeep.ssdeep_wrapper import fuzzy_clone
from pyssdeep.ssdeep_wrapper import fuzzy_update
from pyssdeep.ssdeep_wrapper import fuzzy_digest
from pyssdeep.ssdeep_wrapper import fuzzy_compare
from pyssdeep.ssdeep_wrapper import fuzzy_free
from pyssdeep.ssdeep_wrapper import fuzzy_hash_buf
from pyssdeep.ssdeep_wrapper import fuzzy_hash_filename
from pyssdeep.ssdeep_wrapper import FuzzyHashError

def new(**kwargs):
    """Create a new hashing object and return it.

    Args:
      **data: The data from which to get the fuzzy hash (at a byte or string
        format). If this argument is passed to a function, you can immediately
        use the 'digest' method to calculate the fuzzy hash value after calling
        'new'.  If the argument is not passed to the function, then you must use
        the 'update' method before the 'digest' method.
      **encoding: Encoding is used if 'data' is string (default value is
        'utf-8').

    Returns:
      New hash object.

    Raises:
      FuzzyHashError: If a function execution error occurred or the argument
        type is incorrect.
    """
    encoding = kwargs.get('encoding', 'utf-8')
    data = kwargs.get('data', bytearray(b''))
    return FuzzyHash(data, encoding)

class FuzzyHash:
    """Class that implements the fuzzy hash calculation algorithm.

    Methods:
      copy: Create the copy of the hash object.
      update: Update the hash object with 'data'.
      digest: Obtain the fuzzy hash.
      free: Dispose the fuzzy hash context.

    Attributes:
      block_size: An integer value used to compute fuzzy hash.
      digest_size: An integer value the size of the resulting hash in bytes.
      name: Text string value the name of the fuzzy hashing algorithm
        ('ssdeep').
    """

    def __init__(self, data, encoding):
        """Initialize the hashing object.

        Args:
          data: The data from which to get the hash (as a byte object).
          encoding: Encoding is used if 'data' is string.

        Raises:
          UnicodeEncodeError: If the 'encoding' value is incorrect.
          TypeError: If a argument type is incorrect.
          FuzzyHashError: If a function execution error occurred.
        """
        self._name = 'ssdeep'
        try:
            self._state = fuzzy_new()
        except FuzzyHashError as err:
            self._state = None
            raise FuzzyHashError(
                'Unable to create hash context. Error code: {}.'.
                format(err)
            ) from err
        if data != bytearray(b''):
            self.update(data, encoding)

    def copy(self):
        """Create the copy of the hash object.

        The copy of of the hash object can be used with 'fuzzy_update' and
        'fuzzy_digest' independently of the original.

        Returns:
          Copy of the hash object.

        Raises:
          FuzzyHashError: If an error occurred executing the function.
        """
        try:
            state_copy = fuzzy_clone(self._state)
        except FuzzyHashError as err:
            raise FuzzyHashError(
                'Unable to clone hash object. Error code: {}.'.
                format(err)
            ) from err
        result = FuzzyHash.__new__(FuzzyHash)
        result._state = state_copy
        return result

    def update(self, data, encoding='utf-8'):
        """Update the hash object with 'data'.

        Args:
          data: The data from which to get the hash (as a byte or string
            object).
          encoding: Encoding is used if 'data' is string (default value is
            'utf-8').

        Raises:
          UnicodeEncodeError: If the 'encoding' value is incorrect.
          TypeError: If a argument type is incorrect.
          FuzzyHashError: If a function execution error occurred or if the
            'encoding' value is incorrect.
        """
        if isinstance(data, six.text_type):
            try:
                data = data.encode(encoding)
            except UnicodeEncodeError as err:
                raise FuzzyHashError(
                    'Data encoding error. The "encoding" value cannot be "{}".'.
                    format(encoding)
                ) from err
        if not isinstance(data, six.binary_type):
            raise TypeError(
                'Invalid data type. The data type cannot be "{}".'.
                format(type(data))
            )
        if self._state is None:
            raise FuzzyHashError(
                'Unable to update hash object. Hash context error.'
            )
        try:
            fuzzy_update(self._state, data, len(data))
        except FuzzyHashError as err:
            raise FuzzyHashError(
                'Unable to update hash object. Error code: {}.'.
                format(err)
            ) from err

    def digest(self, flag=0):
        """Obtain the fuzzy hash.

        It reports the hash for the concatenation of the data previously
        fed using 'update' method.

        Args:
          flag: Is a bitwise or of 'FUZZY_FLAG_ELIMSEQ' and 'FUZZY_FLAG_NOTRUNC'
        value (default value is zero).

        Returns:
          Fuzzy hash value (at a string format).

        Raises:
          TypeError: If a argument type is incorrect.
          FuzzyHashError: If a function execution error occurred.
        """
        if not isinstance(flag, int):
            raise TypeError(
                'Flag value must be of int type not "{}".'.
                format(type(flag))
            )
        if self._state is None:
            raise FuzzyHashError(
                'Unable to update hash object. Hash context error.'
            )
        try:
            result = fuzzy_digest(self._state, flag)
        except FuzzyHashError as err:
            raise FuzzyHashError(
                'Unable to compute digest of hash object. Error code: {}.'.
                format(err)
            ) from err
        return result

    def free(self):
        """Dispose the fuzzy hash context."""
        fuzzy_free(self._state)

    @property
    def block_size(self):
        """Return block size value.

        Returns:
          Block size value used to compute fuzzy hash.

        Raises:
          FuzzyHashError: If the block size value cannot be returned.
        """
        try:
            result = int(self.digest().partition(':')[0])
        except FuzzyHashError as err:
            raise FuzzyHashError(
                'Unable to return the block size value.'
            ) from err
        return result

    @property
    def digest_size(self):
        """Return digest size value.

        Returns:
          Digest size value.

        Raises:
          FuzzyHashError: If the digest size value cannot be returned.
        """
        try:
            result = len(self.digest().partition(':')[2])
        except FuzzyHashError as err:
            raise FuzzyHashError(
                'Unable to return the digest size value.'
            ) from err
        return result

    @property
    def name(self):
        """Return the string with the name of the hashing algorithm.

        This value is 'ssdeep'.
        """
        return self._name

def compare(signature_1, signature_2):
    """Compare two fazzy hash signatures.

    Args:
      signature_1: The first fuzzy hash signature (at a string format).
      signature_2: The second fuzzy hash signature (at a string format).

    Returns:
      The value from zero to 100 indicating the match score of the two
      signatures. A match score of zero indicates the signatures did not match. 

    Raises:
      TypeError: If a argument type is incorrect.
      FuzzyHashError: If a function execution error occurred.
    """
    if not isinstance(signature_1, six.text_type):
        raise TypeError(
            'Invalid first operand type. It cannot be "{}".'.
            format(type(signature_1))
        )
    if not isinstance(signature_2, six.text_type):
        raise TypeError(
            'Invalid second operand type. It cannot be "{}".'.
            format(type(signature_2))
        )
    try:
        result = fuzzy_compare(signature_1, signature_2)
    except FuzzyHashError as err:
        raise FuzzyHashError(
                'Unable to compare this fazzy hash signatures. Error code: {}.'.
                format(err)
            ) from err
    return result

def get_hash_file(file_name):
    """Compute the fuzzy hash of a file.

    Args:
      file_name: The file to be hashed (at a string format).

    Returns:
      The fuzzy hash of the file (at a string format).

    Raises:
      IOError: If the file is not found or unavailable.
      FuzzyHashError: If a function execution error occurred.
    """
    if not os.path.isfile(file_name):
        raise IOError(
            'File "{}" not found.'.
            format(file_name)
        )
    if not os.access(file_name, os.R_OK):
        raise IOError(
            'File "{}" is not available.'.
            format(file_name)
        )
    try:
        result = fuzzy_hash_filename(file_name)
    except FuzzyHashError as err:
        raise FuzzyHashError(
            'Unable to compute fuzzy hash of file "{0}". Error code: {1}.'.
            format(file_name, err)
        ) from err
    return result

def get_hash_buffer(buffer, encoding='utf-8'):
    """Compute the fuzzy hash of a buffer.

    Args:
      buffer: The data from which to get the hash (as a byte or string object).
      encoding: Encoding is used if 'buffer' is string (default value is
        'utf-8').

    Returns:
      The fuzzy hash of the buffer (at a string format).

    Raises:
      UnicodeEncodeError: If the 'encoding' value is incorrect.
      TypeError: If a argument type is incorrect.
      FuzzyHashError: If a function execution error occurred or if the
        'encoding' value is incorrect.
    """
    if isinstance(buffer, six.text_type):
        try:
            buffer = buffer.encode(encoding)
        except UnicodeEncodeError as err:
            raise FuzzyHashError(
                'Data encoding error. The "encoding" value cannot be "{}".'.
                format(encoding)
            )
    if not isinstance(buffer, six.binary_type):
        raise TypeError(
            'Invalid data type. The data type cannot be "{}".'.
            format(type(buffer))
        )    
    try:
        result = fuzzy_hash_buf(buffer, len(buffer))
    except FuzzyHashError as err:
        raise FuzzyHashError(
            'Unable to compute fuzzy hash. Error code: {}.'.
            format(err)
        ) from err
    return result

