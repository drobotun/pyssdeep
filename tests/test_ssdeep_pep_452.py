import unittest
from unittest import mock
import pytest

from pyssdeep import FuzzyHash
from pyssdeep import new
from pyssdeep import compare
from pyssdeep import get_hash_file
from pyssdeep import get_hash_buffer
from pyssdeep import FuzzyHashError

def fuzzy_new_mock_raise():
    raise FuzzyHashError(-1)

def fuzzy_clone_mock_raise(state):
    raise FuzzyHashError(-1)

def fuzzy_update_mock_raise(state, buffer, buffer_size):
    raise FuzzyHashError(-1)

def fuzzy_digest_mock_raise(state, flag):
    raise FuzzyHashError(-1)

def digest_mock_raise(flag):
    raise FuzzyHashError

def fuzzy_compare_mock_raise(signature_1, signature_2):
    raise FuzzyHashError(-1)

def fuzzy_hash_buf_mock_raise(buffer, buffer_size):
    raise FuzzyHashError(-1)

def os_path_isfile_mock(filename):
    return False

def os_access_mock(filename, mode):
    return False

def fuzzy_hash_filename_mock_raise(filename):
    raise FuzzyHashError(-1)

class TestSSDEEP(unittest.TestCase):

    def test_new(self):
        test_fuzzy_hash_obj = new()
        self.assertEqual(test_fuzzy_hash_obj._state.contents.bhstart, 0)
        self.assertEqual(test_fuzzy_hash_obj._state.contents.bhend, 1)
        self.assertEqual(test_fuzzy_hash_obj._state.contents.bhendlimit, 30)
        self.assertEqual(test_fuzzy_hash_obj._state.contents.total_size, 0)
        self.assertEqual(test_fuzzy_hash_obj._state.contents.reduce_border, 192)
        self.assertEqual(test_fuzzy_hash_obj._state.contents.flags, 0)
        self.assertEqual(test_fuzzy_hash_obj._state.contents.rollmask, 0)

    def test_new_raise(self):
        with mock.patch(
            'pyssdeep.ssdeep_pep_452.fuzzy_new',
            fuzzy_new_mock_raise
        ):
            with self.assertRaises(FuzzyHashError) as context:
                test_fuzzy_hash_obj = new()
        self.assertTrue(
            'Unable to create hash context. Error code: -1'
            in str(context.exception)
        )

    def test_copy(self):
        test_fuzzy_hash_obj = new()
        test_fuzzy_hash_obj._state.contents.bh[0].digest = b'test_fuzzy_digest'
        test_fuzzy_hash_obj_copy = test_fuzzy_hash_obj.copy()
        test_fuzzy_hash_obj_copy._state.contents.bh[0].digest = b'test_fuzzy_copy_digest'
        self.assertEqual(
            test_fuzzy_hash_obj_copy._state.contents.bh[0].digest,
            b'test_fuzzy_copy_digest'
        )
        self.assertEqual(
            test_fuzzy_hash_obj._state.contents.bh[0].digest,
            b'test_fuzzy_digest'
        )

    def test_copy_raise(self):
        test_fuzzy_hash_obj = new()
        with mock.patch(
            'pyssdeep.ssdeep_pep_452.fuzzy_clone',
            fuzzy_clone_mock_raise
        ):
            with self.assertRaises(FuzzyHashError) as context:
                test_fuzzy_hash_obj_copy = test_fuzzy_hash_obj.copy()
        self.assertTrue(
            'Unable to clone hash object. Error code: -1'
            in str(context.exception)
        )

    def test_update(self):
        test_fuzzy_hash_obj = new()
        test_fuzzy_hash_obj.update(b'this test fuzzy hash string')
        self.assertEqual(
            test_fuzzy_hash_obj._state.contents.total_size, 27
        )

    def test_update_raise(self):
        test_fuzzy_hash_obj = new()
        with mock.patch(
            'pyssdeep.ssdeep_pep_452.fuzzy_update',
            fuzzy_update_mock_raise
        ):
            with self.assertRaises(FuzzyHashError) as context:
                test_fuzzy_hash_obj.update(b'this test fuzzy hash string')
        self.assertTrue(
            'Unable to update hash object. Error code: -1'
            in str(context.exception)
        )

    def test_update_type_error(self):
        test_fuzzy_hash_obj = new()
        with self.assertRaises(TypeError) as context:
            test_fuzzy_hash_obj.update(None)
        self.assertTrue(
            'Invalid data type. The data type cannot be "<class \'NoneType\'>".'
            in str(context.exception)
        )

    def test_update_encode_error(self):
        test_fuzzy_hash_obj = new()
        with self.assertRaises(FuzzyHashError) as context:
            test_fuzzy_hash_obj.update(
                'тестовая строка для fazzy hash',
                'ascii'
            )
        self.assertTrue(
            'Data encoding error. The "encoding" value cannot be'
            in str(context.exception)
        )

    def test_update_hash_context_error(self):
        test_fuzzy_hash_obj = new()
        test_fuzzy_hash_obj._state = None
        with self.assertRaises(FuzzyHashError) as context:
            test_fuzzy_hash_obj.update(b'this test fuzzy hash string')
        self.assertTrue(
            'Unable to update hash object. Hash context error.'
            in str(context.exception)
        )

    def test_digest(self):
        test_fuzzy_hash_obj = new()
        test_result = test_fuzzy_hash_obj.digest()
        self.assertEqual(test_result, '3::')

    def test_digest_raise(self):
        test_fuzzy_hash_obj = new()
        with mock.patch(
            'pyssdeep.ssdeep_pep_452.fuzzy_digest',
            fuzzy_digest_mock_raise
        ):
            with self.assertRaises(FuzzyHashError) as context:
                test_result = test_fuzzy_hash_obj.digest()
        self.assertTrue(
            'Unable to compute digest of hash object. Error code: -1'
            in str(context.exception)
        )

    def test_digest_type_error(self):
        test_fuzzy_hash_obj = new()
        with self.assertRaises(TypeError) as context:
            test_result = test_fuzzy_hash_obj.digest(None)
        self.assertTrue(
            'Flag value must be of int type not "<class \'NoneType\'>".'
            in str(context.exception)
        )

    def test_digest_hash_context_error(self):
        test_fuzzy_hash_obj = new()
        test_fuzzy_hash_obj._state = None
        with self.assertRaises(FuzzyHashError) as context:
            test_result = test_fuzzy_hash_obj.digest()
        self.assertTrue(
            'Unable to update hash object. Hash context error.'
        )

    def test_block_size(self):
        test_fuzzy_hash_obj = new()
        test_result = test_fuzzy_hash_obj.block_size
        self.assertEqual(test_result, 3)

    def test_block_size_raise(self):
        test_fuzzy_hash_obj = new()
        with mock.patch(
            'pyssdeep.ssdeep_pep_452.FuzzyHash.digest',
            digest_mock_raise
        ):
            with self.assertRaises(FuzzyHashError) as context:
                test_result = test_fuzzy_hash_obj.block_size
        self.assertTrue(
            'Unable to return the block size value.'
            in str(context.exception)
        )

    def test_digest_size(self):
        test_fuzzy_hash_obj = new()
        test_result = test_fuzzy_hash_obj.digest_size
        self.assertEqual(test_result, 1)
        
    def test_digest_size_raise(self):
        test_fuzzy_hash_obj = new()
        with mock.patch(
            'pyssdeep.ssdeep_pep_452.FuzzyHash.digest',
            digest_mock_raise
        ):
            with self.assertRaises(FuzzyHashError) as context:
                test_result = test_fuzzy_hash_obj.digest_size
        self.assertTrue(
            'Unable to return the digest size value.'
            in str(context.exception)
        )

    def test_name(self):
        test_fuzzy_hash_obj = new()
        test_result = test_fuzzy_hash_obj.name
        self.assertEqual(test_result, 'ssdeep')
        
    def test_compare(self):
        test_result = compare('3:hRMs3FsRc2:hRpg', '3:hRMs3FsRc2:hRpg')
        self.assertEqual(test_result, 100)
        test_result = compare('3:hRMs3FsRc2:hRpg', '3:3LSve:7ce')
        self.assertEqual(test_result, 0)

    def test_compare_raise(self):
        with mock.patch(
            'pyssdeep.ssdeep_pep_452.fuzzy_compare',
            fuzzy_compare_mock_raise
        ):
            with self.assertRaises(FuzzyHashError) as context:
                test_result = compare('3:hRMs3FsRc2:hRpg', '3:hRMs3FsRc2:hRpg')
        self.assertTrue(
            'Unable to compare this fazzy hash signatures. Error code: -1.'
            in str(context.exception)
        )

    def test_compare_type_error(self):
        with self.assertRaises(TypeError) as context:
            test_result = compare(None, '3:hRMs3FsRc2:hRpg')
        self.assertTrue(
            'Invalid first operand type. It cannot be "<class \'NoneType\'>".'
            in str(context.exception)
        )
        with self.assertRaises(TypeError) as context:
            test_result = compare('3:hRMs3FsRc2:hRpg', None)
        self.assertTrue(
            'Invalid second operand type. It cannot be "<class \'NoneType\'>".'
            in str(context.exception)
        )

    def test_get_hash_buffer(self):
        test_result = get_hash_buffer('This test fuzzy hash string')
        self.assertEqual(test_result, '3:hRMs3FsRc2:hRpg')
        test_result = get_hash_buffer(b'This test fuzzy hash string')
        self.assertEqual(test_result, '3:hRMs3FsRc2:hRpg')

    def test_get_hash_buffer_raise(self):
        with mock.patch(
            'pyssdeep.ssdeep_pep_452.fuzzy_hash_buf',
            fuzzy_hash_buf_mock_raise
        ):
            with self.assertRaises(FuzzyHashError) as context:
                test_result = get_hash_buffer(b'This test fuzzy hash string')
        self.assertTrue(
            'Unable to compute fuzzy hash. Error code: -1.'
            in str(context.exception)
        )

    def test_get_hash_buffer_type_error(self):
        with self.assertRaises(TypeError) as context:
            test_result = get_hash_buffer(None)
        self.assertTrue(
            'Invalid data type. The data type cannot be "<class \'NoneType\'>".'
            in str(context.exception)
        )

    def test_get_hash_buffer_encode_error(self):
        with self.assertRaises(FuzzyHashError) as context:
            test_result = get_hash_buffer(
                'тестовая строка для fazzy hash',
                'ascii'
            )
        self.assertTrue(
            'Data encoding error. The "encoding" value cannot be'
            in str(context.exception)
        )

    def test_get_hash_file(self):
        test_result = get_hash_file('test_file/test_file.txt')
        self.assertEqual(test_result, '3:hRMs3FsRcIn:hRpq')

    def test_get_hash_file_no_file(self):
        with mock.patch('os.path.isfile', os_path_isfile_mock):
            with self.assertRaises(IOError) as context:
                test_result = get_hash_file('test_file/test_file.txt')
        self.assertTrue(
            'File "test_file/test_file.txt" not found.'
            in str(context.exception)
        )

    def test_get_hash_file_no_access(self):
        with mock.patch('os.access', os_access_mock):
            with self.assertRaises(IOError) as context:
                test_result = get_hash_file('test_file/test_file.txt')
        self.assertTrue(
            'File "test_file/test_file.txt" is not available.'
            in str(context.exception)
        )

    def test_get_hash_file_raise(self):
        with mock.patch(
            'pyssdeep.ssdeep_pep_452.fuzzy_hash_filename',
            fuzzy_hash_filename_mock_raise
        ):
            with self.assertRaises(FuzzyHashError) as context:
                test_result = get_hash_file('test_file/test_file.txt')
        self.assertTrue(
            'Unable to compute fuzzy hash of file "test_file/test_file.txt". Error code: -1.'
            in str(context.exception)
        )

