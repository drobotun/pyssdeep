import unittest
import pytest
from unittest import mock

from pyssdeep import fuzzy_new
from pyssdeep import fuzzy_clone
from pyssdeep import fuzzy_update
from pyssdeep import fuzzy_digest
from pyssdeep import fuzzy_compare
from pyssdeep import fuzzy_free
from pyssdeep import fuzzy_hash_buf
from pyssdeep import fuzzy_hash_filename
from pyssdeep import fuzzy_set_total_input_length
from pyssdeep import FuzzyHashError

class TestSSDEEPWrapper(unittest.TestCase):

    def test_fuzzy_new(self):
        test_state = fuzzy_new()
        self.assertEqual(test_state.contents.bhstart, 0)
        self.assertEqual(test_state.contents.bhend, 1)
        self.assertEqual(test_state.contents.bhendlimit, 30)
        self.assertEqual(test_state.contents.total_size, 0)
        self.assertEqual(test_state.contents.reduce_border, 192)
        self.assertEqual(test_state.contents.flags, 0)
        self.assertEqual(test_state.contents.rollmask, 0)

    def test_fuzzy_new_raise(self):
        with mock.patch(
            'pyssdeep.ssdeep_wrapper.fuzzy_lib.fuzzy_new'
        ) as fuzzy_new_mock:
            fuzzy_new_mock.return_value = None
            with self.assertRaises(FuzzyHashError) as context:
                test_state = fuzzy_new()
        self.assertTrue('-1' in str(context.exception))

    def test_fuzzy_clone(self):
        test_state = fuzzy_new()
        test_state.contents.bh[0].digest = b'test_fuzzy_digest'
        test_state_copy = fuzzy_clone(test_state)
        test_state_copy.contents.bh[0].digest = b'test_fuzzy_copy_digest'
        self.assertEqual(
            test_state_copy.contents.bh[0].digest,
            b'test_fuzzy_copy_digest'
        )
        self.assertEqual(
            test_state.contents.bh[0].digest,
            b'test_fuzzy_digest'
        )

    def test_fuzzy_clone_raise(self):
        test_state = fuzzy_new()
        with mock.patch(
            'pyssdeep.ssdeep_wrapper.fuzzy_lib.fuzzy_clone'
        ) as fuzzy_clone_mock:
            fuzzy_clone_mock.return_value = None
            with self.assertRaises(FuzzyHashError) as context:
                test_state_clone = fuzzy_clone(test_state)
        self.assertTrue('-1' in str(context.exception))

    def test_fuzzy_update(self):
        test_state = fuzzy_new()
        fuzzy_update(
            test_state,
            b'This test fuzzy hash string',
            len(b'This test fuzzy hash string')
        )
        self.assertEqual(test_state.contents.total_size, 27)

    def test_fuzzy_update_raise(self):
        test_state = fuzzy_new()
        with mock.patch(
            'pyssdeep.ssdeep_wrapper.fuzzy_lib.fuzzy_update'
        ) as fuzzy_update_mock:
            fuzzy_update_mock.return_value = -1
            with self.assertRaises(FuzzyHashError) as context:
                fuzzy_update(
                    test_state,
                    b'This test fuzzy hash string',
                    len(b'This test fuzzy hash string')
                )
        self.assertTrue('-1' in str(context.exception))

    def test_fuzzy_digest(self):
        test_state = fuzzy_new()
        self.assertEqual(fuzzy_digest(test_state, 0), '3::')

    def test_fuzzy_digest_raise(self):
        test_state = fuzzy_new()
        with mock.patch(
            'pyssdeep.ssdeep_wrapper.fuzzy_lib.fuzzy_digest'
        ) as fuzzy_digest_mock:
            fuzzy_digest_mock.return_value = -1
            with self.assertRaises(FuzzyHashError) as context:
                fuzzy_digest(test_state, 0)
        self.assertTrue('-1' in str(context.exception))

    def test_fuzzy_compare(self):
        test_compare_1 = fuzzy_compare('3:hRMs3FsRc2:hRpg', '3:hRMs3FsRc2:hRpg')
        test_compare_2 = fuzzy_compare('3:hRMs3FsRc2:hRpg', '3:3LSve:7ce')
        self.assertEqual(test_compare_1, 100)
        self.assertEqual(test_compare_2, 0)

    def test_fuzzy_compare_raise(self):
        with mock.patch(
            'pyssdeep.ssdeep_wrapper.fuzzy_lib.fuzzy_compare'
        ) as fuzzy_compare_mock:
            fuzzy_compare_mock.return_value = -1
            with self.assertRaises(FuzzyHashError) as context:
                test_compare = fuzzy_compare(
                    '3:hRMs3FsRc2:hRpg',
                    '3:hRMs3FsRc2:hRpg'
                )
        self.assertTrue('-1' in str(context.exception))

    def test_fuzzy_hash_buf(self):
        test_result = fuzzy_hash_buf(
            b'This test fuzzy hash string',
            len(b'This test fuzzy hash string')
        )
        self.assertEqual(test_result, '3:hRMs3FsRc2:hRpg')

    def test_fuzzy_hash_buf_raise(self):
        with mock.patch(
            'pyssdeep.ssdeep_wrapper.fuzzy_lib.fuzzy_hash_buf'
        ) as fuzzy_hash_buf_mock:
            fuzzy_hash_buf_mock.return_value = -1
            with self.assertRaises(FuzzyHashError) as context:
                test_result = fuzzy_hash_buf(
                    b'This test fuzzy hash string',
                    len(b'This test fuzzy hash string')
                )
        self.assertTrue('-1' in str(context.exception))

    def test_fuzzy_hash_filename(self):
        test_result = fuzzy_hash_filename('test_file/test_file.txt')
        self.assertEqual(test_result, '3:hRMs3FsRcIn:hRpq')

    def test_fuzzy_hash_filename_raise(self):
        with mock.patch(
            'pyssdeep.ssdeep_wrapper.fuzzy_lib.fuzzy_hash_filename'
        ) as fuzzy_hash_filename_mock:
            fuzzy_hash_filename_mock.return_value = -1
            with self.assertRaises(FuzzyHashError) as context:
                test_result = fuzzy_hash_filename('test_file/test_file.txt')
        self.assertTrue('-1' in str(context.exception))

    def test_fuzzy_set_total_input_length(self):
        test_state = fuzzy_new()
        fuzzy_set_total_input_length(test_state, 1000)
        self.assertEqual(test_state.contents.bhendlimit, 4)
        
    def test_fuzzy_set_total_input_length_raise(self):
        test_state = fuzzy_new()
        with mock.patch(
            'pyssdeep.ssdeep_wrapper.fuzzy_lib.fuzzy_set_total_input_length'
        ) as fuzzy_set_total_input_length_mock:
            fuzzy_set_total_input_length_mock.return_value = -1
            with self.assertRaises(FuzzyHashError) as context:
                fuzzy_set_total_input_length(test_state, 1000)
        self.assertTrue('-1' in str(context.exception))
        
