Introduction
============

Overview
--------

This package is a Python wrapper for ssdeep by Jesse Kornblum, which is a
library for computing Context Triggered Piecewise Hashes (CTPH).

Installation
------------

.. code-block:: bash

    $ pip install pyssdeep

Usage
-----

.. rubric:: Get a fuzzy hash value for a string:

.. code-block:: python

    import pyssdeep
    
    try:
        result = pyssdeep.get_hash_buffer(
            'The string for which you want to calculate a fuzzy hash'
        )
    escept pyssdeep.FuzzyHashError as err:
        print(err)
    except TypeError as err:
        print(err)
    print('The fuzzy hash value is {}'.format(result))

.. rubric:: Get a fuzzy hash value for a file:

.. code-block:: python

    import pyssdeep
    
    try:
        result = pyssdeep.get_hash_file('e:/file.txt')
    escept pyssdeep.FuzzyHashError as err:
        print(err)
    except IOError as err:
        print(err)
    print('The fuzzy hash value is {}'.format(result))

.. rubric:: Get a fuzzy hash value for a file (using the pep 452 API):

.. code-block:: python

    import pyssdeep
    
    buffer_size = 1024
    fuzzy_hash_obj = pyssdeep.new()
    with open('e:/file.txt', 'rb') as file:
        buffer = file.read(buffer_size)
        while len(buffer) > 0:
            fuzzy_hash_obj.update(buffer)
            buffer = file.read(buffer_size)
    result = fuzzy_hash_obj.digest()

License
-------

MIT Copyright (c) 2020 Evgeny Drobotun

Source code
-----------

Package source code: https://github.com/drobotun/pyssdeep

Release hystory
---------------

.. rubric:: 1.0.0 (20.10.2020)

- First release of **'pyssdeep'**

