The python-wrapper for ssdeep
=============================

.. image:: https://img.shields.io/github/license/drobotun/virustotalapi3?style=flat
    :target: http://doge.mit-license.org
.. image:: https://readthedocs.org/projects/pyssdeep/badge/?version=latest
    :target: https://pyssdeep.readthedocs.io/
.. image:: https://api.travis-ci.org/drobotun/pyssdeep.svg?branch=master&status=unknown
    :target: https://travis-ci.org/github/drobotun/pyssdeep
.. image:: https://codecov.io/gh/drobotun/pyssdeep/branch/master/graph/badge.svg?token=VHQQRO279Z
    :target: https://codecov.io/gh/drobotun/pyssdeep
.. image:: https://img.shields.io/pypi/dm/pyssdeep
    :target: https://pypi.org/project/pyssdeep/

This package is a Python wrapper for `ssdeep <https://ssdeep-project.github.io/ssdeep/index.html>`_ by Jesse Kornblum, which is a
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
