from setuptools import setup, find_packages
import pyssdeep

with open('README.rst', 'r', encoding='utf-8') as readme_file:
    readme = readme_file.read()
with open('HISTORY.rst', 'r', encoding='utf-8') as history_file:
    history = history_file.read()

setup(
    name = pyssdeep.__name__,
    version = pyssdeep.__version__,
    description = 'The python-wrapper for ssdeep',
    long_description = readme + '\n\n' + history,
    author = pyssdeep.__author__,
    author_email = pyssdeep.__author_email__,
    url='https://github.com/drobotun/pyssdeep/',
    zip_safe=False,
    license = pyssdeep.__license__,
    keywords='ssdeep, fuzzy hash, python',
    project_urls={
        'Documentation': 'https://pyssdeep.readthedocs.io/',
        'Source': 'https://github.com/drobotun/pyssdeep/'
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.0',
        'Programming Language :: Python :: 3.8',
    ],
    test_suite="tests",
    packages=find_packages(),
    include_package_data=True,
    data_files=[('test_file', ['test_file/test_file.txt'])],
    )

