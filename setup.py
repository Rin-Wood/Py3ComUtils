from setuptools import setup

setup(
    name="Py3ComUtils",
    version="1.0.2",
    author='wood',
    author_email='miraclerinwood@gmail.com',
    packages=["Py3ComUtils"],
    url='https://github.com/Rin-Wood/Py3ComUtils',
    description="A collection of commonly used utility functions for Python 3",
    long_description=open('README.md', 'rb').read().decode('utf8'),
	long_description_content_type='text/markdown',
    license="MIT",
    keywords="utilities, Python, common functions, Py3ComUtils",
    install_requires=["bbpb", "brotli", "lz4", "msgpack", "numpy", "Pillow", "pycryptodome", "texture2ddecoder", "xmltodict", "cxxtea", "crijndael"],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Programming Language :: Python :: 3.13',
    ],
    python_requires=">=3.6",
)
