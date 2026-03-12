from setuptools import setup, find_packages

setup(
    name='micropki',
    version='0.1.0',
    description='A minimal PKI implementation for educational purposes',
    author='Your Name',
    packages=find_packages(),
    install_requires=[
        'cryptography>=41.0.0',
    ],
    entry_points={
        'console_scripts': [
            'micropki=micropki.cli:main',
        ],
    },
    python_requires='>=3.8',
)