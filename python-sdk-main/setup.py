from setuptools import setup, find_packages

setup(
    name="golem-base-sdk",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "web3>=6.0.0",
        #"eth-account>=0.8.0",
        "requests>=2.25.0",
    ],
    author="GolemBase Team",
    author_email="info@golem-base.io",
    description="Python SDK for GolemBase",
    keywords="golem, blockchain, storage",
    url="https://github.com/golem-base/python-sdk",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
    python_requires=">=3.8",
)