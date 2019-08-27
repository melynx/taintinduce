import setuptools
import os

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
        name="taintinduce",
        version="0.1.0",
        author="Chua Zheng Leong",
        author_email="czl@iiyume.org",
        description="TaintInduce",
        long_description=long_description,
        url="https://github.com/melynx/taintinduce/",
        packages=setuptools.find_packages(),
        package_data={},
        install_requires=[
            'squirrel-framework',
            'tqdm',
            'capstone',
            'keystone-engine',
            'unicorn',
        ],
        classifiers=[
            "Programming Language :: Python :: 3"
        ],
)
print(setuptools.find_packages())
