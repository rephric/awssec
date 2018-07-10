import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="awssec_pkg",
    version="1.0.0",
    author="Zachary Estrella",
    author_email="zjestrella1@gmail.com",
    description="AWS security posture",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/rephric/awssec",
    packages=setuptools.find_packages(),
    classifiers=(
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ),
)
