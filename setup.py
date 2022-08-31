from setuptools import setup

setup(
    name="dissect.clfs",
    packages=["dissect.clfs"],
    install_requires=[
        "dissect.cstruct>=3.0.dev,<4.0.dev",
    ],
)
