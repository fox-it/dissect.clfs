from setuptools import setup

setup(
    name="dissect.clfs",
    packages=["dissect.clfs"],
    install_requires=[
        "dissect.cstruct>=2.0.dev,<3.0.dev",
    ],
)
