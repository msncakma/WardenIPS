#!/usr/bin/env python3
"""
WardenIPS Setup Configuration
============================
Basic setuptools configuration for Python packaging compatibility.
The main debian packaging is handled via debian/ directory.
"""

from setuptools import setup, find_packages
import sys
from pathlib import Path

# Minimum Python version check
if sys.version_info < (3, 10):
    sys.exit("WardenIPS requires Python 3.10 or higher")

# Read version from package
sys.path.insert(0, str(Path(__file__).parent))
from wardenips import __version__, __author__

# Read requirements
requirements_txt = Path(__file__).parent / "requirements.txt"
if requirements_txt.exists():
    requirements = requirements_txt.read_text(encoding="utf-8").strip().split("\n")
    requirements = [req.strip() for req in requirements if req.strip() and not req.startswith("#")]
else:
    requirements = []

# Read long description from README
readme_path = Path(__file__).parent / "README.md"
long_description = readme_path.read_text(encoding="utf-8") if readme_path.exists() else ""

setup(
    name="wardenips",
    version=__version__,
    author=__author__.replace(" <3", ""),  # Remove emoji for PyPI
    author_email="wardenips@msncakma.dev",
    description="Autonomous Intrusion Prevention System for Linux",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/msncakma/WardenIPS",
    project_urls={
        "Bug Reports": "https://github.com/msncakma/WardenIPS/issues",
        "Source": "https://github.com/msncakma/WardenIPS",
        "Documentation": "https://github.com/msncakma/WardenIPS#readme",
        "Ko-fi": "https://ko-fi.com/msncakma"
    },
    packages=find_packages(),
    include_package_data=True,
    install_requires=requirements,
    python_requires=">=3.10",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Developers", 
        "Topic :: System :: Networking :: Firewalls",
        "Topic :: System :: Systems Administration",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Operating System :: POSIX :: Linux",
        "Environment :: No Input/Output (Daemon)",
    ],
    keywords="ips intrusion-prevention firewall security linux systemd",
    entry_points={
        "console_scripts": [
            "wardenips-python=main:main",  # Alternative Python entry point
        ],
    },
    zip_safe=False,  # Due to bundled assets and configs
)