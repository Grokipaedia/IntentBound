"""
Intent-Bound Authorization (IBA) - Setup Configuration

Author: Grokipaedia Research
License: MIT
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="iba-agentic-security",
    version="0.1.0",
    author="Grokipaedia Research",
    author_email="research@grokipaedia.com",
    description="Intent-Bound Authorization for autonomous AI systems",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Grokipaedia/iba-agentic-security",
    project_urls={
        "Bug Tracker": "https://github.com/Grokipaedia/iba-agentic-security/issues",
        "Documentation": "https://www.grokipaedia.com/TheArchitecture.html",
        "Specification": "https://www.grokipaedia.com/IntentBoundAuthorization.html",
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    packages=find_packages(exclude=["tests", "examples", "docs"]),
    python_requires=">=3.8",
    install_requires=[
        "cryptography>=41.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "black>=23.0.0",
            "mypy>=1.5.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "iba=iba:quick_start",
        ],
    },
    keywords="intent authorization security ai agents autonomous governance",
    include_package_data=True,
    zip_safe=False,
)
