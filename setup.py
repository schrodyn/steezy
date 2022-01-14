from setuptools import setup

r2zin = False

requires = [
    "capstone",
    "mkYARA",
    "r2pipe",
    "rzpipe",
    "yara-python",
]

def is_tool(name):
    """Check whether `name` is on PATH and marked as executable."""
    # from whichcraft import which
    from shutil import which
    return which(name) is not None

for c in [ 'r2', 'radare2', 'rizin']:
    if is_tool(c):
        r2zin = True

if r2zin is False:
    import sys
    print("!!!!!\n[FATAL] Neither rizin or radare2 found!!!\n!!!!!")
    sys.exit(1)

setup(
    name="steezy",
    author="Conor Quigley",
    author_email="schrodinger@konundrum.org",
    url="https://github.com/schrodyn/steezy",
    version="2.0.0",
    packages=["steezy"],
    license="BSD-2-Clause",
    python_requires='>=3.7',
    install_requires=requires,
    classifiers=[
        'Environment :: Console',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 3.7',
    ],
    entry_points={
        "console_scripts": [
            "steezy = steezy.__main__:main"
        ]
    },
)
