from setuptools import setup

with open('README.md', 'r') as readme:
    readme = readme.read()


setup(
    name='smith_console',
    version='0.0.1',
    # keywords of your project that separated by comma ","
    keywords="smith hids server/console",
    description=readme,  # a conceise introduction of your project
    license='mit',
    url='',
    author='',
    author_email='',
    packages=['smith_console'],
    entry_points={"console_scripts": [
        'smith-console=smith_console.cli:console',
        'smith-server=smith_console.cli:server',
    ]},
    install_requires=["redis==2.10.6", "pyfiglet==0.7.6", "ipy==0.83"],
    platforms="any",
    classifiers=[
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: Implementation :: CPython",
    ],
    zip_safe=False,
)
