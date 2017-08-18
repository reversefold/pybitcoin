from setuptools import setup, find_packages

VERSION = '0.4.0'

setup(
    name='pybitcoin',
    version=VERSION,
    author='Justin Patrin',
    author_email='papercrane@reversefold.com',
    maintainer='Justin Patrin',
    maintainer_email='papercrane@reversefold.com',
    description='pybitcoin',
    long_description="""pybitcoin""",
    packages=find_packages(),
    url='https://github.com/reversefold/pybitcoin',
    install_requires=[
        'alembic',
        'ecdsa',
        'greenhouse',
        'netifaces',
        'psycopg2',
        'requests',
        'reversefold.util>=1.12.0',
        'sqlalchemy',
    ],
)
