try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup
config = {
        'description': 'AwsSec',
        'author': 'Zachary Estrella & Trevor Behrens',
        'url': 'github.com',
        'download_url': 'github.com',
        'author_email': 'zjestrella1@gmail.com',
        'version': '1.0',
        'install_requires': ['nose', 'Click'],
        'packages': ['boto3', 'trufflehog'],
        'scripts': [],
        'name': 'AwsSec'
        }

setup(**config)
