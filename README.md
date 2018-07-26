# AWSSEC

AWS S3 Bucket tool to check your buckets for misconfigurations and SSH Key Leaks in your github repos. AWSSEC check your github repositories using trufflehog to see if you included any passwords or ssh keys in your repos.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites
TruffleHog
Pip3
Python3
Boto3

```
Apt-get install python3
Apt -get install pip3
Pip install boto3
Git clone- https://github.com/rephric/awssec.git
Git clone- https://github.com/dxa4481/truffleHog.git or Pip install - trufflehog

```
### verify that AWSSEC is working

Testing AWSSEC

```
Awssec.py --help
```

## Built With

* [TruffleHog](https://github.com/dxa4481/truffleHog) - Check Git hub repos for keys
* [Python](https://www.python.org/) - Powered by Python
* [BOTO3](https://github.com/boto/boto3) - Amazon AWS API

## Authors

* **Zachary Estrella** - *Initial Idea* - [rephric](https://github.com/rephric)
* **Trevor Behrens** - *Contributor* - [tbehrens97](https://github.com/tbehrens97)


## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details

## Acknowledgments

* dxa4481 for TruffleHog
* Amazon for BOTO3
* Python




