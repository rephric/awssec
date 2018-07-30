# AWSSEC

AWS S3 Bucket tool to check your buckets for misconfigurations and SSH Key Leaks in your github repos. AWSSEC check your github repositories using trufflehog to see if you included any passwords or ssh keys in your repos.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites
TruffleHog
Python3
pip3
Boto3

```
apt-get install python3
apt-get install pip3
pip install boto3
git clone https://github.com/rephric/awssec.git
git clone https://github.com/dxa4481/truffleHog.git OR pip install trufflehog

```
### verify that AWSSEC is working

Testing AWSSEC

```
Awssec.py --help
```

## Built With

* [TruffleHog](https://github.com/dxa4481/truffleHog) - Check Github repositories for exposed keys
* [Python](https://www.python.org/) - Python3
* [BOTO3](https://github.com/boto/boto3) - AWS API

## Authors

* **Zachary Estrella** - *Initial Idea* - [rephric](https://github.com/rephric)
* **Trevor Behrens** - *Contributor* - [tbehrens97](https://github.com/tbehrens97)
* **Vlad Dosters** - *Contributor* - [vladdoster](https://github.com/vladdoster)



## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details

## Acknowledgments

* dxa4481 for TruffleHog
* Amazon for Boto3
* Python3