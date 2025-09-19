![CrowdSec Logo](images/logo_crowdsec.png)

# CrowdSec Fastly Bouncer

## Developer guide

A simple guide to help you set up a local development environment and test the bouncer with a local CrowdSec instance.

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**

- [Local installation](#local-installation)
  - [Virtual environment](#virtual-environment)
  - [Install dependencies](#install-dependencies)
  - [Unit tests](#unit-tests)
- [Local tests with Fastly](#local-tests-with-fastly)
  - [Pre-requisites](#pre-requisites)
  - [Launch a CrowdSec container with docker compose](#launch-a-crowdsec-container-with-docker-compose)
  - [Use the bouncer](#use-the-bouncer)
    - [Generate a config file](#generate-a-config-file)
    - [Run the bouncer](#run-the-bouncer)
    - [Interact with the crowdsec container](#interact-with-the-crowdsec-container)
- [Update documentation table of contents](#update-documentation-table-of-contents)
- [Release process](#release-process)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->


## Local installation

### Virtual environment

```bash
pyenv install 3.12.0
pyenv local 3.12.0
python -m venv venv
source venv/bin/activate
```

### Install dependencies

```bash
python -m pip install --upgrade pip 
pip install -r requirements.txt
pip install -r requirements-dev.txt
python -m pip install -e .
```

### Unit tests

```bash
python -m unittest
```

## Local tests with Fastly

### Pre-requisites

You must have a [Fastly account](https://www.fastly.com/) and create at least one service with an API token.

### Launch a CrowdSec container with docker compose

In the `dev` folder, create a `.env` file based on the `.env.example` file.

Then, run the `docker-compose` setup:

```bash
docker compose up -d
```

Thanks to the `.env` file, a `FASTLY_BOUNCER` with the associated `BOUNCER_KEY` should be automatically created in your crowdsec container

### Use the bouncer

#### Generate a config file

First, generate a config file (from the root of the repository):

```bash
crowdsec-fastly-bouncer -g <FASTLY_TOKEN_1>,<FASTLY_TOKEN_2> -o dev/config.yaml
``` 

Edit it to add the `lapi_key` (the `BOUNCER_KEY` created previously) and the `lapi_url` (`http://localhost:8080/` if you are using the docker compose setup).

You can use the provided `dev/config.yaml.example` file as an example.

#### Run the bouncer

```bash
crowdsec-fastly-bouncer -c dev/config.yaml
```

#### Interact with the crowdsec container

Below are some examples of commands you can run in the crowdsec container to add/list/delete decisions.

```shell
docker exec -ti cs-fastly-crowdsec sh -c 'cscli decisions add --ip <SOME_IP> --duration 12m --type ban'
```

```shell
docker exec -ti cs-fastly-crowdsec sh -c 'cscli decisions delete --all'
```

```shell
docker exec -ti cs-fastly-crowdsec sh -c 'cscli decisions list --all'
```

```shell
docker exec -ti cs-fastly-crowdsec sh -c 'cscli decisions delete --ip <SOME_IP>'
```


## Update documentation table of contents

To update the table of contents in the documentation, you can use [the `doctoc` tool](https://github.com/thlorenz/doctoc).

First, install it:

```bash
npm install -g doctoc
```

Then, run it in the documentation folder:

```bash
doctoc dev/* --maxlevel 4
```


## Release process

We use [Semantic Versioning](https://semver.org/spec/v2.0.0.html) approach to determine the next version number of the library.


Once you are ready to release a new version, you should:

- Determine the next version number based on the changes made since the last release: `MAJOR.MINOR.PATCH`
- Update the [setup.cfg](../setup.cfg) file with the new version number.
- Commit the changes with a message like `chore(changelog) Prepare for release MAJOR.MINOR.PATCH`.
- Push the changes to the `main` branch.

&#9888; Pushing on the `main` branch will trigger the `release-drafter` workflow: a new release draft will be created or updated with the merged PRs from the last release.

&#9888; It will also trigger the `publish-docker-doc` workflow: `docker/README.md` will be updated in Docker HUB.

- Create a tag with the new version number: `git tag vMAJOR.MINOR.PATCH`
- Push the tag to GitHub: `git push origin vMAJOR.MINOR.PATCH`

- On GitHub, browse to the draft created by the `release-drafter` workflow and convert it into a real release:
  - Click on `Edit` and select the tag you just created in the `Tag version` dropdown.
  - Click on `Publish release` to trigger the release process.

&#9888; Publishing a release will trigger the `pypi_publish` workflow which will build and push the package to pypi.

&#9888; It will also trigger the `release_publish_docker-image` workflow which will build and push the docker image to Docker HUB.
 
