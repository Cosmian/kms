# How-to

## Pre-requisites

- Install docker
- Install docker-compose

## Import images

```sh
docker load < kms.tar
docker load < postgres.tar
```

## Run docker-compose

```sh
sudo docker-compose up
```

## Run a simple test

```sh
wget http://localhost:9998/objects/owned
```
