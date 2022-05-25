# How-to

## Pre-requisites

- Install docker
- Install docker-compose

## Import images

```
docker load < kms.tar 
docker load < postgres.tar 
```

## Run docker-compose

```
sudo docker-compose up
```

## Run a simple test

```
wget http://localhost:9998/objects/owned
```
