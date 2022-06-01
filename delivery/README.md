# Create a delivery package

Note:
- This delivery procedure has been written for CATS. If you need to generate a
  docker with other parameters, please copy the `Dockerfile`, do not modify it.

## Pre-requisites

- Create a tag from main like that one: http://gitlab.cosmian.com/core/kms/-/tags/2.0.1

## Build the docker

From project root:

```
docker build . -f delivery/Dockerfile.cats --network=host -t  kms:2.0.1
```

Note:
- The docker is created using `--features=dev` because CATS is offline. So they
  can't use https version (communication with Let's Encrypt is not possible)

## Run the docker compose

```
cd delivery
sudo docker-compose up
```

Note:
- The Auth0 is disabled

Make sure it works as follow:

```
wget 127.0.0.1:9998/objects/owned
```

## Save the dockers

```
docker save kms:2.0.1 > kms.tar
docker save postgres > postgres.tar
```

## Package the delivry

```
zip -A delivery_`date +"%Y%m%d"`.zip kms.tar postgres.tar HOW-TO.md docker-compose.yml
```
