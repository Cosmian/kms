# Create a delivery package

Note:

- This delivery procedure has been written for customers that need standalone KMS with no authentication and no HTTPS support.
If you need to generate a docker with other parameters, please copy the `Dockerfile`, do not modify it.

## Pre-requisites

- Create a tag from main like that one: <http://gitlab.cosmian.com/core/kms/-/tags/X.Y.Z>

Then:

```sh
docker checkout tags/X.Y.Z
```

## Build the docker

From project root:

```sh
docker build . -f delivery/Dockerfile.standalone --network=host -t kms:X.Y.Z
```

Note:

- The docker is created without any features, in order to make the KMS run in offline mode. So the customer can't use HTTPS (communication with Let's Encrypt is not possible)

## Run the docker compose

Update the `docker-compose.yaml` with the proper version number.

```sh
cd delivery
sudo docker-compose up
```

Note:

- The Auth0 is disabled

Make sure it works as follow:

```sh
wget 127.0.0.1:9998/objects/owned
wget 127.0.0.1:9998/version
```

## Save the dockers

```sh
docker save kms:X.Y.Z > kms.tar
docker save postgres > postgres.tar
```

## Package the delivery

```sh
zip -A delivery_`date +"%Y%m%d"`.zip kms.tar postgres.tar HOW-TO.md docker-compose.yml
```
