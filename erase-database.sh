#!/bin/bash

docker stop infractory-postgres-1
docker rm infractory-postgres-1
docker volume rm infractory_postgres_data
systemctl stop nebula.service
systemctl disable nebula.service
docker swarm leave --force
