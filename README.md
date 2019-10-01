# Gollector
Tool for the collection (and planned enhancement) of domain names from different sources.
The purpose of `gollector` is to enable the analysis of different vantage points of domain name collection, such as zone files, passive DNS logs and more.

## Components
`gollector` consists of various components, which can be ran independently of each other.
The core of the tool is a `cache` process that provides a gRPC api to the other components to insert entries in an underlying (PostgreSQL) database.
A set of collectors processes can run in parallel.
View the README files for more details about the components:
- [Cache](app/cache/README.md)     
- [Zone files](app/zones/README.md)
- [Passive DNS (Splunk) logs](app/splunk/README.md)
- [ENTRADA logs](app/entrada/README.md)

## How to configure
Each component is configure individually with a `.yml` configuration file.
In order to get started, copy one of the template configuration files in the `config/` directory.

## Running the tool
The tool can be compiled and run with Golang, or run using Docker containers.  

### Golang
- Golang (tested with version 1.13)
- A running PostgreSQL database 

### Docker-compose 
All components are dockerized and can be run with `docker-compose`.
Note that that the cache is expected to be running for any of the collectors to work, so the order in which to start the Docker containers matters.
The following is an example:
```
$ docker-compose build cache zones
$ docker-compose up -d cache
...
...
$ docker-compose up -d zones
```
