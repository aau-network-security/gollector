# go-domains
A set of tools that are used to retrieve domain names from different sources, such as 
- [x] Zone file
    - [x] `.com` zone
    - [x] `.net` zone (or any zone that can be accessed via CZDS)
    - [x] `.dk` zone 
- [x] DNS resolver (i.e Splunk) logs 
- [x] CT logs

**NOTE** the state of the database is kept in memory by each app, and this state is not synchronized across different instances.
Therefore, it is NOT recommended to run multiple instances simultaniously, but rather suggest to run them sequentially.    

## Requirements
- Golang (tested with version 1.11)

## How to run
First, specify a YAML configuration file (see `/config/config.yml.template` for a template).
To retrieve zone files, execute the following:
```bash
$ go run app/zones/main.go --config <path to config.yml>   
$ go run app/ct/main.go --config <path to config.yml>   
$ go run app/splunk/main.go --config <path to config.yml>   
```

### Docker
Build with Docker:
```bash
$ docker build -t zones -f app/zones/Dockerfile .
$ docker build -t ct -f app/ct/Dockerfile .
$ docker build -t splunk -f app/splunk/Dockerfile .
```
run with Docker (under the assumption that `config.yml` is located in the `./config` directory):
```bash
$ docker run zones -v config:/config zones --config /config/config.yml
$ docker run ct -v config:/config ct --config /config/config.yml
$ docker run splunk -v config:/config splunk --config /config/config.yml
```

#### Docker Compose
We also provide a Docker compose specification. 
The `docker-compose.yml` uses several [environment variables](#required-environment-variables), which can be declared in an `.env` file in the root of the project, or set as exported environment variables.
After declaring them, run with
```bash
$ docker-compose up db 
``` 
followed by 
```bash
$ docker-compose up zones 
$ docker-compose up ct 
$ docker-compose up splunk 
```
allowing the Postgres database to start before the zone retrieval container does.

##### Required environment variables
```.env
POSTGRES_PASS=<password for db>
POSTGRES_PORT=<port of db>
DB_VOLUME=<directory in which database is stored persistently>
SSH_DIR=<directory of SSH key (used for SSH proxying)>
SPLUNK_DIR=<directory containing Splunk logs>

COM_FTP_PASS=<password for accessing .com FTP server>
CZDS_PASS=<password for accessing CZDS API>
DK_SSH_PASS=<password for SSH proxy to access DK zone file>
```