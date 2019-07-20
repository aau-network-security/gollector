# go-domains
A set of tools that are used to retrieve domain names from different sources, such as 
- [x] Zone file
    - [x] `.com` zone
    - [x] `.net` zone
    - [x] `.dk` zone
- [ ] DNS resolver logs
- [ ] CT logs

## Requirements
- Golang (tested with version 1.11)

## How to run
First, specify a YAML configuration file (see `/config/config.yml.template` for a template).
To retrieve zone files, execute the following:
```bash
$ go run app/zones/main.go --config <path to config.yml>   
```

### Docker
Build with Docker:
```bash
$ docker build -t go-domains -f app/zones/Dockerfile .
```
run with Docker (under the assumption that `config.yml` is located in the `./config` directory):
```bash
$ docker run go-domains -v config:/config go-domains --config /config/config.yml
```

#### Docker Compose
We also provide a Docker compose specification. 
The `docker-compose.yml` uses several environment variables, which must be declared in an `.env` file in the root of the project (see `docker-compose.yml` for the required environment variables).
After creating this file, run with
```bash
$ docker-compose up db 
``` 
followed by 
```bash
$ docker-compose up zones 
```
allowing the Postgres database to start before the zone retrieval container does.