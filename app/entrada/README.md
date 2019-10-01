# ENTRADA
[ENTRADA](https://entrada.sidnlabs.nl/) is a data collection framework developed by [SIDN](https://www.sidn.nl/en) operating at authoritative name servers of DNS registries.
It collects all DNS requests () between recursive DNS resolvers and the TLD authoritative name servers (i.e. the cache misses). 
This collector collects all unique FQDNs in this the resulting dataset, and their timestamp of the _first observation_ in the ENTRADA dataset.  

## Run
Compile and run with golang:
```
go run app/entrada/*.go --config config/entrada.yml 
```

Build and run as follows
````
$ docker build -t entrada -f app/entrada/Dockerfile .
$ docker run -d \ 
  --name gollector-entrada \ 
  -v config:/config \ 
  entrada --config /config/entrada.yml 
```
