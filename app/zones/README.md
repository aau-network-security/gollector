# Zone files
Retrieves and processes zone files from different TLDs and sources.
The current set of supported retrieval methods are as follows:
- [CZDS](https://czds.icann.org/) REST API
- Over HTTPS (e.g. `dk`)  
- Over FTP (e.g. `.com` TLD)

Supports `gzip` unzipping, access over `SSH` and `ISO8859_1` (which can be easily extended with other similar features).  

## Run
Compile and run with golang:
```
go run app/zones/*.go --config config/zones.yml 
```

Build and run as follows
````
$ docker build -t zones -f app/zones/Dockerfile .
$ docker run -d \ 
  --name gollector-zones \ 
  -v config:/config \ 
  zones --config /config/zones.yml 
```
