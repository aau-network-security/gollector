# Certificate Transparency
Retrieves the entries from all supported [known CT logs](https://www.certificate-transparency.org/known-logs), submitted _after_ a configured date.

## Run
Compile and run with golang:
```
go run app/ct/*.go --config config/ct.yml 
```

Build and run as follows
````
$ docker build -t ct -f app/ct/Dockerfile .
$ docker run -d \ 
  --name gollector-ct \ 
  -v config:/config \ 
  ct --config /config/ct.yml 
```
