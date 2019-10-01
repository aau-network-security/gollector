# Splunk
Retrieves passive DNS logs from [Splunk](https://www.splunk.com/).
There are no restriction on the source of these logs, but the collector was developed with university/organisation DNS traffic in mind.
For each `{ FQDN, query name}` tuple, the timestamp of its _first occurrence_ is stored. 

## Run
Compile and run with golang:
```
go run app/splunk/*.go --config config/splunk.yml 
```

Build and run as follows
````
$ docker build -t splunk -f app/splunk/Dockerfile .
$ docker run -d \ 
  --name gollector-splunk \ 
  -v config:/config \ 
  splunk --config /config/splunk.yml 
```
