# Cache
Acts as a caching layer between the collectors and the underlying PostgreSQL database. 
It internally caches all values in the database and efficiently inserts new entries in the relational database under different tables.  

## Run
Compile and run with golang:
```
go run app/cache/*.go --config config/cache.yml 
```

Build and run as follows
````
$ docker build -t cache -f app/cache/Dockerfile .
$ docker run -d \ 
  --name gollector-cache \ 
  -v config:/config \ 
  cache --config /config/cache.yml 
```
