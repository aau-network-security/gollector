#CQL="DROP keyspace example;
#CREATE KEYSPACE example WITH replication = { 'class' : 'SimpleStrategy', 'replication_factor' : 1 };
#CREATE TABLE example.tweet(timeline text, id UUID, text text, PRIMARY KEY(id));
#CREATE INDEX on example.tweet(timeline);"

#echo batch_size_warn_threshold_in_kb: 1000 >> /etc/cassandra/cassandra.yaml
#echo batch_size_fail_threshold_in_kb: 1000 >> /etc/cassandra/cassandra.yaml
#
CQL="DROP keyspace domains;
CREATE KEYSPACE domains WITH replication = { 'class' : 'SimpleStrategy', 'replication_factor' : 1 };
CREATE TABLE IF NOT EXISTS domains.fqdns(id int, fqdn text, tld_id int, public_suffix_id int, apex_id int, PRIMARY KEY(id));
CREATE INDEX on domains.fqdns(fqdn);
CREATE TABLE IF NOT EXISTS domains.apexes(id int, apex text, tld_id int, public_suffix_id int, PRIMARY KEY(id));
CREATE INDEX on domains.apexes(apex);
CREATE TABLE IF NOT EXISTS domains.public_suffixes(id int, public_suffix text, tld_id int, PRIMARY KEY(id));
CREATE TABLE IF NOT EXISTS domains.tlds(id int, tld text, PRIMARY KEY(id));
CREATE TABLE IF NOT EXISTS domains.log_entries(id int, log_entry int, timestamp timestamp, is_precert boolean, certificate_id int, log_id int, stage_id int, PRIMARY KEY(id));
CREATE TABLE IF NOT EXISTS domains.certificates(id int, sha256_fingerprint text, raw text, PRIMARY KEY(id));
CREATE INDEX on domains.certificates(sha256_fingerprint);
CREATE TABLE IF NOT EXISTS domains.certificate_to_fqdns(id int, fqdn_id int, certificate_id int, PRIMARY KEY(id));
CREATE TABLE IF NOT EXISTS domains.logs(id int, url text, description text, PRIMARY KEY(id));
CREATE TABLE IF NOT EXISTS domains.stages(id int, measurement_id int, stage int, start_time timestamp, stop_time timestamp, PRIMARY KEY(id));
CREATE TABLE IF NOT EXISTS domains.measurements(id int, muid text, description text, host text, start_time timestamp, stop_time timestamp, PRIMARY KEY(id));"

#
#CQL="CREATE KEYSPACE batchtest WITH REPLICATION = {'class':'SimpleStrategy', 'replication_factor': 1};
#CREATE TABLE IF NOT EXISTS batchtest.users (
#userID int PRIMARY KEY,
#password varchar,
#name varchar
#);"
until echo $CQL | cqlsh; do
  echo "cqlsh: Cassandra is unavailable to initialize - will retry later"
  sleep 2
done &

exec /docker-entrypoint.sh "$@"