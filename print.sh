
ELA:

wget -O - http://packages.elasticsearch.org/GPG-KEY-elasticsearch | sudo apt-key add -


echo 'deb http://packages.elasticsearch.org/elasticsearch/1.1/debian stable main' | sudo tee /etc/apt/sources.list.d/elasticsearch.list

sudo apt-get update

sudo apt-get -y install elasticsearch=1.1.1

sudo nano /etc/elasticsearch/elasticsearch.yml

script.disable_dynamic: true

network.host: localhost

sudo service elasticsearch restart

sudo update-rc.d elasticsearch defaults 95 10

cd ~; wget https://download.elasticsearch.org/kibana/kibana/kibana-3.0.1.tar.gz

tar xvf kibana-3.0.1.tar.gz

sudo vi ~/kibana-3.0.1/config.js

  elasticsearch: "http://"+window.location.hostname+":80",

sudo mkdir -p /var/www/kibana3

sudo cp -R ~/kibana-3.0.1/* /var/www/kibana3/

sudo apt-get install nginx

cd ~; wget https://gist.githubusercontent.com/thisismitch/2205786838a6a5d61f55/raw/f91e06198a7c455925f6e3099e3ea7c186d0b263/nginx.conf


nano nginx.conf

server_name FQDN;
  root /var/www/kibana3;

sudo cp nginx.conf /etc/nginx/sites-available/default

sudo apt-get install apache2-utils

sudo htpasswd -c /etc/nginx/conf.d/kibana.myhost.org.htpasswd user
sudo service nginx restart

Install log:


echo 'deb http://packages.elasticsearch.org/logstash/1.4/debian stable main' | sudo tee /etc/apt/sources.list.d/logstash.list


sudo apt-get update


sudo apt-get install logstash=1.4.2-1-2c0f5a1

sudo mkdir -p /etc/pki/tls/certs
sudo mkdir /etc/pki/tls/private


cd /etc/pki/tls; sudo openssl req -x509 -batch -nodes -days 3650 -newkey rsa:2048 -keyout private/logstash-forwarder.key -out certs/logstash-forwarder.crt


Config Log:

sudo vi /etc/logstash/conf.d/01-lumberjack-input.conf


##########################
input {
  lumberjack {
    port => 5000
    type => "logs"
    ssl_certificate => "/etc/pki/tls/certs/logstash-forwarder.crt"
    ssl_key => "/etc/pki/tls/private/logstash-forwarder.key"
  }
}

###################

sudo vi /etc/logstash/conf.d/10-syslog.conf




filter {
  if [type] == "syslog" {
    grok {
      match => { "message" => "%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{DATA:syslog_program}(?:\[%{POSINT:syslog_pid}\])?: %{GREEDYDATA:syslog_message}" }
      add_field => [ "received_at", "%{@timestamp}" ]
      add_field => [ "received_from", "%{host}" ]
    }
    syslog_pri { }
    date {
      match => [ "syslog_timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
    }
  }
}




sudo vi /etc/logstash/conf.d/30-lumberjack-output.conf


output {
  elasticsearch { host => localhost }
  stdout { codec => rubydebug }
}


sudo service logstash restart





















scp /etc/pki/tls/certs/logstash-forwarder.crt user@server_private_IP:/tmp




echo 'deb http://packages.elasticsearch.org/logstashforwarder/debian stable main' | sudo tee /etc/apt/sources.list.d/logstashforwarder.list


sudo apt-get update
sudo apt-get install logstash-forwarder



wget https://assets.digitalocean.com/articles/logstash/logstash-forwarder_0.3.1_i386.deb
sudo dpkg -i logstash-forwarder_0.3.1_i386.deb




cd /etc/init.d/; sudo wget https://raw.github.com/elasticsearch/logstash-forwarder/master/logstash-forwarder.init -O logstash-forwarder
sudo chmod +x logstash-forwarder
sudo update-rc.d logstash-forwarder defaults




sudo mkdir -p /etc/pki/tls/certs
sudo cp /tmp/logstash-forwarder.crt /etc/pki/tls/certs/




sudo vi /etc/logstash-forwarder



{
  "network": {
    "servers": [ "logstash_server_private_IP:5000" ],
    "timeout": 15,
    "ssl ca": "/etc/pki/tls/certs/logstash-forwarder.crt"
  },
  "files": [
    {
      "paths": [
        "/var/log/syslog",
        "/var/log/auth.log"
       ],
      "fields": { "type": "syslog" }
    }
   ]
}




sudo service logstash-forwarder restart




