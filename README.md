# Kubernetes Ingress using kubectl plugin

With Deployments getting bigger and bigger, networking issues are becoming harder and harder to troubleshoot.

This guide will provide basic information on debugging access to your application via the ingress controller using the *ingress-nginx* kubectl plugin.
![Door](./background.jpeg?raw=true)

As of Kubernetes 1.12, custom plugins can be written for kubectl. The Ingress Community, specifically [alexkursell](https://github.com/alexkursell) has done a great job at creating a plugin to help us easily debug ingress issues.

In this tutorial, we will use minikube, but all the troubleshooting examples can be performed on any Kubernetes Cluster(1.12+) with an ingress-nginx deployment(0.23.0+).

## Requirements

In order to get started using this guide, the following must be installed:

- VirtualBox/KVM
- Minikube
- Kubectl
- VT-x/AMD-v virtualization must be enabled in BIOS
- Internet connection on first run

## Installation

The *ingress-nginx* plugin can be installed via **krew**, a kubectl plugin dependency manager. In order to install krew just follow the installation guide provided in https://github.com/kubernetes-sigs/krew.

Once you have krew installed, you can get info on and install the *ingress-nginx* plugin by performing the following:

```bash
$ kubectl krew info ingress-nginx
NAME: ingress-nginx
URI: https://github.com/kubernetes/ingress-nginx/releases/download/nginx-0.25.0/kubectl-ingress_nginx-linux-amd64.tar.gz
SHA256: 00c6d727a9a13405d7cb4ec73ac33a6f1621b01b6ad785a493299e159824d1e0
VERSION: v0.25.0
HOMEPAGE: https://kubernetes.github.io/ingress-nginx/kubectl-plugin/
DESCRIPTION: 
The official kubectl plugin for ingress-nginx.

$ kubectl krew install ingress-nginx
Updated the local copy of plugin index.
Installing plugin: ingress-nginx
Installed plugin: ingress-nginx
\
 | Use this plugin:
 | 	kubectl ingress-nginx
 | Documentation:
 | 	https://kubernetes.github.io/ingress-nginx/kubectl-plugin/
/
WARNING: You installed a plugin from the krew-index plugin repository.
   These plugins are not audited for security by the Krew maintainers.
   Run them at your own risk.
```

For more information on krew and kubectl plugins in general, checkout [Writing kubectl Plugins for Everyone: Develop, Package and Distribute from KubeCon Europe 2019](https://youtu.be/83ITOTsXsHU).


## Usage

First you must create a minikube cluster and enable the ingress controller. We can also verify that the ingress-nginx pods get generated.

```bash
$ minikube start
😄  minikube v1.6.2 on Ubuntu 18.04
✨  Selecting 'kvm2' driver from user configuration (alternates: [virtualbox none])
🔥  Creating kvm2 VM (CPUs=2, Memory=8000MB, Disk=20000MB) ...
🐳  Preparing Kubernetes v1.17.0 on Docker '19.03.5' ...
    ▪ apiserver.service-node-port-range=1-30000
🚜  Pulling images ...
🚀  Launching Kubernetes ... 
⌛  Waiting for cluster to come online ...
🏄  Done! kubectl is now configured to use "minikube"

$ minikube addons enable ingress
✅  ingress was successfully enabled

$ kubectl get pods -n kube-system | grep ingress
nginx-ingress-controller-6fc5bcc8c9-dznmc   0/1     ContainerCreating   0          24s
```

Now we can troubleshoot by running the *ingress-nginx* command directly from kubectl.

```bash
$ kubectl ingress-nginx --help
A kubectl plugin for inspecting your ingress-nginx deployments

Usage:
  ingress-nginx [command]

Available Commands:
  backends    Inspect the dynamic backend information of an ingress-nginx instance
  certs       Output the certificate data stored in an ingress-nginx pod
  conf        Inspect the generated nginx.conf
  exec        Execute a command inside an ingress-nginx pod
  general     Inspect the other dynamic ingress-nginx information
  help        Help about any command
  info        Show information about the ingress-nginx service
  ingresses   Provide a short summary of all of the ingress definitions
  lint        Inspect kubernetes resources for possible issues
  logs        Get the kubernetes logs for an ingress-nginx pod
  ssh         ssh into a running ingress-nginx pod

Flags:
      --as string                      Username to impersonate for the operation
      --as-group stringArray           Group to impersonate for the operation, this flag can be repeated to specify multiple groups.
      --cache-dir string               Default HTTP cache directory (default "/home/hendra/.kube/http-cache")
      --certificate-authority string   Path to a cert file for the certificate authority
      --client-certificate string      Path to a client certificate file for TLS
      --client-key string              Path to a client key file for TLS
      --cluster string                 The name of the kubeconfig cluster to use
      --context string                 The name of the kubeconfig context to use
  -h, --help                           help for ingress-nginx
      --insecure-skip-tls-verify       If true, the server's certificate will not be checked for validity. This will make your HTTPS connections insecure
      --kubeconfig string              Path to the kubeconfig file to use for CLI requests.
  -n, --namespace string               If present, the namespace scope for this CLI request
      --request-timeout string         The length of time to wait before giving up on a single server request. Non-zero values should contain a corresponding time unit (e.g. 1s, 2m, 3h). A value of zero means don't timeout requests. (default "0")
  -s, --server string                  The address and port of the Kubernetes API server
      --token string                   Bearer token for authentication to the API server
      --user string                    The name of the kubeconfig user to use

Use "ingress-nginx [command] --help" for more information about a command.
```

## Adding Ingress Resource for Testing

Let’s Quickly Create an Application, Service, and Ingress to use in this tutorial.

### Deploying an Application

Let’s deploy our application pods(containers), using deployments. More info on deployments can be found [here](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/).

```bash
$ kubectl apply -f deployment.yaml
deployment.apps/meow-echo created
```

### Expose pods via a Service

Here we expose the application on an internal IP of the cluster. For more information on services, see [here](https://kubernetes.io/docs/tutorials/kubernetes-basics/expose/expose-intro/).

```bash
$ kubectl apply -f service.yaml 
service/meow-svc created
```

### Create the Ingress Resource

This allows us to access the service meow-svc via the /meow path. Since we are using minikube and cats.com is our virtual host, so we must pass the host header to access the application.

```bash
$ kubectl apply -f ingress.yaml 
ingress.extensions/meow-ingress created

$ curl $(minikube ip)/meow -H "host: cats.com"


Hostname: meow-64cb7d9b78-xhftf

Pod Information:
	-no pod information available-

Server values:
	server_version=nginx: 1.12.2 - lua: 10010

Request Information:
	client_address=172.17.0.6
	method=GET
	real path=/meow
	query=
	request_version=1.1
	request_scheme=http
	request_uri=http://cats.com:8080/meow

Request Headers:
	accept=*/*
	host=cats.com
	user-agent=curl/7.58.0
	x-forwarded-for=192.168.39.1
	x-forwarded-host=cats.com
	x-forwarded-port=80
	x-forwarded-proto=http
	x-real-ip=192.168.39.1
	x-request-id=4c40a935448bb453446a106d20355211
	x-scheme=http

Request Body:
	-no body in request-
```

Here is the screenshot from browser:
![result](./result.png?raw=true)

## Debuggung

Now let’s get started on some debugging 🐛. We can take a look at some steps which can be taken to troubleshoot common ingress issues.

### Verify Deployments, Ingresses, and Backends

By Verifying Deployments, Ingresses and Backends, we can see if we actually setup things properly.

```bash
$ kubectl ingress-nginx ingresses -n default
INGRESS NAME   HOST+PATH       ADDRESSES        TLS   SERVICE    SERVICE PORT   ENDPOINTS
meow-ingress   cats.com/meow   192.168.39.143   NO    meow-svc   80             0

$ kubectl ingress-nginx backends -n kube-system --list
default-meow-svc-80
upstream-default-backend

$ kubectl ingress-nginx backends -n kube-system --backend default-meow-svc-80
{
  "endpoints": [
    {
      "address": "172.17.0.10",
      "port": "8080"
    },
    {
      "address": "172.17.0.9",
      "port": "8080"
    }
  ],
  "name": "default-meow-svc-80",
  "noServer": false,
  "port": 80,
  "secureCACert": {
    "caFilename": "",
    "caSha": "",
    "crlFileName": "",
    "crlSha": "",
    "secret": ""
  },
  "service": {
    "metadata": {
      "creationTimestamp": null
    },
    "spec": {
      "clusterIP": "10.96.176.179",
      "ports": [
        {
          "name": "http",
          "port": 80,
          "protocol": "TCP",
          "targetPort": 8080
        }
      ],
      "selector": {
        "app": "meow"
      },
      "sessionAffinity": "None",
      "type": "ClusterIP"
    },
    "status": {
      "loadBalancer": {}
    }
  },
  "sessionAffinityConfig": {
    "cookieSessionAffinity": {
      "name": ""
    },
    "mode": "",
    "name": ""
  },
  "sslPassthrough": false,
  "trafficShapingPolicy": {
    "cookie": "",
    "header": "",
    "headerValue": "",
    "weight": 0
  },
  "upstreamHashByConfig": {
    "upstream-hash-by-subset-size": 3
  }
}

$ kubectl ingress-nginx lint -n default
Checking ingresses...
Checking deployments...
```

First by checking the ingress resource, we can see if we have configured our ingress properly. We can also verify that specific backends are configured correctly.

Lastly, we can perform a lint, which checks to see if there are any potential configuration issues.

**Note**: For the backends command you will need to pass the namespace as well as the **--deployment** flag if your *ingress-nginx* deployment is not named *nginx-ingress-controller*.

### Check Logs

If there is a specific issue and we know the service and ingress resource are properly configured, we should go ahead and take a look at the logs. The logs will give specifics on issues processing an ingress resource.

```bash
$ curl $(minikube ip)/meow -H "host: cats.com"


Hostname: meow-64cb7d9b78-xhftf

Pod Information:
	-no pod information available-

Server values:
	server_version=nginx: 1.12.2 - lua: 10010

Request Information:
	client_address=172.17.0.6
	method=GET
	real path=/meow
	query=
	request_version=1.1
	request_scheme=http
	request_uri=http://cats.com:8080/meow

Request Headers:
	accept=*/*
	host=cats.com
	user-agent=curl/7.58.0
	x-forwarded-for=192.168.39.1
	x-forwarded-host=cats.com
	x-forwarded-port=80
	x-forwarded-proto=http
	x-real-ip=192.168.39.1
	x-request-id=4c40a935448bb453446a106d20355211
	x-scheme=http

Request Body:
	-no body in request-

$ kubectl ingress-nginx logs -n kube-system
-------------------------------------------------------------------------------
NGINX Ingress controller
  Release:       0.26.1
  Build:         git-2de5a893a
  Repository:    https://github.com/kubernetes/ingress-nginx
  nginx version: openresty/1.15.8.2

-------------------------------------------------------------------------------

W0101 19:40:03.892473      10 flags.go:243] SSL certificate chain completion is disabled (--enable-ssl-chain-completion=false)
W0101 19:40:03.892563      10 client_config.go:541] Neither --kubeconfig nor --master was specified.  Using the inClusterConfig.  This might not work.
I0101 19:40:03.892740      10 main.go:182] Creating API client for https://10.96.0.1:443
I0101 19:40:03.902282      10 main.go:226] Running in Kubernetes cluster version v1.17 (v1.17.0) - git (clean) commit 70132b0f130acc0bed193d9ba59dd186f0e634cf - platform linux/amd64
I0101 19:40:03.965653      10 main.go:101] SSL fake certificate created /etc/ingress-controller/ssl/default-fake-certificate.pem
I0101 19:40:03.996551      10 nginx.go:263] Starting NGINX Ingress controller
I0101 19:40:04.029227      10 event.go:255] Event(v1.ObjectReference{Kind:"ConfigMap", Namespace:"kube-system", Name:"nginx-load-balancer-conf", UID:"b9dd843f-c531-488d-8415-435dc20547de", APIVersion:"v1", ResourceVersion:"8902", FieldPath:""}): type: 'Normal' reason: 'CREATE' ConfigMap kube-system/nginx-load-balancer-conf
I0101 19:40:04.030084      10 event.go:255] Event(v1.ObjectReference{Kind:"ConfigMap", Namespace:"kube-system", Name:"udp-services", UID:"6078514a-d0dd-4afa-99d1-b35860bd59b2", APIVersion:"v1", ResourceVersion:"8904", FieldPath:""}): type: 'Normal' reason: 'CREATE' ConfigMap kube-system/udp-services
I0101 19:40:04.030232      10 event.go:255] Event(v1.ObjectReference{Kind:"ConfigMap", Namespace:"kube-system", Name:"tcp-services", UID:"f290e5d8-db42-43a7-9be6-17e12aa0718d", APIVersion:"v1", ResourceVersion:"8903", FieldPath:""}): type: 'Normal' reason: 'CREATE' ConfigMap kube-system/tcp-services
I0101 19:40:05.198694      10 nginx.go:307] Starting NGINX process
I0101 19:40:05.199422      10 leaderelection.go:241] attempting to acquire leader lease  kube-system/ingress-controller-leader-nginx...
I0101 19:40:05.200649      10 controller.go:134] Configuration changes detected, backend reload required.
I0101 19:40:05.234354      10 leaderelection.go:251] successfully acquired lease kube-system/ingress-controller-leader-nginx
I0101 19:40:05.236244      10 status.go:86] new leader elected: nginx-ingress-controller-6fc5bcc8c9-dznmc
I0101 19:40:05.305955      10 controller.go:150] Backend successfully reloaded.
I0101 19:40:05.306011      10 controller.go:159] Initial sync, sleeping for 1 second.
W0101 19:53:07.042350      10 controller.go:920] Service "default/meow-svc" does not have any active Endpoint.
I0101 19:53:07.042414      10 controller.go:134] Configuration changes detected, backend reload required.
I0101 19:53:07.043599      10 event.go:255] Event(v1.ObjectReference{Kind:"Ingress", Namespace:"default", Name:"meow-ingress", UID:"77a6d162-92d4-4cf4-88ef-331b9c82c98a", APIVersion:"networking.k8s.io/v1beta1", ResourceVersion:"11211", FieldPath:""}): type: 'Normal' reason: 'CREATE' Ingress default/meow-ingress
I0101 19:53:07.108917      10 controller.go:150] Backend successfully reloaded.
192.168.39.1 - - [01/Jan/2020:19:53:40 +0000] "GET /meow HTTP/1.1" 503 203 "-" "curl/7.58.0" 76 0.000 [default-meow-svc-80] [] - - - - bfc55524ba8e6d172899001e24bfcabf
I0101 19:54:05.262515      10 status.go:274] updating Ingress default/meow-ingress status from [] to [{192.168.39.143 }]
W0101 19:54:05.270778      10 controller.go:920] Service "default/meow-svc" does not have any active Endpoint.
I0101 19:54:05.272429      10 event.go:255] Event(v1.ObjectReference{Kind:"Ingress", Namespace:"default", Name:"meow-ingress", UID:"77a6d162-92d4-4cf4-88ef-331b9c82c98a", APIVersion:"networking.k8s.io/v1beta1", ResourceVersion:"11345", FieldPath:""}): type: 'Normal' reason: 'UPDATE' Ingress default/meow-ingress
192.168.39.1 - - [01/Jan/2020:19:55:14 +0000] "GET /meow HTTP/1.1" 503 203 "-" "curl/7.58.0" 76 0.000 [default-meow-svc-80] [] - - - - 7ecb47f07658936ed23d83fd7f25a18c
192.168.39.1 - - [01/Jan/2020:19:56:07 +0000] "GET /meow HTTP/1.1" 503 203 "-" "curl/7.58.0" 76 0.000 [default-meow-svc-80] [] - - - - 0e6519527c23b130f98aa0875486d2e2
192.168.39.1 - - [01/Jan/2020:20:10:52 +0000] "GET /meow HTTP/1.1" 200 617 "-" "curl/7.58.0" 76 0.001 [default-meow-svc-80] [] 172.17.0.10:8080 617 0.001 200 4c40a935448bb453446a106d20355211
```

This is essentially the same function as checking the logs output by the *ingress-nginx* pods.

We send a curl and then check the logs to see if everything looks good. As you can see there is information on the backend being loaded successfully, as well as the curl going through. We can use these logs to make sure that our ingress was loaded properly as well as to see if traffic is going through.

### Check the NGINX Config

We can examine the nginx configuration to see if all directives and paths are configured correctly. We can use the {nginx documentation](http://nginx.org/en/docs/) to see what the directives and variables do.

```bash
$ kubectl ingress-nginx conf -n kube-system

# Configuration checksum: 9663161570305145270

# setup custom paths that do not require root access
pid /tmp/nginx.pid;

daemon off;

worker_processes 2;

worker_rlimit_nofile 523264;

worker_shutdown_timeout 240s ;

events {
	multi_accept        on;
	worker_connections  16384;
	use                 epoll;
}

http {
	lua_package_path "/etc/nginx/lua/?.lua;;";
	
	lua_shared_dict balancer_ewma 10M;
	lua_shared_dict balancer_ewma_last_touched_at 10M;
	lua_shared_dict balancer_ewma_locks 1M;
	lua_shared_dict certificate_data 20M;
	lua_shared_dict certificate_servers 5M;
	lua_shared_dict configuration_data 20M;
	
	init_by_lua_block {
		collectgarbage("collect")
		
		local lua_resty_waf = require("resty.waf")
		lua_resty_waf.init()
		
		-- init modules
		local ok, res
		
		ok, res = pcall(require, "lua_ingress")
		if not ok then
		error("require failed: " .. tostring(res))
		else
		lua_ingress = res
		lua_ingress.set_config({
			use_forwarded_headers = false,
			is_ssl_passthrough_enabled = false,
			http_redirect_code = 308,
		listen_ports = { ssl_proxy = "442", https = "443" },
			
			hsts = false,
			hsts_max_age = 15724800,
			hsts_include_subdomains = true,
			hsts_preload = false,
		})
		end
		
		ok, res = pcall(require, "configuration")
		if not ok then
		error("require failed: " .. tostring(res))
		else
		configuration = res
		end
		
		ok, res = pcall(require, "balancer")
		if not ok then
		error("require failed: " .. tostring(res))
		else
		balancer = res
		end
		
		ok, res = pcall(require, "monitor")
		if not ok then
		error("require failed: " .. tostring(res))
		else
		monitor = res
		end
		
		ok, res = pcall(require, "certificate")
		if not ok then
		error("require failed: " .. tostring(res))
		else
		certificate = res
		end
		
		ok, res = pcall(require, "plugins")
		if not ok then
		error("require failed: " .. tostring(res))
		else
		plugins = res
		end
		-- load all plugins that'll be used here
	plugins.init({})
	}
	
	init_worker_by_lua_block {
		lua_ingress.init_worker()
		balancer.init_worker()
		
		monitor.init_worker()
		
		plugins.run()
	}
	
	geoip_country       /etc/nginx/geoip/GeoIP.dat;
	geoip_city          /etc/nginx/geoip/GeoLiteCity.dat;
	geoip_org           /etc/nginx/geoip/GeoIPASNum.dat;
	geoip_proxy_recursive on;
	
	aio                 threads;
	aio_write           on;
	
	tcp_nopush          on;
	tcp_nodelay         on;
	
	log_subrequest      on;
	
	reset_timedout_connection on;
	
	keepalive_timeout  75s;
	keepalive_requests 100;
	
	client_body_temp_path           /tmp/client-body;
	fastcgi_temp_path               /tmp/fastcgi-temp;
	proxy_temp_path                 /tmp/proxy-temp;
	ajp_temp_path                   /tmp/ajp-temp;
	
	client_header_buffer_size       1k;
	client_header_timeout           60s;
	large_client_header_buffers     4 8k;
	client_body_buffer_size         8k;
	client_body_timeout             60s;
	
	http2_max_field_size            4k;
	http2_max_header_size           16k;
	http2_max_requests              1000;
	
	types_hash_max_size             2048;
	server_names_hash_max_size      1024;
	server_names_hash_bucket_size   32;
	map_hash_bucket_size            128;
	
	proxy_headers_hash_max_size     512;
	proxy_headers_hash_bucket_size  64;
	
	variables_hash_bucket_size      128;
	variables_hash_max_size         2048;
	
	underscores_in_headers          off;
	ignore_invalid_headers          on;
	
	limit_req_status                503;
	limit_conn_status               503;
	
	include /etc/nginx/mime.types;
	default_type text/html;
	
	gzip on;
	gzip_comp_level 5;
	gzip_http_version 1.1;
	gzip_min_length 256;
	gzip_types application/atom+xml application/javascript application/x-javascript application/json application/rss+xml application/vnd.ms-fontobject application/x-font-ttf application/x-web-app-manifest+json application/xhtml+xml application/xml font/opentype image/svg+xml image/x-icon text/css text/javascript text/plain text/x-component;
	gzip_proxied any;
	gzip_vary on;
	
	# Custom headers for response
	
	server_tokens on;
	
	# disable warnings
	uninitialized_variable_warn off;
	
	# Additional available variables:
	# $namespace
	# $ingress_name
	# $service_name
	# $service_port
	log_format upstreaminfo '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" $request_length $request_time [$proxy_upstream_name] [$proxy_alternative_upstream_name] $upstream_addr $upstream_response_length $upstream_response_time $upstream_status $req_id';
	
	map $request_uri $loggable {
		
		default 1;
	}
	
	access_log /var/log/nginx/access.log upstreaminfo  if=$loggable;
	
	error_log  /var/log/nginx/error.log notice;
	
	resolver 10.96.0.10 valid=30s ipv6=off;
	
	# See https://www.nginx.com/blog/websocket-nginx
	map $http_upgrade $connection_upgrade {
		default          upgrade;
		
		# See http://nginx.org/en/docs/http/ngx_http_upstream_module.html#keepalive
		''               '';
		
	}
	
	# Reverse proxies can detect if a client provides a X-Request-ID header, and pass it on to the backend server.
	# If no such header is provided, it can provide a random value.
	map $http_x_request_id $req_id {
		default   $http_x_request_id;
		
		""        $request_id;
		
	}
	
	# Create a variable that contains the literal $ character.
	# This works because the geo module will not resolve variables.
	geo $literal_dollar {
		default "$";
	}
	
	server_name_in_redirect off;
	port_in_redirect        off;
	
	ssl_protocols TLSv1.2;
	
	ssl_early_data off;
	
	# turn on session caching to drastically improve performance
	
	ssl_session_cache builtin:1000 shared:SSL:10m;
	ssl_session_timeout 10m;
	
	# allow configuring ssl session tickets
	ssl_session_tickets on;
	
	# slightly reduce the time-to-first-byte
	ssl_buffer_size 4k;
	
	# allow configuring custom ssl ciphers
	ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256';
	ssl_prefer_server_ciphers on;
	
	ssl_ecdh_curve auto;
	
	# PEM sha: 3ebf53027401e48f74b387875ff97cf5666da388
	ssl_certificate     /etc/ingress-controller/ssl/default-fake-certificate.pem;
	ssl_certificate_key /etc/ingress-controller/ssl/default-fake-certificate.pem;
	
	proxy_ssl_session_reuse on;
	
	upstream upstream_balancer {
		### Attention!!!
		#
		# We no longer create "upstream" section for every backend.
		# Backends are handled dynamically using Lua. If you would like to debug
		# and see what backends ingress-nginx has in its memory you can
		# install our kubectl plugin https://kubernetes.github.io/ingress-nginx/kubectl-plugin.
		# Once you have the plugin you can use "kubectl ingress-nginx backends" command to
		# inspect current backends.
		#
		###
		
		server 0.0.0.1; # placeholder
		
		balancer_by_lua_block {
			balancer.balance()
		}
		
		keepalive 32;
		
		keepalive_timeout  60s;
		keepalive_requests 100;
		
	}
	
	# Cache for internal auth checks
	proxy_cache_path /tmp/nginx-cache-auth levels=1:2 keys_zone=auth_cache:10m max_size=128m inactive=30m use_temp_path=off;
	
	# Global filters
	
	## start server _
	server {
		server_name _ ;
		
		listen 80 default_server reuseport backlog=511 ;
		listen 443 default_server reuseport backlog=511 ssl http2 ;
		
		set $proxy_upstream_name "-";
		
		ssl_certificate_by_lua_block {
			certificate.call()
		}
		
		location / {
			
			set $namespace      "";
			set $ingress_name   "";
			set $service_name   "";
			set $service_port   "";
			set $location_path  "/";
			
			rewrite_by_lua_block {
				lua_ingress.rewrite({
					force_ssl_redirect = false,
					ssl_redirect = false,
					force_no_ssl_redirect = false,
					use_port_in_redirects = false,
				})
				balancer.rewrite()
				plugins.run()
			}
			
			header_filter_by_lua_block {
				
				plugins.run()
			}
			body_filter_by_lua_block {
				
			}
			
			log_by_lua_block {
				
				balancer.log()
				
				monitor.call()
				
				plugins.run()
			}
			
			access_log off;
			
			port_in_redirect off;
			
			set $balancer_ewma_score -1;
			set $proxy_upstream_name "upstream-default-backend";
			set $proxy_host          $proxy_upstream_name;
			set $pass_access_scheme  $scheme;
			set $pass_server_port    $server_port;
			set $best_http_host      $http_host;
			set $pass_port           $pass_server_port;
			
			set $proxy_alternative_upstream_name "";
			
			client_max_body_size                    1m;
			
			proxy_set_header Host                   $best_http_host;
			
			# Pass the extracted client certificate to the backend
			
			# Allow websocket connections
			proxy_set_header                        Upgrade           $http_upgrade;
			
			proxy_set_header                        Connection        $connection_upgrade;
			
			proxy_set_header X-Request-ID           $req_id;
			proxy_set_header X-Real-IP              $remote_addr;
			
			proxy_set_header X-Forwarded-For        $remote_addr;
			
			proxy_set_header X-Forwarded-Host       $best_http_host;
			proxy_set_header X-Forwarded-Port       $pass_port;
			proxy_set_header X-Forwarded-Proto      $pass_access_scheme;
			
			proxy_set_header X-Scheme               $pass_access_scheme;
			
			# Pass the original X-Forwarded-For
			proxy_set_header X-Original-Forwarded-For $http_x_forwarded_for;
			
			# mitigate HTTPoxy Vulnerability
			# https://www.nginx.com/blog/mitigating-the-httpoxy-vulnerability-with-nginx/
			proxy_set_header Proxy                  "";
			
			# Custom headers to proxied server
			
			proxy_connect_timeout                   5s;
			proxy_send_timeout                      60s;
			proxy_read_timeout                      60s;
			
			proxy_buffering                         off;
			proxy_buffer_size                       4k;
			proxy_buffers                           4 4k;
			
			proxy_max_temp_file_size                1024m;
			
			proxy_request_buffering                 on;
			proxy_http_version                      1.1;
			
			proxy_cookie_domain                     off;
			proxy_cookie_path                       off;
			
			# In case of errors try the next upstream server before returning an error
			proxy_next_upstream                     error timeout;
			proxy_next_upstream_timeout             0;
			proxy_next_upstream_tries               3;
			
			proxy_pass http://upstream_balancer;
			
			proxy_redirect                          off;
			
		}
		
		# health checks in cloud providers require the use of port 80
		location /healthz {
			
			access_log off;
			return 200;
		}
		
		# this is required to avoid error if nginx is being monitored
		# with an external software (like sysdig)
		location /nginx_status {
			
			allow 127.0.0.1;
			
			deny all;
			
			access_log off;
			stub_status on;
		}
		
	}
	## end server _
	
	## start server cats.com
	server {
		server_name cats.com ;
		
		listen 80  ;
		listen 443  ssl http2 ;
		
		set $proxy_upstream_name "-";
		
		ssl_certificate_by_lua_block {
			certificate.call()
		}
		
		location /meow {
			
			set $namespace      "default";
			set $ingress_name   "meow-ingress";
			set $service_name   "meow-svc";
			set $service_port   "80";
			set $location_path  "/meow";
			
			rewrite_by_lua_block {
				lua_ingress.rewrite({
					force_ssl_redirect = false,
					ssl_redirect = true,
					force_no_ssl_redirect = false,
					use_port_in_redirects = false,
				})
				balancer.rewrite()
				plugins.run()
			}
			
			header_filter_by_lua_block {
				
				plugins.run()
			}
			body_filter_by_lua_block {
				
			}
			
			log_by_lua_block {
				
				balancer.log()
				
				monitor.call()
				
				plugins.run()
			}
			
			port_in_redirect off;
			
			set $balancer_ewma_score -1;
			set $proxy_upstream_name "default-meow-svc-80";
			set $proxy_host          $proxy_upstream_name;
			set $pass_access_scheme  $scheme;
			set $pass_server_port    $server_port;
			set $best_http_host      $http_host;
			set $pass_port           $pass_server_port;
			
			set $proxy_alternative_upstream_name "";
			
			client_max_body_size                    1m;
			
			proxy_set_header Host                   $best_http_host;
			
			# Pass the extracted client certificate to the backend
			
			# Allow websocket connections
			proxy_set_header                        Upgrade           $http_upgrade;
			
			proxy_set_header                        Connection        $connection_upgrade;
			
			proxy_set_header X-Request-ID           $req_id;
			proxy_set_header X-Real-IP              $remote_addr;
			
			proxy_set_header X-Forwarded-For        $remote_addr;
			
			proxy_set_header X-Forwarded-Host       $best_http_host;
			proxy_set_header X-Forwarded-Port       $pass_port;
			proxy_set_header X-Forwarded-Proto      $pass_access_scheme;
			
			proxy_set_header X-Scheme               $pass_access_scheme;
			
			# Pass the original X-Forwarded-For
			proxy_set_header X-Original-Forwarded-For $http_x_forwarded_for;
			
			# mitigate HTTPoxy Vulnerability
			# https://www.nginx.com/blog/mitigating-the-httpoxy-vulnerability-with-nginx/
			proxy_set_header Proxy                  "";
			
			# Custom headers to proxied server
			
			proxy_connect_timeout                   5s;
			proxy_send_timeout                      60s;
			proxy_read_timeout                      60s;
			
			proxy_buffering                         off;
			proxy_buffer_size                       4k;
			proxy_buffers                           4 4k;
			
			proxy_max_temp_file_size                1024m;
			
			proxy_request_buffering                 on;
			proxy_http_version                      1.1;
			
			proxy_cookie_domain                     off;
			proxy_cookie_path                       off;
			
			# In case of errors try the next upstream server before returning an error
			proxy_next_upstream                     error timeout;
			proxy_next_upstream_timeout             0;
			proxy_next_upstream_tries               3;
			
			proxy_pass http://upstream_balancer;
			
			proxy_redirect                          off;
			
		}
		
		location / {
			
			set $namespace      "";
			set $ingress_name   "";
			set $service_name   "";
			set $service_port   "";
			set $location_path  "/";
			
			rewrite_by_lua_block {
				lua_ingress.rewrite({
					force_ssl_redirect = false,
					ssl_redirect = true,
					force_no_ssl_redirect = false,
					use_port_in_redirects = false,
				})
				balancer.rewrite()
				plugins.run()
			}
			
			header_filter_by_lua_block {
				
				plugins.run()
			}
			body_filter_by_lua_block {
				
			}
			
			log_by_lua_block {
				
				balancer.log()
				
				monitor.call()
				
				plugins.run()
			}
			
			port_in_redirect off;
			
			set $balancer_ewma_score -1;
			set $proxy_upstream_name "upstream-default-backend";
			set $proxy_host          $proxy_upstream_name;
			set $pass_access_scheme  $scheme;
			set $pass_server_port    $server_port;
			set $best_http_host      $http_host;
			set $pass_port           $pass_server_port;
			
			set $proxy_alternative_upstream_name "";
			
			client_max_body_size                    1m;
			
			proxy_set_header Host                   $best_http_host;
			
			# Pass the extracted client certificate to the backend
			
			# Allow websocket connections
			proxy_set_header                        Upgrade           $http_upgrade;
			
			proxy_set_header                        Connection        $connection_upgrade;
			
			proxy_set_header X-Request-ID           $req_id;
			proxy_set_header X-Real-IP              $remote_addr;
			
			proxy_set_header X-Forwarded-For        $remote_addr;
			
			proxy_set_header X-Forwarded-Host       $best_http_host;
			proxy_set_header X-Forwarded-Port       $pass_port;
			proxy_set_header X-Forwarded-Proto      $pass_access_scheme;
			
			proxy_set_header X-Scheme               $pass_access_scheme;
			
			# Pass the original X-Forwarded-For
			proxy_set_header X-Original-Forwarded-For $http_x_forwarded_for;
			
			# mitigate HTTPoxy Vulnerability
			# https://www.nginx.com/blog/mitigating-the-httpoxy-vulnerability-with-nginx/
			proxy_set_header Proxy                  "";
			
			# Custom headers to proxied server
			
			proxy_connect_timeout                   5s;
			proxy_send_timeout                      60s;
			proxy_read_timeout                      60s;
			
			proxy_buffering                         off;
			proxy_buffer_size                       4k;
			proxy_buffers                           4 4k;
			
			proxy_max_temp_file_size                1024m;
			
			proxy_request_buffering                 on;
			proxy_http_version                      1.1;
			
			proxy_cookie_domain                     off;
			proxy_cookie_path                       off;
			
			# In case of errors try the next upstream server before returning an error
			proxy_next_upstream                     error timeout;
			proxy_next_upstream_timeout             0;
			proxy_next_upstream_tries               3;
			
			proxy_pass http://upstream_balancer;
			
			proxy_redirect                          off;
			
		}
		
	}
	## end server cats.com
	
	# backend for when default-backend-service is not configured or it does not have endpoints
	server {
		listen 8181 default_server reuseport backlog=511;
		
		set $proxy_upstream_name "internal";
		
		access_log off;
		
		location / {
			return 404;
		}
	}
	
	# default server, used for NGINX healthcheck and access to nginx stats
	server {
		listen 127.0.0.1:10246;
		set $proxy_upstream_name "internal";
		
		keepalive_timeout 0;
		gzip off;
		
		access_log off;
		
		location /healthz {
			return 200;
		}
		
		location /is-dynamic-lb-initialized {
			content_by_lua_block {
				local configuration = require("configuration")
				local backend_data = configuration.get_backends_data()
				if not backend_data then
				ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
				return
				end
				
				ngx.say("OK")
				ngx.exit(ngx.HTTP_OK)
			}
		}
		
		location /nginx_status {
			stub_status on;
		}
		
		location /configuration {
			client_max_body_size                    21m;
			client_body_buffer_size                 21m;
			proxy_buffering                         off;
			
			content_by_lua_block {
				configuration.call()
			}
		}
		
		location / {
			content_by_lua_block {
				ngx.exit(ngx.HTTP_NOT_FOUND)
			}
		}
	}
}

stream {
	lua_package_cpath "/usr/local/lib/lua/?.so;/usr/lib/lua-platform-path/lua/5.1/?.so;;";
	lua_package_path "/etc/nginx/lua/?.lua;/etc/nginx/lua/vendor/?.lua;/usr/local/lib/lua/?.lua;;";
	
	lua_shared_dict tcp_udp_configuration_data 5M;
	
	init_by_lua_block {
		collectgarbage("collect")
		
		-- init modules
		local ok, res
		
		ok, res = pcall(require, "configuration")
		if not ok then
		error("require failed: " .. tostring(res))
		else
		configuration = res
		end
		
		ok, res = pcall(require, "tcp_udp_configuration")
		if not ok then
		error("require failed: " .. tostring(res))
		else
		tcp_udp_configuration = res
		end
		
		ok, res = pcall(require, "tcp_udp_balancer")
		if not ok then
		error("require failed: " .. tostring(res))
		else
		tcp_udp_balancer = res
		end
	}
	
	init_worker_by_lua_block {
		tcp_udp_balancer.init_worker()
	}
	
	lua_add_variable $proxy_upstream_name;
	
	log_format log_stream [$time_local] $protocol $status $bytes_sent $bytes_received $session_time;
	
	access_log /var/log/nginx/access.log log_stream ;
	
	error_log  /var/log/nginx/error.log;
	
	upstream upstream_balancer {
		server 0.0.0.1:1234; # placeholder
		
		balancer_by_lua_block {
			tcp_udp_balancer.balance()
		}
	}
	
	server {
		listen 127.0.0.1:10247;
		
		access_log off;
		
		content_by_lua_block {
			tcp_udp_configuration.call()
		}
	}
	
	# TCP services
	
	# UDP services
	
}

$ kubectl ingress-nginx conf -n kube-system --host cats.com
	server {
		server_name cats.com ;
		
		listen 80  ;
		listen 443  ssl http2 ;
		
		set $proxy_upstream_name "-";
		
		ssl_certificate_by_lua_block {
			certificate.call()
		}
		
		location /meow {
			
			set $namespace      "default";
			set $ingress_name   "meow-ingress";
			set $service_name   "meow-svc";
			set $service_port   "80";
			set $location_path  "/meow";
			
			rewrite_by_lua_block {
				lua_ingress.rewrite({
					force_ssl_redirect = false,
					ssl_redirect = true,
					force_no_ssl_redirect = false,
					use_port_in_redirects = false,
				})
				balancer.rewrite()
				plugins.run()
			}
			
			header_filter_by_lua_block {
				
				plugins.run()
			}
			body_filter_by_lua_block {
				
			}
			
			log_by_lua_block {
				
				balancer.log()
				
				monitor.call()
				
				plugins.run()
			}
			
			port_in_redirect off;
			
			set $balancer_ewma_score -1;
			set $proxy_upstream_name "default-meow-svc-80";
			set $proxy_host          $proxy_upstream_name;
			set $pass_access_scheme  $scheme;
			set $pass_server_port    $server_port;
			set $best_http_host      $http_host;
			set $pass_port           $pass_server_port;
			
			set $proxy_alternative_upstream_name "";
			
			client_max_body_size                    1m;
			
			proxy_set_header Host                   $best_http_host;
			
			# Pass the extracted client certificate to the backend
			
			# Allow websocket connections
			proxy_set_header                        Upgrade           $http_upgrade;
			
			proxy_set_header                        Connection        $connection_upgrade;
			
			proxy_set_header X-Request-ID           $req_id;
			proxy_set_header X-Real-IP              $remote_addr;
			
			proxy_set_header X-Forwarded-For        $remote_addr;
			
			proxy_set_header X-Forwarded-Host       $best_http_host;
			proxy_set_header X-Forwarded-Port       $pass_port;
			proxy_set_header X-Forwarded-Proto      $pass_access_scheme;
			
			proxy_set_header X-Scheme               $pass_access_scheme;
			
			# Pass the original X-Forwarded-For
			proxy_set_header X-Original-Forwarded-For $http_x_forwarded_for;
			
			# mitigate HTTPoxy Vulnerability
			# https://www.nginx.com/blog/mitigating-the-httpoxy-vulnerability-with-nginx/
			proxy_set_header Proxy                  "";
			
			# Custom headers to proxied server
			
			proxy_connect_timeout                   5s;
			proxy_send_timeout                      60s;
			proxy_read_timeout                      60s;
			
			proxy_buffering                         off;
			proxy_buffer_size                       4k;
			proxy_buffers                           4 4k;
			
			proxy_max_temp_file_size                1024m;
			
			proxy_request_buffering                 on;
			proxy_http_version                      1.1;
			
			proxy_cookie_domain                     off;
			proxy_cookie_path                       off;
			
			# In case of errors try the next upstream server before returning an error
			proxy_next_upstream                     error timeout;
			proxy_next_upstream_timeout             0;
			proxy_next_upstream_tries               3;
			
			proxy_pass http://upstream_balancer;
			
			proxy_redirect                          off;
			
		}
		
		location / {
			
			set $namespace      "";
			set $ingress_name   "";
			set $service_name   "";
			set $service_port   "";
			set $location_path  "/";
			
			rewrite_by_lua_block {
				lua_ingress.rewrite({
					force_ssl_redirect = false,
					ssl_redirect = true,
					force_no_ssl_redirect = false,
					use_port_in_redirects = false,
				})
				balancer.rewrite()
				plugins.run()
			}
			
			header_filter_by_lua_block {
				
				plugins.run()
			}
			body_filter_by_lua_block {
				
			}
			
			log_by_lua_block {
				
				balancer.log()
				
				monitor.call()
				
				plugins.run()
			}
			
			port_in_redirect off;
			
			set $balancer_ewma_score -1;
			set $proxy_upstream_name "upstream-default-backend";
			set $proxy_host          $proxy_upstream_name;
			set $pass_access_scheme  $scheme;
			set $pass_server_port    $server_port;
			set $best_http_host      $http_host;
			set $pass_port           $pass_server_port;
			
			set $proxy_alternative_upstream_name "";
			
			client_max_body_size                    1m;
			
			proxy_set_header Host                   $best_http_host;
			
			# Pass the extracted client certificate to the backend
			
			# Allow websocket connections
			proxy_set_header                        Upgrade           $http_upgrade;
			
			proxy_set_header                        Connection        $connection_upgrade;
			
			proxy_set_header X-Request-ID           $req_id;
			proxy_set_header X-Real-IP              $remote_addr;
			
			proxy_set_header X-Forwarded-For        $remote_addr;
			
			proxy_set_header X-Forwarded-Host       $best_http_host;
			proxy_set_header X-Forwarded-Port       $pass_port;
			proxy_set_header X-Forwarded-Proto      $pass_access_scheme;
			
			proxy_set_header X-Scheme               $pass_access_scheme;
			
			# Pass the original X-Forwarded-For
			proxy_set_header X-Original-Forwarded-For $http_x_forwarded_for;
			
			# mitigate HTTPoxy Vulnerability
			# https://www.nginx.com/blog/mitigating-the-httpoxy-vulnerability-with-nginx/
			proxy_set_header Proxy                  "";
			
			# Custom headers to proxied server
			
			proxy_connect_timeout                   5s;
			proxy_send_timeout                      60s;
			proxy_read_timeout                      60s;
			
			proxy_buffering                         off;
			proxy_buffer_size                       4k;
			proxy_buffers                           4 4k;
			
			proxy_max_temp_file_size                1024m;
			
			proxy_request_buffering                 on;
			proxy_http_version                      1.1;
			
			proxy_cookie_domain                     off;
			proxy_cookie_path                       off;
			
			# In case of errors try the next upstream server before returning an error
			proxy_next_upstream                     error timeout;
			proxy_next_upstream_timeout             0;
			proxy_next_upstream_tries               3;
			
			proxy_pass http://upstream_balancer;
			
			proxy_redirect                          off;
			
		}
		
	}
```

### Run Commands with the Ingress Controller Pods

If there are any specifics we wish to troubleshoot, we can always run commands within the pod.

```bash
$ kubectl ingress-nginx exec -n kube-system -- curl http://127.0.0.1/meow -H "host: cats.com"
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   599    0   599    0     0   292k      0 --:--:-- --:--:-- --:--:--  584k


Hostname: meow-64cb7d9b78-tztc9

Pod Information:
	-no pod information available-

Server values:
	server_version=nginx: 1.12.2 - lua: 10010

Request Information:
	client_address=172.17.0.6
	method=GET
	real path=/meow
	query=
	request_version=1.1
	request_scheme=http
	request_uri=http://cats.com:8080/meow

Request Headers:
	accept=*/*
	host=cats.com
	user-agent=curl/7.64.0
	x-forwarded-for=127.0.0.1
	x-forwarded-host=cats.com
	x-forwarded-port=80
	x-forwarded-proto=http
	x-real-ip=127.0.0.1
	x-request-id=38831e64669666246ad1c69c301ad70b
	x-scheme=http

Request Body:
	-no body in request-
```

This is essentially the same function as exec-ing into ingress-nginx pods. Above you can see that we are testing if our application is accessible from our ingress pod.

Thanks for reading, hope you Enjoyed! 😸

For more information on the ingress-nginx kubectl plugin, you can checkout it’s [Official Documentation](https://kubernetes.github.io/ingress-nginx/kubectl-plugin/).

## LICENSE

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

