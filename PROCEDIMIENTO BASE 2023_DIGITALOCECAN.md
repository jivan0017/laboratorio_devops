PROCEDIMIENTO BASE 2023

[OK]
# droplet-ubuntu-22-04-memodevs-jdiaz-AMD

[OK]
# ATAJOS - CLAVES - ACCESO A DIRECTORIOS
	- SALIR:  Presionar la tecla:  "q"
	- Ir a la carpeta .ssh:
	[COMANDO]:
	cd ~/.ssh

	- ELIMINAR UN FICHERO:
	[COMANDO]:
	rm /root/time.txt

	- BUSCAR PALABRA CLAVE:
	ctrl + w

	- BUSCAR COMANDDO:
	Ctrl + r

[OK]
# INSTALACIONES GENERAL
	- CURL
	[COMANDO]	:
	sudo apt install curl
	bash -c "$(curl -fsSL https://raw.githubusercontent.com/ohmybash/oh-my-bash/master/tools/install.sh)"

[OK]
# CONECTAR CON SSH - INICIO SSH

	- Adicionar el parametro -i con la ubicación de  la llave PUB: 
	[PATH]
	C:\Users\user\.ssh\proyectos_jdiaz\vps_memodevs\vps_memodevs_access

	[COMANDO]
	ssh root@143.198.65.96 -i "C:\Users\user\.ssh\proyectos_jdiaz\vps_memodevs\vps_memodevs_access"

	- Crear fichero sin extesión: config, en la raíz de la carpeta oculta: .ssh en el usuario: user de la unidad C, el contenido es:

	--------- [INICIO - NO COPY ]---------------
	ServeraAliveInterval 120
	ServerAliveCountMax  3	
	# ROOT - MEMODEVS - UBUNTU 22.04
	Host vps_memodevs_root
		HostName 143.198.65.96
		User root
		IdentityFile "C:\Users\user\.ssh\proyectos_jdiaz\vps_memodevs\vps_memodevs_access"	
	--------- [FIN - NO COPY ]---------------		

[OK]
# GITHUB: 
    - Nuestra VPS ahora necesiara cconectarse con sistemas externos
	- COMANDDOS:
	cd ~/.ssh


	ssh-keygen -t rsa -b 4096 -C "memodevs.main@gmail.com"

	sudo nano ~/.ssh/collnfig
	Add in config file: ForwardAgent yes
	eval `ssh-agent -s`
	eval $(ssh-agent -s)
	ssh-add
	ssh-add ~/.ssh/github

	- Testear conexión con  GITHUB:
	ssh -T git@github.com

# CONFIGURAR DNS - DIGITALOCEAN
	- Configuraci5000ssón
	[LINK]
	
	- verificar:
	https://www.whatsmydns.net/#A/memodevs.com

# ACTUALIZAR E INSNTALAR PAQUETES
	[COMANDO]:
	apt update	
	apt upgrade

# COMANDOS RELACIONADOS CON PROCESOS - SYSTEMCTL
	- systemctl comando util para reiniciar servicios y recargar
	- reload:  NO detiene el proceso, carga desde el comienzo las configuraciones (servidor web), no está fuera de línea
	- restart: detener y volver a iniciar el proceso
	- ejemplos de uso:

	[EJEMPLOS]:
	systemctl stop [NOMBRE_SERVICIO]
	systemctl status [NOMBRE_SERVICIO]
	systemctl reload [NOMBRE_SERVICIO] -- SOLO FUNCIONA CON ALGUNOS SERVICIOS, NO TODOS!
	systemctl status unattended-upgrades.service

	- Reiniciar el servidor:
	[COMANDO]:
	reboot

# SSH REMOTO
	- generar una clave/llave SSH en el servidor:
	ssh-keygen
	- agregar la path específica/customizada (creando previamente la carpeta con: sudo mkdir [FOLDER_NAME]):
	/root/.ssh/projects_keys/id_rsa_projects_key

	- INICIAR AGENTE SSH:
	ssh-agent -s,  es más sencillo usar un comando: eval:
	[COMANDO]:
	eval $(ssh-agent -s)

	- en este punto se ha asignado un process ID: Agent pid 119512
	- cuando se vaya establecer conexión ssh desde nuestro server con cualquier otro sistema que lo requiera (protocolo de comunicación), este agente sepa que llave utilizar:
	[COMANDO]:
	ssh-add /root/.ssh/projects_keys/id_rsa_projects_key
	- Con ello se ha agregado la identidad, conexiones automaticas SSH.

	** TESTEAR CONEXIÓN:
	- se testea conexión con sitio externo
	[COMANDO]:
	ssh -T git@github.com

	- copiamos la llave SSH pub local:
	cat /root/.ssh/projects_keys/id_rsa_projects_key

	- clave pública:
	ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQD23XOpA2/Gj8QjiQ0lb27+s1BgBjs9bBHrq3NHapiG5h2/jQ6JSwyLgiymhhhIPiqep5FV8Xxvl2OEe5qR/7pAGlrYoOzJ6UBYJA9RUxhi2ZrvigzK41M9zYnChQWJpcltMqzcUzNW+O+AhRC8vPF+QDBQb6XGQoGcdRnBOdgGGt15nj9QN58athqV7IpnVrHHbDeLqqmacJnt+dbdU65HnBNYyPFMbZiJiFZDHN1u0FVQz8qMbAuAMnptNcXOuB/4EU+9cCQpCPxVKWAjMU6ZxPIOGhnYr3utOKGVwZ4dI/8JWBq6OqYSx+EiR2/EtjyA0BA7spU6oV1tOavFcgUspof65x0c/eD9KjBVufIF7qOqJhGD+iRtLf0ZmwK4zeuUUgHdbUZVF1FzNJPd7Wwted+WuVpeNxb1IdpezA6TS8pmQK1eVFL530pPG7Mcvl/cQpR1lEP7yjNNZh+YQs/p9r1wPkUEqYL9+GntL0PFD7KvOqoXlS+TF8L+IJdmPtU= root@droplet-ubuntu-22-04-memodevs-jdiaz

# CRON JOBS
	- Saber fecha actual:
	date

	- escribir en un archivo la hora actual:
	[COMANDO]:
	date >> /root/time.txt

	crontab.guru

	- Entrar al cron job dedl sustema:
	crontab -e

# Users - Usuarios
	- Agregar:
	[COMANDO]:
	adduser jdiaz

	- remover usuarios
	[COMANDO]:
	deluser jdiaz --remove-home
	
	- generar ssh keygen para el nuevo usuario:

	ssh-keygen
	 - escribir la path: 
	 C:\Users\user\.ssh\proyectos_jdiaz\vps_memodevs/jdiaz_key

	 - clave pública:
	 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCfAy0FM0EK02D402AKSPpPfrgb9Y0eUssvsuy91sehrSn9hf+Oy/WreD3aqjAaGUxhzgBFDINrHyV1LbK+L+UnTfHryld/HeDuQZSARYUTFi/qQL1XohGKllccCwrgSFWI4UBcQlgF6Y/qvVegshz72ll3QwFYVVWaqPUxh09JmUQKq+OQu1hlxzai4876najzRkfF0U6n6jkiXKxMZrMRpjGvRiDjVcpZBqZ0OCFESRHD1iNtyycSducOvm31zIpAVzyJEoAxFOuJ5Fw1uuaRcpIaMASJKAanwN14bdMQtcDvCKnW1sW3gukhfK7iK8bvBnaVYKfcifBMWItAnTsfhwPEQh7BDjVNT0FdFOMRtLi34vkxKj9M3skRspFzMlKE/LNchQN1aMBSDlJMFRSntjEdxAYJ5GM7pMtgstUkFN0qzlkOGj0rEnnzctkTnyaudCy5abl7dqFBEtBj+jhIEaF6T/3QW7I1ykD1OQJucG16/SG+m38rPvUnr/AO2wU= user@JDIAZ

	 - crear dentro de: /home/jdiaz[otro user]/.ssh  la carpetta ssh
	 - esta llave generada la pegamos en otra linea del fichero AUTHORIZED_KEYS:
	 cd ~
	 cd .ssh
	 sudo nano authorized_keys

	 ** delegar permisos:
	 adduser jdiaz sudo

sudo
	 ** AGREGAR MÁS  SEGURIDAD
	 - Nos dirigimos a:
	 /etc/ssh/sshd_config

	 buscar:  permitRoot [Ctrl + w]  y colocar: no

	 - reiniciar servicio:
	 sudo systemctl reload ssh.service

	 - Para entrar como el usuario ROOT:
	 sudo su

	 - solucionar problema de permisos denegaados al ejecutar el agente ssh para la clave privada:
	 [SOLUCION][COMANDO]
	 chown -R jdiaz:jdiaz .ssh

# HABILITAR FIREWALL VPS:
	- UFW
	[COMANDO]:
	ufw --help [verificar diferentes banderas del comando]

	- asegurarnos de que al habilitarlo no nos bloquee la entrada por SSH (puerto 22)
	[COMANDO]:
	sudo ufw status
	sudo ufw status verbose
	sudo ufw app  list	

	- assegurar permitir SSH conexiones entrantes y habilitar
	sudo ufw allow "OpenSSH"
	sudo ufw enable
	sudo ufw reload
	sudo ufw enable

# CONJUNTO DE PERMISOS
	- comienzo de letras con el [COMANDO]: ll
	d -> directorio
	l -> enlace simbólico

	- despues de la primera letra
	permisos para el propietario de ese archivo o carpeta, el segundo grupo son los permisos para el propietario de ese archivo o carpeta

	-  el tercero, todo lo demás (ni el propietario ni el grupo mismo)

	propietario - grupo - los demás

	- mala práctica:
	[COMANDO]:
	sudo chmod -R 777

	- buena práctica:
	[COMANDO]:
	sudo chown -R jdiaz:[grupo] FOLDER_NAME | jdiaz es propietario y el grupo también es el propietario

	** INSTALAR FAIL TO BAN:
	[COMANDO]:
	sudo apt install fail2ban

	- mirar el esstado: 
	[COMANDO]:
	sudo fail2ban-client set sshd unbanip [IP]

	- detener el servicio
	[COMANDO]:
	systemctl stop fail2ban.service

# SERVIDOR WEB
	- ACTUALIZAR PRIMERO:
	sudo apt update (instalar firma de paquetes)

	- Instatalación:
	sudo apt install nginx

	- habilitando puertos
	ufw status verbose
	sudo ufw app list

	sudo ufw allow "Nginx Full"

# NGINX
	- root: indica la raíz de la carpeta que contiene los datos a retornar por nuestro web server
	- server_name [nombre sub dominio];

	- nos movemos a la ubicación ppal de nginx, default en sites-available
	- removemos el enlace simbólico
	[COMANDO]:
	cd /etc/nginx/sites-enabled/
	sudo rm default

	-- crear ficheros:
	sudo cp default api-scraper-tipsterbyte.memodevs.com
	sudo cp default api-main-tipsterbyte.memodevs.com
	sudo cp default tipsterbyte.memodevs.com
	sudo cp default .memodevs.comv

	- REGARGAR SERVICIO

	- crear enlace simbolico:
	[COMANDO]:
	sudo ln -s /etc/nginx/sites-available/memodevs.com  /etc/nginx/sites-enabled/
	sudo ln -s /etc/nginx/sites-available/api-scraper-tipsterbyte.memodevs.com  /etc/nginx/sites-enabled/
	sudo ln -s /etc/nginx/sites-available/api-main-tipsterbyte.memodevs.com /etc/nginx/sites-enabled/
	sudo ln -s /etc/nginx/sites-available/tipsterbyte.memodevs.com /etc/nginx/sites-enabled/

	sudo mv html/index.html memodevs.com/index.html
	sudo nginx -t

	- SEGURIDAD NGINX
	- nos ubicamos en sites-available:
	sudo nano *

	- agregar esto:
	[CODE]:
        # TODO: add - seguridad .HTTACCESS
        location ~ /\.ht {
                deny all;
        }

        # TODO: add - seguridad para git
        location ~ /\.git {
                deny all;
        }	

    - Reiniciar servicio
    [COMANDO]:
    sudo systemctl reload nginx.service

    - crear fichero de configuración en snippets (security-headers.conf):
    [CODE]:
		##
		# TODO ADD ALL - NEW FILE
		# Security settings
		##

		# Avoid iFrames from different origins
		add_header X-Frame-Options SAMEORIGIN;

		# aVOID mime types sniff
		add_header X-Content-Type-Options nosniff;

		# Avoid XXS attacks
		add_header X-XSS-Protection "1; mode=block";

		# Avoid Referer policy, onoly use full path on same origin
		add_header Referrer-Policy "strict-origin-when-cross-origin";     
	- una vez creado, se agrega en cada fichero ded configuración de sites-available:
	sudo nano *
	        # TODO: add
        include snippets/security-headers.conf;

	- GZIP - comprimir respuestas en nginx.conf

	- verificar cabeceras de nuestro sitio:
	https://securityheaders.com/?q=api-blog.memodevs.com&followRedirects=on

	** [FILE] fichero dentro de: sitets-available: default
		##
		# You should look at the following URL's in order to grasp a solid understanding
		# of Nginx configuration files in order to fully unleash the power of Nginx.
		# https://www.nginx.com/resources/wiki/start/
		# https://www.nginx.com/resources/wiki/start/topics/tutorials/config_pitfalls/
		# https://wiki.debian.org/Nginx/DirectoryStructure
		#
		# In most cases, administrators will remove this file from sites-enabled/ and
		# leave it as reference inside of sites-available where it will continue to be
		# updated by the nginx packaging team.
		#
		# This file will automatically load configuration files provided by other
		# applications, such as Drupal or Wordpress. These applications will be made
		# available underneath a path with that package name, such as /drupal8.
		#
		# Please see /usr/share/doc/nginx-doc/examples/ for more detailed examples.
		##

		# Default server configuration
		#
		server {
		        listen 80 default_server;
		        listen [::]:80 default_server;

		        # TODO: add
		        # include snippets/security-headers.conf

		        # SSL configuration
		        #
		        # listen 443 ssl default_server;
		        # listen [::]:443 ssl default_server;
		        #
        # Note: You should disable gzip for SSL traffic.
        # See: https://bugs.debian.org/773332
        #
        # Read up on ssl_ciphers to ensure a secure configuration.
        # See: https://bugs.debian.org/765782
        #
        # Self signed certs generated by the ssl-cert package
        # Don't use them in a production server!
        #
        # include snippets/snakeoil.conf;

        root /var/www/html;

        # Add index.php to the list if you are using PHP
        index index.html index.htm index.nginx-debian.html;

        server_name _;

        location / {
                # First attempt to serve request as file, then
                # as directory, then fall back to displaying a 404.
                try_files $uri $uri/ =404;
        }

        # pass PHP scripts to FastCGI server
        #
        #location ~ \.php$ {
        #       include snippets/fastcgi-php.conf;
        #
        #       # With php-fpm (or other unix sockets):
        #       fastcgi_pass unix:/run/php/php7.4-fpm.sock;
        #       # With php-cgi (or other tcp sockets):
        #       fastcgi_pass 127.0.0.1:9000;
        #}

        # deny access to .htaccess files, if Apache's document root
        # concurs with nginx's one
        #
        #location ~ /\.ht {
        #       deny all;
        #}
        # TODO: add - seguridad .HTTACCESS
        location ~ /\.ht {
                deny all;
        }

        # TODO: add - seguridad para git
        location ~ /\.git {
                deny all;
        }

		}

		# Virtual Host configuration for example.com
		#
		# You can move that to a different file under sites-available/ and symlink that
		# to sites-enabled/ to enable it.
		#
		#server {
		#       listen 80;
		#       listen [::]:80;
		#
		#       server_name example.com;
		#
		#       root /var/www/example.com;
		#       index index.html;
		#
		#       location / {
		#               try_files $uri $uri/ =404;
		#       }
		#}	

	- NGINX.CONF
	[SOURCE][FRAGMENT]
		http {

		        ##
		        # Basic Settings
		        ##

		        sendfile on;
		        tcp_nopush on;
		        types_hash_max_size 2048;
		        # TODO: descomentado
		        server_tokens off;	

    [EN SITES AVAILABLE]
	server {
		listen 80 default_server;
		listen [::]:80 default_server;

		server_name _;
		return 301 http://memodevs.com;
	}    
	- BORRAR EL DEFAULT MÁS ABAJO EN LA CONF.


# INSTALACIONES - BASE DE DATOS - MYSQL
	- mysql
	[COMANDO]:
	sudo apt install mysqsl-server
	mysql --version
	sudo 

	sudo mysql_secure_installation

	- Conf. aplicada:
	[LINK]
	https://prnt.sc/3uUo74KSohzj

	- iniciar mysql:
	sudo mysql

	- creando usuarios de BD
	[COMANDO]:
	CREATE USER tipsterbyte_main_memodevs@localhost IDENTIFIED BY 'Tipsterbyte_memodevs2024$%.';

	SELECT user, host, plugin FROM mysql.user;
	SHOW databases;

	CREATE DATABASE tipsterbyte_main_memodevs;

	GRANT ALL PRIVILEGES ON tipsterbyte_main_memodevs.* TO tipsterbyte_main_memodevs@localhost;
	FLUSH PRIVILEGES;

	- tunel ssh desde windows:
	ssh vps_memodevs_jdiaz -L 3333:localhost:3306 -N

	- editar propiedades de conexión / propiedades de driver y agregar esta:
	rewriteBatchedStatements: true

	-- DESINSTALAR MYSQL:
	https://dev.to/kinyungu_denis/how-to-uninstall-mysql-server-from-ubuntu-2204-1k9j

# INSTALACIONES - BASE DE DATOS - MONGODB
	- INSTALAR:
	[COMANDO]:
	sudo apt-get install gnupg curl
 	sudo apt install software-properties-common gnupg apt-transport-https ca-certificates -y
	curl -fsSL https://pgp.mongodb.com/server-7.0.asc |  sudo gpg -o /usr/share/keyrings/mongodb-server-7.0.gpg --dearmor

	echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-7.0.gpg ] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/7.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-7.0.list

	sudo apt update
	sudo apt install mongodb-org -y
	sudo systemctl status mongod
	sudo systemctl start mongod
	sudo ss -pnltu | grep 27017
	sudo systemctl enable mongod

	- acceder a mongo:
	mongosh

	db.createUser(
		{
			user: "happy_footprints_test",
			pwd: passwordPrompt(),
			roles: [ {role: "readWrite", db: "happy_footprints_test"}]
		}
	)

	db.getUsers();
	db.dropUser("tipsterbyte_main", {w: "majority", wtimeout: 4000})
	show users
	db.dropDatabase();
	-----------------
	use admin
	db.createUser(
		{
			user: "tipsterbyte_main",
			pwd: passwordPrompt(),
			roles: [ {role: "userAdminAnyDatabase", db: "admin"}, "readWriteAnyDatabase"]
		}
	)

	db.createUser(
		{
			user: "happy_footprints_admin",
			pwd: passwordPrompt(),
			roles: [ {role: "readWrite", db: "happy_footprints_test"}, "readWriteAnyDatabase"]
		}
	)

	db.createUser(
		{
			user: "test_huellitas_felices_db",
			pwd: passwordPrompt(),
			roles: [ {role: "userAdminAnyDatabase", db: "admin"}, "readWriteAnyDatabase"]
		}
	)	

	# huellitas felices:
	db.createUser(
	  {
	    user: "happy_footprints_user",
	    pwd: "1234567890",
	    roles: [ { role: "readWrite", db: "happy_footprints_test" } ]
	  }
	)

	db.createUser(
	  {
	    user: "happy_footprints_user",
	    pwd: "1234567890",
	    db: "happy_footprints_test",
	    roles: [ { role: "userAdminAnyDatabase", db: "happy_footprints_test" } ]
	  }
	)

	db.createUser(
		{
			user: "happy_footprints_user2",
			pwd: "1234567890",
			roles: [ {role: "readWrite", db: "happy_footprints_test"}, "readWriteAnyDatabase"]
		}
	)	


	** modificar el fichero de seguridad:
	sudo nano /etc/mongod.conf

	- habilitar esta línea:
	security:
  		authorization: enabled

  	- guardar y  salir
  	- reiniciar servicio:
  	sudo systemctl restart mongod

  	mongosh -u tipsterbyte_main -p --authenticationDatabase admin

  	----------------
  	** conexión remota:
  	IP digital ocean: 137.184.119.63

  	sudo systemctl restart mongod

  	** permisos en los puertos
  	sudo ufw allow from 137.184.119.63 to any port 27017
  	sudo ufw allow from 191.95.148.202 to any port 27017

  	- Configuración anterior donde permitía solo la IP del pc remoto:  	
	[CODE]
		net:
		  port: 27017
		  bindIp: 127.0.0.1 ,137.184.119.63	



  	mongodb://tipsterbyte_main:tipsterbyte_main@137.184.119.63:27017/tipsterbyte_main

  	- BD tipsterByte
  	mongodb://tipsterbyte_main:18402120@137.184.119.63:27017/?tls=false

  	- BD Huellitas felices
  	mongodb://test_huellitas_felices_db:18402120@137.184.119.63:27017/?tls=false  	

	--------------------------------------------------
  	# ACEPTAR CUALQUIER CONEXIÓN ENTRANTE IPV4 hacia el servidor:
  	[COMMAND]
  	sudo ufw allow 27017

  	- Navegar a: sudo nano /etc/mongod.conf
	[CODE]
		net:
		  port: 27017
		  bindIp: 127.0.0.1 ,137.184.119.63	  

	- reiniciar servicio:
	[COMMAND]
	sudo systemctl restart mongod
	--------------------------------------------------	

  	-- DESINSTALAR:
  	sudo service mongod stop
	sudo apt-get purge mongodb-org*
	sudo rm -r /var/log/mongodb /var/lib/mongodb

	- Check if any mongo service is running:
	launchctl list | grep mongo

	- If you had installed MongoDB using Homebrew, unload mongodb:
	launchctl unload ~/Library/LaunchAgents/homebrew.mxcl.mongodb-community.plist
	rm -f ~/Library/LaunchAgents/homebrew.mxcl.mongodb-community.plist
	launchctl remove homebrew.mxcl.mongodb-community
	
	- Kill the mongod process, if it exists:
	pkill -f mongod

	- If you had installed MongoDB using brew, uninstall MongoDB with the below command:

	brew uninstall mongodb-community 
	brew uninstall mongodb-database-tools
	brew uninstall mongosh
	brew untap mongodb/brew

	- If you installed MongoDB manually (without Homebrew), then use:

	rm -rf <yourmongodb_folder>
	- Remove database files:

	rm -rf /usr/local/var/mongodb
	- To check if the uninstall was properly done, check if any MongoDB files are still present:

	ls -al /usr/local/bin/mongo*
	zsh: no matches found: /usr/local/bin/mongo*
	- To install a newer MongoDB version, visit Install MongoDB on Mac. Alternatively, avoid the need for install/uninstall in the future by trying MongoDB Atlas free today.
	
# SSL - HTTPS
	- WEB:
	https://letsencrypt.org/getting-started/
	https://certbot.eff.org/instructions?ws=nginx&os=ubuntufocal

	- INSTALACIÓN
	[COMANDO]:
	sudo snap install --classic certbot

	- generación de certificado SSL con nginx

	[MEMODEVS.COM]
	sudo certbot --nginx --hsts --staple-ocsp --must-staple -d memodevs.com -d www.memodevs.com

	[TIPSTERBYTE.MEMODEVS.COM]
	sudo certbot --nginx --hsts --staple-ocsp --must-staple  -d tipsterbyte.memodevs.com
	certbot delete --cert-name tipsterbyte.memodevs.com

	[API SCRAPER TIPSTERBYTE.MEMODEVS.COM]
	sudo certbot --nginx --hsts --staple-ocsp --must-staple  -d api-scraper-tipsterbyte.memodevs.com
	certbot delete --cert-name api-scraper-tipsterbyte.memodevs.com	

	[API MAIN TIPSTERBYTE.MEMODEVS.COM]
	sudo certbot --nginx --hsts --staple-ocsp --must-staple  -d api-main-tipsterbyte.memodevs.com
	certbot delete --cert-name api-main-tipsterbyte.memodevs.com		

	** email: memodevs.main@gmail.com

	** verificar estado de los certtificados:
	sudo certbot certificates

	** ELIMINANDO CERTIFICADOS:
	sudo certbot delete --cert-name api-blog.memodevs.com
	sudo certbot delete --cert-name blog.memodevs.com
	sudo certbot delete --cert-name tipsterbyte.memodevs.com
	sudo certbot delete --cert-name memodevs.memodevs.com

	** verificando timers:

	** calificando el nivel de seguridad de los dominios:
	[LINK]:
	https://www.ssllabs.com/ssltest/analyze.html?d=memodevs.com


	server {
	        listen 80 default_server;
	        listen [::]:80 default_server;
	        root /var/www/html;
	        index index.html index.htm index.nginx-debian.html;
	        server_name _;
	        location / {
	                add_header Cache-Control "max-age=0, no-cache, no-store, must-revalidate";
	                add_header Pragma "no-cache";
	                try_files $uri $uri/ =404;
	        }
	}

# PHP
	- comandos instalación

# NODE:
	- Instalar

# JAVA:
	- Desinstalar:
	https://es.linux-console.net/?p=14597

# DOCKER:
	- Docker
	[COMANDO]:

	sudo apt install docker-compose	

	- 

# PYTHON
	- Creaar enlace simbólico de gunicorn:
	sudo ln -s /usr/local/bin/gunicorn /var/www/api-scraper-tipsterbyte.memodevs.com/venv/bin/

	systemctl daemon-reload
	sudo systemctl stop tipsterbyte_scraper
	sudo systemctl start tipsterbyte_scraper
	sudo systemctl enable tipsterbyte_scraper
	sudo systemctl status tipsterbyte_scraper

    location / {
        proxy_pass             http://127.0.0.1:8000;
        proxy_read_timeout     60;
        proxy_connect_timeout  60;
        proxy_redirect         off;

        # Allow the use of websockets
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }	

    -- INSTALACIONESS
	git config --global --add safe.directory /var/www/api-scraper-tipsterbyte.memodevs.com

	sudo git config --global user.email "jaimeivan0017@gmail.com"
	sudo git config --global user.name "jivan0017"

  	Xvfb -ac :99 -screen 0 1280x1024x16 & export DISPLAY=:99
  	executable_path=r'/root/.wdm/drivers/chromedriver/linux64/121.0.6167.85/chromedriver-linux64/chromedriver'


# GESTIÓN DE SERVICIOS
 	- MYSQL
    sudo systemctl  stop mysql
    sudo systemctl  start mysql
    sudo systemctl  enable mysql
    sudo systemctl  status mysql

    - MONGOD
    sudo systemctl  stop mongod
    sudo systemctl  start mongod
    sudo systemctl  enable mongod 
    sudo systemctl  status mongod

    - 
	sudo systemctl stop tipsterbyte_scraper
	sudo systemctl start tipsterbyte_scraper
	sudo systemctl enable tipsterbyte_scraper
	sudo systemctl status tipsterbyte_scraper    

	Xvfb -ac :99 -screen 0 1280x1024x16 & export DISPLAY=:99








	** desde el menu admin: con aleida

	- oferta de empleo

	hacer ->> aaplicacion aa ofertasa empleo
	- seleccciono el ddettaalle ded  cualquier oferta
	- se abre detalle
	- en esstado  asignamos uno ded los dos disponibles
	- click guardar y error

	hacer ->> ofertas dde emplleo
	- click en nueva oferta
	se queda pegado tanto en nnuevo como en el click ddde unaa de las ofertasa existentes

	- SI FUNCIONA:
	Al clickear una dde las ofertas existentes y se modifican datoss de laa mismaa














    actualización de ceremonias => ambiente TEST 
    con guille se corrigió un tema de XHTML
    tuve problemas con la  compilación del proyecto, reiniccié y se pudo soluccioonar

    - estoy viendo el vídeo de Ofertaass de empleo  y aaplicación a ofertaas de empleo
    (allí estoy documentando los scripts para futuras restauraciones - DDL)

    ACTUALICÉ EL AZURE Y CREE LAS 2 TAREITASAS    actualización de ceremonias => ambiente TEST 
    con guille se corrigió un tema de XHTML
    tuve problemas con la  compilación del proyecto, reiniccié y se pudo soluccioonar

    - estoy viendo el vídeo de Ofertaass de empleo  y aaplicación a ofertaas de empleo
    (allí estoy documentando los scripts para futuras restauraciones - DDL)

    ACTUALICÉ EL AZURE Y CREE LAS 2 TAREITASAS


	GRADUAADO
	El estudiante de tipo graduado al entrar  al menú de opciones del graduado en la opción del menú "Ofertas de empleo", se le listan las ofertas de empleo que efectivamente tiene habilitados, al presionar click sobre dicho registro aparece un dialogo de alerta sin contenido, claramente se está rompiendo un segmento de código relativo a los detalles de la oferta de empleo


	https://www.xvideos.com/video69597147/blackedraw_-_overfill_-_la_compilacion_de_corridas_internas


	01/02/2024

	- OJO ! MENCIONAR BUG GRADOS BUSCAR SIN SELECCIÓNN DE FILTROS

	PENDIENTES:
	OFERTA DE EMPLEO CON GRADUADOS OJO!

	- REGISTRO DE TAREAS EN EXCEL DE ENERO