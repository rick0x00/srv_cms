#!/usr/bin/env bash

# ============================================================ #
# Tool Created date: 03 jan 2024                               #
# Tool Created by: Henrique Silva (rick.0x00@gmail.com)        #
# Tool Name: WordPress Install                                 #
# Description: My simple script to provision WordPress Server  #
# License: software = MIT License                              #
# Remote repository 1: https://github.com/rick0x00/srv_cms     #
# Remote repository 2: https://gitlab.com/rick0x00/srv_cms     #
# ============================================================ #
# base content:
#   https://wordpress.org/about/requirements/
#   https://developer.wordpress.org/advanced-administration/before-install/howto-install/

# ============================================================ #
# start root user checking
if [ $(id -u) -ne 0 ]; then
    echo "Please use root user to run the script."
    exit 1
fi
# end root user checking
# ============================================================ #
# start set variables

DATE_NOW="$(date +Y%Ym%md%d-H%HM%MS%S)" # extracting date and time now

### database vars
database_bind_address="127.0.0.1" # setting to listen only localhost
#database_bind_address="0.0.0.0" # setting to listen for everybody
database_bind_port="3306" # setting to listen on default MySQL port

database_host="localhost"
database_root_user="root"
database_root_pass="supersecret123"

database_user="wordpress_db_user"
database_pass="wordpress_db_pass"
database_user_access_host="localhost"
database_db_name="wordpress_db_name"
database_db_charset="utf8mb4"
database_db_collate="utf8mb4_unicode_ci"

### apache vars
site_name="wordpress"
site_path="/var/www/wordpress"
site_subdomain="wordpress"
site_root_domain="local"
site_ssl_enabled="false"


os_distribution="Debian"
os_version=("11" "bullseye")

database_engine="mysql"
webserver_engine="apache"

port_http[0]="80" # http number Port
port_http[1]="tcp" # tcp protocol Port 

port_https[0]="443" # https number Port
port_https[1]="tcp" # tcp protocol Port 

build_path="/usr/local/src"
workdir="/var/www/"
persistence_volumes=("/var/www/" "/var/log/")
expose_ports="${port_http[0]}/${port_http[1]} ${port_https[0]}/${port_https[1]}"
# end set variables
# ============================================================ #
# start definition functions
# ============================== #
# start complement functions

function remove_space_from_beginning_of_line {
    #correct execution
    #remove_space_from_beginning_of_line "<number of spaces>" "<file to remove spaces>"

    # Remove a white apace from beginning of line
    #sed -i 's/^[[:space:]]\+//' "$1"
    #sed -i 's/^[[:blank:]]\+//' "$1"
    #sed -i 's/^ \+//' "$1"

    # check if 2 arguments exist
    if [ $# -eq 2 ]; then
        #echo "correct quantity of args"
        local spaces="${1}"
        local file="${2}"
    else
        #echo "incorrect quantity of args"
        local spaces="4"
        local file="${1}"
    fi 
    sed -i "s/^[[:space:]]\{${spaces}\}//" "${file}"
}

function massager_sharp() {
    line_divisor="###########################################################################################"
    echo "${line_divisor}"
    echo "$*"
    echo "${line_divisor}"
}

function massager_line() {
    line_divisor="-------------------------------------------------------------------------------------------"
    echo "${line_divisor}"
    echo "$*"
    echo "${line_divisor}"
}

function massager_plus() {
    line_divisor="++++++++++++++++++++++++++++++++++++++++++++++++++"
    echo "${line_divisor}"
    echo "$*"
    echo "${line_divisor}"
}

# end complement functions
# ============================== #
# start main functions

function pre_install_server () {
    massager_line "Pre install server step"

    function install_generic_tools() {
        # update repository
        apt update

        #### start generic tools
        # install basic network tools
        apt install -y net-tools iproute2 traceroute iputils-ping mtr
        # install advanced network tools
        apt install -y tcpdump nmap netcat
        # install DNS tools
        apt install -y dnsutils
        # install process inspector
        apt install -y procps htop
        # install text editors
        apt install -y nano vim 
        # install web-content downloader tools
        apt install -y wget curl
        # install uncompression tools
        apt install -y unzip tar
        # install file explorer with CLI
        apt install -y mc
        # install task scheduler 
        apt install -y cron
        # install log register 
        apt install -y rsyslog
        #### stop generic tools
    }

    function install_dependencies () {
        # install dependencies from project
        apt install -y unzip wget
    }

    function install_complements () {
        echo "step not necessary"
        exit 1;
    }

    apt update
    install_generic_tools
    install_dependencies;
    #install_complements;
}

##########################
## install steps

function install_apache () {
    # installing Apache
    massager_plus "Installing Apache"

    function install_from_source () {
        echo "step not configured"
        exit 1;
    }

    function install_from_apt () {
        apt install -y apache2 apache2-utils apache2-doc
    }

    ## Installing apache From Source ##
    #install_from_source

    ## Installing apache From APT (Debian package manager) ##
    install_from_apt
}

function install_php () {
    # installing PHP
    massager_plus "Installing PHP"
    function instal_from_source () {
        echo "step not configured"
        exit 1;
    }

    function install_from_apt () {
        apt install -y php libapache2-mod-php php-mysql
    }

    ## Installing php From Source ##
    #install_from_source

    ## Installing php From APT (Debian package manager) ##
    install_from_apt
}

function install_mariadb () {
    # installing MariaDB
    massager_plus "Installing MariaDB"

    function install_from_source () {
        echo "step not configured"
        exit 1;
    }

    function install_from_apt () {
        apt install -y mariadb-common mariadb-server mariadb-server mariadb-client mariadb-backup
    }

    ## Installing MariaDB From Source ##
    #install_from_source

    ## Installing MariaDB From APT (Debian package manager) ##
    install_from_apt
}

function install_wordpress () {
    # installing WordPress
    massager_plus "Installing WordPress"

    function install_from_source () {
        # Download WordPress in the last version
        wordpress_build_path="${build_path}/wordpress/wordpress-${DATE_NOW}"
        mkdir -p "${wordpress_build_path}"

        wget https://wordpress.org/latest.zip -O "${wordpress_build_path}/wordpress.zip"

        unzip "${wordpress_build_path}/wordpress.zip" -d "${wordpress_build_path}/"

        cp -R ${wordpress_build_path}/wordpress /var/www/wordpress
    }

    function install_from_apt () {
        echo "step not configured"
        exit 1;
    }

    ## Installing wordpress From Source ##
    install_from_source

    ## Installing wordpress From APT (Debian package manager) ##
    #install_from_apt
}
#############################

function install_server () {
    massager_line "Install server step"

    ## WEB SERVER - Apache
    install_apache
    ## DATABASE SERVER - MariaDB
    install_mariadb
    ## PHP
    install_php
    ## CMS - WordPress
    install_wordpress
}

#############################
## start/stop steps ##

function start_apache () {
    # starting apache
    massager_plus "Starting Apache"

    #service apache2 start
    #systemctl start apache
    /etc/init.d/apache2 start

    # Daemon running on foreground mode
    #apachectl -D FOREGROUND
}

function start_mariadb () {
    # starting MariaDB
    massager_plus "Starting MariaDB"

    #service mariadb start
    #systemctl start mariadb
    /etc/init.d/mariadb start

    # Daemon running on foreground mode
    #/usr/sbin/mariadbd
}

function stop_apache () {
    # stopping apache
    massager_plus "Stopping Apache"

    #service apache2 stop
    #systemctl stop apache
    /etc/init.d/apache2 stop

    # ensuring it will be stopped
    # for Daemon running on foreground mode
    killall apache2
}

function stop_mariadb () {
    # stopping mariadb
    massager_plus "Stopping Apache"

    #service mariadb stop
    #systemctl stop mariadb
    /etc/init.d/mariadb stop

    # ensuring it will be stopped
    # for Daemon running on foreground mode
    killall mariadbd
}

################################

function start_server () {
    massager_line "Starting server step"

    # Starting Service

    # starting apache
    start_apache

    # starting mariadb
    start_mariadb
}

function stop_server () {
    massager_line "Stopping server step"

    # stopping server
    stop_apache
    stop_mariadb
}

################################
## configuration steps ##
function configure_apache() {
    # Configuring Apache
    massager_plus "Configuring Apache"

    local site_name="${site_name:-debian}"
    local site_path="${site_path:-'/var/www/html'}"
    local site_subdomain="${site_subdomain:-debian}"
    local site_root_domain="${site_root_domain:-local}"
    local site_ssl_enabled="${site_ssl_enabled:-false}"

    function configure_apache_security() {
        # Configuring Apache Security
        massager_plus "Configuring Apache Security"

        # disable apache directory listing
        cp /etc/apache2/apache2.conf /etc/apache2/apache2.conf.bkp_${DATE_NOW} 
        sed -i "/Options/s/Indexes FollowSymLinks/FollowSymLinks/" /etc/apache2/apache2.conf

        # disable apache server banner
        cp /etc/apache2/conf-enabled/security.conf /etc/apache2/conf-enabled/security.conf.bkp_${DATE_NOW} 
        sed -i "/ServerTokens/s/OS/Prod/" /etc/apache2/conf-enabled/security.conf
        sed -i "/ServerSignature/s/On/Off/" /etc/apache2/conf-enabled/security.conf

        # strict HTTP Options ????????


        # disable default apache site
        a2dissite 000-default.conf

        # enable SSL module to Apache
        a2enmod ssl

        # Creating my personalized configurations of SSL sites
        echo '
        # disable old insecure protocols
        SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
        
        # Enhance cypher suites
        SSLHonorCipherOrder on
        SSLCipherSuite          ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:DES-CBC3-SHA:!DSS
        
        # Disable SSL compression
        SSLCompression off

        # Enable HTTP Strict Transport Security (HSTS)
        SSLOptions +StrictRequire
        ' > /etc/apache2/ssl_options-sites.conf
        remove_space_from_beginning_of_line "8" "/etc/apache2/ssl_options-sites.conf"

    }

    function configure_apache_site() {
        # Configuring Apache Site
        massager_plus "Configuring Apache Site"
        # setting Apache Site

        #site_name="debian"
        #site_path="/var/www/html"
        #site_subdomain="debian"
        #site_root_domain="local"
        #site_ssl_enabled="false"

        
        # setting apache server to listening on specified ports
        sed -i "/Listen 80/s/80/${port_http[0]}/" /etc/apache2/ports.conf
        sed -i "/Listen 443/s/443/${port_https[0]}/" /etc/apache2/ports.conf

        # correct sample file to apache sites
        echo "
        <VirtualHost *:site_http_port>
            ServerName site_subdomain.site_root_domain
            ServerAdmin sysadmin@site_root_domain

            #DocumentRoot site_path

            ## Redirecting to SSL site
            #Redirect / https://site_subdomain.site_root_domain:site_https_port/

            ErrorLog ${APACHE_LOG_DIR}/error.log
            CustomLog ${APACHE_LOG_DIR}/access.log combined

        </VirtualHost>

        <VirtualHost *:site_https_port>
            ServerName site_subdomain.site_root_domain
            ServerAdmin sysadmin@site_root_domain

            DocumentRoot site_path

            ##### Redirecting subpath to another site
            ####Redirect 301 /xpto_subbpath https://another_site.local

            #SSLEngine on
            #SSLCertificateFile      /etc/letsencrypt/live/site_root_domain/cert.pem
            #SSLCertificateKeyFile   /etc/letsencrypt/live/site_root_domain/privkey.pem
            #SSLCertificateChainFile /etc/letsencrypt/live/site_root_domain/chain.pem
            #Include /etc/apache2/ssl_options-sites.conf

            ErrorLog ${APACHE_LOG_DIR}/error.log
            CustomLog ${APACHE_LOG_DIR}/access.log combined

        </VirtualHost>
        " >  /etc/apache2/sites-available/site_sample.conf

        remove_space_from_beginning_of_line "8" "/etc/apache2/sites-available/site_sample.conf"

        # configure site
        cp "/etc/apache2/sites-available/site_sample.conf" "/etc/apache2/sites-available/${site_name}.conf"
        sed -i "s/site_http_port/${port_http[0]}/" "/etc/apache2/sites-available/${site_name}.conf"
        sed -i "s/site_https_port/${port_https[0]}/" "/etc/apache2/sites-available/${site_name}.conf"
        sed -i "s|site_path|${site_path}|" "/etc/apache2/sites-available/${site_name}.conf"
        sed -i "s/site_subdomain/${site_subdomain}/" "/etc/apache2/sites-available/${site_name}.conf"
        sed -i "s/site_root_domain/${site_root_domain}/" "/etc/apache2/sites-available/${site_name}.conf"

        if [ "${site_ssl_enabled}" == "true" ] || [ "${site_ssl_enabled}" == "yes" ]; then
            # SSL Enabled on site
            # Enable SSL page
            # enabling http page redirect for https page
            sed -i "/#Redirect/s/#Redirect/Redirect/" "/etc/apache2/sites-available/${site_name}.conf"
            # Configuring SSL options on page
            sed -i "/SSL/s/#//" "/etc/apache2/sites-available/${site_name}.conf"
            sed -i "/Include/s/#//" "/etc/apache2/sites-available/${site_name}.conf"
        else
            # SSL Disabled on site
            # enabling http page work
            sed -i "/DocumentRoot/s/#//" "/etc/apache2/sites-available/${site_name}.conf"
        fi

        # enabling site
        a2ensite ${site_name}.conf

        # adjusting site path permissions, owner and group
        find ${site_path} -type d -exec chmod 755 {} +
        find ${site_path} -type f -exec chmod 644 {} +
        chown www-data:www-data -R ${site_path}
    }

    # configuring security on Apache
    configure_apache_security

    # setting apache site
    configure_apache_site
}

function configure_mariadb() {
    # Configuring MariaDB
    massager_plus "Configuring MariaDB"

    local database_bind_address="${database_bind_address:-127.0.0.1}" # setting to listen only localhost
    #local database_bind_address="0.0.0.0" # setting to listen for everybody
    local database_bind_port="${database_bind_port:-3306}" # setting to listen on default MySQL port


    local database_host="${database_host:-localhost}"
    local database_port="${database_port:-${database_bind_port}}"
    local database_root_user="${database_root_user:-root}"
    local database_root_pass="${database_root_pass:-supersecret123}"

    local database_user="${database_user:-sysadmin}"
    local database_pass="${database_pass:-masterpassword123}"
    local database_user_access_host="${database_user_access_host:-'%'}" # grant access by database for any host
    local database_db_name="${database_db_name:-xpto}"
    local database_db_charset="${database_db_charset:-utf8mb4}"
    local database_db_collate="${database_db_collate:-utf8mb4_unicode_ci}"

    function check_mariadb_is_alive() {
        # Checking if MariaDB Server is alive
        massager_plus "Checking if MariaDB Server is alive"
        # Retry settings
        local max_retries=5
        local delay_between_retries=2

        for ((i=1; i<=$max_retries; i++)); do
            # Try to connect to MySQL
            echo "port: ${database_port}"
            echo "host: ${database_host}"
            #mysql -h ${database_host} -P ${database_port} -u ${database_root_user} -p"${database_root_pass}" -e "SELECT VERSION();"
            mysqladmin -h ${database_host} -P ${database_port} ping

            # Check the exit code of the previous command
            if [ $? -eq 0 ]; then
                echo "MySQL server is responding."
                break
            else
                echo "Attempt $i of $max_retries: Unable to connect to MySQL server."
                if [ $i -lt $max_retries ]; then
                    echo "Waiting $delay_between_retries seconds before the next attempt..."
                    sleep $delay_between_retries
                else
                    echo "Exceeded the maximum number of retries. Aborting the script."
                    exit 1
                fi
            fi
        done
    }

    function configure_mariadb_server() {
        # Configuring MariaDB Server
        massager_plus "Configuring MariaDB Server"

        echo "
        [mysqld]
        sql-mode="STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION"
        #character-set-server=utf8
        default-authentication-plugin=mysql_native_password
        bind-address=${database_bind_address}
        port=${database_bind_port}

        # log configurations    
        log_error=/var/log/mysql/error.log
        general_log_file=/var/log/mysql/general.log
        general_log=1

        # security configurations
        version = 10

        " > /etc/mysql/mariadb.conf.d/99-server.cnf
        remove_space_from_beginning_of_line "8" "/etc/mysql/mariadb.conf.d/99-server.cnf"

    }

    function configure_mariadb_security() {
        # Configuring MariaDB Security
        massager_plus "Configuring MariaDB Security"

        #  Enables to improve the security of MariaDB
        #mysql_secure_installation
        # Automating `mysql_secure_installation`
        
        # setting root password
        #mysql -uroot -p
        mysql -e "SET PASSWORD FOR '$database_root_user'@localhost = PASSWORD('$database_root_pass');"
        # Make sure that NOBODY can access the server without a password
        mysql -e "ALTER USER '$database_root_user'@'localhost' IDENTIFIED BY '$database_root_pass';"

        # Delete anonymous users
        mysql -h ${database_host} -P ${database_port} -u ${database_root_user} -p"${database_root_pass}" -e "DELETE FROM mysql.user WHERE User='';"

        # disallow remote login for root
        #mysql -h ${database_host} -P ${database_port} -u ${database_root_user} -p"${database_root_pass}" -e "ALTER USER 'root'@'localhost' IDENTIFIED WITH 'mysql_native_password' BY 'sua_senha';"
        mysql -h ${database_host} -P ${database_port} -u ${database_root_user} -p"${database_root_pass}" -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');"

        # Remove the test database
        mysql -h ${database_host} -P ${database_port} -u ${database_root_user} -p"${database_root_pass}" -e "DROP DATABASE IF EXISTS test;"

        # Make our changes take effect
        mysql -h ${database_host} -P ${database_port} -u ${database_root_user} -p"${database_root_pass}" -e "FLUSH PRIVILEGES;"

        # EOF(end-of-file) IS ALTERNATIVE METHOD, MORE VERBOSE
        #mysql --user=root << EOF
        #    SET PASSWORD FOR 'root'@localhost = PASSWORD("$database_root_pass");
        #    ALTER USER 'root'@'localhost' IDENTIFIED BY '$database_root_pass';
        #    DELETE FROM mysql.user WHERE User='';
        #    DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
        #    DROP DATABASE IF EXISTS test;
        #    DELETE FROM mysql.db WHERE Db='test' OR Db='test\_%';
        #    FLUSH PRIVILEGES;
        #EOF
    }

    function creating_mariadb_user() {
        # Configuring MariaDB user
        massager_plus "Configuring MariaDB user"

        # making new user
        mysql -h ${database_host} -P ${database_port} -u ${database_root_user} -p"${database_root_pass}" -e "CREATE USER ${database_user}@'${database_user_access_host}' IDENTIFIED BY '$database_pass';"
        mysql -h ${database_host} -P ${database_port} -u ${database_root_user} -p"${database_root_pass}" -e "FLUSH PRIVILEGES;"
    }

    function creating_mariadb_database() {
        # Creating New Database
        massager_plus "Creating New Database"

        # making new database
        mysql -h ${database_host} -P ${database_port} -u ${database_root_user} -p"${database_root_pass}" -e "CREATE DATABASE ${database_db_name} CHARACTER SET ${database_db_charset} COLLATE ${database_db_collate};"
        mysql -h ${database_host} -P ${database_port} -u ${database_root_user} -p"${database_root_pass}" -e "GRANT ALL PRIVILEGES ON ${database_db_name}.* TO ${database_user}@'${database_user_access_host}';"
        mysql -h ${database_host} -P ${database_port} -u ${database_root_user} -p"${database_root_pass}" -e "FLUSH PRIVILEGES;"
    }

    start_mariadb;
    check_mariadb_is_alive;
    configure_mariadb_server;
    configure_mariadb_security;
    creating_mariadb_user;
    creating_mariadb_database;
    stop_mariadb;

}

function configure_wordpress() {
    # Configuring WordPress
    massager_plus "Configuring WordPress"

    function configure_apache_wordpress() {
        # Configuring Apache for WordPress
        massager_plus "Configure Apache for WordPress"

        # Configure Apache for WordPress

        local site_name="${site_name}"
        local site_path="${site_path}"
        local site_subdomain="${site_subdomain}"
        local site_root_domain="${site_root_domain}"
        local site_ssl_enabled="${site_ssl_enabled}"

        # configuring WordPress on Apache Server
        configure_apache

    }

    function configure_mariadb_wordpress() {
        # Configuring Configuring MariaDB for WordPress
        massager_plus "Configuring MariaDB for WordPress"
        
        local database_host="${database_host}"
        local database_root_user="${database_root_user}"
        local database_root_pass="${database_root_pass}"

        local database_user="${database_user}"
        local database_pass="${database_pass}"
        local database_user_access_host="${database_user_access_host}"
        local database_db_name="${database_db_name}"
        local database_db_charset="${database_db_charset}"
        local database_db_collate="${database_db_collate}"

        configure_mariadb
    }
    
    function configure_wordpress_security() {
        # Configuring WordPress Security
        massager_plus "Configuring WordPress Security"

        echo "Step not configured"
        exit 1;
    }

    function configure_wordpress_configs() {
        # Configuring WordPress configs
        massager_plus "Configuring WordPress configs"

        # setting variables on WordPress
        mv /var/www/wordpress/wp-config-sample.php /var/www/wordpress/wp-config.php
        # The name of the database for WordPress
        sed -i "/DB_NAME/s/database_name_here/${database_db_name}/" /var/www/wordpress/wp-config.php
        # Database username
        sed -i "/DB_USER/s/username_here/${database_user}/" /var/www/wordpress/wp-config.php 
        # database password
        sed -i "/DB_PASSWORD/s/password_here/${database_pass}/" /var/www/wordpress/wp-config.php
        # database hostname
        sed -i "/DB_HOST/s/localhost/${database_host}/" /var/www/wordpress/wp-config.php
        # Database charset
        sed -i "/DB_CHARSET/s/utf8/${database_db_charset}/" /var/www/wordpress/wp-config.php
        # Database collate
        sed -i "/DB_COLLATE/s/''/'${database_db_collate}'/" /var/www/wordpress/wp-config.php

    }

    configure_apache_wordpress
    configure_mariadb_wordpress
    #configure_wordpress_security
    configure_wordpress_configs
}
################################

function configure_server () {
    # configure server
    massager_line "Configure server"

    # configure WordPress 
    configure_wordpress
}

################################
## check steps ##

function check_configs_apache() {
    # Check config of Apache
    massager_plus "Check config of Apache"

    apachectl configtest
}

function check_configs_database() {
    # Check config of Database
    massager_plus "Check config of Database"

    echo "step not configured"
    exit 1;
}

function check_configs_wordpress() {
    #check config of database
    echo "step not configured"
    exit 1;
}

################################

function check_configs () {
    massager_line "Check Configs server"

    # check if the configuration file is ok.
    check_configs_apache
    #check_configs_database
    #check_configs_wordpress
}

################################
## test steps ##

function test_apache () {
    # Testing Apache
    massager_plus "Testing of Apache"


    # is running ????
    #service apache2 status
    #systemctl status  --no-pager -l apache2
    /etc/init.d/apache2 status
    ps -ef --forest | grep apache

    # is listening ?
    ss -pultan | grep :${port_http[0]}
    ss -pultan | grep :${port_https[0]}

    # is creating logs ????
    tail /var/log/apache2/*

    # Validating...

    ## scanning apache ports using NETCAT
    nc -zv localhost ${port_http[0]}
    nc -zv localhost ${port_https[0]}
    #root@wordpress:~# nc -zv localhost 80
    #Connection to localhost (::1) 80 port [tcp/http] succeeded!

    ## scanning apache ports using NMAP
    nmap -A localhost -sT -p ${port_http[0]} 
    nmap -A localhost -sT -p ${port_https[0]} 
    #root@wordpress:~# nmap -A localhost -sT -p 80
	#Starting Nmap 7.80 ( https://nmap.org ) at 2024-01-04 05:54 UTC
	#Nmap scan report for localhost (127.0.0.1)
	#Host is up (0.000091s latency).
	#Other addresses for localhost (not scanned): ::1
	#
	#PORT   STATE SERVICE VERSION
	#80/tcp open  http    Apache httpd 2.4.56 ((Debian))
	#|_http-server-header: Apache/2.4.56 (Debian)
	#| http-title: WordPress &rsaquo; Setup Configuration File
	#|_Requested resource was http://localhost/wp-admin/setup-config.php
	#Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
	#Device type: general purpose
	#Running: Linux 2.6.X
	#OS CPE: cpe:/o:linux:linux_kernel:2.6.32
	#OS details: Linux 2.6.32
	#Network Distance: 0 hops
	#
	#OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
	#Nmap done: 1 IP address (1 host up) scanned in 8.56 seconds

    ## simulating web requests using CURL
    curl --head http://localhost
    #root@wordpress:~# curl --head http://localhost
    #HTTP/1.1 302 Found
    #Date: Thu, 04 Jan 2024 05:17:38 GMT
    #Server: Apache/2.4.56 (Debian)
    #Location: http://localhost/wp-admin/setup-config.php
    #Content-Type: text/html; charset=UTF-8

    curl -v http://localhost
    #root@wordpress:~# curl http://localhost -v
    #*   Trying ::1:80...
    #* Connected to localhost (::1) port 80 (#0)
    #> GET / HTTP/1.1
    #> Host: localhost
    #> User-Agent: curl/7.74.0
    #> Accept: */*
    #> 
    #* Mark bundle as not supporting multiuse
    #< HTTP/1.1 302 Found
    #< Date: Thu, 04 Jan 2024 05:18:21 GMT
    #< Server: Apache/2.4.56 (Debian)
    #< Location: http://localhost/wp-admin/setup-config.php
    #< Content-Length: 0
    #< Content-Type: text/html; charset=UTF-8
    #< 
    #* Connection #0 to host localhost left intact

}

function test_mariadb () {
    # Testing MariaDB
    massager_plus "Testing of MariaDB"

    # is running ????
    #service mariadb status
    #systemctl status  --no-pager -l mariadb
    /etc/init.d/mariadb status
    ps -ef --forest | grep mariadb

    # is listening ?
    ss -pultan | grep :${database_bind_port}

    # is creating logs ????
    tail /var/log/mysql/*

    # Validating...

    ## scanning apache ports using NETCAT
    nc -zv localhost ${database_bind_port}
    #root@wordpress:~# nc -zv localhost 3306
    #nc: connect to localhost (::1) port 3306 (tcp) failed: Connection refused
    #Connection to localhost (127.0.0.1) 3306 port [tcp/mysql] succeeded!


    ## scanning apache ports using NMAP
    nmap -A localhost -sT -p ${database_bind_port}
    #root@wordpress:~# nmap -A localhost -sT -p 3306
	#Starting Nmap 7.80 ( https://nmap.org ) at 2024-01-07 15:49 UTC
	#Nmap scan report for localhost (127.0.0.1)
	#Host is up (0.00013s latency).
	#Other addresses for localhost (not scanned): ::1
	#
	#PORT     STATE SERVICE VERSION
	# 3306/tcp open  mysql   MySQL 5.5.5-10.5.21-MariaDB-0+deb11u1-log
	#| mysql-info: 
	#|   Protocol: 10
	#|   Version: 5.5.5-10.5.21-MariaDB-0+deb11u1-log
	#|   Thread ID: 8
	#|   Capabilities flags: 63486
	#|   Some Capabilities: IgnoreSigpipes, Speaks41ProtocolOld, Support41Auth, SupportsTransactions, ConnectWithDatabase, ODBCClient, SupportsLoadDataLocal, Speaks41ProtocolNew, IgnoreSpaceBeforeParenthesis, InteractiveClient, LongColumnFlag, SupportsCompression, DontAllowDatabaseTableColumn, FoundRows, SupportsMultipleStatments, SupportsAuthPlugins, SupportsMultipleResults
	#|   Status: Autocommit
	#|   Salt: 5C.[bZ})P6\LHeBZ~-`~
	#|_  Auth Plugin Name: mysql_native_password
	#Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
	#Device type: general purpose
	#Running: Linux 2.6.X
	#OS CPE: cpe:/o:linux:linux_kernel:2.6.32
	#OS details: Linux 2.6.32
	#Network Distance: 0 hops
	#
	#OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
	#Nmap done: 1 IP address (1 host up) scanned in 2.66 seconds

    echo -e "\n" | telnet localhost ${database_bind_port}
}

################################

function test_server () {
    massager_line "Testing server"

    # testing Apache
    test_apache

    # testing mariadb
    test_mariadb
}

################################

# end main functions
# ============================== #

# end definition functions
# ============================================================ #
# start argument reading

# end argument reading
# ============================================================ #
# start main executions of code
massager_sharp "Starting WordPress installation script"
pre_install_server;
install_server;
stop_server;
configure_server;
check_configs;
start_server;
test_server;
massager_sharp "Finished WordPress installation script"

