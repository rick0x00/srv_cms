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

os_distribution="debian"
os_version=("11" "bullseye")

database_engine="mysql"
webserver_engine="apache"

port_http[0]="80" # http number Port
port_http[1]="tcp" # tcp protocol Port 

port_https[0]="443" # http number Port
port_https[1]="tcp" # tcp protocol Port 

workdir="/var/www/"
persistence_volumes=("/var/www/" "/var/log/")
expose_ports="${port_http[0]}/${port_http[1]} ${port_https[0]}/${port_https[1]}"
# end set variables
# ============================================================ #
