#!/bin/bash

#
# colors
#
RED='\033[0;31m'
NC='\033[0m' # No Color
GREEN='\033[0;32m'
YELLOW='\033[0;33m'


#
#errors
#
function my_error() {
        if [ $? -ne 0 ];then
                echo "NOK"
        fi
}

#
# Get sys. informations
#

if [ -f /etc/redhat-release ];then
    os_release="EMS $(cat /etc/redhat-release)"
elif [ -f /etc/debian_version ];then
    os_release="$(cat /etc/debian_version)"
elif [ -f /etc/lsb-release ];then
    . /etc/lsb-release
    os_release=$(echo "$DISTRIB_ID $DISTRIB_RELEASE $DISTRIB_CODENAME")
else
    os_release="$(uname -a)"
fi


############################
# Get database credentials #
############################

database_host=$(grep "hostCentreon" /etc/centreon/centreon.conf.php | cut -f 2 -d '"')
database_user=$(grep "conf_centreon\['user'\]" /etc/centreon/centreon.conf.php | cut -f 2 -d '"')
database_passwd=$(grep "conf_centreon\['password'\]" /etc/centreon/centreon.conf.php | cut -f 4 -d "'")

###########################
# Get scope of the server #
###########################

poller_count=$(mysql -h $database_host -u $database_user -p$database_passwd -s -N -e "SELECT count(*) FROM centreon_storage.instances WHERE deleted='0'")
host_count=$(mysql -h $database_host -u $database_user -p$database_passwd -s -N -e "SELECT count(*) FROM centreon_storage.hosts WHERE enabled='1'")
passive_service_count=$(mysql -h $database_host -u $database_user -p$database_passwd -s -N -e "SELECT count(*) FROM centreon_storage.services WHERE enabled='1' AND passive_checks")
active_service_count=$(mysql -h $database_host -u $database_user -p$database_passwd -s -N -e "SELECT count(*) FROM centreon_storage.services WHERE enabled='1' AND active_checks")
metric_count=$(mysql -h $database_host -u $database_user -p$database_passwd -s -N -e "SELECT count(*) FROM centreon_storage.metrics")
total_service_count=$(( $active_service_count+$passive_service_count ))
if [ ! -z "$bam_installed" ]; then
    ba_count=$(mysql -h $database_host -u $database_user -p$database_passwd -s -N -e "SELECT count(*) FROM centreon.mod_bam")
else
    ba_count=0
fi

######################
# Get databases size #
######################

centreon_db_size=$(mysql -h $database_host -u $database_user -p$database_passwd -s -N -e "SELECT SUM(data_length+index_length) FROM information_schema.tables WHERE table_schema='centreon'")
centstorage_db_size=$(mysql -h $database_host -u $database_user -p$database_passwd -s -N -e "SELECT SUM(data_length+index_length) FROM information_schema.tables WHERE table_schema='centreon_storage'")

###############################
# Get partition size (on hdd) #
###############################

#data_bin_avg_part_size=$(find /var/lib/mysql/centreon_storage/data_bin* -newerat $(date --date="30 day ago" +"%Y-%m-%d") ! -newerat $(date --date="10 day ago" +"%Y-%m-%d") -exec du -s {} \;| awk '{SIZE+=$1} END {print SIZE}')
if [ "$database_host" == "127.0.0.1" ] || [ "$database_host" == "localhost" ];then
        data_bin_ten_part_size=`stat -c "%Y %s" /var/lib/mysql/centreon_storage/data_bin#P#p* | awk -v old_date="$(date --date='30 day ago' +%s )" -v new_date="$(date --date='20 day ago' +%s)" -F " " '{if ($1>=old_date && $1<=new_date)size+=$2; print size}' | tail -1`
        logs_ten_part_size=`stat -c "%Y %s" /var/lib/mysql/centreon_storage/logs#P#p* | awk -v old_date="$(date --date='30 day ago' +%s )" -v new_date="$(date --date='20 day ago' +%s)" -F " " '{if ($1>=old_date && $1<=new_date)size+=$2; print size}' | tail -1`
        log_a_host_ten_part_size=`stat -c "%Y %s" /var/lib/mysql/centreon_storage/log_archive_host* | awk -v old_date="$(date --date='30 day ago' +%s )" -v new_date="$(date --date='20 day ago' +%s)" -F " " '{if ($1>=old_date && $1<=new_date)size+=$2; print size}' | tail -1`
        log_a_service_ten_part_size=`stat -c "%Y %s" /var/lib/mysql/centreon_storage/log_archive_service* | awk -v old_date="$(date --date='30 day ago' +%s )" -v new_date="$(date --date='20 day ago' +%s)" -F " " '{if ($1>=old_date && $1<=new_date)size+=$2; print size}' | tail -1`


elif [ "$database_host" != "127.0.0.1" ] && [ "$database_host" != "localhost" ];then
        echo -e "${YELLOW}PLEASE ENTER YOUR $USER PASSWORD IN ORDER TO CONNECT TO $database_host$ SHELL${NC}"
        echo -e "${GREEN}we are just doing a stat command on /var/lib/mysql/centreon_storage to check tables partition state${NC}"
        tables_part_ssh=$(ssh $database_host 'echo "<DATA_BIN>" && stat -c "%Y %s" /var/lib/mysql/centreon_storage/data_bin#P#p* && echo "</DATA_BIN>" && echo "<LOGS>" && stat -c "%Y %s" /var/lib/mysql/centreon_storage/logs#P#p* && echo "</LOGS>" && echo "<LOGAH>" && stat -c "%Y %s" /var/lib/mysql/centreon_storage/log_archive_host* && echo "</LOGAH>" && echo "<LOGAS>" && stat -c "%Y %s" /var/lib/mysql/centreon_storage/log_archive_service* && echo "</LOGAS>"' < /dev/null)
        data_bin_ten_part_size=$(echo "$tables_part_ssh" | sed -n '/<DATA_BIN>/,/<\/DATA_BIN>/p' | egrep -v '<DATA_BIN>|</DATA_BIN>' | awk -v old_date="$(date --date='30 day ago' +%s )" -v new_date="$(date --date='20 day ago' +%s)" -F " " '{if ($1>=old_date && $1<=new_date)size+=$2; print size}' | tail -1)
        logs_ten_part_size=$(echo "$tables_part_ssh" | sed -n '/<LOGS>/,/<\/LOGS>/p' | egrep -v '<LOGS>|</LOGS>' | awk -v old_date="$(date --date='30 day ago' +%s )" -v new_date="$(date --date='20 day ago' +%s)" -F " " '{if ($1>=old_date && $1<=new_date)size+=$2; print size}' | tail -1)
        log_a_host_ten_part_size=$(echo "$tables_part_ssh" | sed -n '/<LOGAH>/,/<\/LOGAH>/p' | egrep -v '<LOGAH>|</LOGAH>' | awk -v old_date="$(date --date='30 day ago' +%s )" -v new_date="$(date --date='20 day ago' +%s)" -F " " '{if ($1>=old_date && $1<=new_date)size+=$2; print size}' | tail -1)
        log_a_service_ten_part_size=$(echo "$tables_part_ssh" | sed -n '/<LOGAS>/,/<\/LOGAS>/p' | egrep -v '<LOGAS>|</LOGAS>' | awk -v old_date="$(date --date='30 day ago' +%s )" -v new_date="$(date --date='20 day ago' +%s)" -F " " '{if ($1>=old_date && $1<=new_date)size+=$2; print size}' | tail -1)
fi

if [ ! -z "$data_bin_ten_part_size" ];then
        data_bin_avg_part_size=$(( $data_bin_ten_part_size/10 ))
else
        data_bin_avg_part_size=""
fi

if [ ! -z "$logs_ten_part_size" ];then
        logs_avg_part_size=$(( $logs_ten_part_size/10 ))
else
        logs_avg_part_size=""
fi

if [ ! -z "$log_a_host_ten_part_size" ];then
        log_a_host_avg_part_size=$(( $log_a_host_ten_part_size/10 ))
else
        log_a_host_avg_part_size=""
fi

if [ ! -z "$log_a_service_ten_part_size" ];then
        log_a_service_avg_part_size=$(( $log_a_service_ten_part_size/10 ))
else
        log_a_service_avg_part_size=""
fi

#################################
# Get graphs and related things #
#################################

size_rrd_metrics=$(du -sb /var/lib/centreon/metrics/ |grep -o '[0-9]\+')
size_rrd_status=$(du -sb /var/lib/centreon/status/ |grep -o '[0-9]\+')

count_rrd_metrics=$(ls -l /var/lib/centreon/metrics/ | wc -l)
count_rrd_status=$(ls -l /var/lib/centreon/status/ | wc -l)

rrd_metrics_outdated=$(find /var/lib/centreon/metrics/ -type f -mmin +288000 | wc -l)
rrd_status_outdated=$(find /var/lib/centreon/status/ -type f -mmin +288000 | wc -l)

###########################
# Get Central system info #
###########################

memory_size_central=$(cat /proc/meminfo | grep 'MemTotal' | awk '{print $2*1024}')
cpu_numbers_central=$(cat /proc/cpuinfo | grep 'cpu cores' | awk '{print $4}' | wc -l)
cpu_frequency_central=$(cat /proc/cpuinfo | grep 'cpu MHz' | awk '{print $4/1000}' | uniq)

##########################
# Get Poller system info #
##########################

declare -A os_release=()
declare -A memory_size=()
declare -A cpu_numbers=()
declare -A cpu_frequency=()
get_pollers_info=$(mysql -u $database_user -p$database_passwd -h $database_host --skip-column-names --execute="select ns_ip_address from centreon.nagios_server where ns_ip_address!='127.0.0.1' and ns_ip_address!='localhost';")
if [ ! -z "$get_pollers_info" ];then
    while read -r line;do
        poller_ip="$line"
        os_release[$poller_ip]=$(runuser centreon -c "ssh centreon@$poller_ip \"cat /etc/redhat-release\"" < /dev/null)
        rc=$(my_error)
        memory_size[$poller_ip]=$(runuser centreon -c "ssh centreon@$poller_ip \"cat /proc/meminfo | grep 'MemTotal' | awk '{print \\\$2*1024}'\"" < /dev/null)
        rc=$(my_error)
        cpu_numbers[$poller_ip]=$(runuser centreon -c "ssh centreon@$poller_ip \"cat /proc/cpuinfo | grep 'cpu cores' | awk '{print \\\$4}' | wc -l\"" < /dev/null)
        rc=$(my_error)
        cpu_frequency[$poller_ip]=$(runuser centreon -c "ssh centreon@$poller_ip \"cat /proc/cpuinfo | grep 'cpu MHz' | awk '{print \\\$4/1000}' | uniq\"" < /dev/null)
        rc=$(my_error)
        if [ "$rc" == "NOK" ];then
                echo -e "${YELLOW}#################################${NC}"
                echo -e "${YELLOW}Couldn't get $poller_ip information${NC}"
                echo -e "${YELLOW}#################################${NC}"
        fi
        poller_sysinfo_label="$poller_sysinfo_label,os_release_$poller_name,memory_size_$poller_name (in Bytes),cpu_numbers_$poller_name,cpu_frequency_$poller_name (in GHz)"
        poller_sysinfo_value="$poller_sysinfo_value,${os_release[$poller_ip]},${memory_size[$poller_ip]},${cpu_numbers[$poller_ip]},${cpu_frequency[$poller_ip]}"
    done <<< "$get_pollers_info"
fi
echo -e "${GREEN}#################################${NC}"
echo -e "${GREEN}          YOUR RESULT ${NC}"
echo -e "${GREEN} please copy the following line${NC}"
echo -e "${GREEN}#################################${NC}"
echo ",,$poller_count,$host_count,$active_service_count,$passive_service_count,$total_service_count,$metric_count,$ba_count,$centreon_db_size,$centstorage_db_size,$data_bin_ten_part_size,$logs_ten_part_size,$log_a_host_ten_part_size,$log_a_service_ten_part_size,$size_rrd_metrics,$size_rrd_status,$count_rrd_metrics,$count_rrd_status,$rrd_metrics_outdated,$rrd_status_outdated,$memory_size_central,$cpu_numbers_central,$cpu_frequency_central$poller_sysinfo_value"
