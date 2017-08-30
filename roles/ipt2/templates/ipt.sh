#!/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
Path=$( cd "$( dirname "\$0" )" && pwd )

### Modules load ###
{% if (  ip_conntrack_ftp is defined ) and (  ip_conntrack_ftp == "YES" ) %}
# add ip_conntrack_ftp
modprobe ip_conntrack_ftp
{% endif %}

##############
iptables -F
iptables -P INPUT DROP
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
iptables -A INPUT -i lo -j ACCEPT

## create chain
## true 
ipset -N trueips iphash
ipset -N truenets nethash
ipset -N botipnets nethash

## badips
ipset -N badips iphash
ipset -N badnets nethash
{% if iptimeout is defined %}
ipset -N badipstime   hash:ip timeout {{iptimeout}}
{% endif %}
{% if nettimeout is defined %}
ipset -N badnetstime   hash:net timeout {{nettimeout}}
{% endif %}

### tables 
iptables -N f2b-sshd
iptables -N ispmgr_allow_ip
iptables -N ispmgr_allow_sub
iptables -N ispmgr_deny_ip
iptables -N ispmgr_deny_sub



#########  ESTABLISHED
iptables -A INPUT -p all -m state --state RELATED,ESTABLISHED -j ACCEPT


{% if (  AntiDDoS is defined ) and (  AntiDDoS == "YES" ) %}

# anti DDoS
iptables -A INPUT -p tcp -m tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s -j ACCEPT
{% endif %}

# antispoofing
iptables -I INPUT -m conntrack --ctstate NEW,INVALID -p tcp --tcp-flags SYN,ACK SYN,ACK -j REJECT --reject-with tcp-reset


########## TRUST
iptables -A INPUT -p all -m state --state RELATED,ESTABLISHED -j ACCEPT


{% if ( TrueIPs is defined ) and ( TrueIPs == "YES" ) %}
######### true_ip

if [ -e "${Path}/true.ip" ] 
then
	while read  true_ip
	do
		if [[ ! $true_ip =~ ^#|^$ ]]
		then	
			ipset -A trueips  ${true_ip}
		fi
	done < ${Path}/true.ip
fi
if [ -e "${Path}/truenets.ip" ] 
then
	while read  true_ip
	do
		if [[ ! $true_ip =~ ^#|^$ ]]
		then	
			ipset -A truenets  ${true_ip}
		fi
	done < ${Path}/truenets.ip
fi
{% endif %}


{% if ( Bots is defined ) and ( Bots == "YES" ) %}

######### Google bot
if [ -e "${Path}/google.bot.ip" ]
then
	while read  true_ip
	do
		if [[ ! $true_ip =~ ^#|^$ ]]
		then	
			ipset -A botipnets ${true_ip}
		fi
	done < ${Path}/google.bot.ip
fi
######## Yandex bot
if [ -e "${Path}/yandex.bot.ip" ]
then
	while read  true_ip
	do	
		if [[ ! $true_ip =~ ^#|^$ ]]
		then 
			ipset -A botipnets ${true_ip}
		fi
	done < ${Path}/yandex.bot.ip
fi
{% endif %}

######## protection 
{% if ( BadIPs is defined ) and ( BadIPs == "YES" ) %}
######## Bad IP 
if [ -e "${Path}/bad.ip" ]
then
	while read  bad_ip
	do	
		if [[ ! $bad_ip =~ ^#|^$ ]]
		then 
                        ipset -A badips ${bad_ip}
		fi
	done < ${Path}/bad.ip
fi
if [ -e "${Path}/badnets.ip" ]
then
	while read  bad_ip
	do	
		if [[ ! $bad_ip =~ ^#|^$ ]] 
		then 
                        ipset -A badnets ${bad_ip}
		fi
	done < ${Path}/badnets.ip
fi
{% endif %}

iptables -A INPUT -p all -m set --match-set trueips  src -j ACCEPT
iptables -A INPUT -p all -m set --match-set truenets  src -j ACCEPT


iptables -A INPUT -m set --match-set badips  src -j DROP
iptables -A INPUT -m set --match-set badipstime  src -j DROP
iptables -A INPUT -m set --match-set badnets src -j DROP
iptables -A INPUT -m set --match-set badnetstime src -j DROP


{% include  "files/" + ansible_hostname  + ".conf" ignore missing %}

{% if ( ssh_ports is defined ) and ( connlimit_ssh is defined ) %}
########## SSH 
ssh_port={{ssh_ports}}

iptables -A INPUT -p tcp -m multiport --dports ${ssh_port} -j f2b-sshd
iptables -A INPUT -m set --match-set f2b-sshd src -j RETURN

iptables -A INPUT  -p tcp -m multiport  --dport ${ssh_port}  -m connlimit --connlimit-above {{connlimit_ssh}} -j LOG --log-prefix "iptables: " --log-level 4
iptables -A INPUT  -p tcp -m multiport  --dport ${ssh_port}  -m connlimit --connlimit-above {{connlimit_ssh}} -j REJECT
iptables -A INPUT  -p tcp -m multiport  --dport ${ssh_port} -j ACCEPT
{% endif %}


{% if ( www_ports is defined ) and ( connlimit_www is defined ) %}
########## WEB
www_port={{www_ports}}

iptables -A INPUT  -p tcp -m set --match-set botipnets src  -m multiport  --dport ${www_port} -j ACCEPT
iptables -A INPUT  -p tcp -m multiport  --dport ${www_port}  -m connlimit --connlimit-above {{connlimit_www}} -j LOG --log-prefix "iptables: " --log-level 4
iptables -A INPUT  -p tcp -m multiport  --dport ${www_port}  -m connlimit --connlimit-above {{connlimit_www}} -j REJECT
iptables -A INPUT  -p tcp -m multiport  --dport ${www_port} -j ACCEPT
{% endif %}



{% if ( additional_tcp_ports is defined ) and ( connlimit_add_tcp is defined ) %}
# TCP additionals 
add_tcp_ports={{additional_tcp_ports}}
iptables -A INPUT  -p tcp -m multiport  --dport ${add_tcp_ports}  -m connlimit --connlimit-above {{connlimit_add_tcp}} -j LOG --log-prefix "iptables: " --log-level 4
iptables -A INPUT  -p tcp -m multiport  --dport ${add_tcp_ports}  -m connlimit --connlimit-above {{connlimit_add_tcp}} -j REJECT
iptables -A INPUT  -p tcp -m multiport  --dport ${add_tcp_ports} -j ACCEPT
{% endif %}

{% if ( additional_udp_ports is defined ) and ( connlimit_add_udp  is defined ) %}
# UDP additionals
add_udp_ports={{additional_udp_ports}}
iptables -A INPUT  -p udp -m multiport  --dport ${add_udp_ports}  -m connlimit --connlimit-above {{connlimit_add_udp}} -j LOG --log-prefix "iptables: " --log-level 4
iptables -A INPUT  -p udp -m multiport  --dport ${add_udp_ports}  -m connlimit --connlimit-above {{connlimit_add_udp}} -j REJECT
iptables -A INPUT  -p udp -m multiport  --dport ${add_udp_ports} -j ACCEPT
{% endif %}

{% if ( ICMP is defined ) and ( ICMP == "YES" ) %}
#  ICMP
iptables  -A INPUT -p icmp -j ACCEPT 
{% endif %}


echo "Finish !!!"
exit 0
