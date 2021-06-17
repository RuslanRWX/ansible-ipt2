#!/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
Path=$( cd "$( dirname "\$0" )" && pwd )

Stop () {

iptables -F
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
iptables -A INPUT -i lo -j ACCEPT
ipset flush
## delete chain
ipset -X trueips
ipset -X truenets
ipset -X botipnets
ipset -X badips
ipset -X badnets
ipset -X badipstime
ipset -X badnetstime
iptables -X fail2ban-sshd

echo "Stopped"
iptables -S
ipset flush

}

Start () {

$Path/ipt.sh
echo "Started"
	
}



case $1 in
      start)  
      Start
;;
      stop)
      Stop
;;
      restart)
      Stop
      Start
;;
     *)
echo "stop|start|restart"
;;

esac

 exit 0
