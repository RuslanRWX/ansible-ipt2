#!/bin/sh

PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
file='/var/log/iptables.log'
botresult='/tmp/bot.result.log'

Count="2"
Time="5"
addr='noc@host4.biz'
CheckPorts='80 443 1500 22 53 21 3306 25 26 110 143 465 587 993 995'
Pid="/tmp/ban.pid"
echo $$ > /tmp/ban.pid


FailMyBan () {


Mark=`date +%s`
read OldMark < /tmp/zabbix.mark.nginx.error.txt

for Port in $CheckPorts
do
#echo $Port
gr="DPT=${Port}"
	grep -A100000000  -w "$OldMark" $file | grep -E "$gr" | awk -F"="  '{ print $5 }' | sed "s/\ //;s/DST//" | sort | uniq -c  > /tmp/check.all.${Port}.txt 

#echo "check"
#cat /tmp/check.all.${Port}.txt

	cat /tmp/check.all.${Port}.txt | awk -v R=$Count '{ if ( $R < $1 ) print $2  }' > /tmp/ipsetadd.${Port}.txt

#echo "ips"
#cat /tmp/ipsetadd.${Port}.txt


		if [ "`cat  /tmp/ipsetadd.${Port}.txt`"  != "" ] 
		then
#echo have data in ipsetadd.${Port}.txt

			while read IP
			do
			echo "Date: `date`.  Banned IP: "$IP 
			ipset test  badipstime $IP ||  ipset add  badipstime  $IP
			echo   "Date `date`  $IP has banned. Many connections on port $Port" | mail -s "Firewall has Baded IP"  $addr 
			done < /tmp/ipsetadd.${Port}.txt
			fi


done
echo "zabbix mark $Mark" >> $file
echo "zabbix mark $Mark" > /tmp/zabbix.mark.nginx.error.txt

}


echo "Start ban `date`" > /var/log/ban.log
while true 
do
#echo "start check `date`  mark "$Mark
FailMyBan >> /var/log/ban.log
#FailMyBan 
sleep $Time;
done

exit 0

