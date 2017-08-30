#!/bin/sh

file="/var/log/iptables/ipt.log"


AddFile () {	
	/bin/rm /tmp/check.bot.tmp
	/bin/cat $file | awk -F"=" '{ print $5 }' | sort -u | sed "s/\ //;s/DST//" >> /tmp/check.bot.tmp
}


CheckIP () {
#/bin/rm /tmp/bot.result.log

while read IP 
do
echo "check "$IP >> /tmp/bot.result.log
whois $IP | grep -iE "google|yandex"  >> /tmp/bot.result.log
#echo $IP

done < /tmp/check.bot.tmp
}


AddFile
CheckIP


