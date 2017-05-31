#!/bin/bash
#set -x
# 
# script name :         security.sh
# created on  :         May 15, 2017
# created by  :         Dheepan Swaminathan
# version     :         1.0
#--- Need root permissions to run script
if [ "$(id -u)" != "0" ]; then
	echo ERROR!......... ERROR!............ ERROR!............
	echo
   	echo "CAUTION:- This script must be run as root user." 1>&2
	echo
   exit 1
fi

>/tmp/security_remediation_output.txt

####Writing Function for each Security Vulnerabilities #######

PASS_MAX_DAYS () {

	printf "PASSWORD MAXIMUM DAYS:- \n" >> /tmp/security_remediation_output.txt
	printf "======================= \n" >> /tmp/security_remediation_output.txt
	printf  "\t\t The Value of PASS_MAX_DAYS Before Remediation :- `grep -v ^# /etc/login.defs | grep  PASS_MAX_DAYS | awk '{print $2}'` \n"  >> /tmp/security_remediation_output.txt
	sed -i '/PASS_MAX_DAYS/s/[0-9]\+/30/g' /etc/login.defs
	printf  "\t\t The Value of PASS_MAX_DAYS After Remediation :- `grep -v ^# /etc/login.defs | grep PASS_MAX_DAYS| awk '{print $2}'` \n \n"  >> /tmp/security_remediation_output.txt

}


PASS_MIN_LEN () {

	printf "PASSWORD MINIMUM LENGTH:- \n" >> /tmp/security_remediation_output.txt
	printf "======================== \n" >> /tmp/security_remediation_output.txt
	printf "\t\t The Value of PASS_MIN_LEN Before Remediation :- `grep -v ^#  /etc/login.defs | grep PASS_MIN_LEN | awk '{print $2}'` \n" >> /tmp/security_remediation_output.txt
	sed -i '/PASS_MIN_LEN/s/[0-9]\+/8/g' /etc/login.defs
	printf "\t\t The Value of PASS_MIN_LEN After Remediation :- `grep -v ^#  /etc/login.defs | grep PASS_MIN_LEN | awk '{print $2}'` \n \n" >> /tmp/security_remediation_output.txt
}


PASS_MIN_DAYS () {
	printf "PASSWORD MINIMUM DAYS:- \n" >> /tmp/security_remediation_output.txt
	printf "======================= \n" >> /tmp/security_remediation_output.txt
	printf "\t\t The Value of PASS_MIN_DAYS Before Remediation :- `grep -v ^#  /etc/login.defs | grep PASS_MIN_DAYS | awk '{print $2}'` \n" >> /tmp/security_remediation_output.txt
	sed -i '/PASS_MIN_DAYS/s/[0-9]\+/1/g' /etc/login.defs
	printf "\t\t The Value of PASS_MIN_DAYS After Remediation :- `grep -v ^#  /etc/login.defs | grep PASS_MIN_DAYS | awk '{print $2}'` \n \n " >> /tmp/security_remediation_output.txt
}


PASSWORD_HIST () {
	PASS_REM=`grep -v ^# /etc/pam.d/system-auth | grep "remember=" | wc -l`
	if [ $PASS_REM -eq 1 ];  then
		printf "PASSWORD HISTORY:- \n" >> /tmp/security_remediation_output.txt
		printf "================== \n" >> /tmp/security_remediation_output.txt
		printf "\t\t The Value of PASSWORD_HISTORY Before Remediation :- `grep -v ^# /etc/pam.d/system-auth | grep remember | awk '{print $9}'` \n" >> /tmp/security_remediation_output.txt
		sed -i '/remember=/s/[0-9]\+/5/g' /etc/pam.d/system-auth
		printf "\t\t The Value of PASSWORD_HISTORY After Remediation :- `grep -v ^# /etc/pam.d/system-auth | grep remember | awk '{print $9}'` \n \n" >> /tmp/security_remediation_output.txt
	else
		printf "PASSWORD HISTORY:- \n" >> /tmp/security_remediation_output.txt
		printf "================== \n" >> /tmp/security_remediation_output.txt
		printf "\t\t The Value of PASSWORD_HISTORY Before Remediation :- `grep -v ^# /etc/pam.d/system-auth | grep remember | awk '{print $9}'` \n" >> /tmp/security_remediation_output.txt
		sed -i '/use_authtok/ s/$/ remember=5/' /etc/pam.d/system-auth
		printf "\t\t The Value of PASSWORD_HISTORY After Remediation :- `grep -v ^# /etc/pam.d/system-auth | grep remember | awk '{print $9}'` \n \n" >> /tmp/security_remediation_output.txt
	fi
}


LOGIN_RETRIES () {
	LOGIN_RETRY=`grep -v ^# /etc/pam.d/system-auth | grep "retry=" | wc -l`
	if [ $LOGIN_RETRY -eq 1 ];  then
		printf "LOGIN_RETRIES:- \n" >> /tmp/security_remediation_output.txt
		printf "================ \n" >> /tmp/security_remediation_output.txt
		printf "\t\t The Value of LOGIN_RETRIES Before Remediation :- `grep -v ^# /etc/pam.d/system-auth | grep retry= | awk '{print $5}'` \n" >> /tmp/security_remediation_output.txt
		sed -i '/retry=/s/[0-9]\+/3/g' /etc/pam.d/system-auth
		printf "\t\t The Value of LOGIN_RETRIES After Remediation :- `grep -v ^# /etc/pam.d/system-auth | grep retry= | awk '{print $5}'` \n \n" >> /tmp/security_remediation_output.txt
	else
		printf "LOGIN_RETRIES:- \n" >> /tmp/security_remediation_output.txt
		printf "================ \n" >> /tmp/security_remediation_output.txt
		printf "\t\t The Value of LOGIN_RETRIES Before Remediation :- `grep -v ^# /etc/pam.d/system-auth | grep retry= | awk '{print $5}'` \n" >> /tmp/security_remediation_output.txt
		sed -i 's/pam_cracklib.so/& retry=3/' /etc/pam.d/system-auth
		printf "\t\t The Value of LOGIN_RETRIES After Remediation :- `grep -v ^# /etc/pam.d/system-auth | grep retry= | awk '{print $5}'` \n \n" >> /tmp/security_remediation_output.txt
	fi
}


#PERMIT_ROOT_LOGIN () {
#	PERMIT_VAL=`grep -v ^# /etc/ssh/sshd_config | grep "PermitRootLogin [a-z][a-z][a-z]" | wc -l`
#	if [ $PERMIT_VAL -gt 0 ]; then
#		printf "PERMIT ROOT LOGIN:- \n" >> /tmp/security_remediation_output.txt
#		printf "================== \n" >> /tmp/security_remediation_output.txt
#		printf "\t\t The Value of PERMIT_ROOT_LOGIN Before Remediation :- `grep -v ^# /etc/ssh/sshd_config | grep 'PermitRootLogin [a-z][a-z]' ` \n" >> /tmp/security_remediation_output.txt
#		sed -i '/PermitRootLogin=/s/\s[a-z]\+/no/g' /etc/ssh/sshd_config
#		sed -i '/PermitRootLogin/s/yes$/no/g' /etc/ssh/sshd_config
#		sed -i 's/^.*PermitRootLogin/PermitRootLogin /' /etc/ssh/sshd_config
		printf "\t\t The Value of PERMIT_ROOT_LOGIN After Remediation :- `grep -v ^# /etc/ssh/sshd_config | grep 'PermitRootLogin [a-z][a-z]' ` \n \n" >> /tmp/security_remediation_output.txt
#	else
#		printf "PERMIT ROOT LOGIN:- \n" >> /tmp/security_remediation_output.txt
#		printf "================== \n" >> /tmp/security_remediation_output.txt
#		printf "\t\t The Value of PERMIT_ROOT_LOGIN Before Remediation :- `grep -v ^# /etc/ssh/sshd_config | grep 'PermitRootLogin [a-z][a-z]' ` \n" >> /tmp/security_remediation_output.txt
#		echo "PermitRootLogin no" >> /etc/ssh/sshd_config
#		printf "\t\t The Value of PERMIT_ROOT_LOGIN After Remediation :- `grep -v ^# /etc/ssh/sshd_config | grep 'PermitRootLogin [a-z][a-z]' ` \n \n" >> /tmp/security_remediation_output.txt
#	fi
#}

WTMP () {
	printf "CHECK WTMP Files:- \n" >> /tmp/security_remediation_output.txt
	printf "================== \n" >> /tmp/security_remediation_output.txt
	ls -ld /var/log/wtmp > /dev/null 2>&1
	if [ $? -eq 0 ]; then
		printf "\t \t /var/log/wtmp File Exist on the server `uname -n`. \n \n " >> /tmp/security_remediation_output.txt
	else
		printf "\t \t /var/log/wtmp NOT File Exist on the server `uname -n`. \n \n" >> /tmp/security_remediation_output.txt
	fi

}

MESSAGES () {
	printf "CHECK /var/log/messages Files:- \n" >> /tmp/security_remediation_output.txt
	printf "=============================== \n" >> /tmp/security_remediation_output.txt
	ls -ld /var/log/messages > /dev/null 2>&1
	if [ $? -eq 0 ]; then
		printf "\t \t /var/log/messages File Exist on the server `uname -n`. \n \n " >> /tmp/security_remediation_output.txt
	else
		printf "\t \t /var/log/messages NOT File Exist on the server `uname -n`. \n \n" >> /tmp/security_remediation_output.txt
	fi

}

TALLYLOG () {
	printf "CHECK /var/log/tallylog Files:- \n" >> /tmp/security_remediation_output.txt
	printf "=============================== \n" >> /tmp/security_remediation_output.txt
	ls -ld /var/log/tallylog > /dev/null 2>&1
	if [ $? -eq 0 ]; then
		printf "\t \t /var/log/tallylog File Exist on the server `uname -n`. \n \n " >> /tmp/security_remediation_output.txt
	else
		printf "\t \t /var/log/tallylog NOT File Exist on the server `uname -n`. \n \n" >> /tmp/security_remediation_output.txt
	fi

}

SECURE () {
	printf "CHECK /var/log/secure Files:- \n" >> /tmp/security_remediation_output.txt
	printf "=============================== \n" >> /tmp/security_remediation_output.txt
	ls -ld /var/log/secure > /dev/null 2>&1
	if [ $? -eq 0 ]; then
		printf "\t \t /var/log/secure File Exist on the server `uname -n`. \n \n " >> /tmp/security_remediation_output.txt
	else
		printf "\t \t /var/log/secure NOT File Exist on the server `uname -n`. \n \n" >> /tmp/security_remediation_output.txt
	fi

}

HOST_EQUIV () {
	printf "CHECK HOST.EQUIV File:- \n" >> /tmp/security_remediation_output.txt
	printf "======================= \n" >> /tmp/security_remediation_output.txt
	ls -ld /etc/hosts.equiv > /dev/null 2>&1
	if [ $? -eq 0 ]; then
		printf "\t \t /etc/hosts.equiv File Exist on the server `uname -n`. \n \n " >> /tmp/security_remediation_output.txt
	else
		printf "\t \t /etc/hosts.equiv NOT File Exist on the server `uname -n`. \n \n" >> /tmp/security_remediation_output.txt
	fi
}

RLOGIN_RSH () {
	printf "CHECK RLOGIN_RSH File:- \n" >> /tmp/security_remediation_output.txt
	printf "======================= \n" >> /tmp/security_remediation_output.txt
	(ls -ld /etc/pam.d/rlogin > /dev/null 2>&1 ) && (ls -ld /etc/pam.d/rsh > /dev/null 2>&1 )
	if [ $? -eq 0 ]; then
		printf "\t \t /etc/pam.d/rlogin and /etc/pam.d/rlogin Files Exist on the server `uname -n`. \n \n " >> /tmp/security_remediation_output.txt
	else
		printf "\t \t /etc/pam.d/rlogin and /etc/pam.d/rlogin  NOT Files Exist on the server `uname -n`. \n \n " >> /tmp/security_remediation_output.txt
	fi
}

SYNCOOKIES () {
	printf "CHECK SYSCOOKIES in sysctl.conf:- \n" >> /tmp/security_remediation_output.txt
	printf "================================= \n" >> /tmp/security_remediation_output.txt
	SYN=`grep -v ^# /etc/sysctl.conf | grep syncookies | awk '{print $3}'`
	if [ $SYN -eq 1 ]; then
		printf "\t \t sysctl value of net.ipv4.tcp_syncookies on the server `uname -n` = $SYN \n \n " >> /tmp/security_remediation_output.txt
	elif [ $SYN -eq 0 ]; then
		printf "\t \t sysctl value of net.ipv4.tcp_syncookies on the server `uname -n` = $SYN \n \n " >> /tmp/security_remediation_output.txt
	else
		printf "\t \t sysctl value of net.ipv4.tcp_syncookies on the server `uname -n` IS NOT PRESENT.\n \n " >> /tmp/security_remediation_output.txt
	fi

}

BROADCASTS () {
	value=1
	printf "CHECK BROADCASTS in sysctl.conf:- \n" >> /tmp/security_remediation_output.txt
	printf "================================= \n" >> /tmp/security_remediation_output.txt

	icmp=$(cat /etc/sysctl.conf | grep -i broadcast | awk {'print $3'})

         if [ "$icmp" = "$value" ]; then

	printf "\t \t sysctl value of net.ipv4.icmp_echo_ignore_broadcasts on the server `uname -n` = $icmp \n \n " >> /tmp/security_remediation_output.txt	
	else 
 	echo "#Added as per tech-Spec" >>/etc/sysctl.conf
	echo -e "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf
	printf "\t \t sysctl value of net.ipv4.icmp_echo_ignore_broadcasts on the server = 1 `uname -n` \n \n " >> /tmp/security_remediation_output.txt

fi 

}

YPPASSWDD () {
        printf "CHECK /usr/sbin/rpc.yppasswdd Files:- \n" >> /tmp/security_remediation_output.txt
        printf "=============================== \n" >> /tmp/security_remediation_output.txt
        ls -ld /usr/sbin/rpc.yppasswdd > /dev/null 2>&1
        if [ $? -eq 0 ]; then
                printf "\t \t /usr/sbin/rpc.yppasswdd File Exist on the server `uname -n`.--NOK \n \n " >> /tmp/security_remediation_output.txt
        else
                printf "\t \t /usr/sbin/rpc.yppasswdd NOT File Exist on the server `uname -n`--OK. \n \n" >> /tmp/security_remediation_output.txt
        fi

}

YPBIND () {

SERVICE=ypbind
	printf "CHECK for ypbind service:- \n" >> /tmp/security_remediation_output.txt
	printf "=============================== \n" >> /tmp/security_remediation_output.txt
	if ps ax | grep -v grep | grep $SERVICE > /dev/null

then
	printf "\t \t ypbind runing on the server `uname -n`.--NOK \n \n " >> /tmp/security_remediation_output.txt    
	echo  "$(/etc/init.d/ypbind stop)"
	printf "\t \t ypbind service is stopping via cmd `uname -n`. \n \n " >> /tmp/security_remediation_output.txt
	
else
    	printf "\t \t ypbind is not runing on the server `uname -n`--OK. \n \n " >> /tmp/security_remediation_output.txt
    
fi

}

XINETD () {

SERVICE=xinetd
        printf "CHECK for ypbind service:- \n" >> /tmp/security_remediation_output.txt
        printf "=============================== \n" >> /tmp/security_remediation_output.txt
        if ps ax | grep -v grep | grep $SERVICE > /dev/null

then
        printf "\t \t xinetd runing on the server `uname -n`.--NOK \n \n " >> /tmp/security_remediation_output.txt
 #       echo  "$(/etc/init.d/ypbind stop)"
  #      printf "\t \t ypbind service is stopping via cmd `uname -n`. \n \n " >> /tmp/security_remediation_output.txt

else
        printf "\t \t xinted is not runing on the server `uname -n`--OK. \n \n " >> /tmp/security_remediation_output.txt

fi

}


SENDMAIL () {

SERVICE=sendmail
        printf "CHECK for sendmail service:- \n" >> /tmp/security_remediation_output.txt
        printf "=============================== \n" >> /tmp/security_remediation_output.txt
        if ps ax | grep -v grep | grep $SERVICE > /dev/null

then
        printf "\t \t sendmail runing on the server `uname -n`.--NOK \n \n " >> /tmp/security_remediation_output.txt

else
        printf "\t \t sendmail is not runing on the server `uname -n`--OK. \n \n " >> /tmp/security_remediation_output.txt

fi

}

HOST () {
        printf "CHECK ~root/.rhosts File:- \n" >> /tmp/security_remediation_output.txt
        printf "======================= \n" >> /tmp/security_remediation_output.txt
        ls -ld ~root/.rhosts > /dev/null 2>&1
        if [ $? -eq 0 ]; then
                printf "\t \t ~root/.rhosts File Exist on the server `uname -n`--NOK. \n \n " >> /tmp/security_remediation_output.txt
        else
                printf "\t \t ~root/.rhosts NOT File Exist on the server `uname -n`--OK. \n \n" >> /tmp/security_remediation_output.txt
        fi
}

NETRC () {

	printf "CHECK ~root/.netrc File:- \n" >> /tmp/security_remediation_output.txt
        printf "======================= \n" >> /tmp/security_remediation_output.txt
        ls -ld ~root/.netrc > /dev/null 2>&1
        if [ $? -eq 0 ]; then
                printf "\t \t ~root/.netrc File Exist on the server `uname -n`--NOK. \n \n " >> /tmp/security_remediation_output.txt
        else
                printf "\t \t ~root/.netrc NOT File Exist on the server `uname -n`--OK. \n \n" >> /tmp/security_remediation_output.txt
        fi
}

ROOTOSR () { 

	printf "CHECK / permission:- \n" >> /tmp/security_remediation_output.txt
        printf "======================= \n" >> /tmp/security_remediation_output.txt
	value=755
	root=$(stat -c "%a" /)
	if [ "$root" = "$value" ]; then 
		printf "\t \t / permission is 755 `uname -n`--OK. \n \n " >> /tmp/security_remediation_output.txt
	else 
		echo "$(chmod 755 /)" 
		printf "\t \t / permission updated as per techspec `uname -n`.= $value \n \n" >> /tmp/security_remediation_output.txt
fi 

}

USROSR () {

        printf "CHECK /usr permission:- \n" >> /tmp/security_remediation_output.txt
        printf "======================= \n" >> /tmp/security_remediation_output.txt
        value=755
        root=$(stat -c "%a" /usr)
        if [ "$root" = "$value" ]; then
                printf "\t \t /usr permission is 755 `uname -n`--OK. \n \n " >> /tmp/security_remediation_output.txt
        else
                echo "$(chmod 755 /usr)" 
                printf "\t \t /usr permission updated as per techspec `uname -n`.= $value \n \n" >> /tmp/security_remediation_output.txt
fi

}

ETCOSR () {

        printf "CHECK /etc permission:- \n" >> /tmp/security_remediation_output.txt
        printf "======================= \n" >> /tmp/security_remediation_output.txt
        value=755
        root=$(stat -c "%a" /etc)
        if [ "$root" = "$value" ]; then
                printf "\t \t /etc permission is 755 `uname -n`--OK. \n \n " >> /tmp/security_remediation_output.txt
        else
                echo "$(chmod 755 /etc)" 
                printf "\t \t /etc permission updated as per techspec `uname -n`.= $value \n \n" >> /tmp/security_remediation_output.txt
fi

}

OPASSWD () {

        printf "CHECK /etc/security/opasswd permission:- \n" >> /tmp/security_remediation_output.txt
        printf "======================= \n" >> /tmp/security_remediation_output.txt
        value=600
        root=$(stat -c "%a" /etc/security/opasswd)
        if [ "$root" = "$value" ]; then
                printf "\t \t /etc/security/opasswd permission is 600 `uname -n`--OK. \n \n " >> /tmp/security_remediation_output.txt
        else
                echo "$(chmod 600 /etc/security/opasswd)" 
                printf "\t \t /etc/security/opasswd permission updated as per techspec `uname -n`.= $value \n \n" >> /tmp/security_remediation_output.txt
fi

}

VAR () {

        printf "CHECK /var permission:- \n" >> /tmp/security_remediation_output.txt
        printf "======================= \n" >> /tmp/security_remediation_output.txt
        value=755
        root=$(stat -c "%a" /var)
        if [ "$root" = "$value" ]; then
                printf "\t \t /var permission is 755 `uname -n`--OK. \n \n " >> /tmp/security_remediation_output.txt
        else
                echo "$(chmod 755 /var)" 
                printf "\t \t /var permission updated as per techspec `uname -n`.= $value \n \n" >> /tmp/security_remediation_output.txt
fi

}

VARLOG () {

        printf "CHECK /var/log permission:- \n" >> /tmp/security_remediation_output.txt
        printf "======================= \n" >> /tmp/security_remediation_output.txt
        value=640
        root=$(stat -c "%a" /var/log)
        if [ "$root" = "$value" ]; then
                printf "\t \t /var/log permission is 640 `uname -n`--OK. \n \n " >> /tmp/security_remediation_output.txt
        else
                echo "$(chmod 640 /var/log)" 
                printf "\t \t /var/log permission updated as per techspec `uname -n`.= $value \n \n" >> /tmp/security_remediation_output.txt
fi

}


VARLOGFAIL () {

        printf "CHECK /var/log/faillog permission:- \n" >> /tmp/security_remediation_output.txt
        printf "======================= \n" >> /tmp/security_remediation_output.txt
        value=644
        root=$(stat -c "%a" /var/log/faillog)
        if [ "$root" = "$value" ]; then
                printf "\t \t /var/log/faillog permission is 644 `uname -n`--OK. \n \n " >> /tmp/security_remediation_output.txt
        else
                echo "$(chmod 644 /var/log/faillog)" 
                printf "\t \t /var/log/faillog permission updated as per techspec `uname -n`.= $value \n \n" >> /tmp/security_remediation_output.txt
fi

}


VARLOGTALLY () {

        printf "CHECK /var/log/tallylog permission:- \n" >> /tmp/security_remediation_output.txt
        printf "======================= \n" >> /tmp/security_remediation_output.txt
        value=600
        root=$(stat -c "%a" /var/log/tallylog)
        if [ "$root" = "$value" ]; then
                printf "\t \t /var/log/tallylog permission is 600 `uname -n`--OK. \n \n " >> /tmp/security_remediation_output.txt
        else
                echo "$(chmod 600 /var/log/tallylog)" 
                printf "\t \t /var/log/tallylog permission updated as per techspec `uname -n`.= $value \n \n" >> /tmp/security_remediation_output.txt
fi

}

VARLOGMESS () {

        printf "CHECK /var/log/messages permission:- \n" >> /tmp/security_remediation_output.txt
        printf "======================== \n" >> /tmp/security_remediation_output.txt
        value=600
        root=$(stat -c "%a" /var/log/messages)
        if [ "$root" = "$value" ]; then
                printf "\t \t /var/log/messages permission is 600 `uname -n`--OK. \n \n " >> /tmp/security_remediation_output.txt
        else
                echo "$(chmod 600 /var/log/messages)" 
                printf "\t \t /var/log/messages permission updated as per techspec `uname -n`.= $value \n \n" >> /tmp/security_remediation_output.txt
fi

}

WTMP () {

        printf "CHECK /var/log/wtmp permission:- \n" >> /tmp/security_remediation_output.txt
        printf "======================== \n" >> /tmp/security_remediation_output.txt
        value=664
        root=$(stat -c "%a" /var/log/wtmp)
        if [ "$root" = "$value" ]; then
                printf "\t \t /var/log/wtmp permission is 664 `uname -n`--OK. \n \n " >> /tmp/security_remediation_output.txt
        else
                echo "$(chmod 664 /var/log/wtmp)" 
                printf "\t \t /var/log/wtmp permission updated as per techspec `uname -n`.= $value \n \n" >> /tmp/security_remediation_output.txt
fi

}

SECURE () {

        printf "CHECK /var/log/secure permission:- \n" >> /tmp/security_remediation_output.txt
        printf "======================== \n" >> /tmp/security_remediation_output.txt
        value=600
        root=$(stat -c "%a" /var/log/secure)
        if [ "$root" = "$value" ]; then
                printf "\t \t /var/log/secure permission is 600 `uname -n`--OK. \n \n " >> /tmp/security_remediation_output.txt
        else
                echo "$(chmod 600 /var/log/secure)" 
                printf "\t \t /var/log/secure permission updated as per techspec `uname -n`.= $value \n \n" >> /tmp/security_remediation_output.txt
fi

}


TMP () {

        printf "CHECK /tmp permission:- \n" >> /tmp/security_remediation_output.txt
        printf "======================== \n" >> /tmp/security_remediation_output.txt
        value=1777
        root=$(stat -c "%a" /tmp)
        if [ "$root" = "$value" ]; then
                printf "\t \t /tmp permission is 1777 `uname -n`--OK. \n \n " >> /tmp/security_remediation_output.txt
        else
                echo "$(chmod 1777 /tmp)" 
                printf "\t \t /tmp permission updated as per techspec `uname -n`.= $value \n \n" >> /tmp/security_remediation_output.txt
fi

}

SNMP () {

        printf "CHECK /etc/snmp/snmp.conf permission:- \n" >> /tmp/security_remediation_output.txt
        printf "======================== \n" >> /tmp/security_remediation_output.txt
        value=640
        root=$(stat -c "%a" /etc/snmp/snmp.conf)
        if [ "$root" = "$value" ]; then
                printf "\t \t /etc/snmp/snmp.conf permission is 640 `uname -n`--OK. \n \n " >> /tmp/security_remediation_output.txt
        else
                echo "$(chmod 640 /etc/snmp/snmp.conf)" 
                printf "\t \t /etc/snmp/snmp.conf permission updated as per techspec `uname -n`.= $value \n \n" >> /tmp/security_remediation_output.txt
fi

}

INITTAB () {

        printf "CHECK /etc/inittab permission:- \n" >> /tmp/security_remediation_output.txt
        printf "======================== \n" >> /tmp/security_remediation_output.txt
        value=644
        root=$(stat -c "%a" /etc/inittab)
        if [ "$root" = "$value" ]; then
                printf "\t \t /etc/inittab permission is 644 `uname -n`--OK. \n \n " >> /tmp/security_remediation_output.txt
        else
                echo "$(chmod 644 /etc/inttab)" 
                printf "\t \t /etc/inittab permission updated as per techspec `uname -n`.= $value \n \n" >> /tmp/security_remediation_output.txt
fi

}


CRON () {

        printf "CHECK /var/spool/cron/ permission:- \n" >> /tmp/security_remediation_output.txt
        printf "======================== \n" >> /tmp/security_remediation_output.txt
        value=700
        root=$(stat -c "%a" /var/spool/cron/)
        if [ "$root" = "$value" ]; then
                printf "\t \t /var/spool/cron/ permission is 700 `uname -n`--OK. \n \n " >> /tmp/security_remediation_output.txt
        else
                echo "$(chmod 700 /var/spool/cron/)" 
                printf "\t \t /var/spool/cron permission updated as per techspec `uname -n`.= $value \n \n" >> /tmp/security_remediation_output.txt
fi

}

CRONTAB () {

        printf "CHECK /etc/crontab permission:- \n" >> /tmp/security_remediation_output.txt
        printf "======================== \n" >> /tmp/security_remediation_output.txt
        value=644
        root=$(stat -c "%a" /etc/crontab)
        if [ "$root" = "$value" ]; then
                printf "\t \t /etc/crontab permission is 644 `uname -n`--OK. \n \n " >> /tmp/security_remediation_output.txt
        else
                echo "$(chmod 644 /etc/crontab)" 
                printf "\t \t /etc/crontab permission updated as per techspec `uname -n`.= $value \n \n" >> /tmp/security_remediation_output.txt
fi

}


XINETDOSR() {

        printf "CHECK /etc/xinetd permission:- \n" >> /tmp/security_remediation_output.txt
        printf "======================== \n" >> /tmp/security_remediation_output.txt
        value=755
        root=$(stat -c "%a" /etc/xinetd)
        if [ "$root" = "$value" ]; then
                printf "\t \t /etc/xinetd permission is 755 `uname -n`--OK. \n \n " >> /tmp/security_remediation_output.txt
        else
                echo "$(chmod 755 /etc/xinetd)" 
                printf "\t \t /etc/xinetd permission updated as per techspec `uname -n`.= $value \n \n" >> /tmp/security_remediation_output.txt
fi

}


CROND () {

        printf "CHECK /etc/cron.d permission:- \n" >> /tmp/security_remediation_output.txt
        printf "======================== \n" >> /tmp/security_remediation_output.txt
        value=755
        root=$(stat -c "%a" /etc/cron.d)
        if [ "$root" = "$value" ]; then
                printf "\t \t /etc/cron.d permission is 755 `uname -n`--OK. \n \n " >> /tmp/security_remediation_output.txt
        else
                echo "$(chmod 755 /etc/cron.d)" 
                printf "\t \t /etc/cron.d permission updated as per techspec `uname -n`.= $value \n \n" >> /tmp/security_remediation_output.txt
fi

}

SPOOL () {

        printf "CHECK /var/spool/cron permission:- \n" >> /tmp/security_remediation_output.txt
        printf "======================== \n" >> /tmp/security_remediation_output.txt
        value=700
        root=$(stat -c "%a" /var/spool/cron)
        if [ "$root" = "$value" ]; then
                printf "\t \t /var/spool/cron permission is 700 `uname -n`--OK. \n \n " >> /tmp/security_remediation_output.txt
        else
                echo "$(chmod 700 /var/spool/cron)" 
                printf "\t \t /var/spool/cron permission updated as per techspec `uname -n`.= $value \n \n" >> /tmp/security_remediation_output.txt
fi

}


OPT () {

        printf "CHECK /opt permission:- \n" >> /tmp/security_remediation_output.txt
        printf "======================== \n" >> /tmp/security_remediation_output.txt
        value=755
        root=$(stat -c "%a" /opt)
        if [ "$root" = "$value" ]; then
                printf "\t \t /opt permission is 755 `uname -n`--OK. \n \n " >> /tmp/security_remediation_output.txt
        else
                echo "$(chmod 755 /opt)" 
                printf "\t \t /opt permission updated as per techspec `uname -n`.= $value \n \n" >> /tmp/security_remediation_output.txt
fi

}

VAR () {

        printf "CHECK /VAR permission:- \n" >> /tmp/security_remediation_output.txt
        printf "======================== \n" >> /tmp/security_remediation_output.txt
        value=755
        root=$(stat -c "%a" /var)
        if [ "$root" = "$value" ]; then
                printf "\t \t /var permission is 755 `uname -n`--OK. \n \n " >> /tmp/security_remediation_output.txt
        else
                echo "$(chmod 755 /var)" 
                printf "\t \t /var permission updated as per techspec `uname -n`.= $value \n \n" >> /tmp/security_remediation_output.txt
fi

}

VAR () {

        printf "CHECK /VAR permission:- \n" >> /tmp/security_remediation_output.txt
        printf "======================== \n" >> /tmp/security_remediation_output.txt
        value=755
        root=$(stat -c "%a" /var)
        if [ "$root" = "$value" ]; then
                printf "\t \t /var permission is 755 `uname -n`--OK. \n \n " >> /tmp/security_remediation_output.txt
        else
                echo "$(chmod 755 /var)" 
                printf "\t \t /var permission updated as per techspec `uname -n`.= $value \n \n" >> /tmp/security_remediation_output.txt
fi

}

USRLOCAL () {

        printf "CHECK /usr/local permission:- \n" >> /tmp/security_remediation_output.txt
        printf "======================== \n" >> /tmp/security_remediation_output.txt
        value=755
        root=$(stat -c "%a" /usr/local)
        if [ "$root" = "$value" ]; then
                printf "\t \t /usr/local permission is 755 `uname -n`--OK. \n \n " >> /tmp/security_remediation_output.txt
        else
                echo "$(chmod 755 /usr/local)" 
                printf "\t \t /usr/local permission updated as per techspec `uname -n`.= $value \n \n" >> /tmp/security_remediation_output.txt
fi

}



PASS_MAX_DAYS
PASS_MIN_LEN
PASS_MIN_DAYS
PASSWORD_HIST
LOGIN_RETRIES
#PERMIT_ROOT_LOGIN
WTMP
MESSAGES
TALLYLOG
SECURE
HOST_EQUIV
RLOGIN_RSH
SYNCOOKIES
BROADCASTS
YPPASSWDD 
YPBIND
XINETD
SENDMAIL
HOST
NETRC
ROOTOSR 
USROSR
ETCOSR
OPASSWD
VAR
VARLOG
VARLOGFAIL
VARLOGTALLY
VARLOGMESS
WTMP
SECURE
TMP
SNMP 
INITTAB 
CRON
CRONTAB
XINETDOSR
CROND 
SPOOL
OPT
VAR
USRLOCAL
