#!/bin/bash
#
# Skrypt do przygotowywania certyfikatow i kluczy
# dla projektu HoneySpy
#

DAYS=365

readkey() {
	local tn
	while :; do
		echo "$1 [t/n]"
		read -n 1 -s tn
		[ "$tn" = t -o "$tn" = n ] && break
	done
	[ $tn = t ];
}

if [ "$1" = 'clean' ]; then
	if readkey 'Usun�� wszystkie klucze i certyfikaty?'; then
		rm *.enc *.pem *.csr && echo "Usuni�to";
		exit 0;
	fi
	exit 1;
fi

if [ "$1" = 'master' ]; then
	echo 'Tworzenie kluczy i certyfikatu serwera centralnego.'
	echo 'Certyfikat b�dzie r�wnie� u�ywany przez centrum certyfikacyjne'
	echo

	openssl genrsa -des3 -out master-key.enc 1024
	openssl rsa -in master-key.enc -out master-key.pem
	openssl req -subj '/C=PL/O=HoneySpy network/OU=Master Server/CN=Master' -new -x509 -days $DAYS -key master-key.pem -out master-cert.pem

	echo
	readkey 'Pokaza� certyfikat?' && \
		openssl x509 -noout -text -in master-cert.pem

	exit 0
fi

if [ "$1" = 'sensor' -o "$1" = 'admin' ]; then
	echo "Tworzenie kluczy i certyfikatu klienta ($1) sieci"
	echo 

	if [ ! -f master-key.pem -o ! -f master-cert.pem ]; then
		echo "B��d: Nie istniej� klucze lub certyfikat serwera centralnego."
		echo "U�yj najpierw $0 master"
		echo
		exit 1
	fi

	mkdir -p demoCA/newcerts 2>/dev/null
	touch demoCA/index.txt
	[ ! -e demoCA/serial ] && echo 01 > demoCA/serial

	echo "Nazwa klienta: "
	read name
	[ "$name" ] || exit 1

	openssl genrsa -des3 -out "$name-key.enc" 1024
	openssl rsa -in "$name-key.enc" -out "$name-key.pem"
	openssl req -subj "/C=PL/O=HoneySpy network/OU=$1/CN=$name" -new -key "$name-key.pem" -out "$name.csr"
	openssl ca -policy policy_anything -keyfile master-key.pem \
		-cert master-cert.pem -in "$name.csr" -out "$name-cert.pem"

	echo
	readkey 'Pokaza� certyfikat?' && \
		openssl x509 -noout -text -in "$name-cert.pem"

	exit 0
fi


echo -e "U�ycie:\n\t$0 clean|master|sensor|admin";

