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
	if readkey 'Usun±æ wszystkie klucze i certyfikaty?'; then
		rm *.enc *.pem *.csr && echo "Usuniêto";
		exit 0;
	fi
	exit 1;
fi

if [ "$1" = 'master' ]; then
	echo 'Tworzenie kluczy i certyfikatu serwera centralnego.'
	echo 'Certyfikat bêdzie równie¿ u¿ywany przez centrum certyfikacyjne'
	echo

	openssl genrsa -des3 -out master-key.enc 1024
	openssl rsa -in master-key.enc -out master-key.pem
	openssl req -subj '/C=PL/O=HoneySpy network/OU=Master Server/CN=Master' -new -x509 -days $DAYS -key master-key.pem -out master-cert.pem

	echo
	readkey 'Pokazaæ certyfikat?' && \
		openssl x509 -noout -text -in master-cert.pem

	exit 0
fi

if [ "$1" = 'sensor' ]; then
	echo 'Tworzenie kluczy i certyfikatu klienta dla sensora.'
	echo 

	if [ ! -f master-key.pem -o ! -f master-cert.pem ]; then
		echo "B³±d: Nie istniej± klucze lub certyfikat serwera centralnego."
		echo "U¿yj najpierw $0 master"
		echo
		exit 1
	fi

	echo "Nazwa sensora: "
	read sensor
	[ "$sensor" ] || exit 1

	openssl genrsa -des3 -out "$sensor-key.enc" 1024
	openssl rsa -in "$sensor-key.enc" -out "$sensor-key.pem"
	openssl req -subj "/C=PL/O=HoneySpy network/OU=Sensor/CN=$sensor" -new -key "$sensor-key.pem" -out "$sensor.csr"
	openssl ca -policy policy_anything -keyfile master-key.pem \
		-cert master-cert.pem -in "$sensor.csr" -out "$sensor-cert.pem"

	echo
	readkey 'Pokazaæ certyfikat sensora?' && \
		openssl x509 -noout -text -in "$sensor-cert.pem"

	exit 0
fi


echo "U¿ycie:\n\t$0 clean|master|sensor";

