#!/usr/bin/perl -w
use strict;
use Switch;

my $komeda;
my $user=0;

print "+OK POP3 Ready poczta.o2.pl\n";

while(1)
{
	$komeda = <STDIN>;
	chop $komeda;


	switch($komeda){
		case /^USER /	{
			print "+OK\n";
			$user=1;
		}
	
		case /^PASS /    {
			if( $user == 1){
			  print "-ERR Invalid password or username\n";
			}else{
		  		print "-ERR give username first\n";
			}
		}
		case "QUIT"{
			print "+OK\n";
			exit 0;
		}
		else {
			if( $user==1 ){
			   print "-ERR use PASS password\n";
		   	}else{
   			   print "-ERR use USER name\n";
		        }
		}
	}
}
