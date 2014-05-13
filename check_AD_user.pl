#!/usr/bin/perl
#
#  2014-05-07  -  Austin Murphy
#
#  Get info about a domain user, including the bits relevant for Linux usage
#
#

use strict; 

use Data::Dumper;
use File::Basename;
use Config::Tiny;
use Time::Local;
use DateTime;
use DateTime::Format::ISO8601;


use Net::LDAP;



#
# Load config from file
#
my $Config = Config::Tiny->new;
my $configfile =  dirname($0).'/ldap-creds.conf';

( -f $configfile ) || die "Configuration file ( $configfile ) missing! \n";
$Config = Config::Tiny->read( $configfile );

my $uri    = $Config->{LDAP}->{uri};
my $binddn = $Config->{LDAP}->{binddn};
my $bindpw = $Config->{LDAP}->{bindpw};
my $base   = $Config->{LDAP}->{base};

# DEBUG
#print "   uri:  $uri    \n";
#print "binddn:  $binddn \n";
#print "bindpw:  $bindpw \n";
#print "  base:  $base   \n";



#
# Process arguments
#
my $numargs = scalar @ARGV;
($numargs != 1 ) && die "Command takes 1 argument, a PMACS domain user ID.\n";

my $user = $ARGV[0];

($user !~ /^[a-z_]{2,16}$/ ) && die "User name must be between 2 and 16 lower-case letters or underscores long.\n";

#print "User to lookup: $user \n";
#print " working ... \n";



#
# Date conversion helpers
#


# "FileTime" 
#  There is a perl module for this, but it seems to be more trouble than it is worth to install
#     DateTime::Format::WindowsFileTime 
#   It is not included in RHEL/CentOS or EPEL
sub WinFileTimeToUnixTime{
    my $adtime = shift;
    #return int( ($adtime /10000000) - 11676009600 ) ;
    return int( ($adtime /10000000) - 11644473600 ) ;
}


#
# Setup LDAP connection
#
# 
#   FYI - LDAPS requies the self-signed cert in /etc/openldap/cacerts 
#
my $ldap = Net::LDAP->new( $uri ) or die "$@";


# 
# bind to AD using the HPC bind service acct 
#
my $mesg = $ldap->bind ( $binddn ,
                      password => $bindpw ,
                      version => 3 );      

$mesg->code && die $mesg->error;




#
# Search for a particular pennkey
# 
$mesg = $ldap->search( # perform a search
                        base   => $base ,
                        filter => "(samAccountName=$user)"
                      );
$mesg->code && die $mesg->error;

# as_struct returns a much nicer data struct to work with
#print Dumper($mesg->as_struct());
my $href = $mesg->as_struct;

# get an array of the DN names
my @arrayOfDNs  = keys %$href;        # use DN hashes


#
#  make sure there is just one DN returned
#

my $numDNs = scalar @arrayOfDNs;

( $numDNs == 0 ) && die "No user with the ID  $user  found in the PMACS domain.\n";
( $numDNs > 1 ) && die "ERROR:  More than 1 user with the ID  $user  found in the PMACS domain.\n";


my $DN = $arrayOfDNs[0];


# $valref is a reference to all the user's attributes & values
my $valref = $$href{$DN};


# 
# DEBUG
# 
# get an array of the attribute names
# passed for this one DN.
#my @arrayOfAttrs = sort keys %$valref; #use Attr hashes
#print "array of all attributes: \n";
#print Dumper(@arrayOfAttrs);
#print "---- \n";



print "\n";
print "   Account basics \n";
print "   -------------- \n";
print "\n";

#print "\n";
#print "      Distinguished Name:\n\n    $DN \n";
print "    $DN \n";
print "\n";

printf ( "%24s: %s \n", "name", $valref->{'name'}->[0] );
printf ( "%24s: %s \n", "telephoneNumber", $valref->{'telephonenumber'}->[0] );
printf ( "%24s: %s \n", "mobile", $valref->{'mobile'}->[0] );
printf ( "%24s: %s \n", "mail", $valref->{'mail'}->[0] );
printf ( "%24s: %s \n", "department", $valref->{'department'}->[0] );
printf ( "%24s: %s \n", "manager", $valref->{'manager'}->[0] );
print "\n";




print "\n";
print "   Account status \n";
print "   -------------- \n";
print "\n";



my $pwdlastset =  $valref->{'pwdlastset'}->[0];
my $passwordsettime;
if ( $pwdlastset eq '0' ) {
  $passwordsettime = "must change password at next login";
} elsif ( $pwdlastset eq '' ) {
  $passwordsettime = "never";
} else {
  $passwordsettime = scalar localtime(WinFileTimeToUnixTime($pwdlastset));
}
printf ( "%24s: %s (%s)\n", "Password last set", $passwordsettime, $pwdlastset );

print "\n";
my $lastlogon = $valref->{'lastlogon'}->[0];
my $lastlogontime;
if ( $lastlogon == 0 ) {
  $lastlogontime = "never";
} else {
  $lastlogontime = scalar localtime(WinFileTimeToUnixTime($lastlogon));
}
printf ( "%24s: %s (%s)\n", "Last logon", $lastlogontime, $lastlogon );

my $badpasswordtime = $valref->{'badpasswordtime'}->[0];
my $badpwdtime;
if ( $badpasswordtime == 0 ) {
  $badpwdtime = "never";
} else {
  $badpwdtime = scalar localtime(WinFileTimeToUnixTime($badpasswordtime));
}
printf ( "%24s: %s (%s)\n", "Last bad password", $badpwdtime, $badpasswordtime );

my $badpwdcount = $valref->{'badpwdcount'}->[0];
printf ( "%24s: %s \n", "Bad password count", $badpwdcount );

# lockoutTime
my $lockouttime = $valref->{'lockouttime'}->[0];
my $lockout;
if ( $lockouttime eq '' ) {
  $lockout = "never logged in";
} elsif ( $lockouttime eq '0' ) {
  $lockout = "not locked out";
} else {
  $lockout = scalar localtime(WinFileTimeToUnixTime($lockouttime));
}
printf ( "%24s: %s (%s)\n", "Lockout time", $lockout, $lockouttime );


print "\n";
my $whencreated = $valref->{'whencreated'}->[0];
my $createdtime =  DateTime::Format::ISO8601->parse_datetime($whencreated);
$createdtime->set_time_zone( 'America/New_York' );
printf ( "%24s: %s (%s) \n", "Account created", $createdtime->strftime('%a %b %e %H:%M:%S %Y'), $whencreated );

my $whenchanged = $valref->{'whenchanged'}->[0];
my $changedtime =  DateTime::Format::ISO8601->parse_datetime($whenchanged);
$changedtime->set_time_zone( 'America/New_York' );
printf ( "%24s: %s (%s) \n", "Account changed", $changedtime->strftime('%a %b %e %H:%M:%S %Y'), $whenchanged );

my $accountexpires = $valref->{'accountexpires'}->[0];
my $expirestime;
# http://msdn.microsoft.com/en-us/library/ms675098%28v=vs.85%29.aspx
if ( $accountexpires == 0 || $accountexpires == 9223372036854775807 ) {
  $expirestime = "never";
} else {
  $expirestime = scalar localtime(WinFileTimeToUnixTime($accountexpires));
}
printf ( "%24s: %s (%s)\n", "Account expires", $expirestime, $accountexpires );

print "\n";


# # http://support.microsoft.com/kb/305144
# #  userAccountControl  FLAGS
# 
# SCRIPT				    0x0001	1
# ACCOUNTDISABLE			    0x0002	2
# HOMEDIR_REQUIRED			    0x0008	8
# LOCKOUT				    0x0010	16
# PASSWD_NOTREQD			    0x0020	32
# PASSWD_CANT_CHANGE 			    0x0040	64
# ENCRYPTED_TEXT_PWD_ALLOWED		    0x0080	128
# TEMP_DUPLICATE_ACCOUNT		    0x0100	256
# NORMAL_ACCOUNT			    0x0200	512
# INTERDOMAIN_TRUST_ACCOUNT		    0x0800	2048
# WORKSTATION_TRUST_ACCOUNT		    0x1000	4096
# SERVER_TRUST_ACCOUNT			    0x2000	8192
# DONT_EXPIRE_PASSWORD			   0x10000	65536
# MNS_LOGON_ACCOUNT			   0x20000	131072
# SMARTCARD_REQUIRED			   0x40000	262144
# TRUSTED_FOR_DELEGATION		   0x80000	524288
# NOT_DELEGATED				  0x100000	1048576
# USE_DES_KEY_ONLY			  0x200000	2097152
# DONT_REQ_PREAUTH			  0x400000	4194304
# PASSWORD_EXPIRED			  0x800000	8388608
# TRUSTED_TO_AUTH_FOR_DELEGATION	 0x1000000	16777216
# PARTIAL_SECRETS_ACCOUNT		0x04000000  	67108864

my $uacnum =  $valref->{'useraccountcontrol'}->[0] ;

printf("%24s: (%s) \n",  "User Account Control", $uacnum );

my @flags = split( '', unpack( "b*", pack ("i", $uacnum) ) );

my @flagnames = (
   "SCRIPT",
   "ACCOUNTDISABLE",
   "unknown",
   "HOMEDIR_REQUIRED",
   "LOCKOUT",
   "PASSWD_NOTREQD",
   "PASSWD_CANT_CHANGE",
   "ENCRYPTED_TEXT_PWD_ALLOWED",
   "TEMP_DUPLICATE_ACCOUNT",
   "NORMAL_ACCOUNT",
   "unknown",
   "INTERDOMAIN_TRUST_ACCOUNT",
   "WORKSTATION_TRUST_ACCOUNT",
   "SERVER_TRUST_ACCOUNT",
   "unknown",
   "unknown",
   "DONT_EXPIRE_PASSWORD",
   "MNS_LOGON_ACCOUNT",
   "SMARTCARD_REQUIRED",
   "TRUSTED_FOR_DELEGATION",
   "NOT_DELEGATED",
   "USE_DES_KEY_ONLY",
   "DONT_REQ_PREAUTH",
   "PASSWORD_EXPIRED",
   "TRUSTED_TO_AUTH_FOR_DELEGATION",
   "unknown",
   "PARTIAL_SECRETS_ACCOUNT"
);

for my $j (0..26) {
  if ( $flags[$j] eq "1" ) {
    printf("%24s: %s \n",  " ", $flagnames[$j] );
    #print "        $flagnames[$j] \n";
  }
}

print "\n";





print "\n";
print "   UNIX Attributes \n";
print "   --------------- \n";
print "\n";

#
# UNIX attributes
#
# note:  attribs in datastructure are all lowercase
my @UnixAttrs = ( 'uid', 'uidNumber', 'gidNumber', 'unixHomeDirectory', 'loginShell' );

my $attrName;        
foreach $attrName (@UnixAttrs) {
  # attrs are converted to lowercase for hash key names
  my $a = lc($attrName);

  # get the attribute value (pointer) using the
  # attribute name as the hash

  my $attrVal =  $valref->{$a}->[0];
  printf ( "%24s: %s \n", $attrName, $attrVal );
}
print "\n";




print "\n";
#print "   Groups relevant to HPC \n";
print "   Relevant AD group memberships \n";
print "   ----------------------------- \n";
print "\n";


# lab group member ?

# ClusterUsers group member?
#    'CN=ClusterUsers,OU=Groups,OU=HPC,OU=PMACS,DC=pmacs,DC=upenn,DC=edu'
# 



#
# list type attributes
#
my @arrayOfListAttrs = ( 'memberOf' );

#print "   --------------- \n";
#print Dumper( $valref ) ;
#print "   --------------- \n";

my @adgroups ;
if ( exists $valref->{'memberof'} ) {
  @adgroups = @{ $valref->{'memberof'} } ;
} 

#print "   --------------- \n";
#print Dumper( @adgroups ) ;
#print "   --------------- \n";


#
# Convert to list of groups to test membership in
#
print "  Member of ClusterUsers: ";
my $grpName ;
my $membership = "--- \n";
foreach $grpName (@adgroups) {
  $membership = "--- \n";
  # print "group: $grpName \n";
  if ($grpName eq 'CN=ClusterUsers,OU=Groups,OU=HPC,OU=PMACS,DC=pmacs,DC=upenn,DC=edu' ) {
    $membership = "YES \n";
    last;
  }
}
print $membership;
print "\n";
  


print "\n";
print "   UNIX group memberships \n";
print "   ---------------------- \n";
print "\n";

#
# show the info for the primary group defined in the user
#

my $prigid = @$valref{'gidnumber'}->[0];

# Search for unix style (ie. gidNumber is defined) groups (objectClass=group)
#
$mesg = $ldap->search( # perform a search
                        base   => $base ,
                        filter => "(&(gidNumber=$prigid)(objectClass=group))"
                      );

$mesg->code && die $mesg->error;
my $prigrphref = $mesg->as_struct;

foreach my $grpdn (keys %$prigrphref )  { 
  printf(" %24s: %s  (primary) \n", $prigrphref->{$grpdn}->{'name'}->[0], $prigrphref->{$grpdn}->{'gidnumber'}->[0]);
}


#
# Search for unix style (ie. gidNumber is defined) groups (objectClass=group)
#  of which this DN is listed as a member
#
$mesg = $ldap->search( # perform a search
                        base   => $base ,
                        filter => "(&(&(gidNumber=*)(objectClass=group))(member=$DN))"
                      );

$mesg->code && die $mesg->error;
my $grphref = $mesg->as_struct;
my @grpnames = keys %$grphref ;

foreach my $grpdn (@grpnames)  { 
  # don't show the primary gid that was previously displayed
  if ($grphref->{$grpdn}->{'gidnumber'}->[0] != $prigid ) {
    printf(" %24s: %s \n", $grphref->{$grpdn}->{'name'}->[0], $grphref->{$grpdn}->{'gidnumber'}->[0]);
  }
}







# home dir created ?




print "\n\n\n";

$mesg = $ldap->unbind;   # take down session

#print Dumper($mesg);
#$mesg->code && die $mesg->error;



