#!/usr/bin/perl
#
#  2014-05-07  -  Austin Murphy
#
#  Get info about a domain user, including the bits relevant for Linux usage
#
#

use strict; 

#use Data::Dumper;
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

my $uri          = $Config->{LDAP}->{uri};
my $binddn       = $Config->{LDAP}->{binddn};
my $bindpw       = $Config->{LDAP}->{bindpw};
my $base         = $Config->{LDAP}->{base};

# DEBUG
#print "       uri:  $uri    \n";
#print "    binddn:  $binddn \n";
#print "    bindpw:  $bindpw \n";
#print "      base:  $base   \n";



#
# Process arguments
#
my $numargs = scalar @ARGV;
($numargs != 1 ) && die "Command takes 1 argument, a PMACS domain user ID.\n";

my $user = $ARGV[0];

($user !~ /^[0-9a-z_]{2,16}$/ ) && die "User name must be between 2 and 16 lower-case letters, numbers or underscores long.\n";

#print "User to lookup: $user \n";
#print " working ... \n";



#
# Date conversion helpers
#


# "FileTime" 
#  There is a perl module for this, but it seems to be more trouble than it is worth to install
#     DateTime::Format::WindowsFileTime 
#   It is not included in RHEL/CentOS or EPEL
#
sub WinFileTimeToUnixTime{
    my $adtime = shift;
    #return int( ($adtime /10000000) - 11676009600 ) ;
    return int( ($adtime /10000000) - 11644473600 ) ;
}
#
sub WinFileTimeDeltaToSec{
    my $adtime = shift;
    return int( ($adtime /10000000) ) ;
}

#
#  UAC  interpreter
# 

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

my $uacnum;
my @uacflags;

my @uacflagnames = (
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
# Search for a particular userid
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
# another query about the domain policy 
#

$mesg = $ldap->search( # perform a search
                        base   => $base ,
                        scope => 'base',
                        filter => "(distinguishedName=$base)"
                      );
$mesg->code && die $mesg->error;

# as_struct returns a much nicer data struct to work with
#print Dumper($mesg->as_struct());
my $dom_href = $mesg->as_struct;



my $curr_time = time();
my $maxpwdage = $dom_href->{$base}->{'maxpwdage'}->[0] ;
my $lockoutduration = $dom_href->{$base}->{'lockoutduration'}->[0] ;

# DEBUG
#print "\n ++++++  \n";
#print "maxPwdAge: $maxpwdage  (raw) \n";
#print "\n ++++++  \n";



# 
# DEBUG
# 
# get an array of the attribute names
# passed for this one DN.
#my @arrayOfAttrs = sort keys %$valref; #use Attr hashes
#print "array of all attributes: \n";
#print Dumper(@arrayOfAttrs);
#print "---- \n";


# LDAP keyword - display section - single/list - rules for interpretation
#
# name - basics - single - literal
# telephonenumber - basics - single - literal
# mobile - basics - single - literal
# mail - basics - single - literal
# department - basics - single - literal
# manager - basics - single - literal
#
# pwdLastSet - status - single - WinFileTime, 0->must change at next, ''-> never?
# lastLogon - status - single - WinFileTime, 0->never
# badPasswordTime - status - single - WinFileTime, 0->never
# whenCreated - status - single - 8601Time
# whenChanged - status - single - 8601Time
# accountExpires - status - single - 8601Time, 0->never
# userAccountControl - status - list - UACcodelist
# uid - unixattr - single - literal
#
# uidNumber - unixattr - single - literal
# gidNumber - unixattr - single - literal
# unixHomeDirectory - unixattr - single - literal
# loginShell - unixattr - single - literal
#
# member - AD groups - list - parsegroup
# memberOf - unix groups - list - parsegroup


my $pwdlastset =  $valref->{'pwdlastset'}->[0];
my $unix_pwdlastset;
my $fmt_pwdlastset;
my $sec_maxpwdage =  WinFileTimeDeltaToSec($maxpwdage);
my $pwdexpstate = "";
my $oldestpwd = $curr_time + $sec_maxpwdage ;
my $lastlogon = $valref->{'lastlogon'}->[0];
my $lastlogontime;
my $badpasswordtime = $valref->{'badpasswordtime'}->[0];
my $fmt_badpasswordtime;
my $badpwdcount = $valref->{'badpwdcount'}->[0];
my $lockoutstate;
my $whencreated = $valref->{'whencreated'}->[0];
my $dt_whencreated =  DateTime::Format::ISO8601->parse_datetime($whencreated);
$dt_whencreated->set_time_zone( 'America/New_York' );
my $whenchanged = $valref->{'whenchanged'}->[0];
my $dt_whenchanged =  DateTime::Format::ISO8601->parse_datetime($whenchanged);
$dt_whenchanged->set_time_zone( 'America/New_York' );
my $accountexpires = $valref->{'accountexpires'}->[0];
my $unix_accountexpires = 0;
my $fmt_accountexpires = "";
my $acctexpstate;
$uacnum =  $valref->{'useraccountcontrol'}->[0] ;
@uacflags = split( '', unpack( "b*", pack ("i", $uacnum) ) );
my $acctdsblstate;
my $pwdnoexp;



#
# Formatting & expiration logic
#

# disabled is simply the UAC flag
if ( $uacflags[1] == 1 ) {
  $acctdsblstate = "DISABLED";
} else {
  $acctdsblstate = "NOT DISABLED";
}

# UAC flag overrides password expiration
if ( $uacflags[16] == 1 ) {
  $pwdnoexp = 1 ;
} else {
  $pwdnoexp = 0 ;
}


if ( $pwdlastset eq '0' ) {
  $fmt_pwdlastset = "must change password at next login";
} elsif ( $pwdlastset eq '' ) {
  $fmt_pwdlastset = "never";
} else {
  $unix_pwdlastset = WinFileTimeToUnixTime($pwdlastset);
  $fmt_pwdlastset = scalar localtime( $unix_pwdlastset );
}
# 
# check if expired by  
#   - get maxPwdAge from  domain  (winfiletime-delta, negative val)
#   - convert to seconds
#   - add to time()
#   - if newer than pwdLastSet, then password is expired
#
if ( $oldestpwd > $unix_pwdlastset ) {
  if ( $pwdnoexp ) {
    $pwdexpstate = "NOT EXPIRED";
  } else {
    $pwdexpstate = "EXPIRED";
  }
} else {
  my $days = int ( ( $unix_pwdlastset - $oldestpwd ) / 86400 );
  $pwdexpstate = "NOT EXPIRED, $days days remaining";
}

if ( $lastlogon == 0 ) {
  $lastlogontime = "never";
} else {
  $lastlogontime = scalar localtime(WinFileTimeToUnixTime($lastlogon));
}

if ( $badpasswordtime == 0 ) {
  $fmt_badpasswordtime = "never";
} else {
  $fmt_badpasswordtime = scalar localtime(WinFileTimeToUnixTime($badpasswordtime));
}


# lockoutTime
my $lockouttime = $valref->{'lockouttime'}->[0];
my $unix_lockouttime = 0;
my $fmt_lockouttime = "";
if ( $lockouttime eq '' ) {
  #$lockout = "never logged in";
  #$fmt_lockouttime = "not locked out";
} elsif ( $lockouttime eq '0' ) {
  #$fmt_lockouttime = "not locked out";
} else {
  $unix_lockouttime = WinFileTimeToUnixTime($lockouttime);
  $fmt_lockouttime = scalar localtime($unix_lockouttime);
}

# lockout ends at  lockoutTime + lockoutduration
if ( $unix_lockouttime > 0 ) {
  if ( $lockoutduration > 0 ) {
    my $unix_lockoutduration = WinFileTimeDeltaToSec( $lockoutduration );
    my $lockoutexp = $unix_lockouttime + $unix_lockoutduration;
    if ( $lockoutexp > $curr_time ) {
      $lockoutstate = "LOCKED OUT"
    } else {
      $lockoutstate = "NOT LOCKED OUT"
    }
  } else {
    $lockoutstate = "LOCKED OUT"
  }
} else {
  $lockoutstate = "NOT LOCKED OUT"
}


# http://msdn.microsoft.com/en-us/library/ms675098%28v=vs.85%29.aspx
if ( $accountexpires == 0 || $accountexpires == 9223372036854775807 ) {
  $fmt_accountexpires = "never";
} else {
  $unix_accountexpires = WinFileTimeToUnixTime($accountexpires);
  $fmt_accountexpires = scalar localtime( $unix_accountexpires );
}

if ( $unix_accountexpires > 0 ) {
  if ( $unix_accountexpires < $curr_time ) {
    $acctexpstate = "EXPIRED";
  } else {
    my $days = int ( ( $unix_accountexpires - $curr_time  ) / 86400 ) ;
    $acctexpstate = "NOT EXPIRED, $days days remaining";
  }
   
} else {
  $acctexpstate = "NOT EXPIRED";
}




# 
# group info lookups 
#

my $prigid = $valref->{'gidnumber'}->[0];

# Search for unix style (ie. gidNumber is defined) groups (objectClass=group)
#
$mesg = $ldap->search( # perform a search
                        base   => $base ,
                        filter => "(&(gidNumber=$prigid)(objectClass=group))"
                      );

$mesg->code && die $mesg->error;
my $prigrphref = $mesg->as_struct;


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


# 
# close LDAP connection
#

$mesg = $ldap->unbind;   # take down session
#print Dumper($mesg);
#$mesg->code && die $mesg->error;




#
#  print out info
#


print "\n";
print "   Account basics \n";
print "   -------------- \n";
print "\n";

#print "\n";
#print "      Distinguished Name:\n\n    $DN \n";
print "    $DN \n";
print "\n";

printf ( "%28s: %s \n", "name",            $valref->{'name'}->[0] );
printf ( "%28s: %s \n", "telephoneNumber", $valref->{'telephonenumber'}->[0] );
printf ( "%28s: %s \n", "mobile",          $valref->{'mobile'}->[0] );
printf ( "%28s: %s \n", "mail",            $valref->{'mail'}->[0] );
printf ( "%28s: %s \n", "department",      $valref->{'department'}->[0] );
printf ( "%28s: %s \n", "manager",         $valref->{'manager'}->[0] );
print "\n";




print "\n";
print "   Account status \n";
print "   -------------- \n";
print "\n";


printf ( "%28s: %s \n", "Password expiration status", $pwdexpstate );
printf ( "%28s: %s \n", "Password Lockout status", $lockoutstate );
printf ( "%28s: %s \n", "Account disabled status", $acctdsblstate );
printf ( "%28s: %s \n", "Account expiration status", $acctexpstate );
print "\n";
printf ( "%28s: %s (%s)\n", "Password last set", $fmt_pwdlastset, $pwdlastset );
#printf ( "%28s: %s \n", "Password expiration status", $pwdexpstate );
print "\n";
printf ( "%28s: %s (%s)\n", "Last logon", $lastlogontime, $lastlogon );
printf ( "%28s: %s (%s)\n", "Last bad password", $fmt_badpasswordtime, $badpasswordtime );
printf ( "%28s: %s \n", "Bad password count", $badpwdcount );
printf ( "%28s: %s (%s)\n", "Lockout time", $fmt_lockouttime, $lockouttime );
#printf ( "%28s: %s \n", "Password Lockout status", $lockoutstate );
print "\n";
printf ( "%28s: %s (%s) \n", "Account created", $dt_whencreated->strftime('%a %b %e %H:%M:%S %Y'), $whencreated );
printf ( "%28s: %s (%s) \n", "Account changed", $dt_whenchanged->strftime('%a %b %e %H:%M:%S %Y'), $whenchanged );
printf ( "%28s: %s (%s)\n", "Account expires", $fmt_accountexpires, $accountexpires );
#printf ( "%28s: %s \n", "Account expiration status", $acctexpstate );
print "\n";
printf("%28s: (%s) \n",  "User Account Control", $uacnum );
for my $j (0..26) {
  if ( $uacflags[$j] eq "1" ) {
    printf("%28s: %s \n",  " ", $uacflagnames[$j] );
    #print "        $uacflagnames[$j] \n";
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
  printf ( "%28s: %s \n", $attrName, $attrVal );
}
print "\n";

#printf("%28s  \n", "UNIX groups");
#printf("%28s----------------- \n", "-----------");
printf("%28s:  \n", "UNIX groups");

#
# show the info for the primary group defined in the user
#
foreach my $grpdn (keys %$prigrphref )  { 
  #printf("%28s: %s (%s) \n", "primary", $prigrphref->{$grpdn}->{'name'}->[0], $prigrphref->{$grpdn}->{'gidnumber'}->[0]);
  printf("%28s: %s (%s) \n", $prigrphref->{$grpdn}->{'gidnumber'}->[0], $prigrphref->{$grpdn}->{'name'}->[0], "primary" );
}

foreach my $grpdn (@grpnames)  { 
  # don't show the primary gid that was previously displayed
  if ($grphref->{$grpdn}->{'gidnumber'}->[0] != $prigid ) {
    #printf("%28s: %s (%s) \n", "", $grphref->{$grpdn}->{'name'}->[0], $grphref->{$grpdn}->{'gidnumber'}->[0]);
    printf("%28s: %s \n", $grphref->{$grpdn}->{'gidnumber'}->[0], $grphref->{$grpdn}->{'name'}->[0] );
  }
}
print "\n";





print "\n";
print "   Relevant AD group memberships \n";
print "   ----------------------------- \n";
print "\n";


# lab group member ?

# ClusterUsers group member?
#    'CN=ClusterUsers,OU=Groups,OU=HPC,OU=PMACS,DC=pmacs,DC=upenn,DC=edu'
#
# TODO: move to config file 



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
my $grpName ;
my $membership = "---";
foreach $grpName (@adgroups) {
  $membership = "---";
  # print "group: $grpName \n";
  if ($grpName eq 'CN=ClusterUsers,OU=Groups,OU=HPC,OU=PMACS,DC=pmacs,DC=upenn,DC=edu' ) {
    $membership = "MEMBER";
    printf("%28s: %s\n ", "HPC ClusterUsers", $membership);
    last;
  }
}
#print $membership;
print "\n";
  





print "\n\n";



