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



sub ADtimeToUnixTime{
    my $adtime = shift;
    return int( ($adtime /10000000) - 11676009600 ) ;
}

sub AcctTimeToUnixTime {
    my $accttime = shift;
    # sample:  20140505145343.0Z
    if ( $accttime =~ /^(....)(..)(..)(..)(..)(..)\.0Z$/ ) {
      return timegm( $6, $5, $4, $3, $2-1, $1 );
    } else {
      # not sure what to do if there is no match
      return $accttime;
    }
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
if ( $pwdlastset == 0 ) {
  $passwordsettime = "never";
} else {
  $passwordsettime = scalar localtime(ADtimeToUnixTime($pwdlastset));
}
printf ( "%24s: %s (%s)\n", "Password last set", $passwordsettime, $pwdlastset );

print "\n";
my $lastlogon = $valref->{'lastlogon'}->[0];
my $lastlogontime;
if ( $lastlogon == 0 ) {
  $lastlogontime = "never";
} else {
  $lastlogontime = scalar localtime(ADtimeToUnixTime($lastlogon));
}
printf ( "%24s: %s (%s)\n", "Last logon", $lastlogontime, $lastlogon );

my $badpasswordtime = $valref->{'badpasswordtime'}->[0];
my $badpwdtime;
if ( $badpasswordtime == 0 ) {
  $badpwdtime = "never";
} else {
  $badpwdtime = scalar localtime(ADtimeToUnixTime($badpasswordtime));
}
printf ( "%24s: %s (%s)\n", "Last bad password", $badpwdtime, $badpasswordtime );

my $badpwdcount = $valref->{'badpwdcount'}->[0];
printf ( "%24s: %s \n", "Bad password count", $badpwdcount );

print "\n";
my $whencreated = $valref->{'whencreated'}->[0];
my $createdtime =  scalar localtime(AcctTimeToUnixTime($whencreated));
printf ( "%24s: %s (%s) \n", "Account created", $createdtime, $whencreated );

my $whenchanged = $valref->{'whenchanged'}->[0];
my $changedtime =  scalar localtime(AcctTimeToUnixTime($whenchanged));
printf ( "%24s: %s (%s) \n", "Account changed", $changedtime, $whenchanged );

my $accountexpires = $valref->{'accountexpires'}->[0];
my $expirestime;
# http://msdn.microsoft.com/en-us/library/ms675098%28v=vs.85%29.aspx
if ( $accountexpires == 0 || $accountexpires == 9223372036854775807 ) {
  $expirestime = "never";
} else {
  #$expirestime = scalar localtime(AcctTimeToUnixTime($accountexpires));
  $expirestime = scalar localtime(ADtimeToUnixTime($accountexpires));
}
printf ( "%24s: %s (%s)\n", "Account expires", $expirestime, $accountexpires );

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

  my $attrVal =  @$valref{$a};
  printf ( "%24s: %s \n", $attrName, @$attrVal );
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


my @adgroups = @{ $valref->{'memberof'} } ;

#print "   --------------- \n";
#print Dumper( @adgroups ) ;
#print "   --------------- \n";


#
# Convert to list of groups to test membership in
#
print "  Member of ClusterUsers: ";
my $grpName ;
my $membership;
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



#print "\n";
#print "   UNIX group memberships \n";
#print "   ---------------------- \n";
#print "\n";
#
#
#
#
## list of unix groups
## '(&(gidNumber=*)(objectClass=group))'
##  search member: 
#
#
## search for all unix groups and test membership
##
#$mesg = $ldap->search( # perform a search
#                        base   => $base ,
#                        filter => "(&(&(gidNumber=*)(objectClass=group))(member=$DN))"
#                      );
#                        #filter => "(&(&(gidNumber=*)(objectClass=group))(member=$DN))"
#                        #filter => "(&(gidNumber=*)(objectClass=group))"
#
#$mesg->code && die $mesg->error;
#
#my $grphref = $mesg->as_struct;
#
#
## DEBUG
#print "   --------------- \n";
#print Dumper($grphref);
#print "   --------------- \n";
#
#
#
#
## home dir created ?
#




print "\n\n\n";

$mesg = $ldap->unbind;   # take down session

#print Dumper($mesg);
#$mesg->code && die $mesg->error;



