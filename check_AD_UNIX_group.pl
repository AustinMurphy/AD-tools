#!/usr/bin/perl
#
#  2014-05-07  -  Austin Murphy
#
#  Get info about a UNIX group defined in AD
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
($numargs != 1 ) && die "Command takes 1 argument, a PMACS domain group.\n";

my $ugrp = $ARGV[0];

($ugrp !~ /^[a-z_]{2,16}$/ ) && die "Group name must be between 2 and 16 lower-case letters or underscores long.\n";

#print "User to lookup: $ugrp \n";
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
# Search for a particular group
# 
$mesg = $ldap->search( # perform a search
                        base   => $base ,
                        filter => "(& (name=$ugrp) (objectClass=group) )"
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

( $numDNs == 0 ) && die "No group with the ID  $ugrp  found in the PMACS domain.\n";
( $numDNs > 1 ) && die "ERROR:  More than 1 group with the ID  $ugrp  found in the PMACS domain.\n";


my $DN = $arrayOfDNs[0];


# $valref is a pointer to a hash
#   each key in the hash is an Attribute name from LDAP
#   the value associated with a key is a pointer to an array of attribute values
#  
#   For example:  the value of the attribute "cn" can be retrieved like this:
#     $valref->{'cn'}->[0]
#  
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
print "   Group basics \n";
print "   ------------ \n";
print "\n";
print "    $DN \n";
print "\n";

printf ( "%24s: %s \n", "name", $valref->{'name'}->[0] );
printf ( "%24s: %s \n", "samAccountName", $valref->{'samaccountname'}->[0] );
printf ( "%24s: %s \n", "cn", $valref->{'cn'}->[0] );
print "\n";




print "\n";
print "   Group status \n";
print "   ------------ \n";
print "\n";

my $whencreated = $valref->{'whencreated'}->[0];
my $createdtime =  DateTime::Format::ISO8601->parse_datetime($whencreated);
$createdtime->set_time_zone( 'America/New_York' );
printf ( "%24s: %s (%s) \n", "Group created", $createdtime->strftime('%a %b %e %H:%M:%S %Y'), $whencreated );

my $whenchanged = $valref->{'whenchanged'}->[0];
my $changedtime =  DateTime::Format::ISO8601->parse_datetime($whenchanged);
$changedtime->set_time_zone( 'America/New_York' );
printf ( "%24s: %s (%s) \n", "Group changed", $changedtime->strftime('%a %b %e %H:%M:%S %Y'), $whenchanged );

print "\n";




print "\n";
print "   UNIX Attributes \n";
print "   --------------- \n";
print "\n";

#
# UNIX attributes
#
# note:  attribs in datastructure are all lowercase
my @UnixAttrs = ( 'name', 'gid', 'gidNumber' );

my $attrName;        
foreach $attrName (@UnixAttrs) {
  # attrs are converted to lowercase for hash key names
  my $a = lc($attrName);

  # get the attribute value (pointer) using the
  # attribute name as the hash

  # the values in the hash point to arrays that hold one value
  my $attrVal =  $valref->{$a}->[0];
  printf ( "%24s: %s \n", $attrName,  $attrVal );
}
print "\n";




print "\n";
print "   Group members \n";
print "   ------------- \n";
print "\n";


#
# Groups defined by "gidNumber:" within the user
# 

my $prigid = @$valref{'gidnumber'}->[0];

$mesg = $ldap->search( # perform a search
                        base   => $base ,
                        filter => "(&(gidNumber=$prigid)(objectClass=user))"
                      );

$mesg->code && die $mesg->error;
my $prigrphref = $mesg->as_struct;

foreach my $memName (keys %$prigrphref )  {
  print "PRI:  $memName  \n";
}



# 
# Groups defined by "member:" within the group
#

if ($valref->{'member'} ) {
  my @adgroups = @{ $valref->{'member'} } ;
  
  #print "   --------------- \n";
  #print Dumper( @adgroups ) ;
  #print "   --------------- \n";
  
  my $memName ;
  foreach $memName (@adgroups) {
    if (! exists $prigrphref->{$memName} ) {
      print "      $memName \n";
    }
  }
  print "\n";
  
}




print "\n\n\n";

$mesg = $ldap->unbind;   # take down session
#$mesg->code && die $mesg->error;



