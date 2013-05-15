#
# NetUtil
#
#   Various utilities subroutines for networking stuff
#

use strict;

package NetUtil;

use POSIX;

use Output;

# --------------------------------------------------------------------
# Export our symbols.  (Called by 'use NetUtil' statement.)
# --------------------------------------------------------------------

sub import
{
   my $pack = shift;
   my ($callpack, $filename) = caller(0);
   my($name);

   no strict "refs";

   for $name (qw(IPv4Normalize IPv4Expand IPv4MaskToPrefixLength IPv4PrefixLengthToMask IPv6Normalize IPv6Compress IPv6Expand IPv6MaskToPrefixLength IPv6PrefixLengthToMask))
   {
      *{"${callpack}::$name"}    = \&{$pack . '::' . $name};
   }
}

#
# IPv4Normalize
#
# Normalize an IPv4 input address to dotted decimal
# Supports a number of legal (although deprecated)
# IP address abbrevations (just because).
#
# Inputs:  IPv4_address
# Outputs: Normalized (dotted decimal) IPv4_address or undef if error
#
sub IPv4Normalize($)
  {

    my $instr = shift;

    return undef if (!defined($instr));

    $instr =~ s/^\s+//;
    $instr =~ s/\s+$//;

    my $a;
    my $b;
    my $c;
    my $d;
    my $ipv4addr;

    if ($instr =~ /^(\d+)$/)
      {
        # Raw integer
        if (($1 > 4294967295))
          {
            return undef;
          }
        $d = 0 + ($1 % 256);
        $c = 0 + (floor($1 / 256) % 256);
        $b = 0 + (floor($1 / 65536) % 256);
        $a = 0 + (floor($1 / 16777216) % 256);
        $ipv4addr = sprintf("%d.%d.%d.%d", $a, $b, $c, $d);
        return $ipv4addr;
      }
    elsif ($instr =~ /^(\d+)\.(\d+)$/)
      {
        # Class A abbrev (i.e. 127.1 => 127.0.0.1)
        if (($1 > 255) || ($2 > 16777215))
          {
            return undef;
          }
        $d = 0 + ($2 % 256);
        $c = 0 + (floor($2 / 256) % 256);
        $b = 0 + (floor($2 / 65536) % 256);
        $a = 0 + ($1);
        $ipv4addr = sprintf("%d.%d.%d.%d", $a, $b, $c, $d);
        return $ipv4addr;
      }
    elsif ($instr =~ /^(\d+)\.(\d+)\.(\d+)$/)
      {
        # Class B abbrev (i.e. 134.79.10 => 134.79.0.10)
        if (($1 > 255) || ($2 > 255) || ($3 > 65535)) 
          {
            return undef;
          }
        $d = 0 + ($3 % 256);
        $c = 0 + (floor($3 / 256) % 256);
        $b = 0 + ($2);
        $a = 0 + ($1);
        $ipv4addr = sprintf("%d.%d.%d.%d", $a, $b, $c, $d);
        return $ipv4addr;
      }
    elsif ($instr =~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/)
      {
        # "Normal" dotted decimal
        if (($1 > 255) || ($2 > 255) || ($3 > 255) || ($4 > 255))
          {
            return undef;
          }
        $d = 0 + ($4);
        $c = 0 + ($3);
        $b = 0 + ($2);
        $a = 0 + ($1);
        $ipv4addr = sprintf("%d.%d.%d.%d", $a, $b, $c, $d);
        return $ipv4addr;
      }
    else
      {
        return undef;
      }

  }

#
# IPv4Expand
#
# Expand an IPv4 address (all groups 3 digits)
# (why would you want to do this?  Maybe a nice
# formatted table?  Maybe for alpha sorting?)
#
# Inputs:  IPv4_address
# Outputs: Expanded (dotted decimal) IPv4_address or undef if error
#
sub IPv4Expand($)
  {

    my $ipv4addr = shift;

    return undef if (!defined($ipv4addr));

    $ipv4addr = IPv4Normalize($ipv4addr);

    return undef if (!defined($ipv4addr));

    # Reformat the string
    my @octet = split("\\.",$ipv4addr);
    $ipv4addr = sprintf("%03d.%03d.%03d.%03d",0+$octet[0],0+$octet[1],0+$octet[2],0+$octet[3]);

    return $ipv4addr;

  }

#
# IPv4PrefixLengthToMask
#
# Convert a CIDR prefix length to a mask
# (i.e. 24 --> 255.255.255.0)
#
# Inputs:  Prefix_Length
# Outputs: Normalized (dotted decimal) IPv4_address mask or undef if error
#
sub IPv4PrefixLengthToMask
  {

    my $prefix_length = shift;

    return undef if (!defined($prefix_length));

    my $mask;

    return undef if (($prefix_length !~ /^(\d+)$/) || ($1 > 32));

    $mask = join('.', unpack('CCCC', pack('B32', substr(substr('11111111111111111111111111111111', 0, $prefix_length) . '00000000000000000000000000000000', 0, 32))));

    return $mask;

  }

#
# IPv4MaskToPrefixLength
#
# Convert mask to CIDR prefix length
# (i.e. 255.255.255.0 --> 24)
#
# Inputs:  IPv4_address_mask
# Outputs: Prefix_Length or undef if error
#
sub IPv4MaskToPrefixLength
  {

    my $ipv4addr = shift;

    return undef if (!defined($ipv4addr = IPv4Normalize($ipv4addr)));

    my $prefix_length;
    my $prefix_bits;

    $prefix_length = index(unpack("B32", pack("CCCC", split(/\./, $ipv4addr))) . "0" , "0");
    $prefix_bits = ((my $s = unpack("B32", pack("CCCC", split(/\./,$ipv4addr)))) =~ s/1/1/g);

    return undef if ($prefix_length != $prefix_bits);

    return $prefix_length;

  }

#
# IPv6Normalize
#
# Normalize (remove ::'s, expose "hidden" 0's) and validate IPv6 addresses
#
# Inputs:  IPv6_address
# Outputs: Normalized (no hidden 0's) IPv6_address or undef if error
#
sub IPv6Normalize($)
  {

    my $instr = shift;

    return undef if (!defined($instr));

    $instr =~ s/^\s+//;
    $instr =~ s/\s+$//;

    my $ipv6addr;
    my $cc;
    my $dc;
    my @hex;

    # Adjust for mixed hex, dotted decimal (convert to pure hex)
    if ($instr =~ /:(\d+)\.(\d+)\.(\d+)\.(\d+)$/)
      {
        if (($1 > 255) || ($2 > 255) || ($3 > 255) || ($4 > 255))
          {
            return undef;
          }
        $instr = sprintf("%s:%x%02x:%x%02x",$`,$1,$2,$3,$4);
      }

    # Adjust for (special) case double :: at beginning or end if enough :'s
    $cc = 0 + ($instr =~ s/:/:/g);
    if (($cc > 7))
      {
        $instr =~ s/^::/0:/ || $instr =~ s/::$/:0/;
      }

    # Perform a syntax check on the result
    $cc = 0 + ($instr =~ s/:/:/g);
    $dc = 0 + ($instr =~ s/::/::/g);
    if (($instr =~ /[^:0-9a-fA-F]/) || ($instr =~ /[0-9a-fA-F]{5,}/) || ($cc > 7) || ($dc > 1) || (($cc < 7) && ($dc < 1)))
      {
        return undef;
      }
    
    # Expand the :: (and deal with begining/end : cases)
    if ($dc == 1)
      {
        $dc = substr(":0:0:0:0:0:0:0:",0,1+((8-$cc)*2));
        $instr =~ s/::/$dc/;
      }
    $instr =~ s/^:/0:/;
    $instr =~ s/:$/:0/;

    # Reformat the string 
    @hex = split(":",$instr);
    $ipv6addr = sprintf("%x:%x:%x:%x:%x:%x:%x:%x",hex($hex[0]),hex($hex[1]),hex($hex[2]),hex($hex[3]),hex($hex[4]),hex($hex[5]),hex($hex[6]),hex($hex[7]));

    return $ipv6addr;

  }

#
# IPv6Expand
#
# Expand an IPv6 address (all groups 4 hex digits) 
# (why would you want to do this?  Maybe a nice
# formatted table?  Maybe for alpha sorting?)
#
# Inputs:  IPv6_address
# Outputs: Expanded (all 4 hex digits) IPv6_address or undef if error
#
sub IPv6Expand($)
  {

    my $ipv6addr = shift;

    return undef if (!defined($ipv6addr));

    $ipv6addr = IPv6Normalize($ipv6addr);

    return undef if (!defined($ipv6addr));

    # Reformat the string
    my @hex = split(":",$ipv6addr);
    $ipv6addr = sprintf("%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",hex($hex[0]),hex($hex[1]),hex($hex[2]),hex($hex[3]),hex($hex[4]),hex($hex[5]),hex($hex[6]),hex($hex[7]));

    return $ipv6addr;

  }

#
# IPv6Compress
#
# Compress an IPv6 address (replace longest set of
# groups of 0's with ::, and eliminate leading/trailing
# bare 0's)
#
# (currently an ugly hack; will clean it up later)
#
# Inputs:  IPv6_address
# Outputs: Compressed (replace max 0's with ::) IPv6_address or undef if error
#
sub IPv6Compress($)
  {

    my $ipv6addr = shift;

    return undef if (!defined($ipv6addr));

    $ipv6addr = IPv6Normalize($ipv6addr);

    return undef if (!defined($ipv6addr));

    $ipv6addr =~ s/0:0:0:0:0:0:0:0/::/ ||
    $ipv6addr =~ s/^0:0:0:0:0:0:0/:/ ||
    $ipv6addr =~ s/0:0:0:0:0:0:0$/:/ ||
    $ipv6addr =~ s/0:0:0:0:0:0:0// ||
    $ipv6addr =~ s/^0:0:0:0:0:0/:/ ||
    $ipv6addr =~ s/0:0:0:0:0:0$/:/ ||
    $ipv6addr =~ s/0:0:0:0:0:0// ||
    $ipv6addr =~ s/^0:0:0:0:0/:/ ||
    $ipv6addr =~ s/0:0:0:0:0$/:/ ||
    $ipv6addr =~ s/0:0:0:0:0// ||
    $ipv6addr =~ s/^0:0:0:0/:/ ||
    $ipv6addr =~ s/0:0:0:0$/:/ ||
    $ipv6addr =~ s/0:0:0:0// ||
    $ipv6addr =~ s/^0:0:0/:/ ||
    $ipv6addr =~ s/0:0:0$/:/ ||
    $ipv6addr =~ s/0:0:0// ||
    $ipv6addr =~ s/^0:0/:/ ||
    $ipv6addr =~ s/0:0$/:/ ||
    $ipv6addr =~ s/0:0// ;

    # Deal with any remaining leading/trailing bare 0 
    $ipv6addr =~ s/^0:/:/;
    $ipv6addr =~ s/:0$/:/;

    return $ipv6addr;

  }

#
# IPv6PrefixLengthToMask
#
# Convert a CIDR prefix length to a mask
# (i.e. 24 --> FFFF:FF00:0:0:0:0:0:0)
#
# Inputs:  Prefix_Length
# Outputs: Normalized IPv6_address_mask or undef if error
#
sub IPv6PrefixLengthToMask
  {

    my $prefix_length = shift;

    return undef if (!defined($prefix_length));

    my $mask;

    return undef if (($prefix_length !~ /^(\d+)$/) || ($1 > 128));

    $mask = join(':', unpack('H4H4H4H4H4H4H4H4', pack('B128', substr(substr('11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111', 0, $prefix_length) . '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', 0, 128))));

    # Reformat the string
    my @hex = split(":",$mask);
    $mask = sprintf("%x:%x:%x:%x:%x:%x:%x:%x",hex($hex[0]),hex($hex[1]),hex($hex[2]),hex($hex[3]),hex($hex[4]),hex($hex[5]),hex($hex[6]),hex($hex[7]));

    return $mask;

  }

#
# IPv6MaskToPrefixLength
#
# Convert mask to CIDR prefix length
# (i.e. FFFF:FFFF:: --> 32)
#
# Inputs:  IPv6_address_mask
# Outputs: Prefix_Length or undef if error
#
sub IPv6MaskToPrefixLength
  {

    my $ipv6addr = shift;

    return undef if (!defined($ipv6addr = IPv6Normalize($ipv6addr)));

    my $prefix_length;
    my $prefix_bits;

    $prefix_length = index(unpack("B128", pack("H4H4H4H4H4H4H4H4", split(/\:/, $ipv6addr))) . "0" , "0");
    $prefix_bits = ((my $s = unpack("B128", pack("H4H4H4H4H4H4H4H4", split(/\:/,$ipv6addr)))) =~ s/1/1/g);

    return undef if ($prefix_length != $prefix_bits);

    return $prefix_length;

  }

1;
