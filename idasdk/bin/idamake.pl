#! /usr/bin/perl

#       Makefile wrapper for Unix
#       Can be used with the following switches:
#         -D    define a symbol (unfortunately, only one such switch is supported)
#         -f    makefile name
#         -j    number of jobs
#         -n    print commands but do not run them
#         -v    ignore IDAMAKE_SIMPLIFY, display full command lines
#         -Z    append raw output to idasrc/current/idamake.log
#         -z    filter stdin to stdout (for debugging)
#
#       The IDAMAKE_SIMPLIFY envvar turns on filtering of compiler command line
#       The IDAMAKE_PARALLEL envvar turns on parallel compilation
#

use strict;
use warnings;

use Getopt::Std;
my %opt;
my @ea32 = ('int', 'unsigned int', 'uint32', 'int32');
my @ea64 = ('long long int', 'long long unsigned int', 'uint64', 'int64');

#--------------------------------------------------------------------------
# can the type be used for %a?
sub is_ea_type
{
  my $type = shift;
  my $is64 = shift;

  $type =~ s/ {aka (.*)}//;
  return 1 if $type eq 'ea_t'
           || $type eq 'adiff_t'
           || $type eq 'asize_t'
           || $type eq 'nodeidx_t'
           || $type eq 'sel_t'
           || $type eq 'tid_t'
           || $type eq 'enum_t'
           || $type eq 'bmask_t'
           || $type eq 'sval_t'
           || $type eq 'uval_t';
  foreach ($is64 ? @ea64 : @ea32)
  {
    return 1 if $type eq $_;
  }
  return 0;
}

#--------------------------------------------------------------------------
sub is_8bytes_if_x64
{
  my $type = shift;

  $type =~ s/ {aka (.*)}//;
  return $type =~ /long( unsigned)? int/
      || $type =~ /^(__)?u?int64_t$/;
}

#--------------------------------------------------------------------------
sub simplify_command_line
{
  my $cmd = shift;

  return 0 if !$ENV{IDAMAKE_SIMPLIFY};

  if ( $cmd =~ /bin\/qar.sh *(\S+) *(\S+)/ )
  {
    print "lib $2\n";
    return 1;
  }
  if ( $cmd =~ /install_name_tool .* (\S+)$/ )
  {
    print "name $1\n";
    return 1;
  }

  my $out = 'compile';
  my $compiling = ($cmd =~ /^(\/opt\/mac\/bin\/i686-apple-darwin8-)?g(\+\+|cc)/);
  if ( $compiling )
  {
    $compiling = $cmd =~ / -c /; # really compiling
  }
  else
  {
    if ( $cmd =~ /\/bin\/qmake / )
    {
      my @words = split(/ +/, $cmd);
      print 'qmake ' . $words[-1];
      return 1;
    }
    if ( $cmd =~ m#objcopy --add-section '\.gdb_index# )
    {
      print "Adding .gdb-index section\n";
      return 1;
    }
    return 0 if $cmd !~ m#bin/(moc|uic|rcc) #;
    $out = $1;
    $compiling = 1;
  }
  if ( $compiling )                 # compilation
  {
    my @words = split(/ +/, $cmd);
    my $skipnext;
    my $i = 0;
    foreach (@words)
    {
      next if $i++ == 0;
      if ( $skipnext )
      {
        $skipnext = 0;
        next;
      }
      if ( /^-o$/ || /^-arch/ )
      {
        $skipnext = 1;
        next;
      }
      next if /^-/ && $_ !~ /^-D__(EA|X)64__/ && $_ !~ /^-O/;
      $out .= " $_";
    }
    $out .= "\n" if substr($out,-1,1) ne "\n";
    print $out;
  }
  else                                  # linking
  {
    return 0 unless $cmd =~ / -o *(\S+)/;
    print "link $1\n";
  }
  return 1;
}

#--------------------------------------------------------------------------
sub print_filtered_gcc_output
{
  my $FP = shift;

  # make stdout unbuffered so we see commands immediately
  select *STDOUT;
  $| = 1;

  my $errfunc;
  my $incs;
  my $is64;
  my $x64;
  while ( <$FP> )
  {
    if ( $opt{Z} )
    {
      my $home = $ENV{'HOME'};
      $home = "" unless $home;
      my $f = "$home/idasrc/current/idamake.log";
      open my $LLL, '>>', $f or die "$f: $!";
      print $LLL $_;
      close $LLL;
    }

    $is64 = 1 if /-D__EA64__/;
    $x64  = 1 if /-D__X64__/;

    # clean file/function info when we start a new command
    if ( /^(g(\+\+|cc)|cp|qcp\.sh|make\[\d\]:|ar:|compile|moc|uic|rcc|link|lib|name|strip|mkdeb|perl|#) /
      || /^(Parsing|Generating|Done|IDA API|Symbol Table Maker) /
      || /bin\/(qar\.sh|moc|uic|rcc) /
      || m#^/usr/bin/python #
      || /^Thank you for using IDA\. Have a nice day!/
      || /make -f makefile\.unx deploy$/
      || /\/(make|nasm|stm|install_name_tool|makerev|rasm|prepfpc|lmxdev|qmake|mkapi\.sh|bin2h)(x?64)? / )
    {
      undef $incs;
      undef $errfunc;
    }

    next if simplify_command_line($_);

    # cache file/function information until we really decide to print a bug
    if ( /^In file included/ )
    {
      $incs .= $_;
      next;
    }
    if ( /^ +from/ )
    {
      $incs .= $_;
      next;
    }
    if ( /In( static)?( member)? (function|constructor|destructor)/ )
    {
      $errfunc .= $_;
      next;
    }
    if ( /(In instantiation of)|(At global scope)/ )
    {
      $errfunc .= $_;
      next;
    }
    if ( /instantiated from/ )
    {
      $errfunc .= $_;
      next;
    }
    if ( /required from here/ )
    {
      $errfunc .= $_;
      next;
    }


    s/(\xE2\x80\x98)|(\xE2\x80\x99)|‘|’|`/'/g;   # convert (utf-8) tick/backtick to apostrophe

    # suppress uninteresting warnings
    if ( /format '\%.*a' expects (argument of )?type 'double', but argument \d+ has type '(.*)'/ )
    {
      next if is_ea_type($2, $is64);
    }
    if ( /format '\%.*a' expects (argument of )?type 'float\*', but argument \d+ has type '([^*]*)\*/ )
    {
      next if is_ea_type($2, $is64);
    }

    if ( /format '%.*ll[duxX]' expects (argument of )?type 'long long( unsigned)? int', but argument \d+ has type '(.*)'/ )
    {
      next if $x64 && is_8bytes_if_x64($3);
    }

    next if /is already a friend of/ && $ENV{__MAC__};
    next if /format '\%.*l[duxX]' expects (argument of )?type 'long( unsigned)? int', but argument \d+ has type 's?size_t( {aka.*})?'/;
    next if /format not a string literal and no format arguments/;
    next if /(double|float) format, different type arg/;
    next if /zero-length (gnu_)?printf format string/;
    next if /command line option "-fvisibility-inlines-hidden" is valid for C\+\+/;
    next if /suggest parentheses around '&&' within '\|\|'/;
    next if /forced in submake: disabling jobserver mode/;
    next if /enumeral and non-enumeral type in conditional expression/;
    next if /warning: -ffunction-sections may affect debugging on some targets/;
    next if /has virtual functions but non-virtual destructor/;
    next if /warning: converting negative value '-0x00000000000000001' to 'uint64'/;
    next if /warning: passing negative value '-0x00000000000000001' for argument 1 to 'bool .*::is_equal_to/;
    next if /warning: ignoring #pragma GCC diagnostic/;
    next if /warning: deleting object of polymorphic class type '(ida)place_t' which has non-virtual destructor/;
    next if /<command-line>:0:0: warning: "_FORTIFY_SOURCE" redefined \[enabled by default\]/;
    next if /note: this is the location of the previous definition/;
    # i do not know why the mac linker issues this warning, the file looks fine:
    next if /object file '(.*)\.a\(.*\)' doesn't contain architecture information for/;

    next if /^$/;

    # ok, it seems to be a real bug/warning
    print "REASON: [$_]" if $opt{z};
    if ( $incs )
    {
      print $incs;
      undef $incs;
    }
    if ( $errfunc )
    {
      print $errfunc;
      undef $errfunc;
    }
    print;
  }
}

#--------------------------------------------------------------------------
sub main
{
  my $make = $ENV{__BSD__} ? "/usr/local/bin/gmake" : "make";
  my $fname = $opt{f} ? $opt{f} : (-f "makefile.unx" ? "makefile.unx" : "makefile");

  my $opts = $opt{D} ? "-D$opt{D}" : "";
  $opts .= " -p" if $opt{p};
  $opts .= " -n" if $opt{n};
  my $jobs = $opt{j};
  unless ( $jobs )
  {
    $jobs = $ENV{IDAMAKE_PARALLEL} || 0;
    if ( $jobs == 1 )
    { # asked to run in parallel, find out the number of processors
      my $ncpus = ($^O eq "MSWin32") ? $ENV{NUMBER_OF_PROCESSORS}     # win
                : ($^O eq "darwin")  ? `/usr/sbin/sysctl hw.ncpu | cut -f 2 -d " "` # mac
                :             `grep processor /proc/cpuinfo | wc -l`; # linux
      $jobs = $ncpus + 0;
    }
  }
  $jobs = $jobs ? ("-j".$jobs) : "";
#  print "$make $jobs -f $fname $opt{D} @ARGV 2>&1|\n";
  open my $FP, "$make $jobs -f $fname $opts @ARGV 2>&1|" or die "Failed to launch make: $!";
  print_filtered_gcc_output($FP);
  close $FP;
  exit($? != 0);
}

#--------------------------------------------------------------------------
getopts("f:D:j:npvZz", \%opt) or die;
if ( $opt{z} )
{
  print_filtered_gcc_output(*STDIN);
}
else
{
  undef $ENV{IDAMAKE_SIMPLIFY} if $opt{v};
  main();
}
