package Config::Identity;
# ABSTRACT: Load (and optionally decrypt via GnuPG) user/pass identity information 

=head1 SYNOPSIS

PAUSE:

    use Config::Identity::PAUSE;

    # 1. Find either $HOME/.pause-identity or $HOME/.pause
    # 2. Decrypt the found file (if necessary), read, and parse it
    # 3. Throw an exception unless  %identity has 'user' and 'password' defined

    my %identity = Config::Identity::PAUSE->load_check;
    print "user: $identity{user} password: $identity{password}\n";
     
GitHub API:

    use Config::Identity::GitHub;

    # 1. Find either $HOME/.github-identity or $HOME/.github
    # 2. Decrypt the found file (if necessary) read, and parse it
    # 3. Throw an exception unless %identity has 'login' and 'token' defined

    my %identity = Config::Identity::PAUSE->load_check;
    print "login: $identity{login} token: $identity{token}\n";

=head1 DESCRIPTION

Config::Identity is a tool for loadiing (and optionally decrypting via GnuPG) user/pass identity information

For GitHub API access, an identity is a C<login>/C<token> pair

For PAUSE access, an identity is a C<user>/C<password> pair

=head1 USAGE

=head2 %identity = Config::Identity->load_best( <stub> )

First attempt to load an identity from $HOME/.<stub>-identity

If that file does not exist, then attempt to load an identity from $HOME/.<stub>

The file may be optionally GnuPG encrypted

%identity will be populated like so:

    <key> <value>

For example:

    username alice
    password hunter2

=head1 Using a custom C<gpg> or passing custom arguments

You can specify a custom C<gpg> executable by setting the CI_GPG environment variable

    export CI_GPG="$HOME/bin/gpg"

You can pass custom arguments by setting the CI_GPG_ARGUMENTS environment variable

    export CI_GPG_ARGUMENTS="--no-secmem-warning"

=head1 Encrypting your identity information with GnuPG

If you've never used GnuPG before, first initialize it:

    # Follow the prompts to create a new key for yourself
    gpg --gen-key 

To encrypt your GitHub identity with GnuPG using the above key:
    
    # Follow the prompts, using the above key as the "recipient"
    # Use ^D once you've finished typing out your authentication information
    gpg -ea > $HOME/.github

=head1 Caching your GnuPG secret key via gpg-agent

Put the following in your .*rc

    if which gpg-agent 1>/dev/null
    then
        if test -f $HOME/.gpg-agent-info && \
            kill -0 `cut -d: -f 2 $HOME/.gpg-agent-info` 2>/dev/null
        then
            . "${HOME}/.gpg-agent-info"
            export GPG_AGENT_INFO
        else
            eval `gpg-agent --daemon --write-env-file "${HOME}/.gpg-agent-info"`
        fi
    else
    fi

=head1 PAUSE identity format

    user <user>
    password <password>

C<username> can also be used as alias for C<user>

=head1 GitHub identity format

    login <login>
    token <token>

=cut

use strict;
use warnings;

use Carp;
use IPC::Run qw/ start finish /;
use File::HomeDir();
use File::Spec;

our $home = File::HomeDir->home;
{
    my $gpg;
    sub GPG() { $ENV{CI_GPG} || ( $gpg ||= do {
        require File::Which;
        $gpg = File::Which::which( $_ ) and last for qw/ gpg gpg2 /;
        $gpg;
    } ) }
}
sub GPG_ARGUMENTS() { $ENV{CI_GPG_ARGUMENTS} || '' }

# TODO Do not even need to do this, since the file is on disk already...
sub decrypt {
    my $self = shift;
    my $file = shift;

    my $gpg = GPG or croak "Missing gpg";
    my $gpg_arguments = GPG_ARGUMENTS;
    my $run;
    # Old versions, please ignore
    #$run = "$gpg $gpg_arguments -qd --no-tty --command-fd 0 --status-fd 1";
    #$run = "$gpg $gpg_arguments -qd --no-tty --command-fd 0";
    $run = "$gpg $gpg_arguments -qd --no-tty";
    my @run = split m/\s+/, $run;
    push @run, $file;
    my $process = start( \@run, '>pipe', \*OUT, '2>pipe', \*ERR );
    my $output = join '', <OUT>;
    my $_error = join '', <ERR>;
    finish $process;
    return ( $output, $_error );
}

sub best {
    my $self = shift;
    my $stub = shift;
    my $base = shift;
    $base = $home unless defined $base;

    croak "Missing stub" unless defined $stub && length $stub;

    for my $i0 ( ".$stub-identity", ".$stub" ) {
        for my $i1 ( "." ) {
            my $path = File::Spec->catfile( $base, $i1, $i0 );
            return $path if -f $path;
        }
    }

    return '';
}

sub read {
    my $self = shift;
    my $file = shift;

    croak "Missing file" unless -f $file;
    croak "Cannot read file ($file)" unless -r $file;

    my $binary = -B $file;

    open my $handle, $file or croak $!;
    binmode $handle if $binary;
    local $/ = undef;
    my $content = <$handle>;
    close $handle or warn $!;

    if ( $binary || $content =~ m/----BEGIN PGP MESSAGE----/ ) {
        my ( $_content, $error ) = $self->decrypt( $file );
        if ( $error ) {
            carp "Error during decryption of content" . $binary ? '' : "\n$content";
            croak "Error during decryption of $file:\n$error";
        }
        $content = $_content;
    }
    
    return $content;
}

sub parse {
    my $self = shift;
    my $content = shift;

    return unless $content;
    my %content;
    for ( split m/\n/, $content ) {
        next if /^\s*#/;
        next unless m/\S/;
        next unless my ($key, $value) = /^\s*(\w+)\s+(.+)$/;
        $content{$key} = $value;
    }
    return %content;
}

sub load_best {
    my $self = shift;
    my $stub = shift;

    die "Unable to find .$stub-identity or .$stub" unless my $path = $self->best( $stub );
    return $self->load( $path );
}

sub try_best {
    my $self = shift;
    my $stub = shift;

    return unless my $path = $self->best( $stub );
    return $self->load( $path );
}

sub load {
    my $self = shift;
    my $file = shift;

    return $self->parse( $self->read( $file ) );
}

1;
