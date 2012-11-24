use strict;
use warnings;

# check to ensure that we can find the various files we should be looking for

use Test::More;
use Test::TempDir 'scratch';
use Directory::Scratch;
use Path::Class;
use Readonly;

use aliased 'Config::Identity' => 'CI';

Readonly my $STUB => 'foo';

test_file_finder(".$STUB$_")
    for q{}, qw{ .gpg -identity -identity.gpg };

done_testing; # <===================

sub test_file_finder {
    my $filename = shift @_;

    my $ds = scratch;
    $ds->touch($filename);

    my $found = CI->best($STUB, $ds->base);
    ok $found, 'found a file!';
    return unless $found;

    $found = file($found)->basename;

    $ds->cleanup
        if is $found, $filename, "found $filename correctly";

    return;
}
