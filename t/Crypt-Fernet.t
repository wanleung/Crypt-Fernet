# Before 'make install' is performed this script should be runnable with
# 'make test'. After 'make install' it should work as 'perl Crypt-Fernet.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use strict;
use warnings;

use Test::More tests => 5;
BEGIN { use_ok('Crypt::Fernet') };

my $key = Crypt::Fernet::generate_key();
my $plaintext = 'This is a test';
my $token = Crypt::Fernet::encrypt($key, $plaintext);
my $verify = Crypt::Fernet::verify($key, $token);
my $decrypttext = Crypt::Fernet::decrypt($key, $token);
ok( $key );
ok( $token );
ok( $verify );
ok( $decrypttext eq $plaintext );

#########################

# Insert your test code below, the Test::More module is use()ed here so read
# its man page ( perldoc Test::More ) for help writing this test script.

