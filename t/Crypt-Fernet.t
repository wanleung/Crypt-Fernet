# Before 'make install' is performed this script should be runnable with
# 'make test'. After 'make install' it should work as 'perl Crypt-Fernet.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use strict;
use warnings;

use Test::More tests => 25;
BEGIN { 
    use_ok('Crypt::CBC');
    use_ok('Digest::SHA');
    use_ok('MIME::Base64::URLSafe');
    use_ok('Crypt::Fernet') 
};

# Test basic functionality
my $key = Crypt::Fernet::generate_key();
my $plaintext = 'This is a test';
my $token = Crypt::Fernet::encrypt($key, $plaintext);
my $verify = Crypt::Fernet::verify($key, $token);
my $decrypttext = Crypt::Fernet::decrypt($key, $token);

ok( $key, "Key generation works" );
ok( $token, "Encryption works" );
ok( $verify, "Verification works" );
ok( $decrypttext eq $plaintext, "Decryption works" );

# Test timestamp functionality
my $timestamp = time() - 1;
my $token_at_time = Crypt::Fernet::encrypt_at_time($key, $plaintext, $timestamp);
my $extracted_timestamp = Crypt::Fernet::extract_timestamp($key, $token_at_time);
ok( $extracted_timestamp == $timestamp, "Timestamp extraction works" );

# Test decrypt_at_time
my $current_time = time();
my $ttl = 10;
my $decrypt_at_time = Crypt::Fernet::decrypt_at_time($key, $token_at_time, $ttl, $current_time);
ok( $decrypt_at_time eq $plaintext, "decrypt_at_time works" );

# Test TTL functionality
my $ttl_verify = Crypt::Fernet::verify($key, $token, $ttl);
my $ttl_decrypttext = Crypt::Fernet::decrypt($key, $token, $ttl);
ok( $ttl_verify, "TTL verification works" );
ok( $ttl_decrypttext eq $plaintext, "TTL decryption works" );

# Test backward compatibility with old tokens
my $old_key = 'cJ3Fw3ehXqef-Vqi-U8YDcJtz8Gv-ZHyxultoAGHi4c=';
my $old_token = 'gAAAAABT8bVcdaked9SPOkuQ77KsfkcoG9GvuU4SVWuMa3ewrxpQdreLdCT6cc7rdqkavhyLgqZC41dW2vwZJAHLYllwBmjgdQ==';

my $old_verify = Crypt::Fernet::verify($old_key, $old_token, $ttl);
my $old_decrypttext;
eval { $old_decrypttext = Crypt::Fernet::decrypt($old_key, $old_token, $ttl); };

ok( $old_verify == 0, "Old token correctly expires with TTL");
ok( !defined $old_decrypttext, "Old token correctly fails decryption with TTL");

# Test MultiFernet functionality
my $key1 = Crypt::Fernet::generate_key();
my $key2 = Crypt::Fernet::generate_key();
my $multi = Crypt::Fernet::MultiFernet->new([$key1, $key2]);

ok( defined $multi, "MultiFernet creation works" );

my $multi_token = $multi->encrypt($plaintext);
my $multi_decrypt = $multi->decrypt($multi_token);
ok( $multi_decrypt eq $plaintext, "MultiFernet encrypt/decrypt works" );

# Test that MultiFernet can decrypt tokens from either key
my $token1 = Crypt::Fernet::encrypt($key1, $plaintext);
my $token2 = Crypt::Fernet::encrypt($key2, $plaintext);
my $multi_decrypt1 = $multi->decrypt($token1);
my $multi_decrypt2 = $multi->decrypt($token2);
ok( $multi_decrypt1 eq $plaintext, "MultiFernet can decrypt with key1" );
ok( $multi_decrypt2 eq $plaintext, "MultiFernet can decrypt with key2" );

# Test token rotation
my $rotated_token = $multi->rotate($token2);
my $rotated_decrypt = $multi->decrypt($rotated_token);
ok( $rotated_decrypt eq $plaintext, "Token rotation works" );

# Test timestamp extraction with MultiFernet
my $multi_timestamp = $multi->extract_timestamp($multi_token);
ok( defined $multi_timestamp, "MultiFernet timestamp extraction works" );

# Test error handling
eval { Crypt::Fernet::decrypt($key, "invalid_token"); };
ok( $@, "Invalid token properly throws exception" );

eval { Crypt::Fernet::decrypt("invalid_key", $token); };
ok( $@, "Invalid key properly throws exception" );

# Test string vs bytes token support
my $string_token = "$token";  # Force to string
my $string_decrypt = Crypt::Fernet::decrypt($key, $string_token);
ok( $string_decrypt eq $plaintext, "String tokens work" );

# Test clock skew protection
my $future_time = time() + 120;  # 2 minutes in future
my $future_token = Crypt::Fernet::encrypt_at_time($key, $plaintext, $future_time);
eval { Crypt::Fernet::decrypt_at_time($key, $future_token, 60, time()); };
ok( $@, "Clock skew protection works" );

#########################

# Insert your test code below, the Test::More module is use()ed here so read
# its man page ( perldoc Test::More ) for help writing this test script.

