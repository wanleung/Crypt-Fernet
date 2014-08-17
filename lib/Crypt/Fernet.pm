package Crypt::Fernet;

use 5.018002;
use strict;
use warnings;

require Exporter;

our @ISA = qw(Exporter);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration	use Crypt::Fernet ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
our %EXPORT_TAGS = ( 'all' => [ qw(
	
) ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our @EXPORT = qw(
	
);

our $VERSION = '0.01';

our $FERNET_TOKEN_VERSION = pack("H*", '80');


# Preloaded methods go here.

use Crypt::CBC;
use Digest::SHA qw(hmac_sha256);
use MIME::Base64::URLSafe;

sub generate_key {
    return urlsafe_b64encode(Crypt::CBC->random_bytes(32));
}

sub encrypt {
    my ($key, $data) = @_;
    my $b64decode_key = urlsafe_b64decode($key);
    my $signkey = substr $b64decode_key, 0, 16;
    my $encryptkey = substr $b64decode_key, 16, 16;
    my $iv = Crypt::CBC->random_bytes(16);
    my $cipher = Crypt::CBC->new(-literal_key => 1,
                                 -key         => $encryptkey,
                                 -iv          => $iv,
                                 -keysize     => 16,
                                 -blocksize   => 16,
                                 -padding     => 'standard',
                                 -cipher => 'Rijndael',
                                 -header      => 'none',
                             );
    my $ciphertext = $cipher->encrypt($data);
    my $pre_token = $FERNET_TOKEN_VERSION . _timestamp() . $iv . $ciphertext;
    my $digest=hmac_sha256($pre_token, $signkey);
    my $token = $pre_token . $digest;
    return urlsafe_b64encode($token);
}

sub decrypt {
    my ($key, $token) = @_;
    verify($key, $token) or return;
    my $b64decode_key = urlsafe_b64decode($key);
    my $token_data = urlsafe_b64decode($token);

    my $encryptkey = substr $b64decode_key, 16, 16;
    my $iv = substr $token_data, 9, 16;

    my $ciphertextlen = (length $token_data) - 25 - 32;
    my $ciphertext = substr $token_data, 25, $ciphertextlen;
 
    my $cipher = Crypt::CBC->new(-literal_key => 1,
                                 -key         => $encryptkey,
                                 -iv          => $iv,
                                 -keysize     => 16,
                                 -blocksize   => 16,
                                 -padding     => 'standard',
                                 -cipher => 'Rijndael',
                                 -header      => 'none',
                             );
    my $plaintext = $cipher->decrypt($ciphertext);
    return $plaintext; 
}

sub verify {
    my ($key, $token) = @_;
    my $b64decode_key = urlsafe_b64decode($key);
    my $msg = urlsafe_b64decode($token);
    my $token_version = substr $msg, 0, 1;
    ($token_version eq $FERNET_TOKEN_VERSION) or return 0;
    
    my $token_sign = substr $msg, (length $msg) - 32, 32;
    my $signkey = substr $b64decode_key, 0, 16;
    my $pre_token = substr $msg, 0, (length $msg) - 32;
    my $verify_digest = hmac_sha256($pre_token , $signkey);
    ($token_sign eq $verify_digest) and return 1;
    return 0;
}

sub _timestamp {
    use bytes;
    my $time = time;
    my $time64bit;
    for my $index (0..7) {
        $time64bit .= substr pack("I", ($time >> $index * 8) & 0xFF), 0, 1;
    }
    my $result = reverse $time64bit;
    no bytes;
    return $result;
}

1;
__END__
# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

Crypt::Fernet - Perl extension for Fernet (symmetric encryption) 

=head1 SYNOPSIS

  use Crypt::Fernet;

  my $key = Crypt::Fernet::generate_key();
  my $plaintext = 'This is a test';
  my $token = Crypt::Fernet::encrypt($key, $plaintext);
  my $verify = Crypt::Fernet::verify($key, $token);
  my $decrypttext = Crypt::Fernet::decrypt($key, $token);

=head1 DESCRIPTION

Fernet provides guarantees that a message encrypted using it cannot be manipulated or read without the key. Fernet is an implementation of symmetric (also known as “secret key”) authenticated cryptography.
This is the Perl Implementation

More Detail:
   https://github.com/fernet/spec/blob/master/Spec.md

=head2 EXPORT

None by default.



=head1 SEE ALSO

More Detail on the Fernet Spec:
   https://github.com/fernet/spec/blob/master/Spec.md

Source of this project:
   https://github.com/wanleung/Crypt-Fernet

=head1 AUTHOR

Wan Leung Wong, E<lt>wanleung@linkomnia.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2014 by LinkOmnia Ltd (Wan Leung Wong wanleung@linkomnia.com)

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.18.2 or,
at your option, any later version of Perl 5 you may have available.


=cut
