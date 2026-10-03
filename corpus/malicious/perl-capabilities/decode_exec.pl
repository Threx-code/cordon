use MIME::Base64;
my $stage = decode_base64($blob);
eval $stage;
