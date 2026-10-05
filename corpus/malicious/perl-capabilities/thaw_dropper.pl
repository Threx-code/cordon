use LWP::UserAgent;
use Storable qw(thaw);
use MIME::Base64;
my $ua = LWP::UserAgent->new;
my $r = $ua->get('https://example.test/obj');
my $obj = thaw(decode_base64($r->content));
