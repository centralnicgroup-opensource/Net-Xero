package Net::Xero;

use Mouse;
use Net::OAuth;
use Template::Alloy;
use LWP::UserAgent;
use HTTP::Request::Common;
use Data::Random qw(rand_chars);
use XML::LibXML::Simple qw(XMLin);

=head1 NAME

Net::Xero - The great new Net::Xero!

=head1 VERSION

Version 0.01

=cut

our $VERSION = '0.01';

has 'debug' => (is => 'rw', isa => 'Bool', default => 0);
has 'error' => (is => 'rw', isa => 'Str', predicate => 'has_error');
has 'key' => (is => 'rw', isa => 'Str');
has 'secret' => (is => 'rw', isa => 'Str');
has 'nonce' => (is => 'ro', isa => 'Str', default => join( '', rand_chars( size => 16, set => 'alphanumeric' ) ));
has 'login_link' => (is => 'rw', isa => 'Str');
has 'callback_url' => (is => 'rw', isa => 'Str', default => 'http://localhost:3000/callback');
has 'request_token' => (is => 'rw', isa => 'Str');
has 'request_secret' => (is => 'rw', isa => 'Str');
has 'access_token' => (is => 'rw', isa => 'Str');
has 'access_secret' => (is => 'rw', isa => 'Str');
#has 'context' => (is => 'rw', isa => 'Str', default => 'sandbox');

=head1 SYNOPSIS

Quick summary of what the module does.

Perhaps a little code snippet.

    use Net::Xero;

    my $foo = Net::Xero->new();
    ...

=head1 EXPORT

A list of functions that can be exported.  You can delete this section
if you don't export anything, such as for a purely object-oriented module.

=head1 FUNCTIONS

=cut

=head2 login

This sets up the initial OAuth handshake and returns the login URL. This
URL has to be clicked by the user and the the user then has to accept
the application in xero. 

Dropbox then redirects back to the callback URL defined with
C<$self-E<gt>callback_url>. If the user already accepted the application the
redirect may happen without the user actually clicking anywhere.

=cut

sub login {
    my $self = shift;

    my $ua = LWP::UserAgent->new;

    my $request = Net::OAuth->request("request token")->new(
        consumer_key => $self->key,
        consumer_secret => $self->secret,
        request_url => 'http://api.xero.com/0/oauth/request_token',
        request_method => 'POST',
        signature_method => 'HMAC-SHA1',
        timestamp => time,
        nonce => $self->nonce,
        callback => $self->callback_url,
    );

    $request->sign;
    my $res = $ua->request(GET $request->to_url);

    if ($res->is_success) {
        my $response = Net::OAuth->response('request token')->from_post_body($res->content);
        $self->request_token($response->token);
        $self->request_secret($response->token_secret);
        print "Got Request Token ", $response->token, "\n" if $self->debug;
        print "Got Request Token Secret ", $response->token_secret, "\n" if $self->debug;
        return 'http://api.xero.com/0/oauth/authorize?oauth_token='.$response->token.'&oauth_callback='.$self->callback_url;
    }
    else {
        $self->error($res->status_line);
        warn "Something went wrong: ".$res->status_line;
    }
}

=head2 auth

The auth method changes the initial request token into access token that we need
for subsequent access to the API. This method only has to be called once
after login.

=cut

sub auth {
    my $self = shift;

    my $ua = LWP::UserAgent->new;
    my $request = Net::OAuth->request("access token")->new(
        consumer_key => $self->key,
        consumer_secret => $self->secret,
        request_url => 'http://api.xero.com/0/oauth/access_token',
        request_method => 'POST',
        signature_method => 'HMAC-SHA1',
        timestamp => time,
        nonce => $self->nonce,
        callback => $self->callback_url,
        token => $self->request_token,
        token_secret => $self->request_secret,
    );

    $request->sign;
    my $res = $ua->request(GET $request->to_url);

    if ($res->is_success) {
        my $response = Net::OAuth->response('access token')->from_post_body($res->content);
        $self->access_token($response->token);
        $self->access_secret($response->token_secret);
        print "Got Access Token ", $response->token, "\n" if $self->debug;
        print "Got Access Token Secret ", $response->token_secret, "\n" if $self->debug;
    }
    else {
        $self->error($res->status_line);
        warn "Something went wrong: ".$res->status_line;
    }
}

=head2 accounts

accounts polls the users accoutns from xero.

=cut

sub accounts {
    my $self = shift;

    return $self->_talk('Accounts');
}

=head1 INTERNAL API

=head2 _talk

_talk handles the access to the restricted resources. You should
normally not need to access this directly.

=cut

sub _talk {
    my $self    = shift;
    my $command = shift;
    my $method  = shift || 'GET';
    my $content = shift;

    my $ua = LWP::UserAgent->new;

    my %opts = (
        consumer_key => $self->key,
        consumer_secret => $self->secret,
        request_url => 'https://api.xero.com/api.xro/2.0/'.$command,
        request_method => $method,
        signature_method => 'HMAC-SHA1',
        timestamp => time,
        nonce => $self->nonce,
        #callback => $self->callback_url,
        token => $self->access_token,
        token_secret => $self->access_secret,
    );
    my $request = Net::OAuth->request("protected resource")->new( %opts );

    $request->sign;

    my $res;
    if($method =~ /get/i){
        $res = $ua->get($request->to_url);
    } else {
        $res = $ua->post($request->to_url, Content_Type => 'form-data', Content => $content );
    }

    if ($res->is_success) {
        print "Got Content ", $res->content, "\n" if $self->debug;
        return XMLin($res->content);
    }
    else {
        $self->error($res->status_line);
        warn "Something went wrong: ".$res->status_line;
    }
    return;
}

=head2 talk

=cut

=head1 AUTHOR

Lenz Gschwendtner, C<< <norbu09 at cpan.org> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-net-xero at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Net-Xero>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.




=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Net::Xero


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Net-Xero>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Net-Xero>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Net-Xero>

=item * Search CPAN

L<http://search.cpan.org/dist/Net-Xero/>

=back


=head1 ACKNOWLEDGEMENTS


=head1 COPYRIGHT & LICENSE

Copyright 2010 Lenz Gschwendtner.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.


=cut

1; # End of Net::Xero
