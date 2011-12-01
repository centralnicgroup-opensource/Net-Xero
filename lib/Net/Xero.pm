package Net::Xero;

use Mouse;
use Net::OAuth;
use LWP::UserAgent;
use HTTP::Request::Common;
use Template::Alloy;
use Data::Random qw(rand_chars);
use XML::LibXML::Simple qw(XMLin);
use File::ShareDir 'dist_dir';
use Template::Alloy;
use Crypt::OpenSSL::RSA;
use Data::Dumper;

=head1 NAME

Net::Xero - The great new Net::Xero!

=head1 VERSION

Version 0.11

=cut

our $VERSION = '0.11';

has 'api_url' => (
    is      => 'rw',
    isa     => 'Str',
    default => 'https://api.xero.com/',
);
has 'ua' => (
    is      => 'rw',
    isa     => 'LWP::UserAgent',
    default => sub { new LWP::UserAgent },
);
has 'debug' => (
    is        => 'rw',
    isa       => 'Bool',
    default   => 0,
    predicate => 'is_debug',
);
has 'error' => (
    is        => 'rw',
    isa       => 'Str',
    predicate => 'has_error',
);
has 'key'    => (is => 'rw', isa => 'Str');
has 'secret' => (is => 'rw', isa => 'Str');
has 'cert'   => (is => 'rw', isa => 'Str');
has 'nonce'  => (
    is      => 'ro',
    isa     => 'Str',
    default => join('', rand_chars(size => 16, set => 'alphanumeric')),
);
has 'login_link' => (is => 'rw', isa => 'Str');
has 'callback_url' => (
    is      => 'rw',
    isa     => 'Str',
    default => 'http://localhost:3000/callback',
);
has 'request_token'  => (is => 'rw', isa => 'Str');
has 'request_secret' => (is => 'rw', isa => 'Str');
has 'access_token'   => (is => 'rw', isa => 'Str');
has 'access_secret'  => (is => 'rw', isa => 'Str');
has 'template_path'  => (
    is      => 'rw',
    isa     => 'Str',
    default => (-d dist_dir('Net-Xero') ? dist_dir('Net-Xero') : {}),
);

#has 'template_path' => (is => 'rw', isa => 'Str');

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

Xero then redirects back to the callback URL defined with
C<$self-E<gt>callback_url>. If the user already accepted the application the
redirect may happen without the user actually clicking anywhere.

=cut

sub login {
    my $self = shift;

    my $request = Net::OAuth->request("request token")->new(
        consumer_key     => $self->key,
        consumer_secret  => $self->secret,
        request_url      => $self->api_url . '/oauth/RequestToken',
        request_method   => 'POST',
        signature_method => 'RSA-SHA1',
        timestamp        => time,
        nonce            => $self->nonce,
        callback         => $self->callback_url,
    );

    my $private_key = Crypt::OpenSSL::RSA->new_private_key($self->cert);
    $request->sign($private_key);
    my $res = $self->ua->request(GET $request->to_url);

    if ($res->is_success) {
        my $response =
            Net::OAuth->response('request token')
            ->from_post_body($res->content);
        $self->request_token($response->token);
        $self->request_secret($response->token_secret);
        print "Got Request Token ", $response->token, "\n" if $self->is_debug;
        print "Got Request Token Secret ", $response->token_secret, "\n"
            if $self->is_debug;
        return
              $self->api_url
            . '/oauth/Authorize?oauth_token='
            . $response->token
            . '&oauth_callback='
            . $self->callback_url;
    }
    else {
        $self->error($res->status_line);
        warn "Something went wrong: " . $res->status_line;
    }
}

=head2 auth

The auth method changes the initial request token into access token that we need
for subsequent access to the API. This method only has to be called once
after login.

=cut

sub auth {
    my $self = shift;

    my $request = Net::OAuth->request("access token")->new(
        consumer_key     => $self->key,
        consumer_secret  => $self->secret,
        request_url      => $self->api_url . '/oauth/AccessToken',
        request_method   => 'POST',
        signature_method => 'RSA-SHA1',
        timestamp        => time,
        nonce            => $self->nonce,
        callback         => $self->callback_url,
        token            => $self->request_token,
        token_secret     => $self->request_secret,
    );
    my $private_key = Crypt::OpenSSL::RSA->new_private_key($self->cert);
    $request->sign($private_key);
    my $res = $self->ua->request(GET $request->to_url);

    if ($res->is_success) {
        my $response =
            Net::OAuth->response('access token')->from_post_body($res->content);
        $self->access_token($response->token);
        $self->access_secret($response->token_secret);
        print "Got Access Token ", $response->token, "\n" if $self->is_debug;
        print "Got Access Token Secret ", $response->token_secret, "\n"
            if $self->is_debug;
    }
    else {
        $self->error($res->status_line);
        warn "Something went wrong: " . $res->status_line;
    }
}

=head2 set_cert

=cut

sub set_cert {
    my ($self, $path) = @_;

    if (-f $path) {
        open(CERT, '<', $path)
            or warn("Could not read certificate at: $path: " . $@);
        my @lines = <CERT>;
        close CERT;
        $self->cert(join('\n', @lines));
    }
}

=head2 get_inv_by_ref

=cut

sub get_inv_by_ref {
    my ($self, $ref) = @_;

    my $path = 'Invoices?where=Reference.ToString()=="' . $ref . '"';
    return $self->_talk($path, 'GET');
}

=head2 create_invoice

=cut

sub create_invoice {
    my ($self, $data) = @_;
    $data->{command} = 'create_invoice';
    return $self->_talk('Invoices', 'POST', $data);
}

=head2 approve_credit_note

=cut

sub approve_credit_note {
    my ($self, $data) = @_;
    $data->{command} = 'approve_credit_note';
    return $self->_talk('CreditNotes', 'POST', $data);
}

=head2 get

=cut

sub get {
    my ($self, $command, $data) = @_;
    $data->{command} = $command;
    my $path = join('', map(ucfirst, split(/_/, $command)));
    return $self->_talk($path, 'GET', $data);
}

=head2 post

=cut

sub post {
    my ($self, $command, $data) = @_;
    $data->{command} = $command;
    my $path = join('', map(ucfirst, split(/_/, $command)));
    return $self->_talk($path, 'POST', $data);
}

=head2 put

=cut

sub put {
    my ($self, $command, $data) = @_;
    $data->{command} = $command;
    my $path = join('', map(ucfirst, split(/_/, $command)));
    return $self->_talk($path, 'PUT', $data);
}


=head1 INTERNAL API

=head2 _talk

_talk handles the access to the restricted resources. You should
normally not need to access this directly.

=cut

sub _talk {
    my ($self, $command, $method, $content) = @_;

    if ($content) {
        $content = $self->_template($content);
    }

    my %opts = (
        consumer_key     => $self->key,
        consumer_secret  => $self->secret,
        request_url      => $self->api_url . '/api.xro/2.0/' . $command,
        request_method   => $method,
        signature_method => 'RSA-SHA1',
        timestamp        => time,
        nonce        => join('', rand_chars(size => 16, set => 'alphanumeric')),
        token        => $self->access_token,
        token_secret => $self->access_secret,
    );
    my $request = Net::OAuth->request("protected resource")->new(%opts);

    my $private_key = Crypt::OpenSSL::RSA->new_private_key($self->cert);
    $request->sign($private_key);

    my $res;

    #my $req = HTTP::Request->new($method => $request->to_url);
    if ($method =~ /get/i) {
        $res = $self->ua->request(GET $request->to_url);
    }
    elsif ($method =~ /put/i) {
        $res = $self->ua->request(
            PUT $request->to_url,
            Content_Type => 'form-data',
            Content      => $content
        );
    }
    else {
        $res = $self->ua->request(
            POST $request->to_url,
            Content_Type => 'form-data',
            Content      => $content
        );
    }

    if ($res->is_success) {
        print "Got Content ", $res->content, "\n" if $self->is_debug;
        return XMLin($res->content);
    }
    else {

        #$self->error($res->status_line);
        warn "Something went wrong: " . $res->status_line;
        $self->error($res->content);
    }
    return;
}

=head2 talk

=cut

sub _template {
    my ($self, $data) = @_;

    $data->{command} .= '.tt';
    print STDERR Dumper($data) if $self->is_debug;
    my $t;
    if ($self->is_debug) {
        $t = Template::Alloy->new(
            DEBUG        => 'DEBUG_ALL',
            INCLUDE_PATH => [ $self->template_path ]);
    }
    else {
        $t = Template::Alloy->new(INCLUDE_PATH => [ $self->template_path ]);
    }
    my $template = '';
    $t->process('frame.tt', $data, \$template) || die $t->error;
    print STDERR $template if $self->is_debug;
    return $template;
}

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

__PACKAGE__->meta->make_immutable();
