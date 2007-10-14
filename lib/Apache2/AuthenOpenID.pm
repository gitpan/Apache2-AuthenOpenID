package Apache2::AuthenOpenID;

use 5.008;
use strict;
use warnings;
use Apache2::RequestRec ();
use Apache2::Module;
use Apache2::ServerUtil;
use Apache2::Const -compile => qw(
    HTTP_UNAUTHORIZED OK DECLINED REDIRECT OR_AUTHCFG TAKE1
);
use CGI;
use CGI::Cookie;
use Net::OpenID::Consumer;
use Digest::HMAC_SHA1;
use LWPx::ParanoidAgent;

our $VERSION = '0.01';

my @directives = (
    {
        name            => 'AuthType',
        func            => __PACKAGE__ . '::AuthType',
        req_override    => Apache2::Const::OR_AUTHCFG,
        args_how        => Apache2::Const::TAKE1
    },
    {
        name            => 'return_to',
        func            => __PACKAGE__ . '::return_to',
        req_override    => Apache2::Const::OR_AUTHCFG,
        args_how        => Apache2::Const::TAKE1
    },
    {
        name            => 'trust_root',
        func            => __PACKAGE__ . '::trust_root',
        req_override    => Apache2::Const::OR_AUTHCFG,
        args_how        => Apache2::Const::TAKE1
    },
    {
        name            => 'consumer_secret',
        func            => __PACKAGE__ . '::consumer_secret',
        req_override    => Apache2::Const::OR_AUTHCFG,
        args_how        => Apache2::Const::TAKE1
    },
);

eval { Apache2::Module::add(__PACKAGE__, \@directives); };

sub AuthType {
    my ($i, $params, $arg) = @_;
    if ($arg =~ /^OpenID$/i) {
        Apache2::ServerUtil->server->push_handlers(
            PerlAuthenHandler => \&handler
        );
    }
}

sub return_to {
    my ($i, $params, $arg) = @_;
    $i = Apache2::Module::get_config(__PACKAGE__, $params->server);
    $i->{'return_to'} = $arg;
}

sub trust_root {
    my ($i, $params, $arg) = @_;
    $i = Apache2::Module::get_config(__PACKAGE__, $params->server);
    $i->{'trust_root'} = $arg;
}

sub consumer_secret {
    my ($i, $params, $arg) = @_;
    $i = Apache2::Module::get_config(__PACKAGE__, $params->server);
    $i->{'consumer_secret'} = $arg;
}

sub handler {
    my $r = shift;

    $r->auth_type =~ m{^OpenID$}i or return Apache2::Const::DECLINED;
    (my $cookie_name = __PACKAGE__."-".$r->auth_name) =~ s/::/-/g;
    my $dest_cookie_name = $cookie_name.'-destination';
    &set_custom_response($r);

    $r->err_headers_out->set('Pragma' => 'no-chache');
    $r->err_headers_out->set(
        'Cache-control' 
            => 'private, no-chache, no-store, must-revalidate, max-age=0'
    );

    my $cf = Apache2::Module::get_config(__PACKAGE__, $r->server);

    my $request_url = "http://"
        . ($r->headers_in->{'X-Forwarded-Host'} || $r->hostname)
        . $r->uri;

    my $q = CGI->new($r);
    my %cookie = CGI::Cookie->parse($r->headers_in->{Cookie});

    my $csr = Net::OpenID::Consumer->new(
        args => $q,
        ua => LWPx::ParanoidAgent->new,
        consumer_secret => $cf->{'consumer_secret'},
    );
    if ($request_url eq $cf->{'return_to'}) {
        if (my $identity = $q->param('identity')) {
            my $claimed_identity = $csr->claimed_identity($identity);
            my $check_url = $claimed_identity->check_url(
                return_to => $cf->{'return_to'},
                trust_root => $cf->{'trust_root'},
            );
            $r->err_headers_out->set(Location => $check_url);
            return Apache2::Const::REDIRECT;
        } elsif (my $setup_url = $csr->user_setup_url) {
            $r->err_headers_out->set(Location => $setup_url);
            return Apache2::Const::REDIRECT;
        } elsif ($csr->user_cancel) {
            return Apache2::Const::HTTP_UNAUTHORIZED;
        } elsif (my $vident = $csr->verified_identity) {
            my $url = $vident->url;
            $url =~ s{(^https?://|/$)}{}g;
            my $time = time();
            my $token = &calc_token($url, $time, $cf->{'consumer_secret'});
            my $cookie = CGI::Cookie->new(
                -name => $cookie_name,
                -value => [ $url, $time, $token ],
            );
            $r->user($url);
            if (%cookie && (my $dest = $cookie{$dest_cookie_name})) {
                $r->headers_out->set('Location' => $dest->value);
            } else {
                $r->headers_out->set('Location' => $cf->{'trust_root'});
            }
            my $erase = CGI::Cookie->new(
                -name => $dest_cookie_name,
                -value => 'erase',
                -expires => '-1d',
            );
            $r->err_headers_out->add('Set-Cookie' => $cookie);
            $r->err_headers_out->add('Set-Cookie' => $erase);
            return Apache2::Const::REDIRECT;
        }
        return Apache2::Const::HTTP_UNAUTHORIZED;
    }
    if (%cookie && $cookie{$cookie_name}){
        my ($url, $time, $token) = $cookie{$cookie_name}->value;
        if (&calc_token($url, $time, $cf->{'consumer_secret'}) eq $token) {
            $r->user($url);
            return Apache2::Const::OK;
        }
    }
    unless (%cookie && $cookie{$dest_cookie_name}) {
        my $dest_cookie = CGI::Cookie->new(
            -name => $dest_cookie_name,
            -value => $request_url,
            -expires => '+10m',
        );
        $r->err_headers_out->set('Set-Cookie' => $dest_cookie);
    }
    return Apache2::Const::HTTP_UNAUTHORIZED;
}

sub set_custom_response {
    my $r = shift;
    my $cf = Apache2::Module::get_config(__PACKAGE__, $r->server);
    my $auth_name = $r->auth_name;
    my $html = <<END;
<html>
<head>
    <title>401 Unauthorized</title>
    <meta http-equiv="Content-Style-Type" content="text/css">
    <style type="text/css"><!--
        body {
            color: #666;
            background-color: #fff9f9;
            margin: 100px;
            padding: 20px;
            border: 2px solid #aaa;
            font-family: "Lucida Grande", verdana, sans-serif;
            line-height: 1.5em;
        }
        #identity {
            background: url(http://www.openid.net/login-bg.gif) no-repeat;
            background-color: #fff;
            width: 30em;
            padding-left: 18px;
        }
    --></style>
</head>
<body>
    <h1>$auth_name</h1>
    <form action="$cf->{'return_to'}" method="POST">
        <p>
        Please enter your OpenID identifiier:<br>
        <input id="identity" type="text" name="identity">
        <input type="submit" value="Login with OpenID">
        </p>
    </form>
</body>
</html>
END
    $r->custom_response(
        Apache2::Const::HTTP_UNAUTHORIZED,
        $html,
    );
}

sub calc_token {
    my ($url, $time, $consumer_secret) = @_;
    my $context = Digest::HMAC_SHA1->new($consumer_secret);
    $context->add($url);
    $context->add($time);
    return $context->hexdigest;
}

1;
__END__
# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

Apache2::AuthenOpenID - OpenID authen hander for mod_perl2.

=head1 SYNOPSIS

  LoadModule perl_module modules/mod_perl.so
  PerlLoadModule Apache2::AuthenOpenID

  AuthType OpenID
  AuthName "My private documents"
  return_to http://sample.com/path/to/callback
  trust_root http://sample.com/your/trust_root/
  consumer_secret "your consumer secret"
  require user sample.com/someidentity

=head1 DESCRIPTION

You can distinguish users with OpenID using this module.

=head1 SEE ALSO

L<Net::OpenID::Consumer>
L<http://openid.net>

=head1 AUTHOR

Nobuo Danjou, L<nobuo.danjou@gmail.com>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2007 by Nobuo Danjou

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.


=cut
