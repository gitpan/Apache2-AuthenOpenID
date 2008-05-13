package Apache2::AuthenOpenID;

use 5.008;
use strict;
use warnings;
use Apache2::RequestRec ();
use Apache2::Module;
use Apache2::ServerUtil;
use Apache2::Log;
use Apache2::Access;
use Apache2::CmdParms;
use Apache2::Const -compile => qw(
    HTTP_UNAUTHORIZED OK DECLINED REDIRECT OR_AUTHCFG TAKE1
);
use CGI;
use CGI::Cookie;
use Net::OpenID::Consumer;
use Digest::HMAC_SHA1;
use LWPx::ParanoidAgent;
use base qw( Class::Data::Inheritable );

our $VERSION = '0.06';

__PACKAGE__->mk_classdata( auth_type => 'openid' );
__PACKAGE__->init;


sub init {
    my $self = shift;

    my @directives = (
        {
            name            => 'return_to',
            req_override    => Apache2::Const::OR_AUTHCFG,
            args_how        => Apache2::Const::TAKE1,
            errmsg          => 'return_to http://sample.com/trust_root/callback',
        },
        {
            name            => 'trust_root',
            req_override    => Apache2::Const::OR_AUTHCFG,
            args_how        => Apache2::Const::TAKE1,
            errmsg          => 'trust_root http://sample.com/trust_root/',
        },
        {
            name            => 'consumer_secret',
            req_override    => Apache2::Const::OR_AUTHCFG,
            args_how        => Apache2::Const::TAKE1,
            errmsg          => 'consumer_secret "Your consumer secret goes here"',
        },
    );

    eval { 
        Apache2::Module::add($self, \@directives); 
        Apache2::ServerUtil->server->push_handlers(
            PerlAuthenHandler => $self,
        );
    };
}

sub return_to {
    my ($self, $params, $arg) = @_;
    my $class = ref $self;
    my $i = Apache2::Module::get_config($class, $params->server);
    $i->{'return_to'} = $arg;
}

sub trust_root {
    my ($self, $params, $arg) = @_;
    my $class = ref $self;
    my $i = Apache2::Module::get_config($class, $params->server);
    $i->{'trust_root'} = $arg;
}

sub consumer_secret {
    my ($self, $params, $arg) = @_;
    my $class = ref $self;
    my $i = Apache2::Module::get_config($class, $params->server);
    $i->{'consumer_secret'} = $arg;
}

sub handler : method {
    my ($self, $r) = @_;
    lc $r->auth_type eq lc $self->auth_type or return Apache2::Const::DECLINED;
    my $cf = Apache2::Module::get_config($self, $r->server);
    unless ($cf->{'trust_root'} && $cf->{'return_to'} && $cf->{'consumer_secret'}) {
        $r->log_error("You need to specify trust_root, return_to, and consumer_secret.");
        die;
    }
    (my $cookie_name = $self."-".$r->auth_name) =~ s/(::|\s+)/-/g;
    my $cookie_dest_name = $cookie_name.'-destination';
    $self->set_custom_response($r);

    $r->err_headers_out->set('Pragma' => 'no-chache');
    $r->err_headers_out->set(
        'Cache-control' 
            => 'private, no-chache, no-store, must-revalidate, max-age=0'
    );

    my $request_url = "http://"
        . ($r->headers_in->{'X-Forwarded-Host'} || $r->hostname)
        . $r->uri;

    my $q = CGI->new($r);
    my %cookie_in = CGI::Cookie->parse($r->headers_in->{Cookie});

    my $csr = Net::OpenID::Consumer->new(
        args => $q,
        ua => LWPx::ParanoidAgent->new,
        consumer_secret => $cf->{'consumer_secret'},
    );
    if ($request_url eq $cf->{'return_to'}) {
        if (my $identity = $q->param('identity')) {
            my $claimed_identity = $csr->claimed_identity($identity)
                or return Apache2::Const::HTTP_UNAUTHORIZED;
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
            my $token = $self->calc_token($url, $time, $cf->{'consumer_secret'});
            my $cookie_out = CGI::Cookie->new(
                -name => $cookie_name,
                -value => [ $url, $time, $token ],
            );
            $r->user($url);
            if (%cookie_in && (my $dest = $cookie_in{$cookie_dest_name})) {
                $r->headers_out->set('Location' => $dest->value);
            } else {
                $r->headers_out->set('Location' => $cf->{'trust_root'});
            }
            my $cookie_dest_erase = CGI::Cookie->new(
                -name => $cookie_dest_name,
                -value => 'erase',
                -expires => '-1d',
            );
            $r->err_headers_out->add('Set-Cookie' => $cookie_out);
            $r->err_headers_out->add('Set-Cookie' => $cookie_dest_erase);
            return Apache2::Const::REDIRECT;
        }
        return Apache2::Const::HTTP_UNAUTHORIZED;
    }
    if (%cookie_in && $cookie_in{$cookie_name}){
        my ($url, $time, $token) = $cookie_in{$cookie_name}->value;
        if ($self->calc_token($url, $time, $cf->{'consumer_secret'}) eq $token) {
            $r->user($url);
            return Apache2::Const::OK;
        }
    }
    unless (%cookie_in && $cookie_in{$cookie_dest_name}) {
        my $cookie_dest_out = CGI::Cookie->new(
            -name => $cookie_dest_name,
            -value => $request_url,
            -expires => '+10m',
        );
        $r->err_headers_out->set('Set-Cookie' => $cookie_dest_out);
    }
    return Apache2::Const::HTTP_UNAUTHORIZED;
}

sub set_custom_response {
    my ($self, $r) = @_;
    my $cf = Apache2::Module::get_config($self, $r->server);
    my $auth_name = $r->auth_name;
    my $html = <<END;
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<html lang="en">
<head>
    <title>401 Unauthorized</title>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
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
        <input id="identity" type="text" name="identity" value="" tabindex="1">
        <input type="submit" value="Login with OpenID" tabindex="2">
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
    my ($self, $url, $time, $consumer_secret) = @_;
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

  AuthType          OpenID
  AuthName          "My private documents"
  return_to         http://sample.com/path/to/callback
  trust_root        http://sample.com/your/trust_root/
  consumer_secret   "your consumer secret"
  require           user sample.com/someidentity

=head1 DESCRIPTION

You can distinguish users with OpenID using this module.

=head1 SEE ALSO

L<Net::OpenID::Consumer>
L<http://openid.net/>

=head1 AUTHOR

Nobuo Danjou, L<nobuo.danjou@gmail.com>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2007 by Nobuo Danjou

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.


=cut
