use strict;
use inc::Module::Install;

BEGIN {
    if ($ENV{TEST_MOD_PERL}) {
        eval {
            require ModPerl::MM;
            require Apache::TestMM;
        };
        if ( $@ ) {
            warn "You need Apache::Test to install with TEST_MOD_PERL\n";
            exit 0;
        }
        Apache::TestMM->import( qw(test clean) );
    }
}


name 'Apache2-AuthenOpenID';
all_from 'lib/Apache2/AuthenOpenID.pm';
requires  'mod_perl2' => 2.000001;
requires  'CGI' => 0;
requires  'Net::OpenID::Consumer' => 0.14;
requires  'Digest::HMAC_SHA1' => 1.01;
requires  'LWPx::ParanoidAgent' => 1.03;
requires  'Class::Data::Inheritable' => 0;


if ($ENV{TEST_MOD_PERL}) {
    Apache::TestMM::filter_args();
    Apache::TestMM::generate_script('t/TEST');
} else {
    warn "set TEST_MOD_PERL to run Apache::Test tests\n";
}
tests('t/*.t');

build_requires 'Test::More';

auto_include;
WriteAll;
