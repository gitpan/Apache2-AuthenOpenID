use strict;
use inc::Module::Install;

BEGIN {
    eval {
        require ModPerl::MM;
        require Apache::TestMM;
    };
    if ( $@ ) {
        exit 0;
    }
    Apache::TestMM->import( qw(test clean) );
}


name 'Apache2-AuthenOpenID';
all_from 'lib/Apache2/AuthenOpenID.pm';
requires  'CGI' => 0;
requires  'Net::OpenID::Consumer' => 0.14;
requires  'Digest::HMAC_SHA1' => 1.01;
requires  'LWPx::ParanoidAgent' => 1.03;
requires  'Class::Data::Inheritable' => 0;

Apache::TestMM::filter_args();
Apache::TestMM::generate_script('t/TEST');
tests('t/*.t');

build_requires 'Test::More';

auto_include;
WriteAll;
