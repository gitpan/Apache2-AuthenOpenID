use strict;
use ExtUtils::MakeMaker;
use mod_perl2 ();
use Apache::TestMM qw(test clean);

Apache::TestMM::filter_args();
Apache::TestMM::generate_script('t/TEST');

WriteMakefile(
    NAME              => 'Apache2::AuthenOpenID',
    VERSION_FROM      => 'lib/Apache2/AuthenOpenID.pm', # finds $VERSION
    PREREQ_PM         => {
        'Test::More' => 0.32,
        'mod_perl2' => 2.000001,
        'Apache::Test' => 0,
        'CGI' => 0,
        'Net::OpenID::Consumer' => 0.14,
        'Digest::HMAC_SHA1' => 1.01,
        'LWPx::ParanoidAgent' => 1.03,
        'Class::Data::Inheritable' => 0,
    }, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM  => 'lib/Apache2/AuthenOpenID.pm', # retrieve abstract from module
       AUTHOR         => 'Nobuo Danjou <nobuo.danjou@gmail.com>') : ()),
);
