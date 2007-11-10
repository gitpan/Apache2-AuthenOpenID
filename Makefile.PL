use 5.008;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME              => 'Apache2::AuthenOpenID',
    VERSION_FROM      => 'lib/Apache2/AuthenOpenID.pm', # finds $VERSION
    PREREQ_PM         => {
        mod_perl2 => 2.000001,
        CGI => 0,
        Net::OpenID::Consumer => 0.14,
        Digest::HMAC_SHA1 => 1.01,
        LWPx::ParanoidAgent => 1.03,
        Class::Data::Inheritable => 0,
    }, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM  => 'lib/Apache2/AuthenOpenID.pm', # retrieve abstract from module
       AUTHOR         => 'Nobuo Danjou <nobuo.danjou@gmail.com>') : ()),
);
