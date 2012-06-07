use inc::Module::Install;

name     'Net-Xero';
all_from 'lib/Net/Xero.pm';
author   q{Lenz Gschwendtner <norbu09@cpan.org>};
license  'perl';

build_requires 'Test::More';

requires 'Mouse';
requires 'Net::OAuth';
requires 'Template';
requires 'LWP::UserAgent';
requires 'HTTP::Request::Common';
requires 'Data::Random';
requires 'XML::LibXML::Simple';
requires 'File::ShareDir';
requires 'Crypt::OpenSSL::RSA';


auto_install;
install_share  'share/Net-Xero';

WriteAll;

