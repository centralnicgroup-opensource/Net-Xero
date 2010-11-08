use inc::Module::Install;

name     'Net-Xero';
all_from 'lib/Net/Xero.pm';
author   q{Lenz Gschwendtner <norbu09@cpan.org>};
license  'perl';

build_requires 'Test::More';

auto_install;

WriteAll;

