#!/usr/bin/perl
use DBI;
use Data::Mirror qw(mirror_fh mirror_json mirror_csv);
use Net::DNS::SEC;
use Net::IDN::Encode qw(:all);
use Net::RDAP;
use constant {
    DB_HOST                 => 'localhost',
    DB_NAME                 => 'rdap_deployment',
    DB_USERNAME             => 'rdap_deployment',
    DB_PASSWORD             => '',
    TLD_LIST_URL            => 'https://data.iana.org/TLD/tlds-alpha-by-domain.txt',
    RDAP_BOOTSTRAP_URL      => 'https://data.iana.org/rdap/dns.json',
    IANA_ROOT_DB_URL        => 'https://importhtml.site/csv/?url=https%3A//www.iana.org/domains/root/db',
    DOMAINTOOLS_STATS_URL   => 'https://importhtml.site/csv/?url=https%3A//research.domaintools.com/statistics/tld-counts/&idx=2',
    STATDNS_STATS_URL       => 'https://importhtml.site/csv/?url=https%3A//www.statdns.com/',
    NTLDSTATS_STATS_URL     => 'https://importhtml.site/csv/?url=https%3A//ntldstats.com/tld/',
    RDAP_TLD_LIST_URL       => 'https://root.rdap.org/domains',
};
use strict;

$Data::Mirror::TTL_SECONDS = 3600;

my %enabled;
my $registry = Net::RDAP::Registry::IANARegistry->new(mirror_json(RDAP_BOOTSTRAP_URL));
foreach my $service ($registry->services) {
	foreach my $tld ($service->registries) {
		$enabled{$tld} = [ $service->urls ];
	}
}
say STDERR 'retrieved RDAP bootstrap registry';

my %type;
foreach my $row (@{mirror_csv(IANA_ROOT_DB_URL)}) {
    next if ('ARRAY' ne ref($row) || scalar(@{$row}) < 1);

    my $tld = clean_tld($row->[0]);

    if ($tld =~ /^xn--/ && 'country-code' eq $row->[1]) {
        $type{$tld} = 'idn-country-code';

    } else {
        $type{$tld} = $row->[1];

    }
}
say STDERR 'retrieved IANA root zone database';

my %dums;

foreach my $row (@{mirror_csv(DOMAINTOOLS_STATS_URL)}) {
    $dums{clean_tld((split(/[ \r\n]+/, $row->[1], 2))[0])} = clean_int($row->[2]);
}

foreach my $row (@{mirror_csv(STATDNS_STATS_URL)}) {
    next if ('ARRAY' ne ref($row) || scalar(@{$row}) != 10);
    $dums{$row->[1]} = $row->[9];
}

foreach my $row (@{mirror_csv(NTLDSTATS_STATS_URL)}) {
    next if ('ARRAY' ne ref($row) || scalar(@{$row}) != 10);
    $dums{clean_tld((split(/[ \r\n]+/, $row->[2], 2))[0])} = clean_int($row->[7]);
}

say STDERR 'retrieved DUM values';

my $db = DBI->connect(
    sprintf(
        'DBI:MariaDB:host=%s;database=%s',
        DB_HOST,
        DB_NAME,
    ),
    DB_USERNAME,
    DB_PASSWORD,
    {
        'RaiseError' => 1,
        'AutoCommit' => 1,
    },
);

my %info;
map { $info{$_->name->name} = $_ } map { Net::RDAP::Object::Domain->new($_) } @{mirror_json(RDAP_TLD_LIST_URL)->{'domainSearchResults'}};
say STDERR 'retrieved RDAP records';

my $sth = $db->prepare(qq(
    INSERT INTO rdap_deployment_report
    (tld, type, port43, rdap, https, dnssec, dane, dums, rdap_enabled)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, IF(? > 0, NOW(), NULL))
    ON DUPLICATE KEY UPDATE type=?, port43=?, rdap=?, https=?, dnssec=?, dane=?, dums=?, rdap_enabled=IFNULL(rdap_enabled, IF(? > 0, NOW(), NULL))
));

say STDERR 'connected to database, updating records...';

my $resolver = Net::DNS::Resolver->new(
    'nameservers'       => [qw(9.9.9.9 8.8.8.8 1.1.1.1)],
    'dnssec'            => 1,
    'usevc'             => 1,
    'persistent_tcp'    => 1,
);

my ($dnssecInfo, $daneInfo);
foreach my $tld (map { chomp ; lc } grep { /^[A-Z0-9-]+$/ } mirror_fh(TLD_LIST_URL)->getlines) {
	my $port43  = (0 < scalar(grep { 'Whois Service' eq $_->title } $info{$tld}->remarks));
	my $rdap    = defined($enabled{$tld});
	my $https   = $rdap && (0 < scalar(grep { 'https' eq $_->scheme } @{$enabled{$tld}}));

	my ($dnssec, $dane);
    if ($rdap) {
    	URL: foreach my $url (@{$enabled{$tld}}) {
            my $host = lc($url->host);

    		if (!defined($dnssecInfo->{$host})) {
    			my $answer = $resolver->query($url->host.'.', 'RRSIG');
    			$dnssecInfo->{$host} = ($answer && $answer->header->ancount > 0);
    		}

            $dnssec = $dnssec || $dnssecInfo->{$host};

    		if ($dnssec) {
    			if (!defined($daneInfo->{$host})) {
    				my $answer = $resolver->query('_443._tcp.'.$url->host.'.', 'TLSA');
    				$daneInfo->{$host} = ($answer && $answer->header->ancount > 0);
    			}

    			$dane = $dane || $daneInfo->{$host};
    		}

            last URL if ($dnssec && $dane);
    	}
    }

    my @values = ($type{$tld}, map { int } ($port43, $rdap, $https, $dnssec, $dane, $dums{$tld}, $rdap));

    $sth->execute($tld, @values, @values);

    say STDERR sprintf('updated .%s', $tld);
}

say STDERR 'done';

sub clean_tld {
    my $tld = shift;

    # remove BiDi code points, leading dots
    $tld =~ s/^[\.\N{U+200F}]+//g;
    $tld =~ s/[\N{U+200E}]+$//g;

    # convert to A-label and lowercase
    return lc(domain_to_ascii($tld));
}

sub clean_int {
    my $int = shift;
    $int =~ s/[^\d]//g;
    return int($int);
}
