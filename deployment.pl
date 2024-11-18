#!/usr/bin/perl
use Carp;
use DBI;
use Data::Mirror qw(mirror_str mirror_fh mirror_json mirror_csv);
use Encode qw(encode decode);
use File::Basename qw(dirname);
use File::Slurp;
use File::Spec;
use HTML::Tiny;
use IPC::Open2;
use JSON::XS;
use List::Util qw(any none);
use Net::DNS::SEC;
use Net::RDAP;
use Number::Format qw(:subs);
use Object::Anon;
use POSIX qw(strftime);
use Template::Liquid;
use constant {
    TLD_LIST_URL            => 'https://data.iana.org/TLD/tlds-alpha-by-domain.txt',
    RDAP_BOOTSTRAP_URL      => 'https://data.iana.org/rdap/dns.json',
    IANA_ROOT_DB_URL        => 'https://importhtml.site/csv/?url=https%3A//www.iana.org/domains/root/db',
    DOMAINTOOLS_STATS_URL   => 'https://importhtml.site/csv/?url=https%3A//research.domaintools.com/statistics/tld-counts/&idx=2',
    STATDNS_STATS_URL       => 'https://importhtml.site/csv/?url=https%3A//www.statdns.com/',
    NTLDSTATS_STATS_URL     => 'https://importhtml.site/csv/?url=https%3A//ntldstats.com/tld/',
    PAGE_TEMPLATE           => 'https://raw.githubusercontent.com/rdap-org/about.rdap.org/main/_layouts/page.html',
    STEALTH_LIST            => 'https://etc.gavinbrown.xyz/stealth.dat',
};
use utf8;
use feature qw(say);
use strict;

my $TODAY = strftime("%Y-%m-%d", gmtime);

$Data::Mirror::TTL_SECONDS = 3600;

my @tlds = sort map { chomp ; lc } grep { /^[A-Z0-9-]+$/ } mirror_fh(TLD_LIST_URL)->getlines;

say STDERR 'retrieved TLD list';

my @idns = grep { /^xn--/ } @tlds;

my $pid = open2(my $out, my $in, qw(idn2 --quiet --decode));

$in->print(join("\n", @idns, ""));
$in->close;

my $ulabels = {};

for (my $i = 0 ; $i < scalar(@idns) ; $i++) {
    chomp ($ulabels->{$idns[$i]} = decode('UTF-8', $out->getline));
}

$out->close;

waitpid($pid, 0);

say STDERR 'generated U-label mapping';

my %stealth = map { lc($_) => 1 } grep { length > 0 } (split(/\n/, mirror_str(STEALTH_LIST)));

say STDERR 'retrieved stealth server list';

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

eval {
    foreach my $row (@{mirror_csv(DOMAINTOOLS_STATS_URL)}) {
        $dums{clean_tld((split(/[ \r\n]+/, $row->[1], 2))[0])} = clean_int($row->[2]);
    }

    say STDERR 'retrieved DUM stats from DomainTools';
};

eval {
    foreach my $row (@{mirror_csv(STATDNS_STATS_URL)}) {
        next if ('ARRAY' ne ref($row) || scalar(@{$row}) != 10);
        $dums{$row->[1]} = $row->[9];
    }

    say STDERR 'retrieved DUM stats from StatDNS';
};

eval {
    foreach my $row (@{mirror_csv(NTLDSTATS_STATS_URL)}) {
        next if ('ARRAY' ne ref($row) || scalar(@{$row}) != 10);

        my $tld = clean_tld([ split(/[ \r\n]+/, $row->[2], 2) ]->[0]);

        $dums{$tld} = clean_int($row->[7]);
    }

    say STDERR 'retrieved DUM stats from nTLDStats';
};

say STDERR $@ if ($@);

say STDERR 'retrieved DUM values';

my $db = DBI->connect(
    'dbi:SQLite:dbname='.$ARGV[0],
    {
        'RaiseError' => 1,
        'AutoCommit' => 1,
    },
);

$db->do(q{
    CREATE TABLE IF NOT EXISTS rdap_deployment_report (
        `id` INTEGER PRIMARY KEY,
        `tld` TEXT,
        `type` TEXT,
        `rdap` INTEGER,
        `https` INTEGER,
        `dnssec` INTEGER,
        `dane` INTEGER,
        `dums` INTEGER,
        `rdap_enabled_on` STRING DEFAULT NULL,
        UNIQUE(tld COLLATE NOCASE)
    )
});

my $isth = $db->prepare(q{
    INSERT INTO `rdap_deployment_report`
    (`tld`, `type`, `rdap`, `https`, `dnssec`, `dane`, `dums`, `rdap_enabled_on`)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
});

my $usth = $db->prepare(q{
    UPDATE `rdap_deployment_report`
    SET `type`=?, `rdap`=?, `https`=?, `dnssec`=?, `dane`=?, `dums`=?, `rdap_enabled_on`=?
    WHERE (`tld`=?)
});

say STDERR 'connected to database';

my $ssth = $db->prepare(q{SELECT * FROM `rdap_deployment_report`});
$ssth->execute;

my $dsth = $db->prepare(q{DELETE FROM `rdap_deployment_report` WHERE (`tld`=?)});

my %records;
while (my $row = $ssth->fetchrow_hashref) {
    $row = anon($row);
    if (none { $_ eq $row->tld } @tlds) {
        say STDERR sprintf('.%s no longer exists, deleting', $row->tld);
        $dsth->execute($row->tld);

    } else {
        $records{$row->tld} = $row;

    }
}

my $resolver = Net::DNS::Resolver->new(
    'nameservers'       => [qw(1.1.1.1)],
    'dnssec'            => 1,
    'usevc'             => 1,
    'persistent_tcp'    => 1,
    'tcp_timeout'       => 10,
);

my ($dnssecInfo, $daneInfo);
foreach my $tld (@tlds) {

	my $rdap    = exists($enabled{$tld});
	my $https   = $rdap && (0 < scalar(grep { 'https' eq $_->scheme } @{$enabled{$tld}}));

	my ($dnssec, $dane, $rdap_enabled_on);

    if ($rdap) {
    	URL: foreach my $url (@{$enabled{$tld}}) {
            my $host = lc($url->host);

    		if (!exists($dnssecInfo->{$host})) {
    			my $answer = $resolver->query($host.'.', 'A');
    			$dnssecInfo->{$host} = ($answer && scalar(grep { "RRSIG" eq $_->type } $answer->answer) > 0);
    		}

            $dnssec = $dnssec || $dnssecInfo->{$host};

    		if ($dnssec) {
    			if (!exists($daneInfo->{$host})) {
    				my $answer = $resolver->query('_443._tcp.'.$host.'.', 'TLSA');
    				$daneInfo->{$host} = ($answer && $answer->header->ancount > 0);
    			}

    			$dane = $dane || $daneInfo->{$host};
    		}

            last URL if ($dnssec && $dane);
    	}

        $rdap_enabled_on = (exists($records{$tld}) ? $records{$tld}->rdap_enabled_on : $TODAY);

    } else {
        $rdap_enabled_on = undef;

    }

    if (!exists($records{$tld})) {
        $isth->execute(
            $tld,
            $type{$tld},
            $rdap,
            $https,
            $dnssec,
            $dane,
            $dums{$tld},
            $rdap_enabled_on,
        );

        say STDERR sprintf('inserted new record for .%s', $tld);

    } else {
        $usth->execute(
            $type{$tld},
            $rdap,
            $https,
            $dnssec,
            $dane,
            $dums{$tld},
            $rdap_enabled_on,
            $tld,
        );

        say STDERR sprintf('updated .%s', $tld);
    }
}

say STDERR 'generating HTML';

my $h = HTML::Tiny->new;

my $content = Template::Liquid
    ->parse(join('', read_file(File::Spec->catfile(dirname(__FILE__), qw(inc preamble.html)))))
    ->render(TODAY => $TODAY);

$content .= $h->open('table', { class => 'sortable table table-striped'});

$content .= $h->open('thead');

foreach my $col (qw(TLD Type Domains RDAP Added HTTPS? DNSSEC? DANE?)) {
    my $attrs = {};

    if ('Domains' eq $col) {
        $attrs->{style} = 'text-align: right';

    } else {
        $attrs->{class} = 'text-center';

    }

    $content .= $h->th($attrs, $col);
}

$content .= $h->close('thead');

$content .= $h->open('tbody');

my @map_data = ([qw(Country Deployment)]);

my $stats = {
    'all' => [['Deployment Status', 'Approx # Domains'], ['Not available', 0], ['Available', 0], ['Stealth', 0]],
};

my $stats_type_map = {
    'sponsored'             => 'generic',
    'generic-restricted'    => 'generic',
    'idn-country-code'      => 'country-code',
};

my $sth = $db->prepare(q{SELECT * FROM `rdap_deployment_report` ORDER BY `tld` ASC});

$sth->execute;

my @rows;

while (my $ref = $sth->fetchrow_hashref) {
    push (@rows, $ref);
}

foreach my $ref (sort { $b->{'dums'} <=> $a->{'dums'} } @rows) {
    $content .= $h->open('tr', {scope => 'row'});

    my $row = anon $ref;

    my $stats_type = $stats_type_map->{$row->type} || $row->type;

    if (!$stats->{$stats_type}) {
        #
        # vivify stats data structure for this TLD type
        #
        $stats->{$stats_type} = [['Deployment Status', 'Approx # Domains'], ['Not available', 0], ['Available', 0], ['Stealth', 0]];
    }

    my $stealth = exists($stealth{$row->tld});

    my $idx = ($row->rdap ? 2 : ($stealth ? 3 : 1));
    $stats->{'all'}->[$idx]->[1] += $row->dums;
    $stats->{$stats_type}->[$idx]->[1] += $row->dums;

    $content .= $h->td({class => 'text-center tld', title => '.'.$row->tld}, '.'.idn_to_unicode($row->tld));
    $content .= $h->td({class => 'text-center type'}, $row->type);
    $content .= $h->td({class => 'dums', style => 'text-align:right'}, format_number($row->dums));
    $content .= $h->td({class => 'text-center text-'.($row->rdap   ? 'success' : ($stealth ? 'warning' : 'danger'))}, $row->rdap ? 'Yes' : ($stealth ? '<span title="See footnote">No*</span>' : 'No'));
    $content .= $h->td({class => 'text-center text-'.($row->rdap   ? 'success' : 'danger')}, $row->rdap_enabled_on || '-');
    $content .= $h->td({class => 'text-center text-'.($row->https  ? 'success' : 'danger')}, $row->https ? 'Yes' : 'No');
    $content .= $h->td({class => 'text-center text-'.($row->dnssec ? 'success' : 'danger')}, $row->dnssec ? 'Yes' : 'No');
    $content .= $h->td({class => 'text-center text-'.($row->dane   ? 'success' : 'danger')}, $row->dane ? 'Yes' : 'No');

    $content .= $h->close('tr');

    if ('country-code' eq $row->type) {
        #
        # skip .gb, as we don't want its status to clobber that of .uk. If
        # .gb ever starts creating delegations, things could get
        # complicated...
        #
        next if ('gb' eq $row->tld);

        #
        # special treatment for .uk, as the Google Charts API only
        # recognises "GB" as the country code for the UK
        #
        my $cc = uc('uk' eq $row->tld ? 'GB' : $row->tld);

        #
        # Has RDAP: 1
        # Stealth RDAP: 0.5
        # No RDAP: 0
        #
        my $value = ($row->rdap ? 1 : ($stealth ? 0.5 : 0));

        push(@map_data, [$cc, $value]);
    }
}

$content .= $h->close('tbody');
$content .= $h->close('table');

if (scalar(keys(%stealth)) > 0) {
    $content .= $h->p($h->em(
        '* This TLD has a '
        .$h->a({target => '_new', href => 'https://regiops.net/row13-agenda#:~:text=15:00,Stealth%20RDAP'}, 'Stealth RDAP')
        .' Server.'
    ));
}

my $json = JSON::XS->new->utf8;

$content .= $h->script(sprintf('drawCharts(%s, %s)', $json->encode(\@map_data), $json->encode($stats)));

say Template::Liquid
    ->parse(mirror_str(PAGE_TEMPLATE))
    ->render(
        site => {
            description => '',
            title       => 'RDAP.ORG',
        },

        page => {
            title => 'Deployment Dashboard',

            stylesheets => [qw(
                /assets/style.css
            )],

            scripts => [qw(
                /assets/sorttable.js
                /assets/chart.js
                https://www.gstatic.com/charts/loader.js
            )],

            alternate => {
                type => 'application/rss+xml',
                href => 'rss.xml'
            },
        },

        content => $content,
    );

say STDERR 'done';

exit(0);

sub clean_tld {
    my $tld = shift;

    # remove BiDi code points, leading dots
    $tld =~ s/^[\.\N{U+200F}]+//g;
    $tld =~ s/[\N{U+200E}]+$//g;

    # convert to A-label and lowercase
    return lc(idn_to_ascii($tld));
}

sub clean_int {
    my $int = shift;
    $int =~ s/[^\d]//g;
    return int($int);
}

sub idn_to_unicode {
    my $alabel = shift;

    return $ulabels->{$alabel} || $alabel;
}

sub idn_to_ascii {
    my $ulabel = shift;

    foreach my $alabel (keys(%{$ulabels})) {
        return $alabel if ($ulabels->{$alabel} eq $ulabel);
    }

    return $ulabel;
}
