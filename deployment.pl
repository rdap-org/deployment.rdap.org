#!/usr/bin/perl
use DBI;
use Data::Mirror qw(mirror_fh mirror_json mirror_csv);
use Net::DNS::SEC;
use Net::RDAP;
use Number::Format qw(:subs);
use HTML::Tiny;
use IPC::Open2;
use JSON::XS;
use Object::Anon;
use POSIX qw(strftime);
use constant {
    TLD_LIST_URL            => 'https://data.iana.org/TLD/tlds-alpha-by-domain.txt',
    RDAP_BOOTSTRAP_URL      => 'https://data.iana.org/rdap/dns.json',
    IANA_ROOT_DB_URL        => 'https://importhtml.site/csv/?url=https%3A//www.iana.org/domains/root/db',
    DOMAINTOOLS_STATS_URL   => 'https://importhtml.site/csv/?url=https%3A//research.domaintools.com/statistics/tld-counts/&idx=2',
    STATDNS_STATS_URL       => 'https://importhtml.site/csv/?url=https%3A//www.statdns.com/',
    NTLDSTATS_STATS_URL     => 'https://importhtml.site/csv/?url=https%3A//ntldstats.com/tld/',
};
use feature qw(say);
use strict;

my $TODAY = strftime("%Y-%m-%d", gmtime);

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

eval {
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
};

say STDERR 'retrieved DUM values';

my $db = DBI->connect(
    sprintf('dbi:SQLite:dbname='.$ARGV[0]),
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
        `rdap_enabled_on` STRING,
        UNIQUE(tld COLLATE NOCASE)
    )
});

my $sth = $db->prepare(q{
    INSERT INTO rdap_deployment_report
    (`tld`, `type`, `rdap`, `https`, `dnssec`, `dane`, `dums`, `rdap_enabled_on`)
    VALUES (
        ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(`tld`) DO UPDATE
    SET `type`=?, `rdap`=?, `https`=?, `dnssec`=?, `dane`=?, `dums`=?,
    `rdap_enabled_on`=COALESCE(`rdap_enabled_on`, ?)
});

say STDERR 'connected to database, updating records...';

my $resolver = Net::DNS::Resolver->new(
    'nameservers'       => [qw(9.9.9.9 8.8.8.8 1.1.1.1)],
    'dnssec'            => 1,
    'usevc'             => 1,
    'persistent_tcp'    => 1,
);

my ($dnssecInfo, $daneInfo);
foreach my $tld (map { chomp ; lc } grep { /^[A-Z0-9-]+$/ } mirror_fh(TLD_LIST_URL)->getlines) {

	my $rdap    = defined($enabled{$tld});
	my $https   = $rdap && (0 < scalar(grep { 'https' eq $_->scheme } @{$enabled{$tld}}));

	my ($dnssec, $dane, $date);

    if ($rdap) {
        $date = $TODAY;

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

    my @values = ($type{$tld}, map { int } ($rdap, $https, $dnssec, $dane, $dums{$tld}), $date);

    $sth->execute($tld, @values, @values);

    say STDERR sprintf('updated .%s', $tld);
}

say STDERR 'generating HTML';

my $h = HTML::Tiny->new;

my $j = JSON::XS->new->utf8->pretty;

say '<!doctype html>';

say($h->open('html', {'lang' => 'en'}));

say <<"END";
<head>
  <meta charset="UTF-8"/>
  <title>RDAP Deployment Dashboard</title>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <link rel="stylesheet" href="https://client.rdap.org/assets/bootstrap.min.css" />
  <script type="text/javascript" src="./sorttable.js"></script>
  <script type="text/javascript" src="https://www.gstatic.com/charts/loader.js"></script>
  <style>
      .world-map {
          width:67%;
          margin:1em auto;
      }
      figcaption {
          text-align:center;
      }

      .world-map figcaption {
          font-weight:bold;
      }

      .pie-chart figcaption {
          font-style:italic;
          font-size:smaller;
      }
      #world-map {
          width:100%;
          height:50wh;
      }
      .pie-chart {
          min-width:275px;
          float:left;
          height:75wh;
      }
      .dums {
          font-variant-numeric: tabular-nums;
      }
  </style>
</head>
END

say($h->open('body'));

say <<"END";
<nav class="navbar navbar-expand-lg navbar-dark bg-dark shadow-sm">
  <span class="text-white font-weight-bold" style="font-size:larger">
    <a class="navbar-brand" href="#">RDAP.ORG</a>
  </span>
  <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbar1" aria-controls="navbar1" aria-expanded="false" aria-label="Toggle navigation">
    <span class="navbar-toggler-icon"></span>
  </button>
  <div class="collapse navbar-collapse" id="navbar1">
    <ul class="navbar-nav mr-auto mt-2 mt-lg-0">
      <li class="nav-item">
        <a class="nav-link" href="https://about.rdap.org/">Home</a>
      </li>
      <li class="nav-item">
        <a class="nav-link" href="https://client.rdap.org/">Web Client</a>
      </li>
      <li class="nav-item">
        <a class="nav-link active" href="https://deployment.rdap.org/">Deployment Dashboard</a>
      </li>
    </ul>
  </div>
</nav>

<br/>

<div class="container">

<p>This page tracks the deployment of <a href="https://about.rdap.org">RDAP</a> among <a href="https://en.wikipedia.org/wiki/Top-level_domain" rel="noopener" target="_new">top-level domains</a>. It is updated once per day <em>(last update: $TODAY)</em>.</p>

<p>Description of columns:</p>
<ul>
	<li><em>TLD</em> - the TLD name. Hover to see the A-label version of IDN TLDs.</li>
	<li><em>Type</em> - the "type" of the TLD. This comes from the <a href="https://www.iana.org/domains/root/db">IANA root zone database</a>.</li>
    <li><em>Domains</em> - the approximate number of second-level domains under the TLD (taken from various public sources)</li>
	<li><em>Port 43</em> - whether a whois server is registered for the TLD at IANA. Some TLDs have whois servers even if IANA has no entry</li>
	<li><em>RDAP</em> - whether there is an RDAP Base URL in the <a href="https://www.iana.org/assignments/rdap-dns/rdap-dns.xhtml">Bootstrap Service Registry</a></li>
	<li><em>Added</em> - the date that an RDAP Base URL was first observed for this TLD in the Bootstrap Registry</li>
	<li><em>HTTPS</em> - whether at least one URL in the registry for this TLD has the <tt>https://</tt> scheme</li>
	<li><em>DNSSEC</em> - whether at least one URL in the registry for this TLD has a host which is covered by a valid <tt>RRSIG</tt> record</li>
	<li><em>DANE</em> - whether at least one URL in the registry for this TLD has a corresponding <tt>TLSA</tt> record (this record is not validated at the moment)</li>
</ul>

<figure class="world-map">
    <figcaption>World map showing ccTLD RDAP deployments</figcaption>
    <div id="world-map"></div>
</figure>

<div style="width:75%;margin: 2em auto 1em auto">
    
    <div style="text-align:center"><strong>RDAP deployment by TLD type (based on approximate # domains)</strong></div>

    <figure class="pie-chart">
        <div id="all-chart"></div>
        <figcaption style="text-decoration: underline;text-decoration-style: dashed" title="includes infrastructure TLDs">All TLDs</figcaption>
    </figure>

    <figure class="pie-chart">
        <div id="generic-chart"></div>
        <figcaption style="text-decoration: underline;text-decoration-style: dashed" title="includes sponsored and restricted TLDs">Generic TLDs</figcaption>
    </figure>

    <figure class="pie-chart">
        <div id="country-code-chart"></div>
        <figcaption style="text-decoration: underline;text-decoration-style: dashed" title="includes IDN ccTLDs">Country-code TLDs</figcaption>
    </figure>

</div>

<table class="sortable table table-striped">
	<thead>
		<tr>
			<th class="text-center">TLD</th>
			<th class="text-center">Type</th>
            <th class="text-right">Domains</th>
			<th class="text-center">RDAP</th>
			<th class="text-center">Added</th>
			<th class="text-center">HTTPS?</th>
			<th class="text-center">DNSSEC?</th>
			<th class="text-center">DANE?</th>
		</tr>
	</thead>
END

say($h->open('tbody'));

my @map_data = (['Country', 'Deployment']);

my $stats = {
    'all' => [['Deployment Status', 'Approx # Domains'], ['Not available', 0], ['Available', 0]],
};

my $stats_type_map = {
    'sponsored' => 'generic',
    'generic-restricted' => 'generic',
    'idn-country-code' => 'country-code',
};

my $sth = $db->prepare(q{SELECT * FROM `rdap_deployment_report` ORDER BY `tld` ASC});

$sth->execute;

my @rows;

while (my $ref = $sth->fetchrow_hashref) {
    push (@rows, $ref);
}

foreach my $ref (sort { $b->{'dums'} <=> $a->{'dums'} } @rows) {
    say($h->open('tr', {scope => 'row'}));

    my $row = anon $ref;

    my $stats_type = $stats_type_map->{$row->type} || $row->type;

    if (!$stats->{$stats_type}) {
        $stats->{$stats_type} = [['Deployment Status', 'Approx # Domains'], ['Not available', 0], ['Available', 0]];
    }

    $stats->{'all'}->[1+$row->rdap]->[1] += $row->dums;
    $stats->{$stats_type}->[1+$row->rdap]->[1] += $row->dums;

    say($h->td({class => 'text-center tld', title => '.'.$row->tld}, '.'.($row->tld =~ /^xn--/i ? idn_to_unicode($row->tld) : $row->tld)));
    say($h->td({class => 'text-center type'}, $row->type));
    say($h->td({class => 'text-right dums'}, format_number($row->dums)));
    say($h->td({class => 'text-center text-'.($row->rdap ? 'success' : 'danger')}, $row->rdap ? 'Yes' : 'No'));
    say($h->td({class => 'text-center text-'.($row->rdap ? 'success' : 'danger')}, $row->rdap_enabled_on || '-'));
    say($h->td({class => 'text-center text-'.($row->https ? 'success' : 'danger')}, $row->https ? 'Yes' : 'No'));
    say($h->td({class => 'text-center text-'.($row->dnssec ? 'success' : 'danger')}, $row->dnssec ? 'Yes' : 'No'));
    say($h->td({class => 'text-center text-'.($row->dane ? 'success' : 'danger')}, $row->dane ? 'Yes' : 'No'));

    if ('country-code' eq $row->type) {
        my $cc = uc('uk' eq $row->tld ? 'gb' : $row->tld);
        push(@map_data, [$cc, $row->rdap]) ;
    }

    say($h->close('tr'));
}

# TODO

say($h->close('tbody'));
say($h->close('table'));

my $mapData = $j->encode(\@map_data);
my $statsData = $j->encode($stats);

say <<"END";
<script type="text/javascript">
  google.charts.load('current', {
    'packages':['corechart', 'geochart'],
  });
  google.charts.setOnLoadCallback(drawCharts);

  function drawCharts() {
    var mapData = google.visualization.arrayToDataTable($mapData);

    var mapOptions = {
        'title':'Deployment of RDAP among ccTLDs',
        'legend':'none',
        'colorAxis': {'colors': ['#eee', '#080']}
    };

    var map = new google.visualization.GeoChart(document.getElementById('world-map'));

    map.draw(mapData, mapOptions);

    var statsData = $statsData;

    var categories = ['all', 'generic', 'country-code'];
    for (var i = 0 ; i < categories.length ; i++) {
        var category = categories[i];
        var data = google.visualization.arrayToDataTable(statsData[category]);
        var chart = new google.visualization.PieChart(document.getElementById(category + '-chart'));
        var chartOptions = {
            'legend': 'none',
            'pieSliceText': 'label',
            'slices': {
                0: { 'color': '#eee' },
                1: { 'color': '#080' },
            },
        };
        chart.draw(data, chartOptions);
    }

  }
</script>
END

say($h->close('div'));

say($h->close('body'));

say($h->close('html'));

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

sub idn2 {
    my ($input, @args) = @_;

    my $pid = open2(my $out, my $in, q{idn2}, @args);

    $in->binmode(':utf8');
    $in->print($input)."\n";
    $in->close;

    $out->binmode(':utf8');

    my $output = $out->getline;
    chomp($output);

    $out->close;

    waitpid($pid, 0);

    return $output;
}

sub idn_to_unicode  { idn2(qw(--quiet --decode), @_) }
sub idn_to_ascii    { idn2(qw(--quiet), @_) }
