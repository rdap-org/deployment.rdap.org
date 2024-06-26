#!/usr/bin/perl
use DateTime;
use DBI;
use XML::LibXML;
use constant RFC822_FMT => "%a, %d %b %Y %H:%M:%S %z";
use strict;

my $doc = XML::LibXML::Document->new;

my $rss = $doc->createElement('rss');
$rss->setAttribute('version', '2.0');

$doc->setDocumentElement($rss);

my $channel = $rss->appendChild($doc->createElement('channel'));

$channel->appendChild($doc->createElement('title'))->appendText('RDAP Deployment Dashboard');
$channel->appendChild($doc->createElement('link'))->appendText('https://deployment.rdap.org');
$channel->appendChild($doc->createElement('description'))->appendText('A feed of newly-observed RDAP Base URLs.');
$channel->appendChild($doc->createElement('pubDate'))->appendText(DateTime->now->strftime(RFC822_FMT));

my $link = $channel->appendChild($doc->createElementNS('http://www.w3.org/2005/Atom', 'link'));
$link->setAttribute('rel', 'self');
$link->setAttribute('type', 'application/rss+xml');
$link->setAttribute('href', 'https://deployment.rdap.org/rss.xml');

my $sth = DBI
    ->connect('dbi:SQLite:dbname='.$ARGV[0])
    ->prepare(q{
        SELECT *
        FROM `rdap_deployment_report`
        WHERE (`rdap`=1)
        ORDER BY `rdap_enabled_on` DESC
        LIMIT 0,5
    });

$sth->execute;

while (my $row = $sth->fetchrow_hashref) {
    my $item = $channel->appendChild($doc->createElement('item'));
    $item->appendChild($doc->createElement('title'))->appendText(sprintf('RDAP Base URL for .%s', uc($row->{tld})));
    $item->appendChild($doc->createElement('guid'))->appendText('data:text/plain,'.$row->{tld}.':'.$row->{rdap_enabled_on});
    $item->appendChild($doc->createElement('link'))->appendText('https://data.iana.org/rdap/dns.json');
    $item->appendChild($doc->createElement('description'))->appendText(sprintf('An entry for .%s was observed in the RDAP Bootstrap Registry on %s.', uc($row->{tld}), $row->{rdap_enabled_on}));

    my ($y, $m, $d) = map { int } split(/-/, $row->{rdap_enabled_on}, 3);
    $item->appendChild($doc->createElement('pubDate'))->appendText(DateTime->new(year => $y, month => $m, day => $m)->strftime(RFC822_FMT));
}

print $doc->toString(1);
