#!/usr/bin/perl
package org::lockaby::db;

use strict;
use warnings;
use utf8;

use Apache::DBI;
use DBI;

sub new {
    my ($class) = @_;
    my $self = {};
    bless ($self, $class);

    return $self;
}

sub connect {
    my ($self, $database, $username, $password) = @_;

    my $dbh = undef;
    eval {
        $dbh = DBI->connect("DBI:mysql:database=${database}", $username, $password, { AutoCommit => 0, RaiseError => 1 }) || die(DBI->errstr);
    };
    if ($@) {
        die "Could not connect to the database: $@\n";
    }

    $self->{dbh} = $dbh;
    return $dbh;
}

sub do {
    my $self = shift;
    my $sql = shift;

    my $sth = $self->{dbh}->prepare($sql);
    $sth->execute(@_);
    return $sth;
}

1;
