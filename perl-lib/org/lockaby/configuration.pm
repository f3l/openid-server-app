#!/usr/bin/perl
package org::lockaby::configuration;

use strict;
use warnings;
use utf8;

sub new {
    my ($class) = @_;
    my $self = {};
    bless ($self, $class);

    return $self;
}

sub loadConfiguration {
    my ($self, $file) = @_;

    # make sure we have the correct environment variables
    die "Environment variable CONFIGURATION not set.\n" unless defined($ENV{CONFIGURATION});

    # if we weren't given a file to load, we load our predefined one
    if (!defined($file)) {
        $file = $ENV{CONFIGURATION} . "/default";
    } else {
        $file = $ENV{CONFIGURATION} . "/" . $file;
    }

    # make sure the file we've chosen exists and that we can read it
    die "Could not open configuration file ${file}.\n" unless (-r $file);

    # open the config file and get our values out of it
    my $config = {};
    open(CONFIG, "< $file") or die "Cannot open $file: $!\n";
    while (<CONFIG>) {
        chomp;      # no newline
        s/^#.*//;   # no comments that begin with a #
        s/^;.*//;   # no comments that begin with a ;
        s/^\s+//;   # no leading white
        s/\s+$//;   # no trailing white
        next unless length;

        my ($k, $v) = split(/\s*=\s*/, $_, 2);
        next unless defined($v);

        $config->{$k} = $v;
    }
    close(CONFIG);

    $self->{config} = $config;
    return $config;
}

sub getConfigurationValues {
    my ($self) = @_;
    return $self->{config};
}

sub getConfigurationValue {
    my ($self, $key) = @_;
    return $self->{config}->{$key};
}

1;
