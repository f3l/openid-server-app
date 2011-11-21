#!/usr/bin/perl
package org::lockaby::id::template;

use strict;
use warnings;
use utf8;

sub new {
    my ($class, $parameters) = @_;
    my $self = {};

    # this stores things like the page title and breadcrumbs
    $self->{parameters} = $parameters;

    bless ($self, $class);
    return $self;
}

sub get_header {
    my ($self) = @_;

    my $title = $self->{parameters}->{title};
    die "Must define a title.\n" unless defined($title);

    my @meta = ();
    if (defined($self->{parameters}->{meta})) {
        foreach my $meta (@{$self->{parameters}->{meta}}) {
            push(@meta, $meta) if defined($meta);
        }
    }

    # add the title on to the end of the meta tag
    push(@meta, "<title>${title}</title>");

    my $result = "<!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 4.0//EN\">\n";
    $result .= "<html>";
        $result .= qq|
            <head>
                <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
                <meta http-equiv="Content-Language" content="en"/>
                <meta name="ROBOTS" content="NOINDEX, NOFOLLOW"/>
                <link REL="stylesheet" TYPE="text/css" HREF="/support/standard.css"/>
                <script type="text/javascript" src="/support/resources/jquery/jquery-current.js"></script>
                <script type="text/javascript" src="/support/standard.js"></script>
                ${\join("\n", @meta)}
            </head>
        |;

        $result .= "<body>";
            $result .= "<div id=\"content\">";


    return $result;
}

sub get_footer {
    my ($self) = @_;

    my $result = "";
            $result .= "</div>"; # close the "content" div tag above
        $result .= "</body>";
    $result .= "</html>";

    return $result;
}

1;
