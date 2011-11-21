#!/usr/bin/perl
package org::lockaby::id::handler;

use strict;
use warnings;
use utf8;

use org::lockaby::db;
use org::lockaby::configuration;
use org::lockaby::id;
use org::lockaby::id::session;
use org::lockaby::id::handler::endpoint;
use org::lockaby::id::handler::service;
use org::lockaby::id::handler::login;
use org::lockaby::id::handler::trust;
use org::lockaby::id::handler::profile;
use org::lockaby::id::handler::logout;

use Apache2::Const qw(:common);
use Apache2::Request;

sub handler {
    my $r = shift;
    my $q = Apache2::Request->new($r);

    my $config = org::lockaby::configuration->new();
    my $values = $config->loadConfiguration();

    my $db = org::lockaby::db->new();
    my $dbh = $db->connect($values->{db_database}, $values->{db_username}, $values->{db_password});

    # figure out what our URI is so we can figure out where to go
    my @uri = grep { length($_) } split(/\s*\/\s*/, $r->uri);

    eval {
        # initialize the user's session
        my $session = org::lockaby::id::session->new(dbh => $dbh, config => $values, r => $r);

        # create a copy of the engine
        my $engine = org::lockaby::id->new(r => $r, q => $q, dbh => $dbh, config => $values, session => $session);

        if (scalar(@uri) == 0) {
            $r->headers_out->set(Location => "https://" . $values->{url} . "/openid/login/");
            $r->status(Apache2::Const::REDIRECT);
            return Apache2::Const::REDIRECT;
        }

        if (scalar(@uri) > 1 && $uri[0] eq "openid") {
            my $https = $ENV{HTTPS} || "off";
            if ($https eq "on") {
                if ($uri[1] eq "login") {
                    my $handler = org::lockaby::id::handler::login->new(config => $values, session => $session, engine => $engine);
                    return $handler->get_login();
                }
                if ($uri[1] eq "trust") {
                    my $handler = org::lockaby::id::handler::trust->new(config => $values, session => $session, engine => $engine);
                    return $handler->get_trust();
                }
                if ($uri[1] eq "profile") {
                    my $handler = org::lockaby::id::handler::profile->new(config => $values, session => $session, engine => $engine);
                    return $handler->get_profile();
                }
                if ($uri[1] eq "logout") {
                    my $handler = org::lockaby::id::handler::logout->new(config => $values, session => $session, engine => $engine);
                    return $handler->get_logout();
                }
                if ($uri[1] eq "service") {
                    my $handler = org::lockaby::id::handler::service->new(config => $values, session => $session, engine => $engine);
                    return $handler->get_service(action => $uri[2]);
                }
            } else {
                if ($uri[1] eq "service") {
                    my $handler = org::lockaby::id::handler::service->new(config => $values, session => $session, engine => $engine);
                    return $handler->get_service(action => $uri[2]);
                }
                $r->headers_out->set(Location => "https://" . $values->{url} . $ENV{REQUEST_URI});
                $r->status(Apache2::Const::REDIRECT);
                return Apache2::Const::REDIRECT;
            }
        }

        # if all else fails, see if we can show an endpoint
        if (scalar(@uri) == 1) {
            my $handler = org::lockaby::id::handler::endpoint->new(config => $values, session => $session, engine => $engine);
            return $handler->get_endpoint(username => $uri[0]);
        }

        $r->status(Apache2::Const::NOT_FOUND);
        return Apache2::Const::NOT_FOUND;
    };
    if ($@) {
        $r->content_type("text/plain; charset=utf-8");
        $r->status(Apache2::Const::SERVER_ERROR);
        print $@;
        return Apache2::Const::SERVER_ERROR;
    }
}

1;
