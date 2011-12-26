#!/usr/bin/perl
package org::lockaby::id::handler::service;

use strict;
use warnings;
use utf8;

use Apache2::Const qw(:common);
use Net::OpenID::Server;
use URI::Escape qw(uri_escape);

sub new {
    my $class = shift;
    my %args = (
        config => undef,
        session => undef,
        engine => undef,
        @_,
    );

    my $self = {
        config => $args{config},
        session => $args{session},
        engine => $args{engine},
        server => $args{engine}->get_server(),
    };

    bless ($self, $class);
    return $self;
}

sub get_service {
    my $self = shift;
    my %args = (
        action => undef,
        @_,
    );

    my $r = $self->{engine}->r();
    my $q = $self->{engine}->q();
    my $dbh = $self->{engine}->dbh();
    my $engine = $self->{engine};
    my $session = $self->{session};
    my $config = $self->{config};
    my $openid = $self->{server};

    my $action = $args{action} || "endpoint";

    my $params = {};
    map { $params->{$_} = $q->param($_) } $q->param();

    # force errors to raise and run transactions
    local $dbh->{AutoCommit} = 0;
    local $dbh->{RaiseError} = 1;

    if ($action eq "endpoint") {
        my ($type, $data) = $openid->handle_page();

        if ($type eq "redirect") {
            # the user and the realm are trusted
            # log it and redirect

            # store errors
            my @errors = ();

            eval {
                my $realm = $params->{'openid.realm'};
                my $username = $session->get('username');
                my $user_id = $session->get('user_id');
                my $trusted_id = $engine->get_trusted_id(realm => $realm);

                my $log_sth = $dbh->prepare(q|
                    INSERT INTO log (user_id, trusted_id, ip_address, useragent, logged)
                             VALUES (?, ?, ?, ?, NOW())
                |);
                $log_sth->execute($user_id, $trusted_id, $ENV{REMOTE_ADDR}, $ENV{HTTP_USER_AGENT});
                $log_sth->finish();

                my $update_trusted_sth = $dbh->prepare(q|
                    UPDATE trusted SET logged = NOW() WHERE id = ?
                |);
                $update_trusted_sth->execute($trusted_id);
                $update_trusted_sth->finish();

                # record in the users table
                my $update_users_sth = $dbh->prepare_cached(q|
                    UPDATE users SET logged = NOW() WHERE id = ?
                |);
                $update_users_sth->execute($user_id);
                $update_users_sth->finish();

                $dbh->commit();
            };
            if ($@) {
                push(@errors, $@);
                eval { $dbh->rollback(); };
                if ($@) { push(@errors, $@); }
            }

            if (scalar(@errors)) {
                $r->content_type("text/plain; charset=utf-8");
                $r->status(Apache2::Const::SERVER_ERROR);
                print join("\n", @errors);
                return Apache2::Const::SERVER_ERROR;
            }

            $r->headers_out->set(Location => $data);
            $r->status(Apache2::Const::REDIRECT);
            return Apache2::Const::REDIRECT;
        }

        # something isn't trusted, send to the setup url
        if ($type eq "setup") {
            my $location = $openid->setup_url;
            $location .= '?' . join ('&', map { $_ . '=' . uri_escape(defined $data->{$_} ? $data->{$_} : '') } keys %{$data});

            # add sreg parameters to the url
            foreach my $key (keys %{$params}) {
                next unless $key =~ m/^openid\.(sreg\..*)/;
                $location .= "&${1}=" . uri_escape(defined $params->{$key} ? $params->{$key} : '');
            }

            $r->headers_out->set(Location => $location);
            $r->status(Apache2::Const::REDIRECT);
            return Apache2::Const::REDIRECT;
        }

        $r->content_type($type);
        print $data;
        return Apache2::Const::OK;
    }

    if ($action eq "setup") {
        # store errors
        my @errors = ();

        my $location = undef;

        # this is in an eval block because using the session writes to the database
        eval {
            my $username = $params->{username} || undef;
            my $realm = $params->{realm} || undef;

            # redirect to the login screen
            $location = 'https://' . $config->{url} . '/openid/login';
            $location .= '?' . join('&', map { $_ . '=' . uri_escape(defined $params->{$_} ? $params->{$_} : '') } keys %{$params});

            # store all of the pieces of the openid request for later verification
            $session->set('openid', $params);

            $dbh->commit();
        };
        if ($@) {
            push(@errors, $@);
            eval { $dbh->rollback(); };
            if ($@) { push(@errors, $@); }
        }

        if (scalar(@errors) || !defined($location)) {
            $r->content_type("text/plain; charset=utf-8");
            $r->status(Apache2::Const::SERVER_ERROR);
            print join("\n", @errors);
            return Apache2::Const::SERVER_ERROR;
        }

        $r->headers_out->set(Location => $location);
        $r->status(Apache2::Const::REDIRECT);
        return Apache2::Const::REDIRECT;
    }

    # the mode was invalid, send back an error message
    $r->content_type("text/plain; charset=utf-8");
    $r->status(Apache2::Const::SERVER_ERROR);
    print "Unrecognized protocol.";
    return Apache2::Const::SERVER_ERROR;
}

1;
