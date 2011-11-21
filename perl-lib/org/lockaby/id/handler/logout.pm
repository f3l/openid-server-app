#!/usr/bin/perl
package org::lockaby::id::handler::logout;

use strict;
use warnings;
use utf8;

use org::lockaby::id;

use Apache2::Const qw(:common);
use Apache2::Cookie;
use Storable qw(freeze thaw);

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

sub get_logout {
    my $self = shift;

    my $r = $self->{engine}->r();
    my $q = $self->{engine}->q();
    my $dbh = $self->{engine}->dbh();
    my $engine = $self->{engine};
    my $session = $self->{session};
    my $config = $self->{config};
    my $openid = $self->{server};

    my $is_logged_in = $engine->is_logged_in();
    if ($is_logged_in) {
        eval {
            my $jar = Apache2::Cookie::Jar->new($r);
            my $cookie = $jar->cookies(org::lockaby::id::COOKIE_NAME_AUTOLOGIN);
            if (defined($cookie)) {
                my $pieces = thaw($cookie->value());
                my $username = $pieces->{username};
                my $secret = $pieces->{secret};

                my $user_id = $engine->get_user_id(username => $username);

                my $delete_secret_sth = $dbh->prepare_cached(q|
                    DELETE FROM autologin WHERE user_id = ? AND secret = ?
                |);
                $delete_secret_sth->execute($user_id, $secret);
                $delete_secret_sth->finish();

                my $session_cookie_jar = Apache2::Cookie->new(
                    $r,
                    -name => org::lockaby::id::COOKIE_NAME_AUTOLOGIN,
                    -value => "",
                    -secure => 1,
                    -httponly => 1,
                    -path => '/openid',
                    -expires => 0,
                );
                $session_cookie_jar->bake($r);
            }

            # log the user out in the session, too
            $session->delete();

            $dbh->commit();
        };
        if ($@) {
            warn $@;
            eval { $dbh->rollback(); };
            if ($@) { warn $@; }
        }
    }

    $r->headers_out->set(Location => "https://" . $config->{url} . "/openid/login");
    $r->status(Apache2::Const::REDIRECT);
    return Apache2::Const::REDIRECT;
}

1;
