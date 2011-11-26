#!/usr/bin/perl
package org::lockaby::id;

use strict;
use warnings;
use utf8;

use constant COOKIE_NAME_SESSION => 'OPENID_SESSION';
use constant COOKIE_NAME_AUTOLOGIN => 'OPENID_USER';

use Storable qw(thaw);
use Net::OpenID::Server;

use org::lockaby::utilities;

sub new {
    my $class = shift;
    my %args = (
        r => undef,
        q => undef,
        dbh => undef,
        config => undef,
        session => undef,
        @_,
    );

    my $self = {
        r => $args{r},
        q => $args{q},
        dbh => $args{dbh},
        config => $args{config},
        session => $args{session},
    };
    bless ($self, $class);
    return $self;
}

sub r {
    my $self = shift;
    return $self->{r};
}

sub q {
    my $self = shift;
    return $self->{q};
}

sub dbh {
    my $self = shift;
    return $self->{dbh};
}

sub change_password {
    my $self = shift;
    my %args = (
        username => undef,
        password => undef,
        @_,
    );

    my $sth = $self->dbh()->prepare_cached(q|
        UPDATE users SET password = MD5(?) WHERE username = LOWER(?)
    |);
    $sth->execute($args{password}, $args{username});
    $sth->finish();

    return 1;
}

sub is_valid_username {
    my $self = shift;
    my %args = (
        username => undef,
        @_,
    );

    my $sth = $self->dbh()->prepare_cached(q|
        SELECT COUNT(*) FROM users WHERE username = LOWER(?) AND is_enabled = 1
    |);
    $sth->execute($args{username});
    my ($user_exists_flag) = $sth->fetchrow();
    $sth->finish();

    return $user_exists_flag;
}

sub is_valid_password {
    my $self = shift;
    my %args = (
        username => undef,
        password => undef,
        @_,
    );

     my $sth = $self->dbh()->prepare_cached(q|
         SELECT COUNT(*) FROM users WHERE username = LOWER(?) AND password = ? AND is_enabled = 1
     |);
     $sth->execute($args{username}, org::lockaby::utilities::get_md5_from_string($args{password}));
     my ($count) = $sth->fetchrow();
     $sth->finish();
 
     return 1 if ($count > 0);
     return 0;
}

sub is_logged_in {
    my $self = shift;

    my $logged_in_flag = 0;

    # remove any secrets that have expired
    my $clear_sth = $self->dbh()->prepare_cached(q|
        DELETE FROM autologin WHERE expires < ?
    |);
    $clear_sth->execute(time());
    $clear_sth->finish();

    my $jar = Apache2::Cookie::Jar->new($self->r());
    my $cookie = $jar->cookies(org::lockaby::id::COOKIE_NAME_AUTOLOGIN);
    if (defined($cookie)) {
        my $pieces = thaw($cookie->value());
        my $username = $pieces->{username};
        my $secret = $pieces->{secret};

        my $sth = $self->dbh()->prepare_cached(q|
            SELECT COUNT(*) FROM autologin WHERE secret = ? AND user_id IN (
                SELECT user_id FROM users WHERE username = LOWER(?) AND is_enabled = 1
            )
        |);
        $sth->execute($secret, $username);
        ($logged_in_flag) = $sth->fetchrow();
        $sth->finish();

        # set a session user name
        $self->{session}->set('username', $username);
    }

    # if the session username exists then the user is logged in
    if ($self->{session}->get('username')) {
        $logged_in_flag = 1;
    }

    return $logged_in_flag;
}

sub is_trusted {
    my $self = shift;
    my %args = (
        realm => undef,
        @_,
    );

    return 0 unless $args{realm};

    my $sth = $self->dbh()->prepare_cached(q|
        SELECT COUNT(*)
        FROM trusted
        WHERE realm = ? AND authorized = 1 AND user_id IN (
            SELECT id FROM users WHERE username = LOWER(?) AND is_enabled = 1
        )
    |);
    $sth->execute($args{realm}, $self->get_username());
    my ($trusted) = $sth->fetchrow();
    $sth->finish();

    return $trusted;
}

sub get_username {
    my $self = shift;
    return $self->{session}->get('username');
}

sub get_user_id {
    my $self = shift;
    my %args = (
        username => undef,
        @_,
    );

    my $id = undef;
    my $sth = $self->dbh()->prepare_cached(q|
        SELECT id FROM users WHERE username = LOWER(?)
    |);
    $sth->execute($args{username});
    if (($id) = $sth->fetchrow()) {
        # nothing to do, successful
    }
    $sth->finish();

    return $id;
}

sub get_trusted_id {
    my $self = shift;
    my %args = (
        realm => undef,
        @_,
    );

    my $id = undef;
    my $sth = $self->dbh()->prepare_cached(q|
        SELECT id FROM trusted WHERE realm = ? AND user_id IN (
            SELECT user_id FROM users WHERE username = LOWER(?)
        )
    |);
    $sth->execute($args{realm}, $self->get_username());
    if (($id) = $sth->fetchrow()) {
        # nothing to do, successful
    }
    $sth->finish();

    return $id;
}

sub get_server {
    my $self = shift;

    return Net::OpenID::Server->new(
        args => $self->q(),
        endpoint_url => 'http://' . $self->{config}->{url} . '/openid/service',
        setup_url    => 'http://' . $self->{config}->{url} . '/openid/service/setup',
        get_user => sub {
            return $self->get_username();
        },
        is_identity => sub {
            my ($username, $identity) = @_;

            # if there is no user then forget it
            return unless $username;
            return unless $self->is_logged_in();

            return $identity eq 'http://' . $self->{config}->{url} . '/' . $username;
        },
        is_trusted => sub {
            my ($username, $realm, $is_identity) = @_;

            # if there is no user or the user isn't logged in then forget it
            return unless $username;
            return unless $is_identity;
            return unless $self->is_logged_in();
            return $self->is_trusted(realm => $realm);
        },
        server_secret => sub {
            my $timestamp = shift;
            my $secret = undef;

            eval {
                # clear old secrets
                my $clear_sth = $self->dbh()->prepare_cached(q|
                    DELETE FROM secrets WHERE created < ?
                |);
                $clear_sth->execute(time() - 3600);
                $clear_sth->finish();

                my $sth = $self->dbh()->prepare_cached(q|
                    SELECT secret FROM secrets WHERE timestamp = ?
                |);
                $sth->execute($timestamp);
                ($secret) = $sth->fetchrow();
                $sth->finish();

                if (!defined($secret)) {
                    $secret = org::lockaby::utilities::get_md5_from_string(
                        org::lockaby::utilities::get_md5_from_string(
                            $timestamp . $$ . $ENV{REMOTE_ADDR} . int(rand(2 ** 48))
                        )
                    );

                    my $save_sth = $self->dbh()->prepare_cached(q|
                        INSERT INTO secrets (secret, timestamp, created) VALUE (?, ?, ?)
                    |);
                    $save_sth->execute($secret, $timestamp, time());
                    $save_sth->finish();
                }

                $self->dbh()->commit();
            };
            if ($@) {
                my $errors = $@;
                eval { $self->dbh()->rollback(); };
                if ($@) { $errors .= "\n" . $@; }
                die "${errors}\n";
            }

            return $secret;
        },
    );
}

sub check_forged_headers {
    my ($self, $a, $b) = @_;

    return 1 unless defined($a);
    return 1 unless defined($b);

    return 1 unless (ref($a) eq "HASH");
    return 1 unless (ref($b) eq "HASH");

    return 1 unless (defined($a->{ns})         && defined($b->{ns}));
    return 1 unless (defined($a->{return_to})  && defined($b->{return_to}));
    return 1 unless (defined($a->{identity})   && defined($b->{identity}));
    return 1 unless (defined($a->{realm})      && defined($b->{realm}));
    return 1 unless (defined($a->{trust_root}) && defined($b->{trust_root}));

    return 1 unless ($a->{ns}         eq $b->{ns});
    return 1 unless ($a->{return_to}  eq $b->{return_to});
    return 1 unless ($a->{identity}   eq $b->{identity});
    return 1 unless ($a->{realm}      eq $b->{realm});
    return 1 unless ($a->{trust_root} eq $b->{trust_root});

    return 0;
}

1;
