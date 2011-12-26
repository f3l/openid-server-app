#!/usr/bin/perl
package org::lockaby::id;

use strict;
use warnings;
use utf8;

use constant COOKIE_NAME_SESSION => 'OPENID_SESSION';
use constant COOKIE_NAME_AUTOLOGIN => 'OPENID_USER';

use Storable qw(thaw);
use Net::OpenID::Server;
use Module::Load;

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

    my $module = $args{config}->{engine};
    die "No user engine configured." unless defined($module);

    $module =~ s/^\s+|\s+$//g;
    die "No user engine configured." unless length($module);

    my $self = {
        r => $args{r},
        q => $args{q},
        dbh => $args{dbh},
        config => $args{config},
        session => $args{session},
        module => $module,
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

sub is_password_changeable {
    my $self = shift;

    load($self->{module});
    my $obj = $self->{module}->new(dbh => $self->{dbh});
    return $obj->is_password_changeable();
}

sub is_user_createable {
    my $self = shift;

    load($self->{module});
    my $obj = $self->{module}->new(dbh => $self->{dbh});
    return $obj->is_user_createable();
}

sub change_password {
    my $self = shift;
    my %args = (
        username => undef,
        password => undef,
        @_,
    );

    my $username = $args{username};
    my $password = $args{password};
    die "No username given." unless defined($username);
    die "No password given." unless defined($password);

    $username =~ s/^\s+|\s+$//g;
    $password =~ s/^\s+|\s+$//g;
    die "No username given." unless length($username);
    die "No password given." unless length($password);

    load($self->{module});
    my $obj = $self->{module}->new(dbh => $self->{dbh});
    return $obj->change_password(username => $username, password => $password);
}

sub create_user {
    my $self = shift;
    my %args = (
        username => undef,
        is_manager => undef,
        is_enabled => undef,
        @_,
    );

    my $username = $args{username};
    die "No username given." unless defined($username);

    $username =~ s/^\s+|\s+$//g;
    die "No username given." unless length($username);

    load($self->{module});
    my $obj = $self->{module}->new(dbh => $self->{dbh});
    return $obj->create_user(username => $username, is_manager => $args{is_manager}, is_enabled => $args{is_enabled});
}

sub is_valid_username {
    my $self = shift;
    my %args = (
        username => undef,
        @_,
    );

    my $username = $args{username};
    die "No username given." unless defined($username);

    $username =~ s/^\s+|\s+$//g;
    die "No username given." unless length($username);

    load($self->{module});
    my $obj = $self->{module}->new(dbh => $self->{dbh});
    return $obj->is_valid_username(username => $username);
}

sub is_valid_password {
    my $self = shift;
    my %args = (
        username => undef,
        password => undef,
        @_,
    );

    my $username = $args{username};
    my $password = $args{password};
    die "No username given." unless defined($username);
    die "No password given." unless defined($password);

    $username =~ s/^\s+|\s+$//g;
    $password =~ s/^\s+|\s+$//g;
    die "No username given." unless length($username);
    die "No password given." unless length($password);

    load($self->{module});
    my $obj = $self->{module}->new(dbh => $self->{dbh});
    return $obj->is_valid_password(username => $username, password => $password);
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
            SELECT u.id, u.username
            FROM autologin a, users u
            WHERE u.id = a.user_id AND a.secret = ? AND u.username = LOWER(?) AND u.is_enabled = 1
        |);
        $sth->execute($secret, $username);
        if (my ($user_id, $username) = $sth->fetchrow()) {
            $self->{session}->set('authorized', 1);
            $self->{session}->set('user_id', $user_id);
            $self->{session}->set('username', $username);
            $logged_in_flag = 1;
        }
        $sth->finish();
    }

    # if the session username exists then the user is logged in
    if ($self->{session}->get('authorized')) {
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
    $sth->execute($args{realm}, $self->{session}->get('username'));
    my ($trusted) = $sth->fetchrow();
    $sth->finish();

    return $trusted;
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
    $sth->execute($args{realm}, $self->{session}->get('username'));
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
            return $self->{session}->get('username');
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

1;
