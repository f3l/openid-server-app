#!/usr/bin/perl
package org::lockaby::id::users::mysql;

sub new {
    my $class = shift;
    my %args = (
        dbh => undef,
        @_,
    );

    my $self = {
        dbh => $args{dbh},
    };
    bless ($self, $class);
    return $self;
}

sub is_valid_username {
    my $self = shift;
    my %args = (
        username => undef,
        @_,
    );

    my $sth = $self->{dbh}->prepare_cached(q|
        SELECT COUNT(*) FROM users WHERE username = LOWER(?) AND is_enabled = 1
    |);
    $sth->execute($args{username});
    my ($count) = $sth->fetchrow();
    $sth->finish();

    return 1 if ($count > 0);
    return 0;
}

sub is_valid_password {
    my $self = shift;
    my %args = (
        username => undef,
        password => undef,
        @_,
    );

    my $sth = $self->{dbh}->prepare_cached(q|
        SELECT COUNT(*) FROM users WHERE username = LOWER(?) AND password = MD5(?) AND is_enabled = 1
    |);
    $sth->execute($args{username}, $args{password});
    my ($count) = $sth->fetchrow();
    $sth->finish();

    return 1 if ($count > 0);
    return 0;
}

sub change_password {
    my $self = shift;
    my %args = (
        username => undef,
        password => undef,
        @_,
    );

    my $sth = $self->{dbh}->prepare_cached(q|
        UPDATE users SET password = MD5(?) WHERE username = LOWER(?)
    |);
    $sth->execute($args{password}, $args{username});
    $sth->finish();

    return 1;
}

sub create_user {
    my $self = shift;
    my %args = (
        username => undef,
        is_manager => undef,
        is_enabled => undef,
        @_,
    );

    my $create_user_sth = $self->{dbh}->prepare_cached(q|
        INSERT INTO users (username, created, is_manager, is_enabled)
                   VALUES (LOWER(?), NOW(), ?, ?)
    |);
    $create_user_sth->execute($args{username}, $args{is_manager}, $args{is_enabled});
    $create_user_sth->finish();

    return 1;
}

sub is_password_changeable {
    my $self = shift;
    return 1;
}

sub is_user_createable {
    my $self = shift;
    return 1;
}

1;
