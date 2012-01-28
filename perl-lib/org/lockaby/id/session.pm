#!/usr/bin/perl
package org::lockaby::id::session;

use strict;
use warnings;
use utf8;

use org::lockaby::id;

use Apache::Session;
use Apache::Session::MySQL;
use Apache2::Cookie;

sub new {
    my $class = shift;
    my %args = (
        dbh          => undef,
        config       => undef,
        r            => undef,
        @_,
    );

    my $self = {
        dbh          => $args{dbh},
        config       => $args{config},
        r            => $args{r},
        _id          => undef,
        _data        => undef,
    };
    bless ($self, $class);

    my $jar = Apache2::Cookie::Jar->new($args{r});

    # try to get a session id from the cookie
    my $session_cookie = $jar->cookies(org::lockaby::id::COOKIE_NAME_SESSION);
    $self->{_id} = $session_cookie->value() if defined($session_cookie);

    # otherwise, create a new session
    # put into eval block just to make sure that the user isn't giving us a stale or invalid session id
    eval {
        tie(%{$self->{_data}}, 'Apache::Session::MySQL', $self->{_id}, {
            Handle      => $self->{dbh},
            LockHandle  => $self->{dbh},
            TableName   => 'sessions',
            Transaction => 1,
        });
    };
    if ($@) {
        tie(%{$self->{_data}}, 'Apache::Session::MySQL', undef, {
            Handle      => $self->{dbh},
            LockHandle  => $self->{dbh},
            TableName   => 'sessions',
            Transaction => 1,
        });
    }

    # store a timestamp to more easily remove sessions later
    $self->{_data}->{timestamp} = time();

    # re-load the session id
    $self->{_id} = $self->{_data}->{_session_id};

    # set a cookie with the new session key in it
    my $session_cookie_jar = Apache2::Cookie->new(
        $args{r},
        -name => org::lockaby::id::COOKIE_NAME_SESSION,
        -value => $self->{_id},
        -httponly => 0, # needs to be readable by javascript so that we can check for cookie functionality
        -secure => 1,
        -path => '/',
    );
    $session_cookie_jar->bake($args{r});

    return $self;
}

sub delete {
    my ($self) = @_;

    eval {
        tied(%{$self->{_data}})->delete();

        # clear the cookie
        my $jar = Apache2::Cookie->new(
            $self->{r},
            -name => org::lockaby::id::COOKIE_NAME_SESSION,
            -value => "",
            -httponly => 1,
            -path => '/',
            -expires => 0,
        );
        $jar->bake($self->{r});

        $self->{dbh}->commit();
    };
    if ($@) {
        my $errors = $@;
        eval { $self->{dbh}->rollback(); };
        if ($@) { $errors .= "\n" . $@; }
        die "${errors}\n";
    }

    $self = undef;
    return 1;
}

sub id {
    my ($self, $value) = @_;
    return $self->{_id};
}

sub get {
    my ($self, $key) = @_;
    return undef unless defined($key);
    return undef unless defined($self->{_data});
    return undef unless defined($self->{_data}->{$key});
    return $self->{_data}->{$key};
}

sub set {
    my ($self, $key, $value) = @_;
    return undef unless defined($key);

    eval {
        # set the value into the data array
        $self->{_data}->{$key} = $value;
        $self->{_data}->{timestamp} = time();

        $self->{dbh}->commit();
    };
    if ($@) {
        my $errors = $@;
        eval { $self->{dbh}->rollback(); };
        if ($@) { $errors .= "\n" . $@; }
        die "${errors}\n";
    }
}

1;
