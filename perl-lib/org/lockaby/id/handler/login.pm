#!/usr/bin/perl
package org::lockaby::id::handler::login;

use strict;
use warnings;
use utf8;

use org::lockaby::utilities;
use org::lockaby::id;
use org::lockaby::id::template;

use Apache2::Const qw(:common);
use Apache2::Cookie;
use URI::Escape qw(uri_escape);
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

sub get_login {
    my $self = shift;

    my $r = $self->{engine}->r();
    my $q = $self->{engine}->q();
    my $dbh = $self->{engine}->dbh();
    my $engine = $self->{engine};
    my $session = $self->{session};
    my $config = $self->{config};
    my $openid = $self->{server};

    # turn HTTP arguments into a hash for easier manipulation
    my $params = {};
    map { $params->{$_} = $q->param($_) } $q->param();
    my $submit = delete($params->{'submit'});

    # force errors to raise and run transactions
    local $dbh->{AutoCommit} = 0;
    local $dbh->{RaiseError} = 1;

    # store any errors from the login process
    my @errors = ();

    # cancel the login
    if (defined($submit) && $submit eq "cancel") {
        my $location = undef;

        eval {
            # default: go to the login page
            $location = "https://" . $config->{url} . "/openid/login";

            # get the link to the cancel page
            $location = $openid->cancel_return_url(return_to => $params->{return_to});

            $dbh->commit();
        };
        if ($@) {
            push(@errors, $@);
            eval { $dbh->rollback(); };
            if ($@) { push(@errors, $@); }
        }

        if (!scalar(@errors) && defined($location)) {
            $r->headers_out->set(Location => $location);
            $r->status(Apache2::Const::REDIRECT);
            return Apache2::Const::REDIRECT;
        }
    }

    # process the login
    if (defined($submit) && $submit eq "login") {
        eval {
            my $username = delete($params->{'username'});
            my $password = delete($params->{"password"});
            my $remember = delete($params->{"remember"});

            die "No username given.\n" unless defined($username) && length($username);
            die "No password given.\n" unless defined($password) && length($password);

            my $success1 = $engine->is_valid_username(username => $username);
            die "Invalid username/password.\n" unless ($success1);

            my $success2 = $engine->is_valid_password(username => $username, password => $password);
            die "Invalid username/password.\n" unless ($success2);

            # get the user's user id
            my $get_id_sth = $dbh->prepare(q|
                SELECT id FROM users WHERE username = LOWER(?)
            |);
            $get_id_sth->execute($username);
            my ($user_id) = $get_id_sth->fetchrow();
            $get_id_sth->finish();

            # record in the users table
            my $update_users_sth = $dbh->prepare_cached(q|
                UPDATE users SET logged = NOW() WHERE id = ?
            |);
            $update_users_sth->execute($user_id);
            $update_users_sth->finish();

            my $log_sth = $dbh->prepare(q|
                INSERT INTO log (user_id, trusted_id, ip_address, useragent, logged)
                         VALUES (?, ?, ?, ?, NOW())
            |);
            $log_sth->execute($user_id, undef, $ENV{REMOTE_ADDR}, $ENV{HTTP_USER_AGENT});
            $log_sth->finish();

            $session->set('authorized', 1);
            $session->set('user_id', $user_id);
            $session->set('username', $username);

            # set a cookie with the new session key in it
            if ($remember) {
                # generate a login ID for this user
                # used to verify that the user is returning, regenerated every time the user logs in
                my $secret = org::lockaby::utilities::get_md5_from_string(
                    org::lockaby::utilities::get_md5_from_string(
                        time . int(rand(2 ** 48)) . $$ . ($ENV{REMOTE_ADDR} || $ENV{USER})
                    )
                );
                my $expires = 2592000; # 30 days

                # save the ID in the database
                # there can be multiple ids for each user because a user could have saved on multiple computers
                my $save_secret_sth = $dbh->prepare_cached(q|
                    INSERT INTO autologin (user_id, secret, expires) VALUES (?, ?, ?)
                |);
                $save_secret_sth->execute($user_id, $secret, time() + $expires);
                $save_secret_sth->finish();

                my $session_cookie_jar = Apache2::Cookie->new(
                    $r,
                    -name => org::lockaby::id::COOKIE_NAME_AUTOLOGIN,
                    -value => freeze({ secret => $secret, username => $username }),
                    -secure => 1,
                    -httponly => 1,
                    -path => '/openid',
                    -expires => $expires,
                );
                $session_cookie_jar->bake($r);
            }

            $dbh->commit();
        };
        if ($@) {
            push(@errors, $@);
            eval { $dbh->rollback(); };
            if ($@) { push(@errors, $@); }
        }
    }

    if (!scalar(@errors) && $engine->is_logged_in()) {
        my $location = undef;

        eval {
            # see if the user is logged in, because if the user is logged in
            # then we don't need to log in again
            # default: go to the profile
            $location = "https://" . $config->{url} . "/openid/profile";

            # if this is coming as an openid request then send it to the trust page
            # with what was submitted earlier
            my $realm = $params->{realm};
            if (defined($realm)) {
                # go to the page where we check for a trusted realm
                $location = "https://" . $config->{url} . "/openid/trust";
                $location .= '?' . join('&', map { $_ . '=' . uri_escape(defined $params->{$_} ? $params->{$_} : '') } keys %{$params});
            }

            $dbh->commit();
        };
        if ($@) {
            push(@errors, $@);
            eval { $dbh->rollback(); };
            if ($@) { push(@errors, $@); }
        }

        if (!scalar(@errors) && defined($location)) {
            $r->headers_out->set(Location => $location);
            $r->status(Apache2::Const::REDIRECT);
            return Apache2::Const::REDIRECT;
        }
    }

    # display the login screen
    my $t = org::lockaby::id::template->new({
        title => $config->{url} . " - login",
    });

    $r->content_type('text/html; charset=utf-8');
    print $t->get_header();
    print qq|
        <form autocomplete="off" method="POST">
            <div id="title">
                ${\$config->{url}}
            </div>
            <div id="login">
                <!-- show an errors from the login process -->
                <div class="error">${\join("<br/>", @errors)}</div>

                <div class="boxes">
                    <div class="label">username:</div>
                    <div class="input">
                        <input type="text" name="username" value=""/>
                    </div>
                    <div style="clear: both;"></div>

                    <div class="label">password:</div>
                    <div class="input">
                        <input type="password" name="password" value=""/>
                    </div>
                    <div style="clear: both;"></div>
                </div>

                <div style="text-align: center;">
                    <input type="checkbox" id="remember" name="remember" checked="checked" value="yes"/>
                    <label for="remember">Remember me?</label>
                </div>
                <div style="clear: both;"></div>

                <div style="text-align: center;">
                    <input type="hidden" name="submit" value="true"/>
                    <input type="submit" name="login" value="login"/>
                    <input type="submit" name="cancel" value="cancel"/>
                </div>
            </div>
        </form>
        <script type="text/javascript">
            jQuery(window).resize(function (event) {
                var margin_top = parseInt((jQuery(window).height() - jQuery('#content').outerHeight()) / 2);
                if (margin_top < 4) margin_top = 4;

                var margin_left = parseInt((jQuery(window).width() - jQuery('#content').outerWidth()) / 2);
                if (margin_left < 0) margin_left = 0;

                jQuery('#content').css({
                    'position': 'absolute',
                    'marginTop': margin_top,
                    'marginLeft': margin_left
                });
            });

            jQuery(document).ready(function() {
                jQuery('#login input[name="username"]').focus();
                jQuery(window).trigger('resize');
                jQuery('#login').closest('form').submit(function (event) {
                    openid.events.login(event, this);
                });
            });
        </script>
    |;
    print $t->get_footer();

    return Apache2::Const::OK;
}

1;
