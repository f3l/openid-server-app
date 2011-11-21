#!/usr/bin/perl
package org::lockaby::id::handler::trust;

use strict;
use warnings;
use utf8;

use org::lockaby::id::template;

use Apache2::Const qw(:common);

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

sub get_trust {
    my $self = shift;

    my $r = $self->{engine}->r();
    my $q = $self->{engine}->q();
    my $dbh = $self->{engine}->dbh();
    my $engine = $self->{engine};
    my $session = $self->{session};
    my $config = $self->{config};
    my $openid = $self->{server};

    my $params = {};
    map { $params->{$_} = $q->param($_) } $q->param();

    my $submit = delete($params->{'submit'});

    local $dbh->{AutoCommit} = 0;
    local $dbh->{RaiseError} = 0;

    # store any errors from the login process
    my @errors = ();

    # cancel the login
    eval {
        if (defined($submit) && $submit eq "cancel") {
            # default: go to the login page
            my $return_to = "https://" . $config->{url} . "/openid/login";

            # if this is an openid request then verify openid fields:
            # -> ns, return_to, identity, realm, trust_root
            my $openid_data = $session->get('openid');
            if (defined($openid_data) &&
                defined($openid_data->{ns})         && defined($params->{ns}) &&
                defined($openid_data->{return_to})  && defined($params->{return_to}) &&
                defined($openid_data->{identity})   && defined($params->{identity}) &&
                defined($openid_data->{realm})      && defined($params->{realm}) &&
                defined($openid_data->{trust_root}) && defined($params->{trust_root})) {
                if ($params->{ns}         eq $openid_data->{ns} &&
                    $params->{return_to}  eq $openid_data->{return_to} &&
                    $params->{identity}   eq $openid_data->{identity} &&
                    $params->{realm}      eq $openid_data->{realm} &&
                    $params->{trust_root} eq $openid_data->{trust_root}) {

                    # send back to the originator's cancel url
                    $return_to = $openid->cancel_return_url(return_to => $params->{return_to});
                } else {
                    die "Detected forged OpenID headers.\n";
                }
            }

            # commit before redirecting
            $dbh->commit();

            $r->headers_out->set(Location => $return_to);
            $r->status(Apache2::Const::REDIRECT);
            return Apache2::Const::REDIRECT;
        }

        my $realm = $params->{realm};
        die "No realm given.\n" unless defined($realm) && length($realm);

        if (defined($submit) && $submit eq "trust") {
            # get the user's id for the logs
            my $username = $engine->get_username();
            my $user_id = $engine->get_user_id(username => $username);

            my $save_sth = $dbh->prepare_cached(q|
                INSERT IGNORE INTO trusted (user_id, realm, authorized, created, logged)
                                    VALUES (?, ?, 1, NOW(), NOW())
            |);
            $save_sth->execute($user_id, $realm);
            $save_sth->finish();

            my $authorize_sth = $dbh->prepare_cached(q|
                UPDATE trusted SET authorized = 1 WHERE user_id = ? AND realm = ?
            |);
            $authorize_sth->execute($user_id, $realm);
            $authorize_sth->finish();

            $dbh->commit();
        }
    };
    if ($@) {
        push(@errors, $@);
        eval { $dbh->rollback(); };
        if ($@) { push(@errors, $@); }
    }

    eval {
        my $realm = $params->{realm};
        die "No realm given.\n" unless defined($realm) && length($realm);

        if (!scalar(@errors) && $engine->is_logged_in() && $engine->is_trusted(realm => $realm)) {
            # default: go to the profile
            my $return_to = "https://" . $config->{url} . "/openid/profile";

            # if this is an openid request then verify openid fields:
            # -> ns, return_to, identity, realm, trust_root
            my $openid_data = $session->get('openid');
            if (defined($openid_data) &&
                $params->{ns}         eq $openid_data->{ns} &&
                $params->{return_to}  eq $openid_data->{return_to} &&
                $params->{identity}   eq $openid_data->{identity} &&
                $params->{realm}      eq $openid_data->{realm} &&
                $params->{trust_root} eq $openid_data->{trust_root}) {

                # go to the originator's url
                my $username = $engine->get_username();
                my $user_id = $engine->get_user_id(username => $username);
                my $trusted_id = $engine->get_trusted_id(realm => $realm);

                # log this
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

                # get email/nickname/fullname from database and put them into "additional fields"
                my $sreg_sth = $dbh->prepare(q|
                    SELECT email_address, nickname, fullname
                    FROM users
                    WHERE username = LOWER(?)
                |);
                $sreg_sth->execute($username);
                my ($email_address, $nickname, $fullname) = $sreg_sth->fetchrow();
                $sreg_sth->finish();

                my $sreg = {};
                $sreg->{'sreg.nickname'} = $nickname if defined($nickname);
                $sreg->{'sreg.fullname'} = $fullname if defined($fullname);
                $sreg->{'sreg.email'} = $email_address if defined($email_address);

                # assign an "identity" to the user
                # this is what the remote application will know us as
                $params->{identity} = 'http://' . $config->{url} . '/' . $username;
                $params->{additional_fields} = $sreg;

                $return_to = $openid->signed_return_url(%{$params});
            }

            # commit to database before redirecting
            $dbh->commit();

            $r->headers_out->set(Location => $return_to);
            $r->status(Apache2::Const::REDIRECT);
            return Apache2::Const::REDIRECT;
        }
    };
    if ($@) {
        push(@errors, $@);
        eval { $dbh->rollback(); };
        if ($@) { push(@errors, $@); }
    }

    my $realm = $params->{realm};
    my $username = $engine->get_username();

    my $t = org::lockaby::id::template->new({
        title => $config->{url} . " - trust",
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

                <div style="text-align: center;">
                    You are logged in as:<br/><br/>
                    <b>${username}</b><br/><br/>

                    This site would like you to trust it:<br/><br/>
                    <b>${realm}</b><br/><br/>

                    By trusting this site, you are allowing it to access
                    your OpenID for the purposes of authentication.<br/>

                    This site will never see your username or password,
                    only your OpenID.<br/>
                </div><br/>

                <div style="text-align: center;">
                    <input type="hidden" name="submit" value="true"/>
                    <input type="submit" name="trust" value="trust"/>
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
                jQuery(window).trigger('resize');
                jQuery('#login').closest('form').submit(function (event) {
                    openid.events.trust(event, this);
                });
            });
        </script>
    |;
    print $t->get_footer();

    return Apache2::Const::OK;
}

1;
