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

    # turn HTTP arguments into a hash for easier manipulation
    my $params = {};
    map { $params->{$_} = $q->param($_) } $q->param();
    my $submit = delete($params->{'submit'});

    # force errors to raise and run transactions
    local $dbh->{AutoCommit} = 0;
    local $dbh->{RaiseError} = 1;

    # store any errors from the login process
    my @errors = ();

    # see if the username is valid, if not then kick back to login page
    my $username = $session->get('username');
    if (!$engine->is_valid_username(username => $username)) {
        $r->headers_out->set(Location => "https://" . $config->{url} . "/openid/login");
        $r->status(Apache2::Const::REDIRECT);
        return Apache2::Const::REDIRECT;
    }

    # see if the realm is valid, if not then kick to the profile page
    my $realm = $params->{realm};
    if (!defined($realm) || !length($realm)) {
        $r->headers_out->set(Location => "https://" . $config->{url} . "/openid/profile");
        $r->status(Apache2::Const::REDIRECT);
        return Apache2::Const::REDIRECT;
    }

    # get email/nickname/fullname from database so we can use them for any sreg requests
    my $sreg_available = {};
    my $sreg_sth = $dbh->prepare(q|
        SELECT email_address, nickname, fullname
        FROM users
        WHERE username = LOWER(?)
    |);
    $sreg_sth->execute($username);
    ($sreg_available->{email},
     $sreg_available->{nickname},
     $sreg_available->{fullname}) = $sreg_sth->fetchrow();
    $sreg_sth->finish();

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

    # we're going to trust this realm
    if (defined($submit) && $submit eq "trust") {
        eval {
            # get the user id to be used in sql statements more easily
            my $user_id = $session->get('user_id');

            # this will insert a new row into the trusted table
            # but only if a row doesn't already exist
            my $save_sth = $dbh->prepare_cached(q|
                SELECT insert_trusted(?, ?);
            |);
            $save_sth->execute($user_id, $realm);
            $save_sth->finish();

            my $authorize_sth = $dbh->prepare_cached(q|
                UPDATE trusted SET authorized = 1 WHERE user_id = ? AND realm = ?
            |);
            $authorize_sth->execute($user_id, $realm);
            $authorize_sth->finish();

            $dbh->commit();
        };
        if ($@) {
            push(@errors, $@);
            eval { $dbh->rollback(); };
            if ($@) { push(@errors, $@); }
        }
    }

    # submit the login for processing
    if (!scalar(@errors) && $engine->is_logged_in() && $engine->is_trusted(realm => $realm)) {
        my $location =  undef;

        eval {
            # default: go to the profile
            $location = "https://" . $config->{url} . "/openid/profile";

            # go to the trusted site now
            my $user_id = $session->get('user_id');
            my $trusted_id = $engine->get_trusted_id(realm => $realm);

            # log this trusted site access
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
            my $sreg = {};
            $sreg->{'ns.sreg'} = "http://openid.net/extensions/sreg/1.1";

            # give the sreg values that were requested
            # then delete all sreg data from the params that we are sending back
            foreach my $key (keys %{$params}) {
                next unless $key =~ m/^sreg[\.\-](.*)$/;
                my $field = $1;
                my $value = delete($params->{$key});

                if ($key =~ /^sreg\-.*$/ && $sreg_available->{$field} && $value) {
                    $sreg->{"sreg.${field}"} = $sreg_available->{$field};
                }
            }

            # assign an "identity" to the user
            # this is what the remote application will know us as
            $params->{identity} = 'http://' . $config->{url} . '/' . $username;
            $params->{additional_fields} = $sreg;

            $location = $openid->signed_return_url(%{$params});

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

    # build some html to see if the requesting site would like some sreg information
    my @sreg_desired = ();
    if (defined($params->{'sreg.optional'})) {
        foreach my $sreg_field (split(/,/, $params->{'sreg.optional'})) {
            $sreg_field =~ s/^\s+|\s+$//g;
            next unless length($sreg_field);
            push(@sreg_desired, $sreg_field);
        }
    }
    if (defined($params->{'sreg.required'})) {
        foreach my $sreg_field (split(/,/, $params->{'sreg.required'})) {
            $sreg_field =~ s/^\s+|\s+$//g;
            next unless length($sreg_field);
            push(@sreg_desired, $sreg_field);
        }
    }

    my $sreg_requested = "";
    if (scalar(@sreg_desired)) {
        my @sreg_requested = ();
        foreach my $sreg_field (sort @sreg_desired) {
            # only work with things we support
            next unless $sreg_available->{$sreg_field};

            push(@sreg_requested, qq|
                <div class="sreg">
                    <input type="checkbox" name="sreg-${sreg_field}" value="1" id="sreg-${sreg_field}"/>
                    <label for="sreg-${sreg_field}">${\ucfirst($sreg_field)}: ${\$sreg_available->{$sreg_field}}</label>
                </div>
            |);
        }

        if (scalar(@sreg_requested)) {
            $sreg_requested =  qq|
                The site is also requesting this information:

                <div class="information">
                    ${\join("\n", @sreg_requested)}
                </div>

                If you choose to not provide this information, the site
                should still work and you should not be asked again for
                this information.<br/><br/>
            |;
        }
    }

    # display the trust screen
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
                    You are logged in as:<br/>
                    <div class="information">${username}</div>

                    This site would like you to trust it:<br/>
                    <div class="information">${realm}</div>

                    By trusting this site, you are allowing it to access
                    your OpenID for the purposes of authentication. This
                    site will never see your username or password, only
                    your OpenID.<br/><br/>

                    <!-- is the site requesting any information about us? -->
                    ${sreg_requested}
                </div>

                <div style="text-align: center;">
                    <input type="hidden" name="submit" value="true"/>
                    <input type="submit" name="trust" value="trust"/>
                    <input type="submit" name="cancel" value="cancel"/>
                </div>
            </div>
        </form>
        <script type="text/javascript">
            jQuery(document).ready(function() {
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
