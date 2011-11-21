#!/usr/bin/perl
package org::lockaby::id::handler::profile;

use strict;
use warnings;
use utf8;

use org::lockaby::utilities;
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

sub get_profile {
    my $self = shift;

    my $r = $self->{engine}->r();
    my $q = $self->{engine}->q();
    my $dbh = $self->{engine}->dbh();
    my $engine = $self->{engine};
    my $session = $self->{session};
    my $config = $self->{config};
    my $openid = $self->{server};

    # if the user is not logged in, send them back to the login page
    my $is_logged_in = $engine->is_logged_in();
    if (!$is_logged_in) {
        $r->headers_out->set(Location => "https://" . $config->{url} . "/openid/login");
        $r->status(Apache2::Const::REDIRECT);
        return Apache2::Const::REDIRECT;
    }

    # figure out who we are
    my $username = $engine->get_username();

    my $submit = $q->param("submit");
    if (defined($submit)) {
        my $content = "";
        my @errors = ();

        local $dbh->{AutoCommit} = 0;
        local $dbh->{RaiseError} = 0;

        eval {
            my $remove = [$q->param('remove[]')];
            foreach my $item (@{$remove}) {
                my $remove_sth = $dbh->prepare_cached(q|
                    UPDATE trusted
                    SET authorized = 0
                    WHERE id = ? AND user_id IN (
                        SELECT user_id FROM users WHERE username = LOWER(?)
                    )
                |);
                $remove_sth->execute($item, $username);
                $remove_sth->finish();
            }

            $content = 'success';

            $dbh->commit();
        };
        if ($@) {
            push(@errors, $@);
            eval { $dbh->rollback(); };
            if ($@) { push(@errors, $@); }
        }

        $r->content_type('text/xml');
        print org::lockaby::utilities::prepare_ajax_response($content, \@errors);
        return Apache2::Const::OK;
    }

    # get the list of trusted sites so we can display them
    my @trusted = ();
    my $trusted_sth = $dbh->prepare_cached(q|
        SELECT id, realm, logged
        FROM trusted
        WHERE authorized = 1 AND user_id IN (
            SELECT id FROM users WHERE username = LOWER(?)
        )
        ORDER BY created ASC
    |);
    $trusted_sth->execute($username);
    while (my ($id, $realm, $logged) = $trusted_sth->fetchrow()) {
        my $access_count_sth = $dbh->prepare_cached(q|
            SELECT COUNT(*) FROM log WHERE trusted_id = ? AND user_id IN (
                SELECT id FROM users WHERE username = LOWER(?)
            )
        |);
        $access_count_sth->execute($id, $username);
        my ($accessed) = $access_count_sth->fetchrow();
        $access_count_sth->finish();

        if (defined($logged)) {
            $logged = org::lockaby::utilities::format_time(
                date => $logged,
                format => "%B %e, %Y at %l:%M%p",
                toTZ => $config->{siteTZ},
            );
        } else {
            $logged = "Never";
        }

        push(@trusted, qq|
            <div class="row" id="trusted-${id}">
                <div class="name">
                    <input type="checkbox" id="trusted-${id}-checkbox" value="${id}"/>
                    <label for="trusted-${id}-checkbox">${realm}</label>
                </div>
                <div class="clear"></div>

                <div class="logged"><b>Last used:</b> ${logged}</div>
                <div class="accessed">Used ${\org::lockaby::utilities::to_human_number($accessed)} times</div>
                <div class="clear"></div>
            </div>
        |);
    }
    $trusted_sth->finish();

    unless (scalar(@trusted)) {
        push(@trusted, q|
            <div class="empty">Currently there are no trusted sites.</div>
        |);
    } else {
        push(@trusted, q|
            <div style="text-align: center;">
                <input type="submit" name="remove" value="remove"/>
            </div>
        |);
    }

    my $t = org::lockaby::id::template->new({
        title => $config->{url} . " - profile",
    });

    $r->content_type('text/html; charset=utf-8');
    print $t->get_header();
    print qq|
        <form autocomplete="off" method="POST">
            <div id="title">
                ${\$config->{url}} profile
            </div>
            <div id="profile">
                <div class="username">Logged in as: <b>${username}</b></div>
                <div class="logout">[<a href="/openid/logout">logout</a>]</div>
                <div class="clear"></div>

                <div style="margin: 4px 0px; text-align: center;">Configure the list of sites that you are authorizing to use your ID.</div>
                Select: <a href="javascript:void(0);" onclick="openid.select(this, 'all');">all</a> \|
                        <a href="javascript:void(0);" onclick="openid.select(this, 'none');">none</a>
                <br/>
                <div class="header">
                    <div class="name">Site</div>
                    <div class="clear"></div>
                </div>
                ${\join("\n", @trusted)}<br/>
            </div>
        </form>
        <script type="text/javascript">
            jQuery(document).ready(function() {
                jQuery('#profile').closest('form').submit(function (event) {
                    openid.events.remove(event, this);
                });
                jQuery('#profile').closest('form').find('input[type="checkbox"]').click(function (event) {
                    openid.checked(event, this);
                });
            });
        </script>
    |;
    print $t->get_footer();

    return Apache2::Const::OK;
}

1;
