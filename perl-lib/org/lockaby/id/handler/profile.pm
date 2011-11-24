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
    if (!$engine->is_logged_in()) {
        $r->headers_out->set(Location => "https://" . $config->{url} . "/openid/login");
        $r->status(Apache2::Const::REDIRECT);
        return Apache2::Const::REDIRECT;
    }

    # figure out who we are
    my $username = $engine->get_username();
    if (!$engine->is_valid_username(username => $username)) {
        $r->headers_out->set(Location => "https://" . $config->{url} . "/openid/login");
        $r->status(Apache2::Const::REDIRECT);
        return Apache2::Const::REDIRECT;
    }

    my $details_sth = $dbh->prepare_cached(q|
        SELECT email_address, nickname, fullname, is_manager
        FROM users
        WHERE username = LOWER(?)
    |);
    $details_sth->execute($username);
    my ($email_address, $nickname, $fullname, $is_manager) = $details_sth->fetchrow();
    $details_sth->finish();

    my $submit = $q->param("submit");
    if (defined($submit)) {
        my $form = $q->param('form');

        my $content = "";
        my @errors = ();

        local $dbh->{AutoCommit} = 0;
        local $dbh->{RaiseError} = 1;

        eval {
            if (defined($form) && $form eq "trusted") {
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
            }

            if (defined($form) && $form eq "profile") {
                my $email_address = $q->param('email_address');
                my $fullname = $q->param('fullname');
                my $nickname = $q->param('nickname');

                my $save_sth = $dbh->prepare_cached(q|
                    UPDATE users
                    SET email_address = ?,
                        fullname = ?,
                        nickname = ?
                    WHERE username = LOWER(?)
                |);
                $save_sth->execute($email_address, $fullname, $nickname, $username);
                $save_sth->finish();
            }

            if (defined($form) && $form eq "management" && $is_manager) {
                my $action = $q->param('action');

                if (defined($action) && $action eq "clear") {
                    my $type = $q->param('type');

                    if (defined($type)) {
                        if ($type eq "sessions") {
                            my $clear_sth = $dbh->prepare("DELETE FROM sessions");
                            $clear_sth->execute();
                            $content = 'success';
                        }
                        if ($type eq "autologin") {
                            my $clear_sth = $dbh->prepare("DELETE FROM autologin");
                            $clear_sth->execute();
                            $content = 'success';
                        }
                        if ($type eq "secrets") {
                            my $clear_sth = $dbh->prepare("DELETE FROM secrets");
                            $clear_sth->execute();
                            $content = 'success';
                        }
                    }
                }

                if (defined($action) && $action eq "toggle") {
                    my $type = $q->param('type');
                    my $value = $q->param('value');
                    my $actor = $q->param('username');

                    if (defined($type) && defined($actor)) {
                        if ($type eq "is_manager") {
                            my $toggle_sth = $dbh->prepare("UPDATE users SET is_manager = ? WHERE username = LOWER(?)");
                            if ($value) {
                                $toggle_sth->execute(1, $actor);
                            } else {
                                $toggle_sth->execute(0, $actor);
                            }
                            $toggle_sth->finish();
                            $content = 'success';
                        }

                        if ($type eq "is_enabled") {
                            my $toggle_sth = $dbh->prepare("UPDATE users SET is_enabled = ? WHERE username = LOWER(?)");
                            if ($value) {
                                $toggle_sth->execute(1, $actor);
                            } else {
                                $toggle_sth->execute(0, $actor);
                            }
                            $toggle_sth->finish();
                            $content = 'success';
                        }
                    }
                }
            }

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

    my $tools_tab_link = "";
    my $tools_tab_content = "";

    if ($is_manager) {
        my $count_sessions_sth = $dbh->prepare_cached("SELECT COUNT(*) FROM sessions");
        $count_sessions_sth->execute();
        my ($count_sessions) = $count_sessions_sth->fetchrow();
        $count_sessions_sth->finish();

        my $count_autologin_sth = $dbh->prepare_cached("SELECT COUNT(*) FROM autologin");
        $count_autologin_sth->execute();
        my ($count_autologin) = $count_autologin_sth->fetchrow();
        $count_autologin_sth->finish();

        my $count_secrets_sth = $dbh->prepare_cached("SELECT COUNT(*) FROM secrets");
        $count_secrets_sth->execute();
        my ($count_secrets) = $count_secrets_sth->fetchrow();
        $count_secrets_sth->finish();

        my @users = ();
        my $all_users_sth = $dbh->prepare_cached(q|
            SELECT id, username, is_manager, is_enabled
            FROM users
            ORDER BY username ASC
        |);
        $all_users_sth->execute();
        while (my ($all_users_id, $all_users_username, $all_users_is_manager, $all_users_is_enabled) = $all_users_sth->fetchrow()) {
            my $is_enabled_checkbox = "";
            $is_enabled_checkbox = q|checked="checked"| if ($all_users_is_enabled);
            my $is_manager_checkbox = "";
            $is_manager_checkbox = q|checked="checked"| if ($all_users_is_manager);

            push(@users, qq|
                <div class="row">
                    <div class="username">${all_users_username}</div>
                    <div class="is">
                        <input type="checkbox" name="is_manager" ${is_manager_checkbox}/>
                    </div>
                    <div class="is">
                        <input type="checkbox" name="is_enabled" ${is_enabled_checkbox}/>
                    </div>
                    <div class="clear"></div>
                </div>
            |);
        }
        $all_users_sth->finish();

        $tools_tab_link = q|
            <li><a href="#management">Management</a></li>
        |;
        $tools_tab_content = qq|
            <div id="management">
                <ul>
                    <li>
                        <a href="javascript:openid.management.clear('sessions');">Clear all sessions.</a>
                          - <span class="count_sessions">${count_sessions}</span> active sessions. THIS WILL END YOUR SESSION, TOO!<br/>
                    </li>
                    <li>
                        <a href="javascript:openid.management.clear('autologin');">Clear all automatic logins.</a>
                          - <span class="count_autologin">${count_autologin}</span> automatic login keys.<br/>
                    </li>
                    <li>
                        <a href="javascript:openid.management.clear('secrets');">Clear all OpenID secrets.</a>
                          - <span class="count_secrets">${count_secrets}</span> OpenID secrets.<br/>
                    </li>
                </ul>

                <form autocomplete="off" method="POST">
                    <div class="header">
                        <div class="username">Username</div>
                        <div class="is">Is manager?</div>
                        <div class="is">Is enabled?</div>
                        <div class="clear"></div>
                    </div>
                    ${\join("", @users)}
                </form><br/>
            </div>
        |;
    }

    my $t = org::lockaby::id::template->new({
        title => $config->{url} . " - profile",
    });

    $r->content_type('text/html; charset=utf-8');
    print $t->get_header();
    print qq|
        <div id="title">
            ${\$config->{url}} profile
        </div>
        <div id="header">
            <div class="username">Logged in as: <b>${username}</b></div>
            <div class="logout">[<a href="/openid/logout">logout</a>]</div>
            <div class="clear"></div>
        </div>
        <div id="tabs">
            <ul>
                <li><a href="#trusted">Trusted Sites</a></li>
                <li><a href="#profile">My Profile</a></li>
                ${tools_tab_link}
            </ul>
            <div id="trusted">
                <form autocomplete="off" method="POST">
                    <div class="introduction">
                        Configure the list of sites that you are authorizing to use your ID.
                    </div>

                    <div class="select">
                        Select: <a href="javascript:void(0);" onclick="openid.trusted.select(this, 'all');">all</a> \|
                                <a href="javascript:void(0);" onclick="openid.trusted.select(this, 'none');">none</a>
                    </div>
                    <div class="header">
                        <div class="name">Site</div>
                        <div class="clear"></div>
                    </div>
                    ${\join("\n", @trusted)}
                </form><br/>
            </div>
            <div id="profile">
                <form autocomplete="off" method="POST">
                    <div class="introduction">
                        These fields will be sent to sites when you log in. For more details, read about the
                        <a href="http://openid.net/specs/openid-simple-registration-extension-1_0.html">OpenID
                        Simple Registration Extension</a>.
                    </div>

                    <div class="row">
                        <div class="label">Email Address:</div>
                        <div class="value">
                            <input type="text" value="${email_address}" name="email_address"/>
                        </div>
                        <div class="clear"></div>
                    </div>

                    <div class="row">
                        <div class="label">Full Name:</div>
                        <div class="value">
                            <input type="text" value="${fullname}" name="fullname"/>
                        </div>
                        <div class="clear"></div>
                    </div>

                    <div class="row">
                        <div class="label">Nickname:</div>
                        <div class="value">
                            <input type="text" value="${nickname}" name="nickname"/>
                        </div>
                        <div class="clear"></div>
                    </div>

                    <div style="text-align: center;">
                        <input type="submit" name="save" value="save"/>
                    </div>
                </form><br/>
            </div>
            ${tools_tab_content}
        </div>
        <script type="text/javascript">
            jQuery(document).ready(function() {
                jQuery('#tabs').tabs();
                jQuery('#management form').submit(function (event) {
                    event.preventDefault();
                });
                jQuery('#management form input[type="checkbox"]').change(function (event) {
                    openid.management.save(event, this);
                });
                jQuery('#profile form').submit(function (event) {
                    openid.profile.save(event, this);
                });
                jQuery('#trusted form').submit(function (event) {
                    openid.trusted.remove(event, this);
                });
                jQuery('#trusted form').find('input[type="checkbox"]').click(function (event) {
                    openid.trusted.checked(event, this);
                });
            });
        </script>
    |;
    print $t->get_footer();

    return Apache2::Const::OK;
}

1;
