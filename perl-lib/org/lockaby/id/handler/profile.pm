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
    my $username = $session->get('username');
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

                $email_address =~ s/^\s+|\s+$//g;
                $fullname =~ s/^\s+|\s+$//g;
                $nickname =~ s/^\s+|\s+$//g;

                my $save_sth = $dbh->prepare_cached(q|
                    UPDATE users
                    SET email_address = ?,
                        fullname = ?,
                        nickname = ?
                    WHERE username = LOWER(?)
                |);
                $save_sth->execute($email_address, $fullname, $nickname, $username);
                $save_sth->finish();

                if ($engine->is_password_changeable()) {
                    my $password1 = $q->param('password1');
                    my $password2 = $q->param('password2');

                    if (defined($password1) && defined($password2)) {
                        $password1 =~ s/^\s+|\s+$//g;
                        $password2 =~ s/^\s+|\s+$//g;

                        if (length($password1) && length($password2)) {
                            if ($password1 eq $password2) {
                                $engine->change_password(username => $username, password => $password1);
                            } else {
                                die "Passwords do not match.\n";
                            }
                        }
                    }
                }

                $content = "success";
            }

            if (defined($form) && $form eq "management" && $is_manager) {
                my $action = $q->param('action');

                if (defined($action) && $action eq "create") {
                    my $username = $q->param('username');
                    my $is_manager = $q->param('is_manager');
                    my $is_enabled = $q->param('is_enabled');

                    if (defined($username)) {
                        $username =~ s/^\s+|\s+$//g;

                        if (length($username)) {
                            my $create_user_sth = $dbh->prepare_cached(q|
                                INSERT INTO users (username, created, is_manager, is_enabled)
                                           VALUES (LOWER(?), NOW(), ?, ?)
                            |);
                            $create_user_sth->execute($username, $is_manager, $is_enabled);
                            $create_user_sth->finish();

                            $content = 'success';
                        } else {
                            die "Could not create user. No username given.\n";
                        }
                    } else {
                        die "Could not create user. No username given.\n";
                    }
                }

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

                if (defined($action) && $action eq "password") {
                    my $username = $q->param('username');
                    my $password1 = $q->param('password1');
                    my $password2 = $q->param('password2');

                    if (defined($username)) {
                        $username =~ s/^\s+|\s+$//g;

                        if (length($username)) {
                            $password1 =~ s/^\s+|\s+$//g if defined($password1);
                            $password2 =~ s/^\s+|\s+$//g if defined($password2);

                            # users can be given an empty password
                            if ($password1 eq $password2) {
                                $engine->change_password(username => $username, password => $password1);

                                $content = 'success';
                            } else {
                                die "Could not change password. Passwords do not match.\n";
                            }
                        } else {
                            die "Could not change password. No username given.\n";
                        }
                    } else {
                        die "Could not change password. No username given.\n";
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

    my $management_tab_link = "";
    my $management_tab_content = "";
    my $management_tab_script = "";

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

            my $change_password_link = "";
            $change_password_link = '[<a href="javascript:void(0);" onclick="openid.management.password.change(this);">change password</a>]' if $engine->is_password_changeable();

            push(@users, qq|
                <div class="row">
                    <div class="user">
                        <div class="username">${all_users_username}</div>
                        <div class="password">${change_password_link}</div>
                        <div class="clear"></div>
                    </div>
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

        my $create_user_html = "";
        if ($engine->is_user_createable()) {
            my $create_user_password_html = "";
            if ($engine->is_password_changeable()) {
                $create_user_password_html = q|
                    <div class="label">Password:</div>
                    <div class="value">
                        <input type="password" name="password1" value=""/>
                    </div>
                    <div class="clear"></div>

                    <div class="label">Verify Password:</div>
                    <div class="value">
                        <input type="password" name="password2" value=""/>
                    </div>
                    <div class="clear"></div>
                |;
            }

            $create_user_html = qq|
                <div class="create">
                    <div class="header">
                        <div class="username">Create New User</div>
                        <div class="is">Is manager?</div>
                        <div class="is">Is enabled?</div>
                        <div class="clear"></div>
                    </div>
                    <div class="row">
                        <div class="user">
                            <div class="label">Username:</div>
                            <div class="value">
                                <input type="text" name="username" value=""/>
                            </div>
                            <div class="clear"></div>

                            <!-- can the user change the password -->
                            ${create_user_password_html}
                        </div>
                        <div class="is">
                            <input type="checkbox" name="is_manager"/>
                        </div>
                        <div class="is">
                            <input type="checkbox" name="is_enabled" checked="checked"/>
                        </div>
                        <div class="clear"></div>
                    </div>
                </div>
            |;
        }

        my $change_password_html = "";
        if ($engine->is_password_changeable()) {
            $change_password_html = q|
                <div class="change">
                    <div class="username">
                        Changing password for <span class="username"></span>.
                    </div>

                    <div class="label">Password:</div>
                    <div class="value">
                        <input type="password" name="password1" value=""/>
                    </div>
                    <div class="clear"></div>

                    <div class="label">Verify Password:</div>
                    <div class="value">
                        <input type="password" name="password2" value=""/>
                    </div>
                    <div class="clear"></div>
                </div>
            |;
        }

        my $change_password_script = "";
        if ($engine->is_password_changeable()) {
            $change_password_script = q|
                openid.management.password.create();
            |;
        }

        $management_tab_link = q|
            <li><a href="#management">Management</a></li>
        |;

        $management_tab_content = qq|
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

                <form autocomplete="off" method="POST" name="toggle">
                    <div class="users">
                        <div class="header">
                            <div class="username">Username</div>
                            <div class="is">Is manager?</div>
                            <div class="is">Is enabled?</div>
                            <div class="clear"></div>
                        </div>
                        ${\join("", @users)}
                    </div>

                    <!-- create user, if users are createable -->
                    ${create_user_html}

                    <!-- change password, if the password is changeable -->
                    ${change_password_html}

                    <div style="text-align: center;">
                        <input type="submit" name="save" value="save"/>
                    </div>
                </form><br/>
            </div>
        |;

        $management_tab_script = qq|
            ${change_password_script}

            jQuery('#management form').submit(function (event) {
                // save a new user
                openid.management.save(event, this);
            });
            jQuery('#management form input[type="checkbox"]').change(function (event) {
                // toggle an existing user
                openid.management.toggle(event, this);
            });
        |;
    }

    my $profile_password_change = "";
    if ($engine->is_password_changeable()) {
        $profile_password_change = q|
            <div class="row" style="text-align: center;">
                Enter a new password to change your password.<br/>
                Enter no password to leave your password as it is.<br/>
            </div>

            <div class="row">
                 <div class="label">Password:</div>
                 <div class="value">
                     <input type="password" value="" name="password1"/>
                 </div>
                 <div class="clear"></div>
            </div>

            <div class="row">
                <div class="label">Verify Password:</div>
                <div class="value">
                    <input type="password" value="" name="password2"/>
                </div>
                <div class="clear"></div>
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
                ${management_tab_link}
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
                            <input type="text" value="${\((defined($email_address) ? $email_address : ""))}" name="email_address"/>
                        </div>
                        <div class="clear"></div>
                    </div>

                    <div class="row">
                        <div class="label">Full Name:</div>
                        <div class="value">
                            <input type="text" value="${\((defined($fullname) ? $fullname : ""))}" name="fullname"/>
                        </div>
                        <div class="clear"></div>
                    </div>

                    <div class="row">
                        <div class="label">Nickname:</div>
                        <div class="value">
                            <input type="text" value="${\((defined($nickname) ? $nickname : ""))}" name="nickname"/>
                        </div>
                        <div class="clear"></div>
                    </div>

                    <!-- if the user can change his or her password, it goes here -->
                    ${profile_password_change}

                    <div style="text-align: center;">
                        <input type="submit" name="save" value="save"/>
                    </div>
                </form><br/>
            </div>
            ${management_tab_content}
        </div>
        <script type="text/javascript">
            jQuery(document).ready(function() {
                jQuery('#tabs').tabs();

                // add javascript for management here, if necessary
                ${management_tab_script}

                jQuery('#trusted form').submit(function (event) {
                    openid.trusted.remove(event, this);
                });
                jQuery('#trusted form').find('input[type="checkbox"]').click(function (event) {
                    openid.trusted.checked(event, this);
                });

                jQuery('#profile form').submit(function (event) {
                    openid.profile.save(event, this);
                });
            });
        </script>
    |;
    print $t->get_footer();

    return Apache2::Const::OK;
}

1;
