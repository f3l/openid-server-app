#!/usr/bin/perl
package org::lockaby::id::handler::endpoint;

use strict;
use warnings;
use utf8;

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
    };

    bless ($self, $class);
    return $self;
}

sub get_endpoint {
    my $self = shift;
    my %args = (
        username => undef,
        @_,
    );

    eval {
        if ($self->{engine}->is_valid_username(username => $args{username})) {
            my $format = $self->{engine}->q()->param('format');
            if (defined($format)) {
                return $self->_get_xrds(username => $args{username}) if ($format eq "xrds");
            } else {
                return $self->_get_user(username => $args{username});
            }
        }

        $self->{engine}->r()->status(Apache2::Const::NOT_FOUND);
        return Apache2::Const::NOT_FOUND;
    };
    if ($@) {
        $self->{engine}->r()->content_type("text/plain");
        $self->{engine}->r()->print($@);
        $self->{engine}->r()->status(Apache2::Const::SERVER_ERROR);
        return Apache2::Const::SERVER_ERROR;
    }

}

sub _get_xrds {
    my $self = shift;
    my %args = (
        username => undef,
        @_,
    );

    $self->{engine}->r()->content_type('application/xrds+xml; charset=utf-8');
    $self->{engine}->r()->print("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    $self->{engine}->r()->print(qq|
        <xrds:XRDS 
            xmlns:xrds="xri://\$xrds"
            xmlns="xri://\$xrd*(\$v*2.0)"
            xmlns:openid="http://openid.net/xmlns/1.0">
            <XRD>
                <!-- OpenID 2.0 login service -->
                <Service priority="10">
                    <Type>http://specs.openid.net/auth/2.0/signon</Type>
                    <URI>http://${\$self->{config}->{url}}/openid/service</URI>
                    <LocalID>http://${\$self->{config}->{url}}/${\$args{username}}</LocalID>
                </Service>
                <!-- OpenID 1.1 login service -->
                <Service priority="20">
                    <Type>http://openid.net/signon/1.1</Type>
                    <URI>http://${\$self->{config}->{url}}/openid/service</URI>
                    <openid:Delegate>http://${\$self->{config}->{url}}/${\$args{username}}</openid:Delegate>
                </Service>
                <!-- OpenID 1.0 login service -->
                <Service priority="30">
                    <Type>http://openid.net/signon/1.0</Type>
                    <URI>http://${\$self->{config}->{url}}/openid/service</URI>
                    <openid:Delegate>http://${\$self->{config}->{url}}/${\$args{username}}</openid:Delegate>
                </Service>
            </XRD>
        </xrds:XRDS>
    |);

    return Apache2::Const::OK;
}

sub _get_user {
    my $self = shift;
    my %args = (
        username => undef,
        @_,
    );

    my $t = org::lockaby::id::template->new({
        title => $self->{config}->{url} . " - " . $args{username},
        meta  => [
            '<link rel="openid2.provider" href="http://' . $self->{config}->{url} . '/openid/service"/>',
            '<link rel="openid2.local_id" href="http://' . $self->{config}->{url} . '/' . $args{username} . '"/>',
            '<link rel="openid.server" href="http://' . $self->{config}->{url} . '/openid/service"/>',
            '<link rel="openid.delegate" href="http://' . $self->{config}->{url} . '/' . $args{username} . '"/>',
            '<meta http-equiv="X-XRDS-Location" content="http://' . $self->{config}->{url} . '/' . $args{username} . '?format=xrds">',
        ],
    });

    $self->{engine}->r()->content_type('text/html; charset=utf-8');
    $self->{engine}->r()->headers_out->set('X-XRDS-Location', 'http://' . $self->{config}->{url} . "/" . $args{username} . '?format=xrds');
    $self->{engine}->r()->print($t->get_header());
    $self->{engine}->r()->print(qq|
        This is the OpenID endpoint for <b>${\$args{username}}</b> on <b>${\$self->{config}->{url}}</b>.
    |);
    $self->{engine}->r()->print($t->get_footer());

    return Apache2::Const::OK;
}

1;
