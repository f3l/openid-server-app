#!/usr/bin/perl
package org::lockaby::utilities;

use strict;
use warnings;
use utf8;

use Time::Local;
use MIME::Base64 qw(encode_base64 decode_base64);
use Digest::MD5;
use DateTime;

sub is_md5_hash {
    my ($value) = @_;
    return ($value =~ /^[0-9abcdef]{32}$/);
}

sub is_guid {
    my ($value) = @_;
    return ($value =~ /^[0-9ABCDEF]{8}-[0-9ABCDEF]{4}-[0-9ABCDEF]{4}-[0-9ABCDEF]{4}-[0-9ABCDEF]{12}$/);
}

sub to_epoch {
    my ($date) = @_;

    my ($year, $month, $day, $hour, $minute, $second) = ($date =~ m/(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})/);
    return timegm($second, $minute, $hour, $day, ($month - 1), ($year - 1900));
}

sub format_time {
    my %args = (
        date => undef,
        epoch => undef,
        format => undef,
        fromTZ => undef,
        toTZ => undef,
        @_,
    );

    # if the format isn't specified then send it back in YYYY-MM-DD HH24:MI::SS format
    $args{format} = "%Y-%m-%d %H:%M:%S" unless defined($args{format});

    my $date = $args{date};
    if (!defined($date)) {
        my ($now_second, $now_minute, $now_hour, $now_day, $now_month, $now_year);
        if (defined($args{epoch}) && length($args{epoch})) {
            ($now_second, $now_minute, $now_hour, $now_day, $now_month, $now_year) = (gmtime($args{epoch}))[0, 1, 2, 3, 4, 5];
        } else {
            ($now_second, $now_minute, $now_hour, $now_day, $now_month, $now_year) = (gmtime)[0, 1, 2, 3, 4, 5];
        }
        $date = sprintf("%04d-%02d-%02d %02d:%02d:%02d", ($now_year + 1900), ($now_month + 1), $now_day, $now_hour, $now_minute, $now_second);
    }

    my ($year, $month, $day, $hour, $minute, $second) = ($date =~ m/(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})/);
    my $dt = DateTime->new(
        year => $year,
        month => $month,
        day => $day,
        hour => $hour,
        minute => $minute,
        second => $second,
        time_zone => $args{fromTZ} || "GMT",
    );
    $dt->set_time_zone($args{toTZ}) if defined($args{toTZ});
    return $dt->strftime($args{format});
}

# expects time in seconds since 1970 (epoch)
sub to_human_time {
    my ($base) = @_;

    return undef unless defined($base);
    return undef unless ($base =~ /^[0-9]+$/);

    my $metric = "seconds";
    if ($base > 60) {
        # turn to minutes
        $base = ($base / 60);
        $metric = "minutes";

        if ($base > 60) {
            # turn to hours
            $base = ($base / 60);
            $metric = "hours";

            if ($base > 24) {
                # turn to days
                $base = ($base / 24);
                $metric = "days";
            }
        }
    }

    return sprintf("%.2f %s", $base, $metric);
}

# expects time in seconds since 1970 (epoch)
sub to_human_time_offset {
    my ($base) = @_;

    return undef unless defined($base);
    return undef unless ($base =~ /^[0-9]+$/);

    my $current_time = time;

    # if the offset is greater than the current time, get out of here
    return undef unless ($base < $current_time);

    # now we can convert into something useful
    my $difference = ($current_time - $base);

    # if the difference is less than a minute
    if ($difference < 60) {
        $difference = to_human_number($difference);

        my $plural = ($difference eq 1) ? "a second" : "${difference} seconds";
        return "${plural} ago";
    }

    # if the difference is less than an hour
    if ($difference < 3600) {
        my $value = int($difference / 60);
        $value = to_human_number($value);

        my $plural = ($value eq 1) ? "a minute" : "${value} minutes";
        return "${plural} ago";
    }

    # if the difference is less than 24 hours
    if ($difference < 86400) {
        my $value = int($difference / 3600);
        $value = to_human_number($value);

        my $plural = ($value eq 1) ? "an hour" : "${value} hours";
        return "about ${plural} ago";
    }

    # if the difference is more than 24 hours
    if ($difference >= 86400) {
        my $value = int($difference / 86400);
        $value = to_human_number($value);

        my $plural = ($value eq 1) ? "a day" : "${value} days";
        return "about ${plural} ago";
    }

    return undef;
}

sub to_human_bytes {
    my ($base, $precision) = @_;

    return undef unless defined($base);
    $precision = 2 unless defined($precision);

    my $metric = "";
    while ($base > 1024) {
        $base = ($base / 1024);
        if    ($metric eq "")  { $metric = "K"; }
        elsif ($metric eq "K") { $metric = "M"; }
        elsif ($metric eq "M") { $metric = "G"; }
        elsif ($metric eq "G") { $metric = "T"; }
        elsif ($metric eq "T") { $metric = "P"; }
        elsif ($metric eq "P") { $metric = "E"; }
        elsif ($metric eq "E") { $metric = "Y"; }
        elsif ($metric eq "Y") { $metric = "Z"; }
        else                   { $metric = "inf"; }
    }
    return sprintf("%.${precision}f", $base) . $metric . 'B';
}

sub to_human_number {
    my ($base, $precision) = @_;

    return undef unless defined($base);
    $base = sprintf("%.${precision}f", $base) if defined($precision);

    1 while $base =~ s/^(-?\d+)(\d{3})/$1,$2/;
    return $base;
}

sub remove_directory {
    my ($directory) = @_;

    if (!(-d $directory)) {
        unlink($directory);
        return;
    } else {
        opendir(my $dh, $directory) || warn "ERROR: Can't open ${directory}: $!\n";
        if ($dh) {
        while (defined(my $file = readdir($dh))) {
            if ($file eq "." || $file eq "..") { next; }
            remove_directory("${directory}/${file}");

            if (-d "${directory}/${file}") {
                rmdir("${directory}/${file}");
            }
        }
        closedir($dh);
        }

        # finally, remove the directory
        rmdir($directory);
    }
}

sub get_md5_from_file {
    my ($filename) = @_;
    return undef unless defined($filename);

    open(FILE, "<:encoding(UTF-8)", $filename) || die "Could not open file $filename: $!\n";
    binmode(FILE);
    my $hash = Digest::MD5->new->addfile(*FILE)->hexdigest;
    close(FILE);

    return $hash;
}

sub get_md5_from_string {
    my ($string) = @_;
    return undef unless defined($string);
    return Digest::MD5::md5_hex($string);
}

sub encode_base64_from_string {
    my ($string) = @_;
    return undef unless defined($string);

    my $result = encode_base64($string);
    $result =~ s/^\s+|\s+$//g;
    $result =~ s/\n//g;
    return $result;
}

sub decode_base64_from_string {
    my ($string) = @_;
    return undef unless defined($string);

    my $result = decode_base64($string);
    $result =~ s/^\s+|\s+$//g;
    return $result;
}

# content should be a string that we are sending back
# errors would be an array reference with each error an element in the array
sub prepare_ajax_response {
    my ($content, $errors) = @_;

    my $result = '<?xml version="1.0" encoding="UTF-8" ?>' . "\n";
    $result .= "<ajax-response>";

        if (defined($content)) {
            $result .= "<content>" . $content . "</content>";
        }

        if (defined($errors)) {
            $result .= "<errors>";
            foreach my $error (@{$errors}) {
                $result .= "<error><![CDATA[" . $error . "]]></error>";
            }
            $result .= "</errors>";
        }

    $result .= "</ajax-response>";
    return $result;
}

1;
