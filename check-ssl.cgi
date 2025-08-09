#!/usr/bin/perl

	use Data::Dumper;
	use JSON;
	use Term::ANSIColor;
	use File::Temp qw(tempfile);
	use Time::Piece;	

	# get all the domains in the system ready, so we only have to do this once
	my $tmp = `v-list-users plain | cut -f1`;

	my @error_domains;
	my @warn_domains;

	# CONFIG SETTINGS
	my $subject = "SSL certificate status report";
	my $to   = 'andy@ultranerds.co.uk';
	my $warn_days = 14; # tweak as you like
	my $sendmail_path = '/usr/sbin/sendmail';

	#######################################
 	# You shouldn't need to edit anything after this :)
	#######################################

	foreach (split /\n/, $tmp) {
		next if $_ eq '';

		print color('yellow');
		print "\n\ndoing user: $_\n";
		print color('reset');

 		my $results = `v-list-web-domains $_ json`;
		if (length($results) > 10) {
			
			print color('green');
			print qq|Checking web domains:\n\n|;
			print color('reset');

			my $json = decode_json($results);

			foreach (keys %$json) {
				print qq|\tDomain: $_\n|;
				if ($json->{$_}->{SSL} eq "yes") {
					use Data::Dumper;
					print qq|\t\tSSL is enabled - lets check it...\n|;
					check_ssl_domain($_);
					#print Dumper($json->{$_});
				} else {
					print "\t\tSSL is not enabled for this domain\n";
				}
			}

		} else {
			print qq|\tNo web domains found for user $_\n|;
		}
			
		my $results = `v-list-mail-domains $_ json`;
		if (length($results) > 10) {

			print color('green');
			print qq|Checking mail domains:\n\n|;
			print color('reset');

			my $json_mail = decode_json($results);

			foreach (keys %$json_mail) {
				print qq|\tMail Domain: $_\n|;
				if ($json_mail->{$_}->{SSL} eq "yes") {
					use Data::Dumper;
					print qq|\t\tSSL is enabled - lets check it...\n|;
					check_ssl_domain("mail.". $_);
				} else {
					print "\t\tSSL is not enabled for this domain\n";
				}
			}

		} else {
			print qq|\t\tNo mail domains found for user $_\n|;
		}


	}

	# if @error_domains or @warn_domains are not empty, send an email
	if (@error_domains || @warn_domains) {

		my $hostname = `hostname`;

		
		my $body;

		$body .= qq|SERVER: $hostname\n\n|;
		if (int @error_domains > 0) {
			$body .= "ERRORS (expired SSLs):";
			foreach my $domain (@error_domains) {
				$body .= sprintf(" - %s\n", $domain->{domain});
			}
		}
 
		if (int @warn_domains > 0) {
			$body .= "WARNINGS (expiring SSLs):";
			foreach my $domain (@warn_domains) {
				$body .= sprintf(" - %s (~%d days left)\n", $domain->{domain}, $domain->{days_left});
			}
		}

		print qq|There are some warnings about SSL certificates. Please check the email.|;
		send_email_sendmail($subject, $body); 
	}
	
sub send_email_sendmail {
    my ($subject, $body) = @_;
    
	my $hostname = `hostname`;
	chomp $hostname;
	my $from = 'root@' . $hostname;

    open my $mail, '|-', $sendmail_path . ' -t' or die "open sendmail: $!";
    print $mail "From: $from\nTo: $to\nSubject: $subject\nContent-Type: text/plain; charset=UTF-8\n\n";
    print $mail ($body), "\n";
    close $mail or warn "sendmail close: $?";
}

sub check_ssl_domain {

	my $domain = shift;
	
	my $res = check_ssl_cert($domain, 443, $warn_days);

	if ($res->{status} eq 'ok') {
		print color('green');
		printf "\t\tOK: cert valid (notAfter=%s, ~%s days left)\n",
			($res->{not_after} || 'unknown'),
			(defined $res->{days_left} ? $res->{days_left} : '?');
		print color('reset');
	} elsif ($res->{status} eq 'warning') {
		print color('yellow');
		printf "\t\tWARNING: expires within %d days (notAfter=%s, ~%s days left)\n",
			$warn_days, ($res->{not_after} || 'unknown'),
			(defined $res->{days_left} ? $res->{days_left} : '?');
		print color('reset');
		push @warn_domains, { domain => $domain, days_left => $res->{days_left} };
	} elsif ($res->{status} eq 'expired') {
		print color('red');
		printf "\t\tEXPIRED: notAfter=%s\n", ($res->{not_after} || 'unknown');
		print color('reset');

		push @error_domains, { domain => $domain };
	}
	else {
		print color('red');
		printf "\t\tERROR: %s\n", ($res->{error} || 'could not retrieve certificate');
		print color('reset');
	}	

}

sub check_ssl_cert {
    my ($host, $port, $warn_days) = @_;
    $port      ||= 443;
    $warn_days ||= 0;

    # fetch the leaf certificate (SNI-aware)
    my $fetch_cmd = qq{openssl s_client -servername $host -connect $host:$port -verify_hostname $host};
    # use GNU timeout if available to avoid hanging
    my $timeout = `command -v timeout 2>/dev/null` ? "timeout 10s " : "";
    my $cert_pem = `$timeout$fetch_cmd < /dev/null 2>/dev/null | sed -n '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p'`;

    return { status => 'error', error => "No certificate from $host:$port" }
        unless $cert_pem && $cert_pem =~ /BEGIN CERTIFICATE/;

    # write cert to a temp file
    my ($fh, $tmp) = tempfile();
    print $fh $cert_pem;
    close $fh;

    # read notAfter
    my $end_line = `openssl x509 -in "$tmp" -noout -enddate 2>/dev/null`;
    $end_line =~ s/^\s+|\s+$//g;
    my ($not_after) = $end_line =~ /notAfter=(.*)/;
    $not_after ||= '';

    # expired?  (-checkend N returns 0 if valid for at least N seconds, 1 otherwise)
    my $expired_rc = system(qq{openssl x509 -in "$tmp" -noout -checkend 0 >/dev/null 2>&1});
    my $is_expired = ($expired_rc != 0);

    my $warn = 0;
    if ($warn_days && !$is_expired) {
        my $secs = $warn_days * 86400;
        my $warn_rc = system(qq{openssl x509 -in "$tmp" -noout -checkend $secs >/dev/null 2>&1});
        $warn = ($warn_rc != 0);  # true if expires within warn window
    }

    # days left (best effort)
    my $days_left = undef;
    if ($not_after) {
        eval {
            my $t_end = Time::Piece->strptime($not_after, "%b %e %H:%M:%S %Y %Z")->epoch;
            my $now   = time;
            $days_left = int( ($t_end - $now) / 86400 );
        };
    }

    my $status = $is_expired ? 'expired' : ($warn ? 'warning' : 'ok');
    return {
        status     => $status,        # 'ok' | 'warning' | 'expired' | 'error'
        not_after  => $not_after,     # e.g. "Aug  9 12:00:00 2025 GMT"
        days_left  => $days_left,     # integer, may be undef if parsing fails
        error      => ($status eq 'error' ? 'Unknown error' : undef),
        host       => $host,
        port       => $port,
    };
}
