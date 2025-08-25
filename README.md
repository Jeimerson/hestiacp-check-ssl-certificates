# hestiacp-check-ssl-certificates
A script to run on cron to check all the SSL certificates are valid and haven't expired / stalled
Enable SMTP authentication via port 587

Test it manually by just running it via SSH with:

`perl check-ssl.cgi`

If thats ok, then set it up as a cron under root: 

`@weekly perl /path/to/check-ssl.cgi >/dev/null 2>&1`

This should then email you if a SSL certificate (for web or mail) has expired, or is due to expire in x days 
