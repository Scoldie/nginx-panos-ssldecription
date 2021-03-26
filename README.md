It would be wise to propose several options of cipher suites with different levels of security for compatibility with clients.

    Very High Security (Paranoid + TLS 1.3 Support)
    ssl_ciphers 'ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-CCM:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-CCM';

    High Security (Mozilla SSL Configuration Generator)
    ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256';

    Intermediate Security (Mozilla SSL Configuration Generator)
    ssl_ciphers 'ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:DES-CBC3-SHA:!DSS';

    Old Security (Mozilla SSL Configuration Generator)
    ssl_ciphers 'ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-ECDSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:DES-CBC3-SHA:HIGH:SEED:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!RSAPSK:!aDH:!aECDH:!EDH-DSS-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA:!SRP';

Diffie Hellman Parameters

For DHE Cipher Suites, add a DH Parameters key is a good practice.

It would be nice to offer an option in the ssl.conf file for this parameter.
This option would not be enabled by default but available and possibly with a comment explaining how to generate a DH Parameters file.

EX : dhparam /etc/nginx/dhparam_key.pem;
openssl dhparam -out dhparam.pem 4096 # For a 4096-bits key
Elliptic Curve Diffie Hellman

For ECDH Cipher Suites, it would be great to add the option ssl_ecdh_curve, not enabled by default.
The administrators will be able to choose the elliptic curves allowed by the web server.

EX : ssl_ecdh_curve 'secp521r1:secp384r1'; # To allow only P-521 and P-384 elliptic curves
HTTP Public Key Pinning

Finally, it would be interesting to add an option regarding the HPKP configuration and how to set it up.

EX : add_header Public-Key-Pins 'pin-sha256="base64:primary_key"; pin-sha256="base64:secondary_key"; max-age=2592000; includeSubDomains';

To generate the certificate pin :
openssl x509 -noout -in certificate.pem -pubkey | openssl asn1parse -noout -inform pem -out public.key | openssl dgst -sha256 -binary public.key | openssl enc -base64

HTTP Public Key Pinning requires at least two PINs.
It is not necessary to generate an additional certificate. Use your RSA certificate for the first PIN and your ECDSA certificate for the second PIN.

These are just suggestions for improvements to adopt good security practices for web servers.
If this can help.

Sample in my case:
```
server {
	listen 80 default_server;
	listen 443 ssl default_server;

	root /var/www/html;

	index index.html index.htm index.nginx-debian.html;

    server_name		example.com;
    ssl_certificate           /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key       /etc/letsencrypt/live/example.com/privkey.pem;

    ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers 'ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-CCM:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-CCM';
    ssl_ecdh_curve 'secp521r1:secp384r1';
    ssl_dhparam /etc/ssl/dhparam.pem;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;
    #ssl_stapling on;
    ssl_stapling_verify on;

    resolver <your resolver ip> valid=300s;
    resolver_timeout 5s;
    add_header Strict-Transport-Security "max-age=63072000; includeSubdomains";
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;

  location / {
    index     index.html index.htm index.php;
    try_files $uri /index.php?$args;
  }
```