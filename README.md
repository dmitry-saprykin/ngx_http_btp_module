Btp module for nginx
======================

What
----
This is a Btp module for nginx. It sends statistics packets by UDP that are received and processed by Btp server.
See <https://github.com/mambaru/btp-daemon> for more details.

Pre-requisites
--------------
nginx sources, C compiler.

Installation
------------
Add this to your nginx configure line:  

`--add-module=/path/to/ngx_http_btp_module.git/`  

and then do `make install`.

Configuration options
---------------------
All configuration options must be added to the `http {}` section of the config file,
but you can always modify them in location/server sections.

`btp_enable` - on/off.
The module is disabled by default.

`btp_server` - the adress of Pinba server.  
Should be a valid `host:port` or `ip_address:port` combination.

`btp_ignore_codes` - a list of HTTP status codes.  
Can be comma separated list or comma separated ranges of codes or both.  
No data packet will be sent if a request is finished with a final status from the list.

Example:  
`btp_ignore_codes 200-399,499;`
