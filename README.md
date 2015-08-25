# R.A.R.S. Razor Authenticating Resource Server


__Browser Support__ - IE9+, Chrome, FF, Safari, Opera


Requires a DB connection with the following tables...


* Table: banned
* Column: id (int PK AI)
* Column: ip_address (string 20)
* Column: user_agent (string 255)
* Column: created (timestamp CURRENT_TIMESTAMP)


* Table: user
* Column: id (int PK AI)
* Column: active (bool or tinyint(1))
* Column: name (string 255, does first and last name together to stop issues with name conventions around world)
* Column: email_address (string 255)
* Column: password (string 255)
* Column: access_level (int 2)
* Column: last_logged_in (timestamp yyyy-mm-dd hh:mm:ss)
* Column: last_accessed (timestamp yyyy-mm-dd hh:mm:ss)
* Column: failed_attempts (int)
* Column: lock_until (timestamp yyyy-mm-dd hh:mm:ss)
* Column: ip_address (string 20)
* Column: created (timestamp CURRENT_TIMESTAMP)
* Column: activate_token (string 255)
* Column: reminder_token (string 255)
* Column: reminder_time (timestamp)


TBC...
