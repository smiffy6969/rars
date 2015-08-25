# R.A.R.S. Razor Authenticating Resource Server


__REQUIRES__ - PHP5


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


Once the DB is set, you should configure the server via the index.php file, this will configure the system, phpmailer (bundled) and other things to get a fully fledged resource erver running on PHP.


Once you have the system setup and running, you may add resources to the rars/api folder using a resource/type structure such as user/access which is already present for accessing the user table via various methods. This will allow you to serve your DB to your front end application via REST/JSON.


Various tools are provided in the extended class (RarsAPI) such as authentication checking (usng the authorization header), please see user/api files for how to use these tools..... more to follow....


TBC...
