<?php if (!defined("RARS_BASE_PATH")) die("No direct script access to this content");

/**
 * Razor Authenticating Resource Server
 * Copywrite 2014 to Present Day - Paul Smith (aka smiffy6969, razorcms)
 *
 * @author Paul Smith
 * @site ulsmith.net
 * @created Feb 2014
 *
 * Requires the following tables and columns (rename at your peril, just ensure you change in code below, ctrl-d is your friend)
 *
 * Table: banned
 * Column: id (int PK AI)
 * Column: ip_address (string 20)
 * Column: user_agent (string 255)
 * Column: created (timestamp CURRENT_TIMESTAMP)
 *
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
 *
 * get user access internally in other api classes using the following in the contsruct
 *
 * include_once(RARS_BASE_PATH.'api/user/access.php');
 * $access = new UserAccess();
 * $this->user = $access->check();
 *
 * Then simply check $this->user['access_level'] is at the level youo require, or respond with 401 if failed access
 */

class UserAccess extends RarsAPI
{
	function __construct()
	{
		// REQUIRED IN EXTENDED CLASS TO LOAD DEFAULTS
		parent::__construct();
	}

	/**
	 * REST GET - Check access, this requires a table called 'user' in your db with various fields as per header
	 * @header Authorization The token to check access against
	 * @cookie token [alternative to header] The token to check access against
	 * @return array Basic user details of varified account against the authorization header
	 */
	public function get()
	{
		$user = $this->check();
		if ($user === false) $this->response('Check failed: No access', 'json', 401);
		else $this->response($user, 'json');
	}

	/**
	 * REST POST - Log in user, this requires a table called 'user' nad 'banned' in your db with various fields as per header
	 * @param $data The login data via rest request containing 'username' and 'password', note username contains the email_address
	 * @return array Basic user details of varified account against the username and password, also sets correct return Autherization header for token generated
	 */
	public function post($data)
	{
		// check if email set
		if (!isset($data["username"]) || !isset($data['password'])) $this->response('Login failed: username or password missmatch', 'json', 401);

		$ip_address = preg_replace("/[^0-9.]/", '', substr($_SERVER["REMOTE_ADDR"], 0, 50));
		$user_agent = preg_replace("/[^0-9a-zA-Z.:;-_]/", '', substr($_SERVER["HTTP_USER_AGENT"], 0, 250));

		// check ban list if active before doing anything else
		if (RARS_ACCESS_BAN_ATTEMPS > 0)
		{
			// find banned rows
			$banned = $this->rars_db->get_first('banned', '*', array('ip_address' => $ip_address, 'user_agent' => $user_agent));
			if (!empty($banned))  $this->response('Login failed: ip banned', 'json', 401);
		}

		/* carry on with login */

		// find user
		$user = $this->rars_db->get_first('user', '*', array('email_address' => $data['username']));

		// check user found
		if (empty($user)) $this->response('Login failed: username or password missmatch', 'json', 401);

		// check if user is locked out here
		if (!empty($user['lock_until']) && strtotime($user['lock_until']) > time()) $this->response('Login failed: user locked out please try later', 'json', 401);

		// check active user
		if (!$user['active']) $this->response('Login failed: user not active', 'json', 401);

		// now check if password ok (we need password first to get salt from it before we can check it), if not then send response
		if (RarsAPI::create_hash($data['password'],substr($user['password'],0,(strlen($user['password'])/2)),'sha1') !== $user['password'])
		{
			// data to update
			$update_data = array('failed_attempts' => $user['failed_attempts']++);
			if ($user['failed_attempts'] > 0 && $user['failed_attempts'] % RARS_ACCESS_ATTEMPTS == 0) $update_data['lock_until'] = date('Y-m-d H:i:s', time() + RARS_ACCESS_LOCKOUT);

			// update
			$this->rars_db->edit_data('user', $update_data, array('id' => $user['id']));

			// add to banned list if banned active and too many attempts
			if (RARS_ACCESS_BAN_ATTEMPS > 0 && $user['failed_attempts'] + 1 >= RARS_ACCESS_BAN_ATTEMPS)
			{
	            // add ip and agent to banned
	            $this->rars_db->add_data('banned', array('ip_address' => $ip_address, 'user_agent' => $user_agent, 'created' => date('Y-m-d H:i:s', time())));
			}

			$this->response('Login failed: username or password missmatch', 'json', 401);
		}

		/* we are now authenticated, respond and send token back */

		// need to create a token and last logged stamp and save it in the db
		$last_logged = date('Y-m-d H:i:s', time());
		$pass_hash = $user['password'];
		$token = sha1($last_logged.$user_agent.$ip_address.$pass_hash).'_'.$user['id'];

		// update data
		$update_data = array(
			'id' => $user['id'],
			'last_logged_in' => $last_logged,
			'last_accessed' => $last_logged,
			'ip_address' => $ip_address
		);

		$user = $this->rars_db->edit_data('user', $update_data, array('id' => $user['id']), '*');

		// collect user data
		$user_data = array(
			'id' => $user[0]['id'],
			'name' => $user[0]['name'],
			'email_address' => $user[0]['email_address'],
			'last_logged_in' => $user[0]['last_logged_in'],
			'access_level' => $user[0]['access_level']
		);

		// setup response with authorization token
		$_SERVER['HTTP_AUTHORIZATION'] = $token;
		$this->response($user_data, 'json');
	}

	/**
	 * Check user is logged in, this requires a table called 'user' in your db with various fields as per header
	 * @header Authorization The token to check access against
	 * @cookie token [alternative to header] The token to check access against
	 * @return array Basic user details of varified account against the authorization header
	 */
	public function check()
	{
		// retrieve token from incoming request
		$token = (isset($_SERVER['HTTP_AUTHORIZATION']) ? $_SERVER['HTTP_AUTHORIZATION'] : (isset($_SERVER['REDIRECT_HTTP_AUTHORIZATION']) ? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] : (isset($_COOKIE['token']) ? $_COOKIE['token'] : null )));
		if (empty($token)) return false;

		$ip_address = preg_replace("/[^0-9.]/", '', substr($_SERVER["REMOTE_ADDR"], 0, 50));
		$user_agent = preg_replace("/[^0-9a-zA-Z.:;-_]/", '', substr($_SERVER["HTTP_USER_AGENT"], 0, 250));

		// check ban list if active before doing anything else
		if (RARS_ACCESS_BAN_ATTEMPS > 0)
		{
			// find banned rows
			$banned = $this->rars_db->get_first('banned', '*', array('ip_address' => $ip_address, 'user_agent' => $user_agent));
			if (!empty($banned))  return false;
		}

		// extract token and id
		$token_data = explode('_', $token);
		if (count($token_data) != 2) return false;
		$token = preg_replace('/[^a-zA-Z0-9]/', '', $token_data[0]);
		$id = (int) $token_data[1];

		// find user
		$user = $this->rars_db->get_first('user', '*', array('id' => $id));

		// no user found or no access in XXX seconds
		if (empty($user)) return false;
		if (strtotime($user['last_accessed']) < time() - RARS_ACCESS_TIMEOUT) return false;

		/* all ok, so go verify user */

		// need to create a token and last logged stamp
		$last_logged = $user['last_logged_in'];
		$user_agent = preg_replace('/[^0-9a-zA-Z.:;-_]/', '', substr($_SERVER['HTTP_USER_AGENT'], 0, 250));
		$ip_address = preg_replace('/[^0-9.]/', '', substr($_SERVER['REMOTE_ADDR'], 0, 50));
		$pass_hash = $user['password'];
		$gen_token = sha1($last_logged.$user_agent.$ip_address.$pass_hash);

		if ($gen_token !== $token)
		{
			// add to banned list if banned active and too many attempts
			if (RARS_ACCESS_BAN_ATTEMPS > 0 && $user['failed_attempts'] + 1 >= RARS_ACCESS_BAN_ATTEMPS)
			{
				// add ip and agent to banned
				$this->rars_db->add_data('banned', array('ip_address' => $ip_address, 'user_agent' => $user_agent));
			}
			return false;
		}

		/* all verified, carry on */

		// build return data
		$user_data = array(
			'id' => $user['id'],
			'name' => $user['name'],
			'email_address' => $user['email_address'],
			'last_logged_in' => $user['last_logged_in'],
			'access_level' => $user['access_level']
		);

		// update access time to keep connection alive, only do this every 15min to keep writes to db down for user table
		// connection will stay live for a day anyway so we do not need to be this heavy on the last access time writes
		if (strtotime($user['last_accessed']) > time() - 300) return $user_data;

		// update last accessed
		$return_columns = array(
			'id',
			'name',
			'email_address',
			'last_logged_in',
			'access_level'
		);

		$user_data = $this->rars_db->edit_data('user', array('last_accessed' => date('Y-m-d H:i:s', time())), array('id' => $user['id']), $return_columns);
		return $user_data[0];
	}
}

/* EOF */
