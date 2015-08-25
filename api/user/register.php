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
 * Column: id (int PK AI NN)
 * Column: ip_address (string 20 NN)
 * Column: user_agent (string 255 NN)
 * Column: created (timestamp NN default = CURRENT_TIMESTAMP)
 *
 * Table: user
 * Column: id (int PK AI NN)
 * Column: active (tinyint(1) NN default = 0)
 * Column: name (string 255 NN, does first and last name together to stop issues with name conventions around world)
 * Column: email_address (string 255 NN)
 * Column: password (string 255 NN)
 * Column: access_level (tinyint(1) NN default 0)
 * Column: last_logged_in (timestamp yyyy-mm-dd hh:mm:ss)
 * Column: last_accessed (timestamp yyyy-mm-dd hh:mm:ss)
 * Column: failed_attempts (int NN default 0)
 * Column: lock_until (timestamp yyyy-mm-dd hh:mm:ss)
 * Column: ip_address (string 20 NN)
 * Column: activate_token (string 255)
 * Column: created (timestamp NN default = CURRENT_TIMESTAMP)
 * Column: activate_token (string 255)
 * Column: reminder_token (string 255)
 * Column: reminder_time (timestamp)
 */

class UserRegister extends RarsAPI
{
	function __construct()
	{
		// REQUIRED IN EXTENDED CLASS TO LOAD DEFAULTS
		parent::__construct();

		session_start();
		session_regenerate_id();
	}

	/**
	 * REST GET - Activate a user by the activation token, this requires a table called 'user' and 'banned' in your db with various fields as per header
	 * @param $id The activation token as set per REST GET URL ending path
	 * @return emails result to user, or returns error
	 */
	public function get($id)
	{
		if (strlen($id) < 20) $this->response("Activation key not set",  400);

		$user = $this->rars_db->get_first('user', '*', array("activate_token" => $id));
		if (empty($user) || strtotime($user['created']) < time() - RARS_SYSTEM_ACTIVATION_EXPIRE) $this->response('User could not be activated', null, 409);

		// now we know token is ok and only an hour old, lets activate user

		// set active
		$row = array(
			"activate_token" => null,
			"active" => true
		);
		$this->rars_db->edit_data('user', $row, array('id' => $user['id']));

		// if all ok, redirect to login page and set activate message off
		$redirect = RARS_BASE_URL."../#user-registration-activated";
		header("Location: {$redirect}");
		exit();
	}

	/**
	 * REST POST - Register a user, this requires a table called 'user' and 'banned' in your db with various fields as per header
	 * @param $data The login data via rest request containing 'name', 'email', 'password' and 'human' (which should be there, but empty)
	 * @return emails result to either user or admin, or returns error
	 */
	public function post($data)
	{
		// are we accepting registrations
		if (!RARS_SYSTEM_REGISTRATION_ALLOWED) $this->response('Registrations deactivated', 'json', 405);

		// Check details
		if (!isset($_SERVER["REMOTE_ADDR"], $_SERVER["HTTP_USER_AGENT"], $_SERVER["HTTP_REFERER"])) $this->response('Invalid registration request', 'json', 400);
		if (empty($_SERVER["REMOTE_ADDR"]) || empty($_SERVER["HTTP_USER_AGENT"]) || empty($_SERVER["HTTP_REFERER"])) $this->response('Invalid registration request', 'json', 400);

		// basic check referer matches the site
		if (strpos(RARS_BASE_URL, $_SERVER["HTTP_REFERER"]) !== 0) $this->response('Invalid registration request', 'json', 400);

		// check data
		if (!isset($data["name"], $data["email"], $data["password"])) $this->response('Invalid registration request', 'json', 400);
		if (empty($data["name"]) || empty($data["email"]) || empty($data["password"])) $this->response('Invalid registration request', 'json', 400);
		if (!isset($data["human"]) || !empty($data["human"])) $this->response("Only humans can register", "json", 406);

		// check if already banned
		if (RARS_SYSTEM_BAN > 0)
		{
			// find banned rows
			$banned = $this->rars_db->get_first('banned', '*', array('ip_address' => $_SERVER["REMOTE_ADDR"], 'user_agent' => $_SERVER["HTTP_USER_AGENT"]));
			if (!empty($banned)) $this->response('Registration failed flood limit: ip banned', 'json', 401);
		}

		// ban/lock user if too many registrations from same fingerprint
		$regs = $this->rars_db->get_all('user', '*', array('ip_address' => $_SERVER["REMOTE_ADDR"]));
		$ban = 0;
		$lock = 0;
		foreach ($regs as $reg)
		{
			if (!$reg['active'] && strtotime($reg['created']) > time() - 3600) $ban++;
			if (!$reg['active'] && strtotime($reg['created']) > time() - 60) $lock++;
		}
		if (RARS_SYSTEM_BAN !== 0 && $ban >= RARS_SYSTEM_BAN)
		{
			$this->rars_db->add_data('banned', array('ip_address' => $_SERVER["REMOTE_ADDR"], 'user_agent' => $_SERVER["HTTP_USER_AGENT"], 'created' => date('Y-m-d H:i:s', time())));
			$this->response('Registration failed flood limit: ip banned', 'json', 401);
		}
		if (RARS_SYSTEM_FLOOD !== 0 && $lock >= RARS_SYSTEM_FLOOD)
		{
			$this->response('Registration failed flood limit: ip locked out for 1 min', 'json', 401);
		}

		// now we know registrations allowed, form came from website etc so lets check email unique and proceed with adding user

		// check email is unique
		$user = $this->rars_db->get_first('user', '*', array('email_address' => $data['email']));

 		// do we build activation links
        $password = $this->create_hash($data["password"]);
		$activate_link = "";
		if (RARS_SYSTEM_REGISTRATION_ACTIVATION)
		{
			$activate_token = sha1($_SERVER["HTTP_USER_AGENT"].$_SERVER["REMOTE_ADDR"].$password);
			$row["activate_token"] = $activate_token;
			$activate_link = RARS_BASE_URL."rars/user/register/{$activate_token}";
		}

		// choose to add new user or update activate link and resend emails
		if (!empty($user))
		{
			// do we allow activation reset
			if ($user['name'] == $data['name'] && $user['email_address'] == $data['email'] && !$user['active'])
			{
				// update activation token
				if (RARS_SYSTEM_REGISTRATION_ACTIVATION)
				{
					// rebuild activation token
					$activate_token = sha1($_SERVER["HTTP_USER_AGENT"].$_SERVER["REMOTE_ADDR"].$user['password']);
					$activate_link = RARS_BASE_URL."user/register/{$activate_token}";
					$data['email'] = $user['email_address']; // ensure we only email the user set in the system, this should be ok, but belt and braces

					$this->rars_db->edit_data('user', array(
						'created' => date('Y-m-d H:i:s', time()),
						'activate_token' => $activate_token
					), array('id' => $user['id']));
				}
			}
			else $this->response('Email already registered', 'json', 409);
		}
		else
		{
			// create new user
			$row = array(
				"name" => $data["name"],
				"email_address" => $data["email"],
				"access_level" => 1,
				"active" => 0,
				"password" => $this->create_hash($data["password"]),
				"ip_address" => $_SERVER["REMOTE_ADDR"],
				"created" => date('Y-m-d H:i:s', time())
			);

			// update activation token
			if (RARS_SYSTEM_REGISTRATION_ACTIVATION) $row['activate_token'] = $activate_token;

		 	$this->rars_db->add_data('user', $row);
		}

		// email text replacement
		$search = array(
			"**server_name**",
			"**user_email**",
			"**activation_link**"
		);

		$replace = array(
			$_SERVER["SERVER_NAME"],
			$data["email"],
			$activate_link
		);

		if (!RARS_SYSTEM_REGISTRATION_ACTIVATION)
		{
			// send notifcation of registration and activation is manual to user
			$message1 = str_replace($search, $replace, RARS_SYSTEM_EMAIL_REGISTRATION);
			$result_1 = $this->email($data["email"], $data["name"], "{$_SERVER["SERVER_NAME"]} Account Registered", $message1);

			// send notifcation to super admin email that someone has registered and needs activation
			$message2 = str_replace($search, $replace, RARS_SYSTEM_EMAIL_MANUAL_ACTIVATE);
			$result_2 = $this->email(RARS_SYSTEM_EMAIL_ADDRESS, RARS_SYSTEM_EMAIL_ADDRESS_NAME, "{$_SERVER["SERVER_NAME"]} Account Registered", $message2);

			if (!$result_1 || !$result_2) throw new Exception('Could not send email, please contact administrator');
			$this->response("Someone will activate your account shortly", "json");
		}
		else
		{
			$message3 = str_replace($search, $replace, RARS_SYSTEM_EMAIL_EMAIL_ACTIVATE);
			$result = $this->email($data["email"], $data["name"], "{$_SERVER["SERVER_NAME"]} Account Activation", $message3);
			if (!$result) throw new Exception('Could not send email, please contact administrator');
			$this->response("Please check your email to activate account", "json");
		}
	}
}
