<?php
/**
 * UWUM Login based on Joomline SLogin
 *
 * @version     0.1
 * @author      Ioannis Tsampoulatidis, Infalia
 * @license     GNU/GPL v.3 or later.
 */

// No direct access
defined('_JEXEC') or die;

class plgSlogin_authUwum extends JPlugin
{
	public function onSloginAuth()
	{
		if($this->params->get('allow_remote_check', 1))
		{
			$remotelUrl = JURI::getInstance($_SERVER['HTTP_REFERER'])->toString(array('host'));
			$localUrl = JURI::getInstance()->toString(array('host'));
			if($remotelUrl != $localUrl){
				die('Remote authorization not allowed');
			}
		}

		$redirect = JURI::base().'?option=com_slogin&task=check&plugin=uwum';

		$params = array(
			'client_id=' . $this->params->get('id'),
			'redirect_uri=' . urlencode($redirect),
			'response_type=code',
			'scope=identification notify_email_detached',
			'state=' . hash('sha256', microtime(TRUE).rand().$_SERVER['REMOTE_ADDR'])
		);
		$params = implode('&', $params);
		$url = 'https://wegovnow.liquidfeedback.com/api/1/authorization?'.$params;
		return $url;
	}

	public function onSloginCheck()
	{
		$input = JFactory::getApplication()->input;
		$error = $input->getString('error', '');
		if($error == 'access_denied'){
			die('ERROR: access_denied.');
		}

		$code = $input->getString('code', '');
		$state = $input->getString('state', '');
		$returnRequest = new SloginRequest();

		if ($code) 
		{
			if (!function_exists('curl_init')) 
			{
				die('ERROR: CURL library not found!');
			}

			// get access_token
			$redirect = JURI::base().'?option=com_slogin&task=check&plugin=uwum';

			$params = array(
				'client_id' => $this->params->get('id'),
				'redirect_uri' => $redirect,
				'client_secret' => $this->params->get('password'),
				'code' => $code, // The code from the previous request
				'grant_type' => 'authorization_code',
				'state' => $state // The state from the previous request
			);

			//also use the signed pem by UWUM Authority
			$curl = curl_init( "https://wegovnow-cert.liquidfeedback.com/api/1/token" );
			curl_setopt($curl, CURLOPT_POST, 1);
			curl_setopt($curl, CURLOPT_POSTFIELDS, $params);
			curl_setopt($curl, CURLOPT_HEADER, 0);
			curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
			curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, FALSE);
			curl_setopt($curl, CURLOPT_SSLCERTTYPE, 'PEM'); 
			curl_setopt($curl, CURLOPT_SSLCERT, $this->params->get('cert'));
		
			$auth = curl_exec( $curl );
			curl_close($curl);

			$secret = json_decode($auth);

			if(empty($secret)){
				echo 'WGN Error - empty access token';
				exit;
			}
			if(!empty($secret->error)){
				echo 'WGN Error - '. $secret->error_description;
				exit;
			}

			$access_key = $secret->access_token;

			$app =JFactory::getApplication();
			$app->setUserState( 'uwum_access_token', $access_key );


			$params_info = array(
				'include_member' => 1
			);	    

			$curl = curl_init( "https://wegovnow.liquidfeedback.com/api/1/info" );
			curl_setopt( $curl, CURLOPT_HTTPHEADER, array( 'Authorization: Bearer ' . $access_key ) );
			curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
			curl_setopt($curl, CURLOPT_POSTFIELDS, $params_info);
			curl_setopt($curl, CURLOPT_SSLCERT, $this->params->get('cert'));
	
			curl_exec( $curl );
			$request = curl_exec($curl);
			curl_close($curl);
			$request = json_decode($request);

			if(empty($request)){
				echo 'Error - empty user data';
				exit;
			}
			if(!empty($request->error)){
				echo 'Error - '. $request->error_description;
				exit;
			}

			$returnRequest->id              = $request->member->id;
			$returnRequest->display_name    = $request->member->name;
			$returnRequest->first_name      = $request->member->name;

			//we also need the email
			$curl = curl_init( "https://wegovnow.liquidfeedback.com/api/1/notify_email" );
			curl_setopt( $curl, CURLOPT_HTTPHEADER, array( 'Authorization: Bearer ' . $access_key ) );
			curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
			curl_setopt($curl, CURLOPT_POSTFIELDS, $params_info);
			curl_setopt($curl, CURLOPT_SSLCERT, $this->params->get('cert'));

			curl_exec( $curl );
			$request = curl_exec($curl);
			curl_close($curl);
			$request = json_decode($request);

			if(empty($request)){
				echo 'Error - empty user data';
				exit;
			}
			if(!empty($request->error)){
				echo 'Error - '. $request->error_description;
				exit;
			}

			$returnRequest->email           = $request->result->notify_email;
			$returnRequest->all_request     = $request-result;
			return $returnRequest;
		}
		else
		{
			echo 'Error - empty code';
			exit;
		}
	}

	public function onCreateSloginLink(&$links, $add = '')
	{
		$i = count($links);
		$links[$i]['link'] = 'index.php?option=com_slogin&task=auth&plugin=uwum' . $add;
		$links[$i]['class'] = 'uwumlogin';
		$links[$i]['plugin_name'] = 'uwum';
		$links[$i]['plugin_title'] = 'WeGovNow UWUM';
	}
}