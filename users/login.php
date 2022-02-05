
<?php
    /**
     Processes login request for a user

     @param data Encrypted parameter(s):
        @param email User email address
        @param password User password
        @param language User language 
		@param deviceid Request device ID
        @param source Request source (eg. 'IO' for iOS, 'AN' for Android))
     @return json encoded response array
     
     @discussion
     This script assumes database used is MS SQL Server.
     This script assumes a stored procedure for login access exists.
     This script assumes an encrypted payload.
     The response array contains an "error" value which is the error description, if any.
     The response array contains a "success" value which is:
	 -4 for session/token errors
     -3 for SQL errors
     -2 for missing parameter(s)
     -1 for invalid parameter(s) and other errors
     0 initially
     1 for success
     
     @author Priyanka Bhatia
     */
    
	require(basename(dirname(__FILE__)). '/sensitive/credentials.php'); // Include functions for sensitive data (eg. any keys)
    require(basename(dirname(__FILE__)). '/sensitive/b_crypt.php'); // Include functions for encryption/decryption operations
    require(basename(dirname(__FILE__)). '/general/string_functions.php'); // Include functions for string operations
    require(basename(dirname(__FILE__)). '/general/operation_data.php'); // Include functions for request operations
    require(basename(dirname(__FILE__)). '/general/log_error.php'); // Include functions for logging request errors

    
    ini_set('default_charset','utf-8');

	// Create a new request operation
	$operation = new Operation();
    
    // Get server details and other sensitive values 
    // Add or remove as per your requirements
    $server = getServer();
    if($server)
    {
        $dbName = getDB();
        if($dbName)
        {
            $dbUsername = getDBUsername();
            if($dbUsername)
            {
                $dbPassword = getDBPassword();
                if($dbPassword)
                {
                    $IV = getIV();
                    if($IV)
                    {
                        $secret = getSecret();
                        if($secret)
                        {
                        	$authKey = getAuthKey();
                        	if($authKey)
                        	{}
                        	else
                        		$operation->markInformationFileError();
                        }
                        else
                        	$operation->markInformationFileError();
                    }
                    else
                    	$operation->markInformationFileError();
                }
                else
                	$operation->markInformationFileError();
            }
            else
            	$operation->markInformationFileError();
        }
        else
        	$operation->markInformationFileError();
    }
    else
    	$operation->markInformationFileError();


   // Request type check
   // Ideally, you should send the correct status code here (405) and in other places where markRequestError() is called
   if($_SERVER['REQUEST_METHOD'] !== 'POST')
		$operation->markRequestError(); 
		
   if(!$operation->isError)
    {
    	if(!isset($_SERVER['HTTP_AUTH_USER']) || !isset($_SERVER['HTTP_AUTH_PASSWORD']))
    		$operation->markRequestError();// Simple auth/password check
		else
		{
			$requestTimestamp = decrypt($_SERVER['HTTP_AUTH_USER'], $secret, $IV);
			$timeDifference = time() - $requestTimestamp;
			if($timeDifference > (5 * 60) || $timeDifference < (-5 * 60))
				$operation->markRequestError();// Simple request time check for security
			else
			{
				// Use auth key to create checksum
				$checksum = "CREATE CHECKSUM HERE";
				
				if(strcmp($checksum, base64_decode($_SERVER['HTTP_AUTH_PASSWORD'])) != 0)
					$operation->markRequestError(); // Simple request password check
			}
			
		}
    }
    
    
    if(!$operation->isError)
    {
    
        // Check for a complete request
        if(!isset($_POST["data"]))
        	$operation->markRequestInputError(1);
        else
        {
            // Decrypt received data
            $plainTextData = decrypt($_POST["data"], $secret, $IV);
            
            // Check whether all values received
            if (strpos($plainTextData, "username") === false || strpos($plainTextData, "password") === false || strpos($plainTextData, "deviceid") === false || strpos($plainTextData, "language") === false || strpos($plainTextData, "source") === false)
            	$operation->markRequestInputError(2); 
            else
            {
	            $keyValuePairs = json_decode($plainTextData);
	            
	            $username = $keyValuePairs->{"username"};
	            $password = $keyValuePairs->{"password"};
	            $language = $keyValuePairs->{"language"};
	            $deviceID = $keyValuePairs->{"deviceid"};
				$source = $keyValuePairs->{"source"};
               	
               	// Input validation
               	if(!filter_var($language, FILTER_VALIDATE_INT))
                	$operation->markParamaterError('language');
                else if(is_valid_language($language) === false)
                	$operation->markParamaterError('language');
                else if((strcmp($source, "IO") != 0) && (strcmp($source, "AN") != 0))
                	$operation->markParamaterError('source');
            }
        }
    }

    
    if(!$operation->isError)
    {
    	// Open DB connection
        $connectionInfo = array( "Database"=>$dbName, "UID"=>$dbUsername, "PWD"=>$dbPassword, "CharacterSet" => "UTF-8");
        $conn = sqlsrv_connect($server, $connectionInfo);
        
        
        if( $conn === false)
        	$operation->markDBError();
        else
        {
            // Specify the procedure params - MUST be a variable that can be passed by reference!
            $myparams['username'] = $username;
            $myparams['password'] = $password;
			//$myparams['param3'] = $VALUE; //uncomment to add more parameters
			//$myparams['param4'] = $VALUE;
			//$myparams['paramN'] = $VALUE; 
            
            
            // Set up the procedure params array - be sure to pass the param by reference
            $procedure_params = array(
                                      array(&$myparams['username'], SQLSRV_PARAM_IN),
                                      array(&$myparams['password'], SQLSRV_PARAM_IN)
//                                      array(&$myparams['param3'], SQLSRV_PARAM_IN),
//                                      array(&$myparams['param4'], SQLSRV_PARAM_IN),
//                                      array(&$myparams['paramN'], SQLSRV_PARAM_OUT)
                                      );
            
            
            // EXEC the procedure, {call sp_name (@var1 = ?, @var2 = ?)} seems to fail with various errors in my experiments
            $sql = "EXEC YOUR_PROCERDURE @username = ?, @password = ?, @invalid_user = ?, @invalid_password = ?, @userid = ?";
            
            $stmt = sqlsrv_prepare($conn, $sql, $procedure_params);
            
            
            if( $stmt === false )
            	$operation->markDBError();
            else
            {
                try{
                    
                    $res = sqlsrv_execute($stmt);
                    
                    if($res === false)
                    	$operation->markDBError();
                    else
                    {
                        while($res = sqlsrv_next_result($stmt))
                        {
                            // make sure all result sets are stepped through, since the output params may not be set until this happens
                        }
                        
                        // Fetch procedure result
                        $username = $myparams['username'];
                        $userID = $myparams['userid'];
                        $invalidUser = $myparams['invalid_user'];
                        $invalidPassword = $myparams['invalid_password'];
                        
                        // Close the connection
                        sqlsrv_close($conn);
                        
                        // Continue only if account is active
                        // Continue only if credentials are correct and country of residence is valid
                        // You can add more checks here
                        if ($userID != 0)
                    	{
                    		// Create a login message
                            $operation->response["loginmessage"] = "NA";
														
							// Check for other active tokens and deactivate them
							// Remove these checks to allow login sessions on multiple devices for a single user						
							$otherActiveDevices = YOUR_ACTIVE_DEVICES_CHECK_FUNCTION($user["id"], $deviceID);
							$deactivatedTokensCount = YOUR_DEACTIVATION_FUNCTION($user["id"]);
															
							if($deactivatedTokensCount === false)
								$operation->markSessionError();
							else
                            {
                            	// Create a new session token
                                $token = YOUR_SESSION_FUNCTION($user["id"], $source, false, $deviceID);
															
								if($token === false)
									$operation->markSessionError();
								else
								{
										$user["token"] = $token->value;
										$user["tokenexpiry"] = "";//$token->expiryDate;
										$operation->response["user"] = $user;
	                        	        $operation->setSuccessful();
	                        	                     
	                        	        // Remove this check to allow login sessions on multiple devices for a single user                           
	                        	        if($otherActiveDevices == true)
	                        	        {
	                        	        	$operation->response["loginmessage"] = "You can only login with one device at a time. Please note that if you were logged in on any other devices, all sessions on those devices have been terminated.";
	                	        	    }
	                        	}
                             }
                        }
                        else
                        {
                        	// Either user or password is incorrect
                            if ($invalidUser == 1 || ($invalidPassword == 1))
                            {
                                $operation->response["success"] = -1;
                                $operation->response["error"] = "Invalid credentials";
                            }
                        }
                        
                        
                    }
                    
                }catch(Exception $e)
                {
                    $operation->markException($e);
                    
                    log_error($conn, $e, __FILE__);
                }

            }
            
            
        }
        
    }

	// Set content type
    header('Content-Type: application/json; charset=utf-8');
    
    // Send JSON response
    echo json_encode(($operation->response));

    //Done! :)
?>
