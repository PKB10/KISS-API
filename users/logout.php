
<?php
    /**
     Processes logout request for a user

     @param data Encrypted parameter(s):
        @param userid User email address
        @param token Token
		@param sessionid Session ID 
		@param source Request source (eg. "IO" for iOS, "AN" for Andorid)
     @return json encoded response array
     
     @discussion
     This script assumes database used is MS SQL Server.
     This script assumes a stored procedure for logout/session termination exists.
     This script assumes an encrypted payload
     The response array contains an "error" value which is the error description, if any.
     The response array contains a "success" value which is:
	 -5 for session/token errors
	 -4 for security protocol breaches
	 -3 for SQL errors
     -2 for missing parameter(s)
     -1 for invalid parameter(s) and other errors
     0 initially
     1 for success
     
     @author Priyanka
     */
    
	require(basename(dirname(__FILE__)). '/sensitive/credentials.php'); // Include functions for sensitive data (eg. any keys)
    require(basename(dirname(__FILE__)). '/sensitive/b_crypt.php'); // Include functions for encryption/decryption operations
    require(basename(dirname(__FILE__)). '/general/string_functions.php'); // Include functions for string operations
	require(basename(dirname(__FILE__)). '/general/token_data.php'); // Include token class
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
            if (strpos($plainTextData, "userid") === false || strpos($plainTextData, "sessionid") === false || strpos($plainTextData, "token") === false || strpos($plainTextData, "source") === false)
            	$operation->markRequestInputError(2);
            else
            {
	            $keyValuePairs = json_decode($plainTextData);
	            
				$userID = $keyValuePairs->{"userid"};
	            $token = $keyValuePairs->{"token"};
				$sessionID = $keyValuePairs->{"sessionid"};
	            $source = $keyValuePairs->{"source"};
               	
               	// Input validation
               	if(!filter_var($userID, FILTER_VALIDATE_INT))
               		$operation->markParameterError('userid');
                else if(!filter_var($sessionID, FILTER_VALIDATE_INT))
                	$operation->markParameterError('sessionid');
                else if((strcmp($source, "IO") != 0) && (strcmp($source, "AN") != 0))
                	$operation->markParameterError('source');
            }
        }
    }
    
    if(!$operation->isError)
    {
    	// Check if session is active and valid
        if(valid_login_token($userID, $token, $sessionID, $source) === false)
			$operation->markSessionError();
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
            $myparams['sessionid'] = $sessionID;
	        $myparams['userid'] = $userID;
	        //$myparams['param3'] = $VALUE; //uncomment to add more parameters
			//$myparams['param4'] = $VALUE;
			//$myparams['paramN'] = $VALUE; 
	        
            // Set up the procedure params array - be sure to pass the param by reference
            $procedure_params = array(
                                      array(&$myparams['sessionid'], SQLSRV_PARAM_IN),
                                      array(&$myparams['userid'], SQLSRV_PARAM_IN)
//                                      array(&$myparams['param3'], SQLSRV_PARAM_IN),
//                                      array(&$myparams['param4'], SQLSRV_PARAM_IN),
//                                      array(&$myparams['paramN'], SQLSRV_PARAM_OUT)
                                      );
            
            
            // EXEC the procedure, {call sp_name (@var1 = ?, @var2 = ?)} seems to fail with various errors in my experiments
            $sql = "EXEC YOUR_PROCERDURE @sessionid = ?, @userid = ?";
            
            $stmt = sqlsrv_prepare($conn, $sql, $procedure_params);
            
            
            if( $stmt === false )
            	$operation->markDBError();
            else
            {
                try{
                    
                    $res = sqlsrv_execute($stmt);
                    
                    // Exit if procedure fails
                    if($res === false)
                    	$operation->markDBError();
                    else
                    {
						$operation->setSuccessful();
						
                        while($res = sqlsrv_next_result($stmt))
                        {
                            // make sure all result sets are stepped through, since the output params may not be set until this happens
                        }
                        
                        // Close the connection
                        sqlsrv_close($conn);
                                
                    	if(!$operation->isError)
                        {
                            try
                        	{
                        		// Deactivate session token and mark it as terminated
                        		$deactivatedTokensCount = YOUR_DEACTIVATION_FUNCTION($userID, $token);
                        	}
	                        catch(Exception $e)
    	                    {
        	                	$operation->markException($e);
        	                	
        	                	log_error($conn, $e, __FILE__);
            	            }                
                        
						}
                        
                    }
                    
                }
                catch(Exception $e)
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

    
?>
