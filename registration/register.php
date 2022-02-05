
<?php
    
    /**
     Processes registration request for a new user
     
     @param data Encrypted parameter(s):
        @param password User password
        @param email User email address
        @param username Username
        @param fullname User fullname
        @param referralcode Referral code ('NA' when not avalaible)
        @param language User language (eg. 1 for English, 2 for French)
        @param source Request source (eg. 'IO' for iOS, 'AN' for Android)
        @param deviceid User device ID
     @return json encoded response array
     
     @discussion
     This script assumes database used is MS SQL Server.
     This script assumes a stored procedure for creating user records.
     This script assumes an encrypted payload.
     The response array contains an "error" value which is the error description, if any.
     The response array contains a "success" value which is:
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
		$putData = '';
        $putfp = fopen('php://input', 'r');
		while($data = fread($putfp, 1024))
	    $putData .= $data;
		fclose($putfp);
		
        // Check for a complete request
       	if(strpos($putData, 'data=') === false)
        	$operation->markRequestInputError(1);
        else if(strpos($putData, 'data=') !== false)
        {
        	$firstName = '';
        	$lastName = '';
			$email = '';
            $password = '';
			$username = '';
            $mobile = '';
            $source = '';
            $language = '';
				
            
            
            $putDataArray = explode('data=', urldecode($putData));
			
			// Decrypt received data
            $plainTextData = decrypt($putDataArray[1], $secret, $IV);
             
            // Check whether all values received            
            if (strpos($plainTextData, "fullname") === false || strpos($plainTextData, "email") === false || strpos($plainTextData, "password") === false)
            	$operation->markRequestInputError(2);
            else if (strpos($plainTextData, "username") === false) 
            	$operation->markRequestInputError(2);
            else if (strpos($plainTextData, "source") === false || strpos($plainTextData, "language") === false || strpos($plainTextData, "deviceid") === false) 
            	$operation->markRequestInputError(2);
            else if (strpos($plainTextData, "referralcode") === false) 
            	$operation->markRequestInputError(2);
            else
            {
                $keyValuePairs = json_decode($plainTextData);
                
                $fullName = $keyValuePairs->{"fullname"};
                $email = $keyValuePairs->{"email"};
                $password = $keyValuePairs->{"password"};
                $username = $keyValuePairs->{"username"};
                $referralCode = $keyValuePairs->{"referralcode"}; 
                $source = $keyValuePairs->{"source"};
                $language = $keyValuePairs->{"language"};
                $deviceID = $keyValuePairs->{"deviceid"};
				
               	// Input validation
               	if(strlen($fullName) < 5 || strpos($fullName, " ") === false)
               		$operation->markParameterError('fullname');
               	else if(!filter_var($email, FILTER_VALIDATE_EMAIL))
               		$operation->markParameterError('email');
                else if(strcmp($referralCode, "NA") != 0 && strlen($referralCode) < 6) 
                	$operation->markParameterError('referralcode');
                else if(!filter_var($language, FILTER_VALIDATE_INT))
                	$operation->markParameterError('language');
                else if(is_valid_language($language) === false)
                	$operation->markParameterError('language');
                else if((strcmp($source, "IO") != 0) && (strcmp($source, "AN") != 0))
                	$operation->markParameterError('source');
                else if((strcmp($source, "IO") == 0) && (strlen($deviceID) != 36))
                	$operation->markParameterError('deviceid');
                else if((strcmp($source, "AN") == 0) && ((strlen($deviceID) < 10) || (strlen($deviceID) > 20)))
                	$operation->markParameterError('deviceid');
            }
        }
    }
                
    if(!$operation->isError)
    {
    	// Check if referral code is valid
       	// Skip this check if not needed
    	if(strcmp($referralCode, "NA") != 0)
    	{
    		try
       	    {
       	    	// Open DB connection
            	$conn = new PDO( "sqlsrv:server=$server ; Database=$dbName", "$dbUsername", "$dbPassword");
            	$conn->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
        	}
        	catch(Exception $e)
        	{
            	$operation->markException($e);
        	}
        	
        	if(!$operation->isError)
    		{
    			try
       	    	{
       	    	
		        	$sqlGetReferrerID = "SELECT userid FROM users_t WHERE referralcode = :referralcode";
                	$stmtGetReferrerID = $conn->prepare($sqlGetReferrerID);
	                $stmtGetReferrerID->bindParam(':referralcode', $referralCode);
	                
	                if($stmtGetReferrerID->execute() === false)
                		$operation->markDBError();
               		else
					{
						$referrerID = 0;
					
						while($rowGetReferrerID = $stmtGetReferrerID->fetch())
						{
                        	$referrerID = $rowGetReferrerID["userid"];
							break;
						}
						
						if($referrerID == 0)
						{
							$operation->markParameterError('referralcode');
						}
					}
    			}
	        	catch(Exception $e)
	   			{
           			$operation->markException($e);
    			}
    		}		
        	
    	}
    	else
    	{
    	 	$referrerID = ''; // no referrer
    	} 
    }
    
    if(!$operation->isError)
    {
        sqlsrv_configure("WarningsReturnAsErrors", 0);
        
      	// Open DB connection
        $connectionInfo = array( "Database"=>$dbName, "UID"=>$dbUsername, "PWD"=>$dbPassword, "CharacterSet"=>"UTF-8");
        $conn = sqlsrv_connect( $server, $connectionInfo);
        
        if( $conn === false)
        	$operation->markDBError();
        else
        {
            // Specify the procedure params - MUST be a variable that can be passed by reference!
            $fullNameComponents = explode(" ", $fullName, 2);
            $myparams['firstname'] = $fullNameComponents[0];
            $myparams['lastname'] = $fullNameComponents[1];
            $myparams['email'] = $email;
            $myparams['password'] = $password;
            $myparams['username'] = $username;
            $myparams['userid'] = intval(0);
            $myparams['mobile'] = 0;
            $myparams['devicetype'] = $source;
            $myparams['deviceid'] = $deviceID;
            $myparams['language'] = intval($language);
            
            if(strcmp($referralCode, "NA") == 0)
	            $myparams['referredby'] = '';
	        else 
	        	$myparams['referredby'] = $referrerID;
            
                                
            $procedure_params = array(
                                      array(&$myparams['firstname'], SQLSRV_PARAM_IN),
                                      array(&$myparams['lastname'], SQLSRV_PARAM_IN),
                                      array(&$myparams['email'], SQLSRV_PARAM_IN),
                                      array(&$myparams['username'], SQLSRV_PARAM_IN),
                                      array(&$myparams['password'], SQLSRV_PARAM_IN),
                                      array(&$myparams['userid'], SQLSRV_PARAM_OUT), // User ID assumed to be generated by the procedure
                                      array(&$myparams['mobile'], SQLSRV_PARAM_IN),
                                      array(&$myparams['devicetype'], SQLSRV_PARAM_IN),
                                      array(&$myparams['deviceid'], SQLSRV_PARAM_IN),
                                      array(&$myparams['language'], SQLSRV_PARAM_IN),
                                      array(&$myparams['referredby'], SQLSRV_PARAM_IN)
                                      );
            
            // EXEC the procedure, {call sp_name (@var1 = ?, @var2 = ?)} seems to fail with various errors in my experiments
            $sql = "EXEC YOUR_PROCERDURE @firstname = ?, @lastname = ?, @email = ?, @password = ?, @userid = ?, @username = ?, @mobile = ?, @devicetype = ?, @deviceid = ?, @language = ?, @referredby = ?";
            
            $stmt = sqlsrv_prepare($conn, $sql, $procedure_params);
            
            if( $stmt === false )
            {
            	$operation->markDBError();
            	$operation->response["details"]= sqlsrv_errors();
            }
            else
            {
               $operation->setSuccessful();

               try{
                    
                    $res = sqlsrv_execute($stmt);
                    
                    
                    if($res === false)
                    {
                    	$operation->markDBError();
                    }
                    else
                    {
                        while($res = sqlsrv_next_result($stmt))
                        {
                            // make sure all result sets are stepped through, since the output params may not be set until this happens
                        }
                        
                        $operation->setSuccessful();
                        $operation->response["userid"] = $myparams['userid'];
                            
                        // At this point, a user record is succesfully created  
                        // You can now fire any verification emails/SMS OTPs here
                        
                        //Uncomment the following if you wish to create a login session for the user as well
                        //See users/login.php
                        /*if(!$operation->isError)
                        {
                        	$loginResult = YOUR_LOGIN_FUNCTION($username, $password, $language, $deviceID, $source);								
							$loginDetails = json_decode($loginResult);
							
							if(!property_exists($loginDetails, "success"))
							{
								$operation->response["success"] = -1;
			                    $operation->response["error"] = "Server error at login  ". $loginResult;
							}
							else if(intval($loginDetails->success) !== 1)
							{
								$operation->response["success"] = $loginDetails->success;
			                	$operation->response["error"] = $loginDetails->error;
							}
							else
							{
								$operation->response = $loginDetails;
							}
                        }*/
                            
                            
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
    echo json_encode($operation->response);
    
    
    //Done! :)
?>
