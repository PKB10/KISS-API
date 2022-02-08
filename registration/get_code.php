<?php
    
    /**
     Processes account verification code generation request for a user
     Calls the corresponding SMS service
     
     @param data Encrypted parameter(s):
        @param userid User ID
        @param source Request source (eg. 'IO' for iOS, 'AN' for Android)
     @return json encoded response array
     
     @discussion
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
        
        // Check for a complete request
        if(!isset($_POST["data"]))
        	$operation->markRequestInputError(1);
        else
        {
            // Decrypt received data
            $plainTextData = decrypt($_POST["data"], $secret, $IV);
            
            // Check whether all values received         
            if (strpos($plainTextData, "userid") === false || strpos($plainTextData, "source") === false || strpos($plainTextData, "language") === false)
            	$operation->markRequestInputError(2);
            else
            {
                $keyValuePairs = json_decode($plainTextData);
                
                $userID = $keyValuePairs->{"userid"};
                $source = $keyValuePairs->{"source"};
                $language = $keyValuePairs->{"language"};
               	
               	// Input validation
               	if(!filter_var($userID, FILTER_VALIDATE_INT))
	               	$operation->markParameterError('userid');
                else if((strcmp($source, "IO") != 0) && (strcmp($source, "AN") != 0))
                	$operation->markParameterError('source');
                else if(!filter_var($language, FILTER_VALIDATE_INT))
            		$operation->markParameterError('language');
	        	else if(!is_valid_language($language))
    		        $operation->markParameterError('language');
                	
            }
        }
    }


    if(!$operation->isError)
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
            	// Create two flags to mark non-existent user and already verified user scenarios
                $userIDExists = false;
                $userAlreadyVerified = false;
                
                // Search for userid and verification status 
                $sql = "SELECT email_verification_status FROM users_t WHERE userid = :userid and deleted != 1";
                $stmt = $conn->prepare($sql);
                $stmt->bindParam(':userid', $userID);
                
                if($stmt->execute() === false)
                	$operation->markDBError();
                else
                {
                	// Loop through results
                	// Ideally, you will only need the first row
                	// I am looping just in case there are any corrupted records (eg. in a test DB)
                    while ($rowEmail = $stmt->fetch())
                    {
                    	if(!is_null($rowEmail["email_verification_status"]))//Just in case column allows null values
                    	{
                    		if($rowEmail["email_verification_status"] == true)
                    		{
                    			// User is already verified
                    			// Set corresponding flag to true 
                    			$userAlreadyVerified = true;
                    			break;
                    		}
                    	}
                    	
                    	// User ID found
                    	// Set corresponding flag to true 
                        $userIDExists = true;
                    }
                    
                    
                    // Continue only if a matching user ID exists
                    if($userIDExists !== false)
                    {
                        $operation->setSuccessful();
                        
						$result = YOUR_SMS_API_FUNCTION($userID, $source, $language);// Change parameters as per your function
						
                        if($result === false)
    	                {
        	            	$operation->response["success"] = -1;
                            $operation->response["error"] = "Server error";//"Server error = " . curl_error($ch);
            	        }
                        else
                        {
                        	//You can add more checks based on SMS API responses before marking the request as succesful
                            $operation->setSuccessful(); 
                        }
                        
                    }
                    else if($userAlreadyVerified == true)
                    {
                    	$operation->response["success"] = -1;
                        $operation->response["error"] = "Application error";
                    }
                    else
                    {	// Send a false positive response for invalid user IDs
                    	// This is recommended to increase security in case of a suspicious request
                    	// You can change this as per your system setup
                        $operation->setSuccessful();
                    }
                }
                
            }
            catch(Exception $e)
            {
                $operation->markException($e);
				
				e_log($conn, $e, __FILE__);
            }
        }
    }
    
   
    // Set content type
    header('Content-Type: application/json; charset=utf-8');
    
    // Send JSON response
    echo json_encode($operation->response);
    
    
    //Done! :)
?>
