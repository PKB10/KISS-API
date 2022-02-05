<?php
    /**
     Processes username and email uniqueness validation request for a new user
     
     @param data Encrypted parameter(s):
		@param username Username
     	@param email User email address
     @return json encoded response array
     
     @discussion
     This script assumes database used is MS SQL Server.
     This script assumes username and/or email must be unique.
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
    
    // Request type check
    // Ideally, you should send the correct status code here (405) and in other places where markRequestError() is called
    if($_SERVER['REQUEST_METHOD'] !== 'POST')
		$operation->markRequestError(); 
		
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
            if (strpos($plainTextData, "username") === false || strpos($plainTextData, "email") === false)
            	$operation->markRequestInputError(2);
            else
            {
                $keyValuePairs = json_decode($plainTextData);
                
                $username = $keyValuePairs->{"username"};
                $email = $keyValuePairs->{"email"};
                
                // Input validation
               	if(!filter_var($email, FILTER_VALIDATE_EMAIL) && strcmp($email, "NA") !== 0)
               		$operation->markParameterError('email');
                
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
                // Set up flags and count holders
                $isDuplicateUsername = false;
                $isDuplicateEmail = false;
                $usernameCount = 0;
                $emailCount = 0;
                                
                // Check for duplicate username
                // Count all profiles with this username 
                // Do not include accounts markes as deleted
                $sqlGetUsernameCount = "select count(*) as duplicateusernames from users_t where username = :username AND deleted != 1";
                $stmtGetUsernameCount = $conn->prepare($sqlGetUsernameCount);
                $stmtGetUsernameCount->bindParam(':username', $username);
                
                
                if($stmtGetUsernameCount->execute() === false)
                	$operation->markDBError();
                else 
                {
	                if(strcmp($username, "NA") != 0)
                	{
                		while($rowgetcount = $stmtGetUsernameCount->fetch())
                    	{
                    		if($rowgetcount["duplicateusernames"] > 0)
	                        	$usernameCount++;
	                    }
                	}
                    
                	
                
                    if($usernameCount >= 1)
                        $isDuplicateUsername = true;
                    else
                    {
                    	// No duplicate username match
                    	// Check for duplicate email
	        		    // Count all profiles with this email address
    	            	$sqlGetEmailCount = "select count(*) as duplicateemails from users_t where email = :email AND deleted != 1";
			            $stmtGetEmailCount = $conn->prepare($sqlGetEmailCount);
        		        $stmtGetEmailCount->bindParam(':email', $email);
                
                
            			if($stmtGetEmailCount->execute() === false)
	            	    	$operation->markDBError();
    		        	else
                		{
                			if(strcmp($email, "NA") != 0)
                			{
            					while($rowgetcount = $stmtGetEmailCount->fetch())
        	            		{
            		    			if($rowgetcount["duplicateemails"] > 0)
                    	   				$emailCount++;
		                    	}
                			}
		                    
                    
		                	if($emailCount >= 1)
        		            	$isDuplicateEmail = true;
        		        }
        		            
                    
                    }
                    
                    // Proceed only if there was no DB error 
                    if($operation->response["success"] != -3)
                    {
                        if(($isDuplicateUsername || $isDuplicateEmail))
                        {
                            $operation->response["success"] = -1;
                            
                            if($isDuplicateUsername)
                                $operation->response["error"] = "Username already in user.";
                            else if($isDuplicateEmail)
                                $operation->response["error"] = "Email address already registered.";
                        }
                        else
                            $operation->setSuccessful();
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

    
    // Set content type
    header('Content-Type: application/json; charset=utf-8');
    
    // Send JSON response
    echo json_encode($operation->response);
    
    
    // Done! :)
?>
