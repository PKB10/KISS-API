<?php
    
    ini_set('default_charset','utf-8');
    
    function getServer()
    {
        
        $sFile = "YOUR_PATH/server.txt";
        if (file_exists($sFile))
        {
            $fh = fopen($sFile, 'r');
            $server = fgets($fh);
            fclose($fh);
            
            return $server;
        }
        else
        {
            
            return false;
        }
        
    }
    
    function getDBUsername()
    {
        
        $dbuFile = "YOUR_PATH/database_username.txt";
        if (file_exists($dbuFile))
        {
            $fh = fopen($dbuFile, 'r');
            $dbusername = fgets($fh);
            fclose($fh);
            
            return $dbusername;
        }
        else
        {
            
            return false;
        }
        
    }
    
    function getDBPassword()
    { 
        
        // Function to fetch DB password
        
    }

    function getDB()
    {
        
        $dbFile = "YOUR_PATH/database.txt";
        if (file_exists($dbFile))
        {
            $fh = fopen($dbFile, 'r');
            $db = fgets($fh);
            fclose($fh);
            
            return $db;
        }
        else
        {
            
            return false;
        }
        
    }
    
    function getAuthKey()
    {
        
        $akFile = "YOUR_PATH/auth_key.txt";
        if (file_exists($akFile))
        {
            $fh = fopen($akFile, 'r');
            $authKey =  fgets($fh);
            fclose($fh);
            return $authKey;
        }
        else
        {
            
            return false;
        }
        
    }
    
    function getIV()
    {
        
        // Function to fetch IV for encryption/decryption
        
    }
    
    function getSecret()
    {
        
        // Function to fetch secret for encryption/decryption
        
    }
    
    function is_valid_language($language)
    {
    	// Add more language codes if needed
    	switch($language)
    	{
    	case 1:
    	case 2:
    		return true;
    	default: 
    		return false;
    	
    	}
    	return false;
    }
    
    
    
    ?>