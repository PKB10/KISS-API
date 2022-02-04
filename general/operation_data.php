<?php

	class Operation
	{
		var $response;
		var $isError;
		
		public function __construct() 
		{
        	$this->response = array();
    		$this->response["success"] = 0;
		    $this->response["error"] = "none";
    
		    $this->isError = false;
    	}
    	
    	public function markInformationFileError()
    	{
    		$this->response["success"] = -1;
            $this->response["error"] = "Internal error: unable to extract required information";
                            
            $this->isError = true;
    	}
    	
    	public function markRequestError()
    	{
			$this->response["success"] = -3;
       		$this->response["error"] = "Invalid request";
            
	       	$this->isError = true;
    	}
    	
    	public function markRequestInputError($type)
    	{
			$this->response["success"] = -2;
			
			switch($type)
			{
				case 1: $this->response["error"] = "Missing data";
						break;
				case 2: $this->response["error"] = "Missing/Invalid parameter(s)";
						break;
				default: break;
			}
			
	       	$this->isError = true;
    	}
    	
    	public function markParameterError($parameterName)
    	{
    		$this->response["success"] = -2;
         	$this->response["error"] = "Invalid parameter : '" . $parameterName . "'";
            
            $this->isError = true;
    	}
    
    	public function markDBError()
    	{
    		$this->response["success"] = -3;
	    	$this->response["error"] = "Database error";
    	
    		$this->isError = true;
    	}
    
    	public function markSessionError()
    	{
    		$this->response["success"] = -5;
	    	$this->response["error"] = "Session error";
    	
    		$this->isError = true;
    	}
    	
    	public function markImageError($type)
    	{
    		$this->response["success"] = -2;
			
			switch($type)
			{
				case 1: $this->response["error"] = "Missing image file";
						break;
				case 2: $this->response["error"] = "Invalid file";
						break;
				case 3:	$this->response["success"] = -1;
						$this->response["error"] = "Image error";
						break;
				default: break;
			}
			
	       	$this->isError = true;
    	}
    
    
    	public function markException(Exception $e)
    	{
    		$this->response["success"] = -3;
	    	$this->response["error"] = $e;//set to "Server error" for added security
	    	
	    	$this->isError = true;
    	}
    	
    	public function setSuccessful()
    	{
    		$this->response["success"] = 1;
    	}
    	
    	public function setSuccessfulWithNoResults()
    	{
    		$this->response["success"] = 2;
    	}

	}
?>
