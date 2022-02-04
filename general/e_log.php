<?php

    function log_error($conn, $e, $file)
    {	
		try
        {
			if($_SERVER['REQUEST_METHOD'] == 'GET')
					$input = $_SERVER['QUERY_STRING'];
			else if($_SERVER['REQUEST_METHOD'] == 'POST')
					{
						$input = "";
						foreach ($_POST as $key => $value) 
						{
  							$input = $input . "#" . $key . "=" . $value; 
						}
					}
			else
					{
						$input = '';
        				$putfp = fopen('php://input', 'r');
						while($data = fread($putfp, 1024))
	    				$input .= $data;
						fclose($putfp);
					}
					
			$sqlLog = "INSERT INTO error_log (errormessage, filename, requestinput, linenumber, requestmethod, requestdatetime) VALUES (:message, :filename, :inputvalue, :linenumber, :requestmethod, GETDATE())";
            $stmtLog = $conn->prepare($sqlLog);
            $stmtLog->bindParam(':message', $e->getMessage());
			$stmtLog->bindParam(':filename', $file);
			$stmtLog->bindParam(':requestinput', $input);
			$stmtLog->bindParam(':linenumber', $e->getLine());
			$stmtLog->bindParam(':requestmethod', $_SERVER['REQUEST_METHOD']);
            
			$stmtLog->execute();
			
        }
		catch(Exception $e)
        {
			echo $e;
			error_log($e);
		}
        
    }
?>