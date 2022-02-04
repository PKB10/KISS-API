<?php
	/*
	* Change the functions as per your algorithm of choice
	* I have used Blowfish here
	*/


    function encrypt($data, $key, $iv)
    {
        $iv = base64_decode($iv);
        return openssl_encrypt($data, 'BF-CBC', $key, 0, $iv);
    }

    
    function decrypt($data, $key, $iv)
    {
        $iv = base64_decode($iv);
        return openssl_decrypt($data, 'BF-CBC', $key, 0, $iv);
    }
    
?>
