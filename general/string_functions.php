<?php

    function get_string_between($string, $start, $end){
    $string = ' ' . $string;
    $ini = strpos($string, $start);
    if ($ini == 0) return '';
    $ini += strlen($start);
    $len = strpos($string, $end, $ini) - $ini;
    return substr($string, $ini, $len);
    }
	
	function get_string_between_first_and_last($string, $start, $end){
    
	$startingGarbageLength = strpos($string, $start);
	$trailingGarbagePosition = strrpos($string, $end);
	return substr($string, $startingGarbageLength, $trailingGarbagePosition -  $startingGarbageLength) . $end;
	
    }
?>