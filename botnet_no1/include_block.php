<?PHP
 $ip = $_SERVER['REMOTE_ADDR'];
 $packedIp = @inet_pton($ip);
 if($packedIp === false || strlen($packedIp) !== 4) { return; }
 $ipList   = @file_get_contents('blockips.raw');
 if($ipList === false)                              { return; }
 if(strpos($ipList, $packedIp) !== false)           { exit;   }
?>
