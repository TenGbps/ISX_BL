<?PHP
 $ip = $_SERVER['REMOTE_ADDR'];
 $packedIp = @inet_pton($ip);
 if($packedIp === false || strlen($packedIp) !== 4) { return; }
 $ipList   = @file_get_contents('blockips.raw');
 if($ipList === false)                              { return; }
 $pos = strpos($ipList, $packedIp);
 while($pos !== false) {
  if($pos % 4 === 0)                                { exit;   }
  $pos = strpos($ipList, $packedIp, $pos + 1);
 }
?>
