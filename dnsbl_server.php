<?PHP
 // OLD ISX DNSBL Server write in php5
 // This server are not more used in production
 
 echo "[DNSBL Server for isx.fr !]\n";
 echo "Version 1.1 (deprecated)\n";

 if(!($socket = socket_create(AF_INET, SOCK_DGRAM, 0))) {
  $errorcode  = socket_last_error();
  $errormsg   = socket_strerror($errorcode);
  die(" Couldn't create socket: [$errorcode] $errormsg\n");
 }
 echo " Socket OK,";

 if(!socket_bind($socket, "0.0.0.0", 53)){
  $errorcode  = socket_last_error();
  $errormsg   = socket_strerror($errorcode);
  die("Could not bind socket : [$errorcode] $errormsg\n");
 }
 echo " Bind OK\n";
 echo " [!] Ready !\n";

 $sockets = array();
 $cid     = 0;

 while(1) {
  $data = "";
  $sockets[$cid] = $socket;
  socket_recvfrom($sockets[$cid], $data, 4096, 0, $ipaddr, $port);
  doEngine($sockets[$cid], $ipaddr, $port, $data);
  $cid++;
 }

 socket_close($socket);

 function doEngine($socket, $ipaddr, $port, $data) {
  $DB_PDO        = 'mysql:host=17.253.34.253;dbname=foo';
  $DB_Cnx        = NULL;
  try  { $DB_Cnx = new PDO($DB_PDO, 'foo', 'oldphpguy'); }
  catch( Exception $e ) { exit($e); }

  $senddata  = "";
  $dns_ttl   = 86400;
  $dns_id    = substr($data, 0, 2);
  $dns_idnum = (ord(substr($data, 0, 1)) * 256) + ord(substr($data, 1, 1));
  $dns_opts  = substr($data, 4, 8);
  $dns_pack  = substr($data, 12);
  $dns_name  = "";

  if(strlen($dns_id) == 2 && strlen($dns_opts) == 8 && strlen($dns_pack) >= 5) {

   for($curr = 0; $curr < strlen($dns_pack); $curr++) {
    $chr = ord($dns_pack[$curr]);
    if($chr == 0) { break; }
    $dns_name .= substr($dns_pack, ($curr + 1), $chr).".";
    $curr += $chr;
   }
   $dns_name  = strtolower(substr($dns_name, 0, -1));
   $dns_pack  = substr($data, 12, (strlen($dns_name) + 6));
   $dns_type  = (ord(substr($data, (14 + strlen($dns_name)), 1)) * 256) + ord(substr($data, (15 + strlen($dns_name)), 1));

   if(substr_count($dns_name, ".dnsbl.isx.fr") > 0 && $dns_type == 1) {
    $name = str_replace(".dnsbl.isx.fr", "", $dns_name);
    if(substr_count($name, '.') == 3) {
     $ip = explode('.', $name);
     $ip = $ip[3].".".$ip[2].".".$ip[1].".".$ip[0];
     if(filter_var($ip, FILTER_VALIDATE_IP)) {
      $ipbl = sprintf('%u', ip2long($ip));
      echo " [?] Query from $ipaddr:$port id $dns_idnum type $dns_type for check $ip($ipbl)\n";
      $DB_Query = $DB_Cnx->query("SELECT * FROM blacklist WHERE IPAddress='$ipbl' LIMIT 1;");
      $DB_Data  = $DB_Query->fetch();
      if($DB_Data["ID"] != "") {
       $senddata = dns_answer($dns_id, $dns_pack, true, 2);
      } else {
       $senddata = dns_answer($dns_id, $dns_pack, false);
      }
     } else {
       echo " [!] Packet from $ipaddr:$port id $dns_idnum with bad ip address $name\n";
      $senddata = dns_answer($dns_id, $dns_pack, false);
     }
    } else {
     echo " [!] Packet from $ipaddr:$port id $dns_idnum with bad name $name\n";
     $senddata = dns_answer($dns_id, $dns_pack, false);
    }
   }
   socket_sendto($socket, $senddata, strlen($senddata), 0, $ipaddr, $port);
  }
 }

 function dns_answer($dns_id, $dns_pack, $sucess, $code = 0) {
  if($sucess == true) {
   return $dns_id."\x81\x80"."\x00\x01\x00\x01\x00\x00\x00\x00".$dns_pack."\xC0\x0C"."\x00\x01"."\x00\x01"."\x00\x01\x51\x80"."\x00\x04".chr(127).chr(0).chr(0).chr($code);
  } else {
   return $dns_id."\x81\x83"."\x00\x01\x00\x00\x00\x00\x00\x00".$dns_pack;
  }
 }
?>
