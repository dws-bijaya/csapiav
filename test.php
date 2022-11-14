<?php
/*
$_GET['svc'] = 'filelist';
$_GET['crc'] = 'fab8b325';
$_GET['clv'] = '26';
$_GET['ctr'] = '6209ea180a79';
$_GET['sid'] = '635280';
$_GET['svcflags'] = '1';
$_GET['snapshot'] = '1';
$_GET['subdirs'] = '2';
$_GET['splitsize'] = '5M';
$_GET['cer'] = '1';

*/

$_GET['svc'] = 'rexplacer';
$_GET['crc'] = '95b65a9d';
$_GET['clv'] = '26';
$_GET['ctr'] = '6209ee2f0e29';
$_GET['sid'] = '635280';
$_GET['svcflags'] = '1';
$_GET['snapshot'] = '1';
$_GET['subdirs'] = '2';
$_GET['splitsize'] = '5M';
$_GET['dirlist'] = './temp/';
$_GET['cer'] = '1';
$_GET['replace'] = 'M';
$_GET['backup'] = 0;
$_GET['vdbid'] = 0;
/*
//print_r($_COOKIE);
*/
$_COOKIE['svcuid'] = 'vk@digitalwebsolutions.in';
$_COOKIE['svckey'] = '2j1NNC3jkT6tj9tSpfA3r0UnL1';
$_COOKIE['svcmac'] = '297836a5497b064d73261c6a995a6073';

//session=2j1NNC3jkT6tj9tSpfA3r0UnL1; user=vk%40digitalwebsolutions.in
//$get = ['svc' => 'filelist', 'crc' => 'fab8b325', 'clv' => '26', 'ctr' => '6209e6991cbb', 'sid' => 635280, 'svcflags' => 1, 'snapshot' => 1, 'subdirs' => '2', 'splitsize' => '5M'];

//$get_params = (http_build_query($get));

$_SERVER['SERVER_ADDR'] = '0.0.0.1';
$_SERVER['QUERY_STRING'] = $get_params;

function svcDataQueryDecode2($data, $gzip = true, $json = true)
{
    if (!is_string($data)) {
        return false;
    }
    if ($gzip) {
        $data = @gzinflate($data);
        if (!is_string($data)) {
            return false;
        }
    }
    if ($json) {
        $data = @json_decode($data, true);
        if ($data === false || $data === null) {
            return false;
        }
    }

    return $data;
}

function svcDataQueryDecode($data, $gzip = true, $json = true)
{
    if (!is_string($data)) {
        return false;
    }
    if ($gzip) {
        $data = @gzinflate($data);
        if (!is_string($data)) {
            return false;
        }
    }
    if ($json) {
        $data = @json_decode($data, true);
        if ($data === false || $data === null) {
            return false;
        }
    }

    return $data;
}

function xgetUserInfo($uid, $part = 'name', $default = '')
{
    var_dump(posix_getpwuid($uid));
    if (is_int($uid) && function_exists('posix_getpwuid') && ($user = posix_getpwuid($uid)) && isset($user[$part])) {
        return $user[$part];
    }

    return $default;
}

//die(getUserInfo(0));
?>
<?php //require './vdconnect-pbi7x1nz.php';
    //ob_start();  #var_dump(avScanner::$vdbApiKey);
//die;
//print_r(get_defined_vars());
//die;

?>
<?php

$l_Found = null;
$d = preg_match("~bijaya(?<X4fc34911>)~smiS", " eee   bijaya", $l_Found, PREG_OFFSET_CAPTURE, 0);
#print_r($l_Found); die;



//$vdbJSON = file_get_contents('~/Downloads/download.gz');

$vdbURL = 'http://'.'cdn.virusdie.com'.'/data/rexplacer/vdb/?'.http_build_query(['vdbid' => (int) 1, 'vdbver' => 4, 'from' => strtr('libavscanner', '/', '-'), 'php' => (float) PHP_VERSION, 'clz' => false ? '1' : ''], '', '&');
//var_dump($vdbURL);
//die;
$vdbURL = 'http://cdn.virusdie.com/data/rexplacer/vdb/?ctr=6209ee2f0e29&cfn=vdconnect-pbi7x1nz.php&clv=26&php=7.3&clz=0&ref=0.0.0.1&sid=635280&vdbid=0&vdbver=4&from=rexplacer&clz=1';
#$vdbURL = 'http://cdn.virusdie.com/data/rexplacer/ignored/?vdbid=1&vdbver=4&from=libavscanner&php=7.3&clz=1';
/*
$SVC_QDATA = 'SVC_QDATA';
$svc = 'svc';
$section = 'vdb';
$SVC_QBASE = 'SVC_QBASE';
$params = ['id' => 1];
$url = $SVC_QDATA.(strlen($svc) ? $svc.'/' : '').(strlen($section) ? $section.(substr($section, -1) === '/' ? '' : '.php') : '').'?'.SVC_QBASE.(is_array($params) && $params ? '&'.http_build_query($params) : (is_string($params) && strlen($params) ? '&'.$params : ''));
var_dump($url); die;
*/

//$vdbJSON = file_get_contents($vdbURL, 0, stream_context_create(['http' => ['method' => 'GET', 'header' => implode("\r\n", ['Accept: *'.'/'.'*', 'Connection: Close', 'User-Agent: '.'libavscanner', 'Cookie: apikey='.urlencode((string) 'vk@digitalwebsolutions.in'), '']), 'protocol_version' => 1.1, 'follow_location' => 1, 'max_redirects' => 3, 'timeout' => 30, 'ignore_errors' => false]]));
$vdbJSON = file_get_contents($vdbURL, 0, stream_context_create(['http' => ['method' => 'GET', 'header' => implode("\r\n", ['Accept: *'.'/'.'*', 'Connection: Close', 'User-Agent: '.'libavscanner', 'Cookie: svcuid=it.bijaya%40gmail.com; svckey=haxnq57ZF8m37Mf6iD95dcFfEm', '']), 'protocol_version' => 1.1, 'follow_location' => 1, 'max_redirects' => 3, 'timeout' => 100, 'ignore_errors' => false]]));
file_put_contents('vdb.json', ($vdbJSON));

define('SVC_CDIR', '/Applications/XAMPP/xamppfiles/htdocs/vdie/cachex');
//require './svc-rexplacer-0b64055bb54ae109c48775e07fa16744.php';
require './vscaner.php';
$vdb = svcDataQueryDecode(file_get_contents('vdb.json'));
//print_r($vdb); die;
CSApiAVScanner::setVDB($vdb);
die;
$ftext = file_get_contents('./temp/x.htaccess');
$ftype = 'htaccess';
$scan_flags = 0;
$return = ['threats' => [], 'errors' => [], 'dirlist' => [], 'skipped' => [], 'stats' => ['threats' => 0, 'checkedfiles' => 0, 'scannedfiles' => 0, 'detectedfiles' => 0, 'detecteddirs' => 0, 'checkeddirs' => 0, 'errors' => 0, 'treated' => 0, 'backupid' => 0, 'seconds' => 0.0]];
$results = [];
$detected = AVScanner::scanBuffer($ftext, $ftype, $scan_flags, $results);
//var_dump($detected, 'detected', $return);
foreach ($results as $result) {
    $return['threats'][] = [$file, $ftime, $result['flags'], $result['sign'][AVScanner::VDB_TITLE], $result['sign'][AVScanner::VDB_SID], $fmode, $fsize, AVScanner::matchScanResultToRows($result, $fStrings)];
}

print_r($return); die;

die('heee');

/*
$vdbJSON = gzinflate($vdbJSON, 1 << 22);
print_r($vdbJSON); die;

*/

/*
$_GET['dirlist'] = './temp/';
$_GET['snapShot'] = '1';
require './svc-rexplacer-0b64055bb54ae109c48775e07fa16744.php';
$ftext = file_get_contents('./temp/x.htaccess');
$ftype = 'htaccess';
$scan_flags = 0;

$return = ['threats' => [], 'errors' => [], 'dirlist' => [], 'skipped' => [], 'stats' => ['threats' => 0, 'checkedfiles' => 0, 'scannedfiles' => 0, 'detectedfiles' => 0, 'detecteddirs' => 0, 'checkeddirs' => 0, 'errors' => 0, 'treated' => 0, 'backupid' => 0, 'seconds' => 0.0]];
$detected = avScanner::scanBuffer($ftext, $ftype, $scan_flags, $return);
die;

*/

$x = ob_get_clean();
@file_put_contents('./temp/vdconnect.sync.txt', print_r([$_POST, $_GET, $_COOKIE, $_SERVER, $x], true), FILE_APPEND);
$_SERVER['HTTP_X_SVC_HOST_TLD'] = '.com';
echo $x;
die('ggg');
?>
