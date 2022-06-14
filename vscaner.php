<?php

class CSApiAVScanner
{
    const version = '5.4.0';
    const VDBVERSION = 4;
    const VDB_TITLE = 0;
    const VDB_SIGNATURE = 1;
    const VDB_REPLACE = 2;
    const VDB_CALLBACK = 3;
    const VDB_INCURABLE = 4;
    const VDB_DOUBT = 5;
    const VDB_LAST = 6;
    const VDB_CVE = 7;
    const VDB_FTYPES = 8;
    const VDB_ACK = 9;
    const VDB_EXC = 10;
    const VDB_SUB = 11;
    const VDB_ORDER = 12;
    const VDB_SID = 13;
    const RET_DETECTED = 1;
    const RET_INCURABLE = 2;
    const RET_DOUBT = 4;
    const RET_LAST = 8;
    const RET_CVE = 256;
    const RET_REPLACED = 16;
    const RET_DELETE = 32;
    const RET_CANREPLACE = 64;
    const RET_CANDELETE = 128;
    const RET_EBACKUP = 1024;
    const RET_EWRITE = 2048;
    const RET_EDELETE = 4096;
    const RET_EREAD = 8192;
    const SCAN_REPLACE = 1;
    const SCAN_REPLACE_AFTER = 2;
    const SCAN_APPLY_AFTER_TREATMENT = 4;
    const SCAN_PACK_RESULTS = 8;
    const SCAN_REPLACE_TYPE_MALWARE = 1024;
    const SCAN_REPLACE_TYPE_DOUBT = 2048;
    const SCAN_REPLACE_TYPE_CVE = 4096;
    protected static $vdbHost = '';
    protected static $vdbApiKey = '';
    protected static $cacheFile = '';
    protected static $cacheTime = 0;
    protected static $vdbID = 0;
    protected static $userAgent = 'libavscanner';
    public static $vdb = [];
    public static $vdbTop = [];
    protected static $min_size = 10;
    protected static $max_size = 1 << 20;
    protected static $file_types = ['htm' => 0, 'html' => 0, 'php' => 0, 'phps' => 0, 'phtml' => 0, 'php4' => 0, 'php5' => 0, 'php7' => 0, 'inc' => 0, 'tpl' => 0, 'class' => 0, 'js' => 0, 'pl' => 0, 'perl' => 0, 'py' => 0, 'asp' => 0, 'aspx' => 0, 'svg' => 0, 'xml' => 0];

    public static function version()
    {
        return self::version;
    }

    public static function init($options, &$error = null)
    {
        if (!is_array($options)) {
            return !($error = 'Invalid options in init()');
        }
        foreach ($options as $key => $val) {
            self::$$key = $val;
        }

        return true;
    }

    public static function loadVDB(&$error = null)
    {
        var_dump(self::$cacheFile);
        $vdbCached = strlen(self::$cacheFile) && (int) self::$cacheTime && is_file(self::$cacheFile) && filesize(self::$cacheFile) && (filemtime(self::$cacheFile) + (int) self::$cacheTime >= time());
        $vdb = $vdbJSON = null;
        $useGZIP = function_exists('gzinflate');
        if ($vdbCached) {
            $vdbURL = self::$cacheFile;
            $vdbJSON = file_get_contents($vdbURL);
            if (!is_string($vdbJSON)) {
                return !($error = 'Cache file read failed');
            }
        } else {
            if (!strlen(self::$vdbHost)) {
                return !($error = 'Invalid vdbHost configuration option');
            }
            $vdbURL = 'http://'.self::$vdbHost.'/data/rexplacer/vdb/?'.http_build_query(['vdbid' => (int) self::$vdbID, 'vdbver' => self::VDBVERSION, 'from' => strtr(self::$userAgent, '/', '-'), 'php' => (float) PHP_VERSION, 'clz' => $useGZIP ? '1' : ''], '', '&');
            if ((int) ini_get('allow_url_fopen')) {
                $vdbJSON = @file_get_contents($vdbURL, 0, stream_context_create(['http' => ['method' => 'GET', 'header' => implode("\r\n", ['Accept: *'.'/'.'*', 'Connection: Close', 'User-Agent: '.self::$userAgent, 'Cookie: apikey='.urlencode((string) self::$vdbApiKey), '']), 'protocol_version' => 1.1, 'follow_location' => 1, 'max_redirects' => 3, 'timeout' => 30, 'ignore_errors' => false]]));
            } elseif (is_callable('curl_init')) {
                $curl = curl_init();
                curl_setopt_array($curl, [CURLOPT_URL => $vdbURL, CURLOPT_RETURNTRANSFER => true, CURLOPT_COOKIE => 'apikey='.urlencode((string) self::$vdbApiKey), CURLOPT_USERAGENT => self::$userAgent, CURLOPT_FOLLOWLOCATION => true, CURLOPT_MAXREDIRS => 3, CURLOPT_CONNECTTIMEOUT => 30, CURLOPT_FAILONERROR => true, CURLOPT_SSL_VERIFYPEER => false]);
                $vdbJSON = curl_exec($curl);
                curl_close($curl);
                unset($curl);
            } else {
                return !($error = 'No allow_url_fopen/CURL available');
            }
            if (!is_string($vdbJSON)) {
                return !($error = 'Request failed');
            }
            if ($useGZIP) {
                $vdbJSON = gzinflate($vdbJSON, 1 << 22);
                if (!is_string($vdbJSON)) {
                    return !($error = 'gzinflate() failed');
                }
            }
        }
        if (!strlen($vdbJSON) || !strpos(' [{', $vdbJSON[0], 1)) {
            return !($error = 'Invalid data received');
        }
        $vdb = json_decode($vdbJSON, true);
        if (!is_array($vdb) || empty($vdb)) {
            return !($error = 'Decoding failed');
        }
        $vdbCached || strlen(self::$cacheFile) && @file_put_contents(self::$cacheFile, $vdbJSON, LOCK_EX) && chmod(self::$cacheFile, 0664);

        return self::setVDB($vdb, $error);
    }

    public static function setVDB(&$vdb, &$error = null)
    {
        if (!is_array($vdb) || empty($vdb)) {
            return !($error = 'Invalid or empty VDB');
        }

        if (!is_array(self::$vdbTop) || self::$vdbTop) {
            self::$vdbTop = [];
        }

        #

    
        $trees = [self::VDB_ACK => [], self::VDB_EXC => [], self::VDB_SUB => []];


        $sids = [];
        foreach ($vdb as $sid => &$sign) {

            
            if (!strlen($sign[self::VDB_SIGNATURE]) && !strlen($sign[self::VDB_CALLBACK])) {
                return !($error = "$sid: No RegExp/Constant");
            }

            
            if (strlen($sign[self::VDB_SIGNATURE])) {  
                

                if ($sign[self::VDB_SIGNATURE][0] === ':') {


                    $sign[self::VDB_SIGNATURE] = ':'.pack('H*', substr($sign[self::VDB_SIGNATURE], 1));
                    var_dump($sign[self::VDB_SIGNATURE]); 
                    if (strlen($sign[self::VDB_SIGNATURE]) < 3) {
                        return !($error = "$sid: Invalid constant (HEX)");
                    }
                } elseif ($sign[self::VDB_SIGNATURE][0] === '=') {
                    $sign[self::VDB_SIGNATURE][0] = ':';
                    if (strlen($sign[self::VDB_SIGNATURE]) < 3) {
                        return !($error = "$sid: Invalid constant (TEXT)");
                    }
                } else {
                    if (strlen($sign[self::VDB_SIGNATURE]) < 4) {
                        return !($error = "$sid: Invalid PCRE");
                    }
                    if (!strpos(' #/~', $sign[self::VDB_SIGNATURE][0])) {
                        return !($error = "$sid: Invalid PCRE delimiter");
                    }
                }
            }
            if (!strlen($sign[self::VDB_CALLBACK])) {
                $sign[self::VDB_CALLBACK] = 'cbDefault';
            }
            $sign[self::VDB_INCURABLE] = (int) $sign[self::VDB_INCURABLE];
            $sign[self::VDB_DOUBT] = (int) $sign[self::VDB_DOUBT];
            $sign[self::VDB_LAST] = (int) $sign[self::VDB_LAST];
            $sign[self::VDB_CVE] = (int) $sign[self::VDB_CVE];
            $sign[self::VDB_FTYPES] = strlen($sign[self::VDB_FTYPES]) ? array_flip(explode(',', $sign[self::VDB_FTYPES])) : null;
            
            $sign[self::VDB_ORDER] = (int) $sign[self::VDB_ORDER];
            $sign[self::VDB_SID] = (int) $sid;

            

            #var_dump($sign, self::VDB_SID); die;

            if ($sign[self::VDB_SUB]) {
                $trees[self::VDB_SUB][$sign[self::VDB_SUB]][] = $sign[self::VDB_SID];
            } elseif ($sign[self::VDB_EXC]) {
                $trees[self::VDB_EXC][$sign[self::VDB_EXC]][] = $sign[self::VDB_SID];
            } elseif ($sign[self::VDB_ACK]) {
                $trees[self::VDB_ACK][$sign[self::VDB_ACK]][] = $sign[self::VDB_SID];
            } else {
                self::$vdbTop[] = &$sign;
            }
            $sign[self::VDB_ACK] = $sign[self::VDB_EXC] = $sign[self::VDB_SUB] = null;

            $sids[]=$sign[self::VDB_CALLBACK];
        }
        unset($sign);
        reset($vdb);

       # var_dump( ( array_unique($sids))); die;


        foreach ($trees as $treeID => $tree) {
            var_dump($treeID , $tree);
            die;
            foreach ($tree as $pid => $cids) {
                if (isset($vdb[$pid])) {
                    $vdb[$pid][$treeID] = $cids;
                } else {
                    return !($error = "$pid: No such parent signature");
                }
            }
        }

        #var_dump(count($vdb), 333); die;
        self::$vdb = &$vdb;

        die;

        #var_dump(count($vdb));die;
        #print_r(self::$vdb);die;
        return true;
    }

    public static function file_rewrite($file, $contents)
    {
        $mode = (int) fileperms($file);
        chmod($file, $mode | 0220);
        $ret = (file_put_contents($file, $contents) === strlen($contents));
        chmod($file, $mode);

        return $ret;
    }

    public static function file_unlink($file)
    {
        $mode = (int) fileperms($file);
        chmod($file, $mode | 0220);
        if (!$ret = unlink($file)) {
            chmod($file, $mode);
        }

        return $ret;
    }

    public static function afterTreatment(&$text, $fileType)
    {
        switch ($fileType) { case 'php': case 'phps': case 'phtml': case 'php4': case 'php5': case 'php7': case 'inc': case 'tpl': case 'class': $text = preg_replace('/<\?(?:php)?\s*\?>/', '', $text);

return true; }

        return false;
    }

    public static function scanBuffer(&$text, $fileType = '', $flags = 0, &$results = null)
    {
        $detected = 0;
        if ($results !== null) {
            if (!is_array($results) || $results) {
                $results = [];
            }
        }
        $cbs = [];
        foreach (self::$vdbTop as $sign) {
            $cb = $sign[self::VDB_CALLBACK];
            #$cbs[] = $sign[8]; continue;
            $detected |= self::$cb($sign, $text, $fileType, $flags, $results);
            if ($detected & self::RET_LAST) {
                break;
            }
        }
        #print_r($cbs);die;
        #var_dump( [count ($cbs)], count(self::$vdbTop)); die;


        #die;
        if ($detected === 0) {
            return $detected;
        }
        if (false) {
            if ($results !== null && !'disabled') {
                if ($flags & self::SCAN_REPLACE_AFTER) {
                    if (count($results) > 1) {
                        usort($results, __CLASS__.'::sortResults_last_length');
                    }
                    for ($i = 0; $i < count($results); ++$i) {
                        $sign = $results[$i]['sign'];
                        if ($sign[self::VDB_INCURABLE]) {
                            continue;
                        }
                        if ($sign[self::VDB_DOUBT] && !($flags & self::SCAN_REPLACE_TYPE_DOUBT)) {
                            continue;
                        }
                        if ($sign[self::VDB_CVE] && !($flags & self::SCAN_REPLACE_TYPE_CVE)) {
                            continue;
                        }
                        if (!$sign[self::VDB_DOUBT] && !$sign[self::VDB_CVE] && !($flags & self::SCAN_REPLACE_TYPE_MALWARE)) {
                            continue;
                        }
                        if ($sign[self::VDB_LAST]) {
                            $results[$i]['flags'] |= self::RET_DELETE;
                            $detected |= self::RET_DELETE;
                            break;
                        } elseif ($sign[self::VDB_CALLBACK] !== 'cbDefault') {
                            $cb = $sign[self::VDB_CALLBACK];
                            $results[$i]['flags'] |= self::$cb($sign, $text, $fileType, $flags | self::SCAN_REPLACE);
                            $detected |= $results[$i]['flags'];
                        } else {
                            $text = ($sign[self::VDB_SIGNATURE][0] === ':') ? str_replace(substr($sign[self::VDB_SIGNATURE], 1), $sign[self::VDB_REPLACE], $text) : preg_replace($sign[self::VDB_SIGNATURE], $sign[self::VDB_REPLACE], $text);
                            $results[$i]['flags'] |= self::RET_REPLACED;
                            $detected |= self::RET_REPLACED;
                        }
                    }
                }
                if (count($results) > 1 && ($flags & self::SCAN_PACK_RESULTS)) {
                    if ($detected & self::RET_LAST) {
                        $results = $results[0]['sign'][self::VDB_LAST] ? [$results[0]] : [$results[count($results) - 1]];
                    } else {
                        self::resultsRemoveOverlaps($results, true);
                    }
                }
                if (count($results) > 1) {
                    usort($results, __CLASS__.'::sortResults_order_id');
                }
            } elseif ($flags & self::SCAN_REPLACE_AFTER) {
                throw new Exception('The `SCAN_REPLACE_AFTER` flag requires non NULL $results buffer');
            }
            if (($flags & self::SCAN_APPLY_AFTER_TREATMENT) && strlen($fileType) && ($detected & self::RET_REPLACED) && !($detected & self::RET_DELETE)) {
                self::afterTreatment($text, $fileType);
            }
        }

        return $detected;
    }

    protected static function sortResults_last_length($i, $j)
    {
        if ($i['sign'][self::VDB_LAST] !== $j['sign'][self::VDB_LAST]) {
            return $i['sign'][self::VDB_LAST] ? -1 : 1;
        }

        return $j['length'] - $i['length'];
    }

    protected static function sortResults_order_id($i, $j)
    {
        if ($i['sign'][self::VDB_ORDER] !== $j['sign'][self::VDB_ORDER]) {
            return $i['sign'][self::VDB_ORDER] < $j['sign'][self::VDB_ORDER] ? -1 : 1;
        }

        return $i['sign'][self::VDB_SID] < $j['sign'][self::VDB_SID] ? -1 : 1;
    }

    protected static function resultsRemoveOverlaps(&$results, $compact = false)
    {
        $removed = 0;
        $h = count($results) - 1;
        for ($i = 0; $i < $h; ++$i) {
            if (!$results[$i] || $results[$i]['offset'] < 0) {
                continue;
            }
            $iL = $results[$i]['offset'];
            $iR = $iL + $results[$i]['length'];
            for ($j = $i + 1; $j <= $h; ++$j) {
                if (!$results[$j] || $results[$j]['offset'] < 0) {
                    continue;
                }
                $jL = $results[$j]['offset'];
                $jR = $jL + $results[$j]['length'];
                if ($iL <= $jL && $jR <= $iR) {
                    $results[$j] = false;
                    ++$removed;
                } elseif ($jL <= $iL && $iR <= $jR) {
                    $results[$i] = false;
                    ++$removed;
                    break;
                }
            }
        }
        if ($compact && $removed > 0) {
            $results = array_values(array_filter($results));
        }

        return $removed;
    }

    public static function cbDefault($sign, &$text, $fileType, $replace = 0, &$results = null)
    {


        #die("$text");
        if ($sign[self::VDB_FTYPES] && !isset($sign[self::VDB_FTYPES][$fileType])) {
            return 0;
        }
        $const = ($sign[self::VDB_SIGNATURE][0] === ':');
        if ($const) {
            $startOffset = strpos($text, substr($sign[self::VDB_SIGNATURE], 1));
            if ($startOffset === false) {
                return 0;
            }
            $length = strlen($sign[self::VDB_SIGNATURE]) - 1;
            $endOffset = $startOffset + $length;
        } else {
            if (!preg_match($sign[self::VDB_SIGNATURE], $text, $match, PREG_OFFSET_CAPTURE)) {
                return 0;
            }
            $startOffset = $match[0][1];
            $length = strlen($match[0][0]);
            $endOffset = $startOffset + $length;
            $match = null;
        }
        if ($sign[self::VDB_ACK]) {
            var_dump($sign[self::VDB_ACK]); die;
            die("self::VDB_ACK");
            foreach ($sign[self::VDB_ACK] as $subSignID) {
                if (($cb = self::$vdb[$subSignID][self::VDB_CALLBACK]) && self::$cb(self::$vdb[$subSignID], $text, $fileType, 0) === 0) {
                    return 0;
                }
            }
        }
        if ($sign[self::VDB_EXC]) {


            print_r($sign);

            #die("self::VDB_ACK");
            foreach ($sign[self::VDB_EXC] as $subSignID) {
                var_dump($subSignID, $sign[self::VDB_EXC], self::$vdb[$subSignID], $sign, self::$vdb[$subSignID][self::VDB_CALLBACK]);
                if (($cb = self::$vdb[$subSignID][self::VDB_CALLBACK]) && self::$cb(self::$vdb[$subSignID], $text, $fileType, 0) !== 0) {
                    return 0;
                }
            }

            die;
        }
        if ($sign[self::VDB_SUB]) {
            die("self::VDB_SUB");
            $detected = 0;
            foreach ($sign[self::VDB_SUB] as $subSignID) {
                if (($subSign = self::$vdb[$subSignID]) && ($cb = $subSign[self::VDB_CALLBACK])) {
                    $detected |= self::$cb($subSign, $text, $fileType, $replace, $results);
                    if ($detected & self::RET_LAST) {
                        break;
                    }
                }
            }

            return $detected;
        }
        $doReplace = ($replace & self::SCAN_REPLACE) && !$sign[self::VDB_INCURABLE];
        if ($doReplace) {
            if ($doReplace && $sign[self::VDB_DOUBT] && !($replace & self::SCAN_REPLACE_TYPE_DOUBT)) {
                $doReplace = false;
            }
            if ($doReplace && $sign[self::VDB_CVE] && !($replace & self::SCAN_REPLACE_TYPE_CVE)) {
                $doReplace = false;
            }
            if ($doReplace && !$sign[self::VDB_DOUBT] && !$sign[self::VDB_CVE] && !($replace & self::SCAN_REPLACE_TYPE_MALWARE)) {
                $doReplace = false;
            }
        }
        $detected = self::RET_DETECTED | ($sign[self::VDB_INCURABLE] ? self::RET_INCURABLE : ($sign[self::VDB_LAST] ? self::RET_CANDELETE : self::RET_CANREPLACE)) | ($sign[self::VDB_DOUBT] ? self::RET_DOUBT : 0) | ($sign[self::VDB_LAST] ? self::RET_LAST : 0) | ($sign[self::VDB_CVE] ? self::RET_CVE : 0) | ($doReplace ? ($sign[self::VDB_LAST] ? self::RET_DELETE : self::RET_REPLACED) : 0);
        if ($results !== null) {
            $results[] = ['sign' => $sign, 'flags' => $detected, 'offset' => $startOffset, 'length' => $length, 'match' => substr($text, $startOffset, $endOffset)];
        }
        if ($doReplace && !$sign[self::VDB_LAST]) {
            $text = $const ? str_replace(substr($sign[self::VDB_SIGNATURE], 1), $sign[self::VDB_REPLACE], $text) : preg_replace($sign[self::VDB_SIGNATURE], $sign[self::VDB_REPLACE], $text);
        }

        return $detected;
    }

    public static function cbhtaccessredirect($sign, &$text, $fileType, $replace = 0, &$results = null)
    {
        if (!defined('SVC_CHOST') || $sign[self::VDB_FTYPES] && !isset($sign[self::VDB_FTYPES][$fileType])) {
            return 0;
        }
        $host = strtolower(SVC_CHOST);
        if (substr($host, 0, 4) === 'www.') {
            $host = substr($host, 4);
        }
        if (!strlen($host)) {
            return 0;
        }
        $doReplace = ($replace & self::SCAN_REPLACE) && !$sign[self::VDB_INCURABLE];
        $detected = 0;
        $lines = explode("\n", $text);
        $nLines = count($lines);
        $pCond = $pEngine = -1;
        for ($i = 0; $i < $nLines; ++$i) {
            $line = strtolower(trim($lines[$i]));
            if (strlen($line) < 11 || $line[0] === '#') {
                continue;
            }
            if (substr($line, 0, 13) === 'rewriteengine') {
                if ($pEngine < 0) {
                    $pEngine = $i;
                } else {
                    $lines[$i] = '';
                }
            } elseif (substr($line, 0, 11) === 'rewritecond') {
                if ($pCond < 0) {
                    $pCond = $i;
                }
            } elseif (substr($line, 0, 11) === 'rewriterule') {
                if (preg_match('~https?:/~', $line) && !strpos($line, $host) && !preg_match('~https?:/+(?:w+\.)?(?:[\%\$]\d|\%\{\w+\})~', $line)) {
                    $detected |= self::RET_DETECTED;
                    if (self::cbhtaccessredirect_appendResult($sign, $lines[$i], $doReplace, $results)) {
                        if ($pCond < 0) {
                            unset($lines[$i]);
                        } else {
                            for ($j = $pCond; $j <= $i; ++$j) {
                                unset($lines[$j]);
                            }
                        }
                    }
                }
                $pCond = -1;
            } elseif (substr($line, 0, 13) === 'errordocument') {
                if (preg_match('~https?:/~', $line) && !strpos($line, $host)) {
                    $detected |= self::RET_DETECTED;
                    if (self::cbhtaccessredirect_appendResult($sign, $lines[$i], $doReplace, $results)) {
                        unset($lines[$i]);
                    }
                }
            }
        }
        if ($detected) {
            $detected |= ($sign[self::VDB_INCURABLE] ? self::RET_INCURABLE : self::RET_CANREPLACE) | ($sign[self::VDB_DOUBT] ? self::RET_DOUBT : 0);
            if ($doReplace) {
                $detected |= self::RET_REPLACED;
                $text = implode("\n", $lines);
            }
        }

        return $detected;
    }

    protected static function cbhtaccessredirect_appendResult($sign, $line, $replaced, &$results)
    {
        if ($results === null) {
            return $replaced;
        }
        $results[] = ['sign' => $sign, 'flags' => self::RET_DETECTED | ($sign[self::VDB_INCURABLE] ? self::RET_INCURABLE : self::RET_CANREPLACE) | ($sign[self::VDB_DOUBT] ? self::RET_DOUBT : 0) | ($replaced ? self::RET_REPLACED : 0), 'offset' => -1, 'length' => strlen($line), 'match' => $line];

        return $replaced;
    }

    public static function reMatchOffsets($re, $text, $formatter = null)
    {
        if (!strlen($re) || !is_int(@preg_match_all($re, $text, $matches, PREG_OFFSET_CAPTURE))) {
            return false;
        }
        if (!$matches[0]) {
            return [];
        }

        return self::matchOffsetsToRows($matches[0], $text, $formatter);
    }

    public static function constMatchOffsets($sub, $text, $formatter = null)
    {
        if (!is_string($sub) || !strlen($sub) || !is_int($pos = strpos($text, $sub))) {
            return [];
        }
        $matches = [];
        do {
            $matches[] = [strlen($sub), $pos];
            $pos = strpos($text, $sub, $pos + strlen($sub));
        } while (is_int($pos));

        return self::matchOffsetsToRows($matches, $text, $formatter);
    }

    public static function matchScanResultToRows($result, $text, $formatter = null)
    {
        if (!is_array($result) || !isset($result['offset'], $result['length']) || $result['offset'] < 0) {
            return null;
        }
        $absOffsets = [[$result['length'], $result['offset']]];
        $lineOffsets = self::matchOffsetsToRows($absOffsets, $text);

        return reset($lineOffsets);
    }

    public static function matchOffsetsToRows($offsets, $text, $formatter = null)
    {
        $nResult = 0;
        $results = [];
        foreach ($offsets as $offset) {
            if (!$nResult || $results[$nResult - 1][5] < $offset[1]) {
                $results[$nResult++] = [-1, -1, -1, -1, $offset[1], is_int($offset[0]) ? $offset[1] + $offset[0] : $offset[1] + strlen($offset[0])];
            }
        }
        $cPos = $nResult = 0;
        $rows = is_array($text) ? $text : explode("\n", $text);
        for ($nRow = 0, $nRows = count($rows); $nRow < $nRows; ++$nRow) {
            $rowEndAt = $cPos + strlen($rows[$nRow]) + 1;
            if ($results[$nResult][0] > -1) {
                if ($rowEndAt > $results[$nResult][5]) {
                    $results[$nResult][2] = $nRow;
                    $results[$nResult][3] = $results[$nResult][5] - $cPos;
                    --$nRow;
                    $formatter && $formatter($results[$nResult]);
                    if (!isset($results[++$nResult])) {
                        break;
                    }
                } else {
                    $cPos = $rowEndAt;
                }
            } elseif ($rowEndAt > $results[$nResult][4]) {
                $results[$nResult][0] = $nRow;
                $results[$nResult][1] = $results[$nResult][4] - $cPos;
                --$nRow;
            } else {
                $cPos = $rowEndAt;
            }
        }

        return $results;
    }

    public static function Decode($data, $gzip = true, $json = true)
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

    public static function scan_file($file, &$return)
    {
        
        self::echo_checkfile($file);
        if (!is_readable($file)) {
            return;
        }

        $fsize = filesize($file);
        $ftime = filemtime($file);
        if ($fsize < self::$min_size || self::$max_size < $fsize) {
            return;
        }
        $ftype = pathinfo($file, PATHINFO_EXTENSION);
        if (!$ftype || !isset(self::$file_types)) {
            return;
        }
        $ftext = file_get_contents($file);
        //var_dump($ftype);
        if (!is_string($ftext) || strlen($ftext) < $fsize) {
            return;
        }
        $scan_flags = 0;
        $results = [];
        $detected = self::scanBuffer($ftext, $ftype, $scan_flags, $results);
        ++$return['stats']['scannedfiles'];
        if (!$detected) {
            return;
        }

        
        foreach ($results as $result) {
            $return['threats'][] = [$file, $ftime, $result['flags'], $result['sign'][self::VDB_TITLE], $result['sign'][self::VDB_SID], $fmode, $fsize, self::matchScanResultToRows($result, $fStrings)];
        }

        //print_r($return);
    }

    public static function scan_dir($dir, &$return, $recursive = false)
    {
        $sd = realpath($dir);
        if (!$sd) {
            return;
        }
        if ($return['scan_root'] == null) {
            $return['scan_root'] = $sd;
        }
        //if (!$return['stats']['scanneddirs'])

        ++$return['stats']['scanneddirs'];

        foreach (scandir($dir) as $file) {
            if (connection_aborted()) {
                break;
            }

            if ($file[0] === '.' || $file[0] === '..') {
                continue;
            }
            $f_d = $sd.DIRECTORY_SEPARATOR.$file;
            if (is_dir($f_d)) {
                //++$return['stats']['scanneddirs'];
                if ($recursive) {
                    ++$return['stats']['checkeddirs'];
                    self::scan_dir($f_d, $return, $recursive);
                }
            } else {
                ++$result['stats']['scannedfiles'];
                self::scan_file($f_d, $return);
            }
        }

        //var_dump($cd);
    }

    public static function join_path($dirname, $basedir)
    {
        if ($dirname && len($dirname) && substr($dirname, 0, 1) == '/') {
            return $dirname;
        }

        return  $basedir.rtrim(DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR.$dirname;
    }

    public static function display_return(&$return)
    {
        echo "\033[2K\r";
        echo "\nSr No   FIle In";
        foreach ($return['threats'] as $sr => $threat) {
            echo sprintf("\n%s   %s %s", ++$sr, $threat[0], $threat[3]);
        }
        echo "\n========================<CSApiAV Scanner Report>=========================";
        echo "\nScanned ".(is_file($dir_file) ? 'File: ' : 'Directory: ').$return['scan_root'];

        echo "\nScanned No Of Dirs: ".$return['stats']['scanneddirs'];
        echo "\nChecked No Of Dirs: ".$return['stats']['checkeddirs'];
        echo "\nDetected No Of Dirs: ".$return['stats']['detecteddir'];

        echo "\nChecked Files: ".$return['stats']['checkeddirs'];
        echo "\nScanned Files: ".$return['stats']['scannedfiles'];

        echo "\nInfected Files: ".count($return['threats']);
        echo "\n========================</CSApiAV Scanner Report>========================\n";
    }



    public static function echo_checkfile($file)
    {
        static $newline;
        if (!$newline) {
            $newline = true;
            echo "\n";
        }
        $file = str_replace(getcwd(), '', $file);
        echo "\033[2K\r";
        echo "Scanning ... $file";
    }
}
if (PHP_SAPI !== 'cli') {
    return true;
}
$version = CSApiAVScanner::version();
<<<AVOUTBANNER
AVScanner Ver: {$version} , DB Version: 4

AVOUTBANNER;

/*
$shortopts = '';
$shortopts .= 'f:';  // Required value
$shortopts .= 'h:';  // Required value
$shortopts .= 'r:'; // Optional value
$options = getopt($shortopts);
if (!isset($options['f'])) {
    exit('Required scan path or file.'.chr(10));
}

if (!isset($options['r'])) {
    $options['r'] = 1;
}

$options['r'] = $options['r'] && true;
*/

if (0)
{

$options['f'] = "/Applications/XAMPP/xamppfiles/htdocs/vdie/malwares_samples";

$f_vdir_db = './v1/vdie/sigs.db';
$vdb = json_decode( file_get_contents($f_vdir_db), true);
#$vdb = CSApiAVScanner::Decode(file_get_contents('vdb.json'));
#print_r( count($vdb)); die;
$error = null;
CSApiAVScanner::setVDB($vdb, $error);
#print_r( count( CSApiAVScanner::$vdb)); die;
$return = ['threats' => [], 'scan_root' => null,  'errors' => [], 'dirlist' => [], 'skipped' => [], 'stats' => ['threats' => 0, 'checkedfiles' => 0, 'scannedfiles' => 0, 'detectedfiles' => 0, 'detecteddirs' => 0,  'checkeddirs' => 0, 'scanneddirs' => 0, 'errors' => 0, 'treated' => 0, 'backupid' => 0, 'seconds' => 0.0]];
$return['stats']['seconds'] = microtime(true);
CSApiAVScanner::scan_dir($options['f'], $return, $options['r']);
CSApiAVScanner::display_return($return);
die;
}


class CodeMatch
{
    const DANGEROUS = 'danger';
    const WARNING = 'warn';

}

class Exploits
{
    /**
     * Default exploits definitions.
     *
     * @var array
     */
    protected static $default = [
        'eval_chr' => [
            'description' => 'RCE (Remote Code Execution) allow remote attackers to execute arbitrary commands or code on the target machine',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/eval[\s]*\([\s]*chr[\s]*\(.*?[\s]*\)/i',
        ],
        'eval_chr_obf' => [
            'description' => 'RCE (Remote Code Execution) allow remote attackers to execute arbitrary commands or code on the target machine',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/chr[\s]*\([\s]*101[\s]*\)[\s]*\.[\s]*chr[\s]*\([\s]*118[\s]*\)[\s]*\.[\s]*chr[\s]*\([\s]*97[\s]*\)[\s]*\.[\s]*chr[\s]*\([\s]*108[\s]*\)/i',
        ],
        'eval_preg' => [
            'description' => 'RCE (Remote Code Execution), through PCRE (Perl compatible Regular Expression), allow remote attackers to execute arbitrary commands or code on the target machine',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/(preg_replace(_callback)?|mb_ereg_replace|preg_filter)[\s]*\([^)]*(\/|\\\\x2f)(e|\\\\x65)[\\\'\"].*?(?=\))\)/i',
        ],
        'eval_base64' => [
            'description' => 'RCE (Remote Code Execution), through Base64 text, allow remote attackers to execute arbitrary commands or code on the target machine',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/eval[\s]*\([\s]*base64_decode[\s]*\((?<=\().*?(?=\))\)/i',
        ],
        'eval_comment' => [
            'description' => 'RCE (Remote Code Execution) allow remote attackers to execute arbitrary commands or code on the target machine',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/(eval|preg_replace|system|assert|passthru|(pcntl_)?exec|shell_exec|call_user_func(_array)?)\/\*[^\*]*\*\/\((?<=\().*?(?=\))\)/',
        ],
        'eval_execution' => [
            'description' => 'RCE (Remote Code Execution) and Code Injection allow remote attackers to execute arbitrary commands or code on the target machine via HTTP request',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/(eval[\s]*\([\s]*\$[a-z0-9_]+[\s]*\([\s]*(?<=\()@?\$_(GET|POST|SERVER|COOKIE|REQUEST).*?(?=\))\)/si',
        ],
        'align' => [
            'description' => 'Code alignment technique is usually used for the obfuscation of malicious code',
            'level' => CodeMatch::WARNING,
            'pattern' => '/(\$\w+=[^;]*)*;\$\w+=@?\$\w+\((?<=\().*?(?=\))\)/si',
        ],
        // b374k shell
        'b374k' => [
            'description' => 'Web shell (b374k) for the remote management',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/[\'"]ev[\'"]\.[\'"]al[\'"]\.[\'"][\s]*\([\s]*("|\\\')[\s]*\?>/i',
            'link' => 'https://github.com/b374k/b374k',
        ],
        // weevely3 launcher
        'weevely3' => [
            'description' => 'Web shell (Weevely) for post-exploitation purposes that can be extended over the network at runtime',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/\$\w=\$[a-zA-Z]\(\'\',\$\w\);\$\w\(\);/i',
            'link' => 'https://github.com/epinna/weevely3',
        ],
        'c99_launcher' => [
            'description' => 'Web Shell (C99) designed for post-exploitation purposes that can be extended over the network at runtime',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/;\$\w+\(\$\w+(,\s?\$\w+)+\);/i',
            'link' => 'https://github.com/4Hackerz/C99-Shell',
        ],
        // concatenation of more than eight `chr()`
        'too_many_chr' => [
            'description' => 'Concatenation of `chr` technique is usually used for the obfuscation of malicious code',
            'level' => CodeMatch::WARNING,
            'pattern' => '/(chr\([\d]+\)\.){8}/i',
        ],
        // concatenation of vars array
        'concat' => [
            'description' => 'Concatenation of arrays technique is usually used for the obfuscation of malicious code',
            'level' => CodeMatch::WARNING,
            'pattern' => '/(\$[\w\[\]\\\'\"]+\\.[\n\r]*){10}/i',
        ],
        // concatenation of more than 6 words, with spaces
        'concat_vars_with_spaces' => [
            'description' => 'Concatenation of vars technique is usually used for the obfuscation of malicious code',
            'level' => CodeMatch::WARNING,
            'pattern' => '/(\$([a-zA-Z0-9]+)[\s]*\.[\s]*){6}/',
        ],
        // concatenation of more than 6 words, with spaces
        'concat_vars_array' => [
            'description' => 'Concatenation of arrays technique is usually used for the obfuscation of malicious code',
            'level' => CodeMatch::WARNING,
            'pattern' => '/(\$([a-zA-Z0-9]+)(\{|\[)([0-9]+)(\}|\])[\s]*\.[\s]*){6}.*?(?=\})\}/i',
        ],
        'var_as_func' => [
            'description' => 'RCE (Remote Code Execution) and Code Injection, through global vars used as PHP function, allow remote attackers to execute PHP code on the target machine via HTTP request',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/\$_(GET|POST|COOKIE|REQUEST|SERVER)[\s]*\[[^\]]+\][\s]*\((?<=\().*?(?=\))\)/i',
        ],
        'global_var_string' => [
            'description' => 'Code Injection, through escaped global vars, allow inject attackers to execute PHP code on the target machine via HTTP request',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/\$\{[\s]*[\'"]_(GET|POST|COOKIE|REQUEST|SERVER)[\'"][\s]*\}/i',
        ],
        'extract_global' => [
            'description' => 'Code Injection, extracting global var arrays, allow remote attackers to inject PHP code on the target machine via HTTP request',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/extract\([\s]*\$_(GET|POST|COOKIE|REQUEST|SERVER).*?(?=\))\)/i',
        ],
        'escaped_path' => [
            'description' => 'Escaped path technique is usually used for the obfuscation of malicious code',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/(\\\\x[0-9abcdef]{2}[a-z0-9.-\/]{1,4}){4,}/i',
        ],
        'include_icon' => [
            'description' => 'LFI (Local File Inclusion), including `.ico` file, allow remote attackers to execute arbitrary commands or code on the target machine',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/@?include[\s]*(\([\s]*)?("|\\\')([^"\\\']*)(\.|\\\\056\\\\046\\\\2E)(\i|\\\\151|\\\\x69|\\\\105)(c|\\\\143\\\\099\\\\x63)(o|\\\\157\\\\111|\\\\x6f)(\"|\\\')((?=\))\))?/mi',
        ],
        'backdoor_code' => [
            'description' => 'Backdoor that checks to see if the user is a web spider and if not, retrieves data from another webserver and displays it to the visitor',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/eva1fYlbakBcVSir/i',
        ],
        'infected_comment' => [
            'description' => 'Comments composed by 5 random chars usually used to detect if a file is infected yet',
            'level' => CodeMatch::WARNING,
            'pattern' => '/\/\*[a-z0-9]{5}\*\//i',
        ],
        'hex_char' => [
            'description' => 'Hex char is usually used for the obfuscation of malicious code',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/\\\\[Xx](5[Ff])/i',
        ],
        'hacked_by' => [
            'description' => 'Hacker credits',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/hacked[\s]*by/i',
        ],
        'killall' => [
            'description' => 'RCE (Remote Code Execution) that allow remote attackers to kill processes on the target machine',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/killall[\s]*\-9/i',
        ],
        'globals_concat' => [
            'description' => 'Concatenation of globals vars technique is usually used for the obfuscation of malicious code',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/\$GLOBALS\[[\s]*\$GLOBALS[\\\'[a-z0-9]{4,}\\\'\]/i',
        ],
        'globals_assign' => [
            'description' => 'Global vars assignment is usually used for the obfuscation of malicious code',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/\$GLOBALS\[\\\'[a-z0-9]{5,}\\\'\][\s]*=[\s]*\$[a-z]+\d+\[\d+\]\.\$[a-z]+\d+\[\d+\]\.\$[a-z]+\d+\[\d+\]\.\$[a-z]+\d+\[\d+\]\./i',
        ],
        'base64_long' => [
            'description' => 'Long Base64 encoded text is usually used for the obfuscation of malicious code',
            'level' => CodeMatch::WARNING,
            'pattern' => '/[\\\'\"][A-Za-z0-9+\/]{260,}={0,3}[\\\'\"]/',
        ],
        'base64_inclusion' => [
            'description' => 'LFI (Local File Inclusion), through a Base64 inclusion, allow remote attackers to inject and execute arbitrary commands or code on the target machine',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/@?include[\s]*(\([\s]*)?("|\\\')data\:text/plain;base64[\s]*\,[\s]*\$_GET\[[^\]]+\](\\\'|")[\s]*((?=\))\))?/si',
        ],
        'clever_include' => [
            'description' => 'LFI (Local File Inclusion), through a image inclusion, allow remote attackers to inject and execute arbitrary commands or code on the target machine',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/@?include[\s]*(\([\s]*)?("|\\\')[\s]*[^\.]+\.(png|jpe?g|gif|bmp|ico).*?("|\\\')[\s]*((?=\))\))?/i',
        ],
        'basedir_bypass' => [
            'description' => 'Basedir bypass used for manipulate files or execute code outside the base directory set on the server configuration',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/curl_init[\s]*\([\s]*[\"\\\']file:\/\/.*?(?=\))\)/i',
        ],
        'basedir_bypass2' => [
            'description' => 'Basedir bypass used for manipulate files or execute code outside the base directory set on the server configuration',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/file\:file\:\/\//i',
        ],
        'non_printable' => [
            'description' => 'Non printable technique is usually used for the obfuscation of malicious code',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/(function|return|base64_decode).{,256}[^\\x00-\\x1F\\x7F-\\xFF]{3}/i',
        ],
        'double_var' => [
            'description' => 'Double var technique is usually used for the obfuscation of malicious code',
            'level' => CodeMatch::WARNING,
            'pattern' => '/\${[\s]*\${.*?}(.*)?}/i',
        ],
        'double_var2' => [
            'description' => 'Double var technique is usually used for the obfuscation of malicious code',
            'level' => CodeMatch::WARNING,
            'pattern' => '/\${\$[0-9a-zA-z]+}/i',
        ],
        'global_save' => [
            'description' => 'Globals assignment technique is usually used for the obfuscation of malicious code',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/\[\s]*=[\s]*\$GLOBALS[\s]*\;[\s]*\$[\s]*\{/i',
        ],
        // Check for ${"\xFF"}, IonCube use this method ${"\x
        'hex_var' => [
            'description' => 'Hex var technique is usually used for the obfuscation of malicious code, it is also used by IonCube',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/\$\{[\s]*[\'"]\\\\x.*?(?=\})\}/i',
        ],
        'register_function' => [
            'description' => 'RCE (Remote Code Execution) allow remote attackers to execute PHP code on the target machine',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/register_[a-z]+_function[\s]*\([\s]*[\\\'\"][\s]*(eval|assert|passthru|exec|include|system|shell_exec|`).*?(?=\))\)/i',
        ],
        'safemode_bypass' => [
            'description' => 'RCE (Remote Code Execution) allow remote attackers to execute PHP code on the target machine',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/\x00\/\.\.\/|LD_PRELOAD/i',
        ],
        'ioncube_loader' => [
            'description' => 'IonCube is a PHP encoder and hence a module/library for protected functions and often used for the obfuscation of malicious code',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/IonCube\_loader/i',
            'link' => 'https://www.ioncube.com',
        ],
        'nano' => [
            'description' => 'Nano is a family of PHP webshells which are code golfed to be extremely stealthy and efficient',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/\$[a-z0-9-_]+\[[^]]+\]\((?<=\().*?(?=\))\)/',
            'link' => 'https://github.com/s0md3v/nano',
        ],
        'nano2' => [
            'description' => 'Nano is a family of PHP webshells which are code golfed to be extremely stealthy and efficient',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/base64_decode[^;]+getallheaders/',
            'link' => 'https://github.com/s0md3v/nano',
        ],
        // function that takes a callback as 1st parameter
        'execution' => [
            'description' => 'RCE (Remote Code Execution) allow remote attackers to execute PHP code on the target machine via HTTP',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/\b(eval|assert|passthru|exec|include|system|pcntl_exec|shell_exec|base64_decode|`|array_map|ob_start|call_user_func(_array)?)[\s]*\([\s]*(base64_decode|php:\/\/input|str_rot13|gz(inflate|uncompress)|getenv|pack|\\\\?@?\$_(GET|REQUEST|POST|COOKIE|SERVER)).*?(?=\))\)/',
            'link' => 'https://cwe.mitre.org/data/definitions/77.html, https://cwe.mitre.org/data/definitions/78.html',
        ],
        // functions that takes a callback as 2nd parameter
        'execution2' => [
            'description' => 'RCE (Remote Code Execution) allow remote attackers to execute PHP code on the target machine via HTTP',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/\b(array_filter|array_reduce|array_walk(_recursive)?|array_walk|assert_options|uasort|uksort|usort|preg_replace_callback|iterator_apply)[\s]*\([\s]*[^,]+,[\s]*(base64_decode|php:\/\/input|str_rot13|gz(inflate|uncompress)|getenv|pack|\\\\?@?\$_(GET|REQUEST|POST|COOKIE|SERVER)).*?(?=\))\)/',
            'link' => 'https://cwe.mitre.org/data/definitions/77.html, https://cwe.mitre.org/data/definitions/78.html',
        ],
        // functions that takes a callback as 2nd parameter
        'execution3' => [
            'description' => 'RCE (Remote Code Execution) allow remote attackers to execute PHP code on the target machine via HTTP',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/\b(array_(diff|intersect)_u(key|assoc)|array_udiff)[\s]*\([\s]*([^,]+[\s]*,?)+[\s]*(base64_decode|php:\/\/input|str_rot13|gz(inflate|uncompress)|getenv|pack|\\\\?@?\$_(GET|REQUEST|POST|COOKIE|SERVER))[\s]*\[[^]]+\][\s]*\)+[\s]*;/',
            'link' => 'https://cwe.mitre.org/data/definitions/77.html, https://cwe.mitre.org/data/definitions/78.html',
        ],
        'shellshock' => [
            'description' => 'Shell shock technique is usually used for the obfuscation of malicious code using PHP functions',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/\(\)[\s]*{[\s]*[a-z:][\s]*;[\s]*}[\s]*;/',
        ],
        'silenced_eval' => [
            'description' => 'RCE (Remote Code Execution) allow remote attackers to execute PHP code on the target machine',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/@eval[\s]*\((?<=\().*?(?=\))\)/',
        ],
        'silence_inclusion' => [
            'description' => 'LFI (Local File Inclusion), through a silent inclusion, allow remote attackers to inject and execute arbitrary commands or code on the target machine',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/@(include|include_once|require|require_once)[\s\r\n]+([\s]*\()?("|\\\')([^"\\\']*)(\\\\x[0-9a-f]{2,}.*?){2,}([^"\\\']*)("|\\\')[\s]*((?=\))\))?/si',
        ],
        'silence_inclusion2' => [
            'description' => 'LFI (Local File Inclusion), through a silent inclusion, allow remote attackers to inject and execut arbitrary commands or code on the target machine',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/@(include|include_once|require|require_once)[\s\r\n]+([\s]*\()?("|\\\')([^"\\\']*)(\\[0-9]{3,}.*?){2,}([^"\\\']*)("|\\\')[\s]*((?=\))\))?/si',
        ],
        'ssi_exec' => [
            'description' => 'SSI (Server-Side Includes) injection allows the exploitation of a web application by injecting malicious code on the target machine',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/\<\!\-\-\#exec[\s]*cmd\=/i',
            'link' => 'https://owasp.org/www-community/attacks/Server-Side_Includes_(SSI)_Injection, http://www.w3.org/Jigsaw/Doc/User/SSI.html#exec',
        ],
        'htaccess_handler' => [
            'description' => 'RCE (Remote Code Execution), through Htaccess handler x-httpd-php/cgi, interpreting PHP code, allow remote attackers to execute PHP code on the target machine',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/SetHandler[\s]*application\/x\-httpd\-(php|cgi)/i',
        ],
        'htaccess_type' => [
            'description' => 'RCE (Remote Code Execution), through Htaccess add type x-httpd-php/cgi, interpreting PHP code, allow remote attackers to execute PHP code on the target machine',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/AddType\s+application\/x-httpd-(php|cgi)/i',
        ],
        'file_prepend' => [
            'description' => 'LFI (Local File Inclusion), prepending a file at the bottom of every others PHP files, allow remote attackers to inject and execute arbitrary commands or code on the target machine',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/php_value[\s]*auto_prepend_file/i',
        ],
        'iis_com' => [
            'description' => 'RCE (Remote Code Execution), through ISS Server, allow remote attackers to execute arbitrary commands or code on the target machine',
            'level' => CodeMatch::WARNING,
            'pattern' => '/IIS\:\/\/localhost\/w3svc/i',
        ],
        'reversed' => [
            'description' => 'Reverse function technique is used for the obfuscation of dangerous PHP functions',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/(noitcnuf\_etaerc|metsys|urhtssap|edulcni|etucexe\_llehs|ecalper\_rts|ecalper_rts)/i',
        ],
        'rawurlendcode_rot13' => [
            'description' => 'Raw url decode and rot13 string together technique is usually used for the obfuscation of malicious code',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/rawurldecode[\s]*\(str_rot13[\s]*\((?<=\().*?(?=\))\)/i',
        ],
        'serialize_phpversion' => [
            'description' => 'RCE (Remote Code Execution), unserializing php version, allow remote attackers to execute arbitrary commands or code on the target machine',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/\@serialize[\s]*\([\s]*(Array\(|\[)[\'"]php[\'"][\s]*\=\>[\s]*\@phpversion[\s]*\((?<=\().*?(?=\))\)/si',
        ],
        'md5_create_function' => [
            'description' => 'The `create_function` technique is usually used for the obfuscation of malicious code',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/\$md5[\s]*=[\s]*.*create_function[\s]*\(.*?\);[\s]*\$.*?\)[\s]*;/si',
        ],
        'god_mode' => [
            'description' => 'RCE (Remote Code Execution) allow remote attackers to execute arbitrary commands or code on the target machine',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/\/\*god_mode_on\*\/eval\(base64_decode\([\"\\\'][^\"\\\']{255,}[\"\\\']\)\);[\s]*\/\*god_mode_off\*\//si',
        ],
        'wordpress_filter' => [
            'description' => 'Wordpress Filter RCE (Remote Code Execution) allow remote attackers to execute arbitrary commands or code on the target machine',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/\$md5[\s]*=[\s]*[\"|\\\']\w+[\"|\\\'];[\s]*\$wp_salt[\s]*=[\s]*[\w\(\),\"\\\'\;$]+[\s]*\$wp_add_filter[\s]*=[\s]*create_function\(.*?\);[\s]*\$wp_add_filter\(.*?\);/si',
        ],
        'password_protection_md5' => [
            'description' => 'MD5 Password protection file, typically used on web shells',
            'level' => CodeMatch::WARNING,
            'pattern' => '/md5[\s]*\([\s]*@?\$_(GET|REQUEST|POST|COOKIE|SERVER)[^)]+\)[\s]*===?[\s]*[\\\'\"][0-9a-f]{32}[\\\'\"]/si',
        ],
        'password_protection_sha' => [
            'description' => 'SHA Password protection file, typically used on web shells',
            'level' => CodeMatch::WARNING,
            'pattern' => '/sha[\d]+[\s]*\([\s]*@?\$_(GET|REQUEST|POST|COOKIE|SERVER)[^)]+\)[\s]*===?[\s]*[\\\'\"][0-9a-f]{40}[\\\'\"]/si',
        ],
        'custom_math' => [
            'description' => 'Custom math technique is usually used for the obfuscation of malicious code',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/%\(\d+[\s]*\-[\s]*\d+[\s]*\+[\s]*\d+\)[\s]*==[\s]*\([\s]*\-[\s]*\d+[\s]*\+[\s]*\d+[\s]*\+[\s]*\d+[\s]*\)/si',
        ],
        'custom_math2' => [
            'description' => 'Custom math technique is usually used for the obfuscation of malicious code',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/\([\s]*\$[a-zA-Z0-9]+%\d[\s]*==[\s]*\([\s]*\d+[\s]*\-[\s]*\d+[\s]*\+[\s]*\d+[\s]*\)/si',
        ],
        'uncommon_function' => [
            'description' => 'Function name technique usually used for the obfuscation of malicious code',
            'level' => CodeMatch::WARNING,
            'pattern' => 'function\s+_[0-9]{8,}[\s]*\([\s]*(?<=\().*?(?=\))\)',
        ],
        'download_remote_code' => [
            'description' => 'RFU (Remote File Upload), via HTTP, allow to write malicious code on the target machine',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/file_get_contents[\s]*\([\s]*base64_url_decode[\s]*\([\s]*@*\$_(GET|POST|SERVER|COOKIE|REQUEST).*?(?=\))\)/i',
        ],
        'download_remote_code2' => [
            'description' => 'RFU (Remote File Upload), via HTTP, allow to write malicious code on the target machine',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/fwrite[\s]*(\(\w+\((?<=\().*?(?=\))\))?[^\)]*\$_(GET|POST|SERVER|COOKIE|REQUEST).*?(?=\))\)/si',
        ],
        'download_remote_code3' => [
            'description' => 'RFU (Remote File Upload), via HTTP, allow to write malicious code on the target machine',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/(file_get_contents|fwrite)[\s]*\([\s]*@?*\$_(GET|POST|SERVER|COOKIE|REQUEST).*?(?=\))\)/si',
            'link' => 'https://www.acunetix.com/blog/articles/local-file-inclusion-lfi',
        ],
        'download_remote_code_web' => [
            'description' => 'RFU (Remote File Upload), from external website, allow to write malicious code on the target machine',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/(file_get_contents|file_put_contents)[\s]*\([\s]*[\'"]https?:\/\/(codepad|pastebin|controlc|hastebin|justpaste|privatebin|cryptbin|zerobin)\.(org|com|net|in|me).*?(?=\))\)/i',
        ],
        'php_uname' => [
            'description' => 'RCE (Remote Code Execution) allow remote attackers to execute arbitrary commands or code on the target machine',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/php_uname[\s]*\([\s]*["\'asrvm]+[\s]*\)/si',
        ],
        'etc_passwd' => [
            'description' => 'The `/etc/passwd` file on Unix systems contains password information, an attacker who has accessed the `etc/passwd` file may attempt a brute force attack of all passwords on the system',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/(\/)*etc\/+passwd\/*/si',
        ],
        'etc_shadow' => [
            'description' => 'The `/etc/shadow` file on Unix systems contains password information, an attacker who has accessed the `etc/shadow` file may attempt a brute force attack of all passwords on the system',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/(\/)*etc\/+shadow\/*/si',
        ],
        'explode_chr' => [
            'description' => 'RCE (Remote Code Execution), exploding chars, allow remote attackers to execute arbitrary commands or code on the target machine',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/explode[\s]*\(chr[\s]*\([\s]*\(?\d{3}([\s]*-[\s]*\d{3})?[\s]*\).*?(?=\))\)/i',
        ],
        'imap_open' => [
            'description' => 'RCE (Remote Code Execution), through imap_open, allow remote attackers to execute arbitrary commands or code on the target machine',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/imap_open\([\'"]{[\'"][\s]*\.[\s]*\$_(GET|POST|SERVER|COOKIE|REQUEST).*?(?=\))\)/i',
            'link' => 'https://bugs.php.net/bug.php?id=76428',
        ],
        'imap_open_proxy' => [
            'description' => 'RCE (Remote Code Execution), through imap, allow remote attackers to execute arbitrary commands or code on the target machine',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/x[\s]*\-oProxyCommand[\s]*\=(.*?\|base64(\\\\t\-d)?(\|sh)?)?/i',
        ],
        'exec_escaped' => [
            'description' => 'RCE (Remote Code Execution), through exec escaped chars, allow remote attackers to execute arbitrary commands or code on the target machine',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/exec[\s]*[\s]*\([\s]*[\'"][\s]*([\s]*\\[0-9a-fx]{2,3}[\s]*){3,}/i',
        ],
        'urldecode_concat' => [
            'description' => 'RCE (Remote Code Execution), through concatenated text encoded with urldecode or rawurldecode, allow remote attackers to execute arbitrary commands or code on the target machine',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/(\$[a-z]{2,}[\s]*=[\s]*(urldecode|rawurldecode)[\s]*\([\s]*\$_(GET|REQUEST|POST|COOKIE|SERVER)[\s]*\[[\s]*\'[\s]*[a-z]{2,}[\s]*\'[\s]*\][\s]*\)[\s]*;[\s]*){3,}/i',
        ],
        'xor_post_payload' => [
            'description' => 'XOR post technique is usually used for the obfuscation of malicious code',
            'level' => CodeMatch::WARNING,
            'pattern' => '/([\s]*\$\w+[\s]*\[[\s]*\$\w+[\s]*%[\s]*strlen[\s]*\([\s]*\$\w+\)[\s]*\][\s]*\;?[\s]*){2,}/i',
        ],
        'source_guardian' => [
            'description' => 'SourceGuardian is a PHP encoder often used for the obfuscation of malicious code',
            'level' => CodeMatch::DANGEROUS,
            'pattern' => '/[;\s]*sg\_load[\s]*\([\s]*[\\\'\"][A-Za-z0-9+\/]{150,}={0,3}[\\\'\"][\s]*\)/i',
            'link' => 'https://www.sourceguardian.com',
        ],
    ];

    /**
     * Get all exploits.
     *
     * @return array[]
     */
    public static function getAll()
    {
        return self::$default;
    }

    /**
     * Get lite exploits.
     *
     * @return array[]
     */
    public static function getLite()
    {
        $exploits = self::$default;

        // Function that takes a callback as 1st parameter
        $exploits['execution']['pattern'] = '/\b(eval|assert|passthru|exec|include|system|pcntl_exec|shell_exec|`|array_map|ob_start|call_user_func(_array)?)\s*\(\s*(base64_decode|php:\/\/input|str_rot13|gz(inflate|uncompress)|getenv|pack|\\?\$_(GET|REQUEST|POST|COOKIE|SERVER)).*?(?=\))\)/';
        // Concatenation of more than 8 words, with spaces
        $exploits['concat_vars_with_spaces']['pattern'] = '/(\$([a-zA-Z0-9]+)[\s\r\n]*\.[\s\r\n]*){8}/';
        // Concatenation of more than 8 words, with spaces
        $exploits['concat_vars_array']['pattern'] = '/(\$([a-zA-Z0-9]+)(\{|\[)([0-9]+)(\}|\])[\s\r\n]*\.[\s\r\n]*){8}.*?(?=\})\}/i';

        unset(
            $exploits['nano'],
            $exploits['double_var2'],
            $exploits['base64_long']
        );

        return $exploits;
    }
}

/*
die(var_dump( preg_match('#[\'"]\)\);return;\?>(?<X76af356d>)#ims', '"));return;?>', $matches), $matches)); 
*/

/*
base = "https://www.zbapis.net/api/bl/checks-by-black-list-id?host=expresshomeandofficecleaning.co.nz&captcha=" + "1650371408.741.148" +"&id="
base = "https://www.zbapis.net/api/bl/get-blacklist-by-host?host=rankwatch.com&captcha=" + "1650371408.741.148"
ALL = [];
31ee456f2ef8477b970d5cd1092aa42c
for(var i=1; i<=1; i++)
{
    uri = base + i;
    const response = await fetch(uri);
    console.log("[" + i +"] " + "[" + response.status + "] " + uri);
    if (response.status !== 200)
        break;
    ALL.push(await response.json())
}


*/

$chekclist = [
          "url.0spam.org",
          "0spamurl.fusionzero.com",
          "uribl.zeustracker.abuse.ch",
          "uribl.abuse.ro",
          "blacklist.netcore.co.in",
          "bsb.empty.us",
          "bsb.spamlookup.net",
          "black.dnsbl.brukalai.lt",
          "light.dnsbl.brukalai.lt",
          "bl.fmb.la",
          "communicado.fmb.la",
          "nsbl.fmb.la",
          "short.fmb.la",
          "black.junkemailfilter.com",
          "uribl.mailcleaner.net",
          "dbl.nordspam.com",
          "ubl.nszones.com",
          "uribl.pofon.foobar.hu",
          "rhsbl.rbl.polspam.pl",
          "rhsbl-h.rbl.polspam.pl",
          "mailsl.dnsbl.rjek.com",
          "urlsl.dnsbl.rjek.com",
          "rhsbl.rymsho.ru",
          "public.sarbl.org",
          "rhsbl.scientificspam.net",
          "nomail.rhsbl.sorbs.net",
          "badconf.rhsbl.sorbs.net",
          "rhsbl.sorbs.net",
          "fresh.spameatingmonkey.net",
          "fresh10.spameatingmonkey.net",
          "fresh15.spameatingmonkey.net",
          "fresh30.spameatingmonkey.net",
          "freshzero.spameatingmonkey.net",
          "uribl.spameatingmonkey.net",
          "urired.spameatingmonkey.net",
          "dbl.spamhaus.org",
          "dnsbl.spfbl.net",
          "dbl.suomispam.net",
          "multi.surbl.org",
          "uribl.swinog.ch",
          "dob.sibl.support-intelligence.net",
          "dbl.tiopan.com",
          "black.uribl.com",
          "grey.uribl.com",
           "multi.uribl.com",
          "red.uribl.com",
          "uri.blacklist.woody.ch",
          "rhsbl.zapbl.net",
          "all.s5h.net",
        "b.barracudacentral.org",
        "bl.spamcop.net",
        "blacklist.woody.ch",
        "bogons.cymru.com",
        "cbl.abuseat.org",
        "cdl.anti-spam.org.cn",
        "combined.abuse.ch",
        "db.wpbl.info",
        "dnsbl-1.uceprotect.net",
        "dnsbl-2.uceprotect.net",
        "dnsbl-3.uceprotect.net",
        "dnsbl.anticaptcha.net",
        "dnsbl.dronebl.org",
        "dnsbl.inps.de",
        "dnsbl.sorbs.net",
        "drone.abuse.ch",
        "duinv.aupads.org",
        "dul.dnsbl.sorbs.net",
        "dyna.spamrats.com",
        "dynip.rothen.com",
        "http.dnsbl.sorbs.net",
        "ips.backscatterer.org",
        "ix.dnsbl.manitu.net",
        "korea.services.net",
        "misc.dnsbl.sorbs.net",
        "noptr.spamrats.com",
        "orvedb.aupads.org",
        "pbl.spamhaus.org",
        "proxy.bl.gweep.ca",
        "psbl.surriel.com",
        "relays.bl.gweep.ca",
        "relays.nether.net",
        "sbl.spamhaus.org",
        "short.rbl.jp",
        "singular.ttk.pte.hu",
        "smtp.dnsbl.sorbs.net",
        "socks.dnsbl.sorbs.net",
        "spam.abuse.ch",
        "spam.dnsbl.anonmails.de",
        "spam.dnsbl.sorbs.net",
        "spam.spamrats.com",
        "spambot.bls.digibase.ca",
        "spamrbl.imp.ch",
        "spamsources.fabel.dk",
        "ubl.lashback.com",
        "ubl.unsubscore.com",
        "virus.rbl.jp",
        "web.dnsbl.sorbs.net",
        "wormrbl.imp.ch",
        "xbl.spamhaus.org",
        "z.mailspike.net",
        "zen.spamhaus.org",
        "zombie.dnsbl.sorbs.net"
];

/*

echo "\nCount : ", count($chekclist), "\n";
$check_ip = 0;
$_GET[ $check_ip ? 'check_ip' : 'check_domain'] = $check_ip  ? "69.167.154.36" : 'expresshomeandofficecleaning.co.nz' ;
foreach($chekclist as $sr=> $dns) {
    if ( isset($_GET['check_ip'])) {
        $reverse_ip = implode(".", array_reverse(explode(".", $_GET['check_ip']))) . "." .  $dns . ".";     
    } else {
        $reverse_ip = $_GET['check_domain'] . "." .  $dns . ".";  
    }
    echo "\n {$sr} - $reverse_ip : " , (( checkdnsrr($reverse_ip, "A")) ? 'False' : 'True');
}
die("ee");

*/

function build_blacklisted($save=false) {
    /* https://www.zerobounce.net/services/blacklist-checker.html */
    /* https://www.zbapis.net/api/bl/get-blacklist-by-host?host=rankwatch.com&captcha=1650434177.869.967 */
    /* https://www.zbapis.net/api/bl/checks-by-black-list-id?host=rankwatch.com&captcha=1650434177.869.967&id=6 */

    $blist_host = json_decode(file_get_contents('./zbapis-blacklists-host.json'), true);
    #die(print_r($blist_host));die;
    echo "\nCount of Hosts: ", count($blist_host), "\n";

    $sgns = [];
    foreach($blist_host as $host) {
        $sgns[]  = [$host['Id'], 1,  $host['Name'], $host['DnsZone'], $host['Url']];
    }
    



    #
    $blist_ip = json_decode(file_get_contents('./zbapis-blacklists-ip.json'), true);
    echo "Count of IP: ", count($blist_ip), "\n";
    foreach($blist_ip as $host) {
        $sgns[]  = [$host['Id'], 2, $host['Name'], $host['DnsZone'], $host['Url']];
    }


    #
    $blist_ip = json_decode( str_replace("'", '"', file_get_contents('./malware-blacklists-ip.json'))); #, true);
    #print_r($blist_ip); die;
    foreach($blist_ip as $host) {
        $b = false;
        foreach($sgns as $s) {
            if ( $s[3] ===  $host )
                {$b = true;break;}
        }

        if (!$b)
        {
            $new = ['virus.rbl.jp' => [1012, 'RBL JP', 'http://www.rbl.jp/' ], 'ubl.unsubscore.com' => [1011, 'Unsubscribe Blacklist (UBL)', 'https://blacklist.lashback.com/' ], 'ubl.lashback.com' => [1010, 'LashBack - Unsubscribe Blacklist', 'http://blacklist.lashback.com/' ], 'spam.abuse.ch' => [1009, 'Fighting malware and botnets', 'https://www.abuse.ch/?p=532' ],  'short.rbl.jp' => [1008, 'rbl.jp', 'http://www.rbl.jp/' ],  'relays.bl.gweep.ca' => [1007, 'Relays gweep', 'http://relays.bl.gweep.ca' ],  'proxy.bl.gweep.ca' => [1006, 'Blacklist Proxy Gweep', '' ],   'duinv.aupads.org' => [1005, 'ANTISPAM UFRJ', 'http://www.aupads.org' ],  'drone.abuse.ch' => [1004, 'abuse.ch FastFlux Tracker', 'https://www.abuse.ch/?p=532' ],  'dnsbl.anticaptcha.net' => [1003, 'AntiCaptcha.NET Project', 'http://anticaptcha.net/' ], 'combined.abuse.ch' => [1002, 'abuse.ch | Fighting malware and botnets', 'https://www.abuse.ch/?p=532' ], 'cdl.anti-spam.org.cn' => [1001, 'CASA RBL', 'http://www.anti-spam.org.cn/' ]  ]; 
            if ( !isset($new[$host])) {
                die($host);
            }
            $sgns[]  = [$new[$host][0], 2, $new[$host][1], $host, $new[$host][2]];
        }
    }
    #print_r($sgns); die;
    if ($save)
    {
        file_put_contents('./../bin/blacklist_servers.json',  json_encode($sgns));
    }
    return $sgns;
}

print_r([4=>"1","2", "3"]);
die;
die(print_r(build_blacklisted(true)));


function  build_db() {
    require_once('./LoadSignaturesForScan.php');
    define('AI_EXPERT',  2);  define('DEBUG_PERFORMANCE',  0);
    #var_dump(AI_EXPERT, DEBUG_PERFORMANCE);
    $signs = new LoadSignaturesForScan('./v1/aibolit/ai-bolit-hoster-full.db', AI_EXPERT, DEBUG_PERFORMANCE);
   # print_r( $signs->_FlexDBShe); die;



    $signs_regex  = [];
    $signs_regex["EX"] = [];
    #https://github.com/marcocesarato/PHP-Antimalware-Scanner 
    foreach(Exploits::getAll() as $key => $value) {
        $key =  join(":", explode("_",   strtoupper($key)));
        $sign = sprintf("EXP:%s:%s", $key,  $value['level'] == 'danger' ? 'D' : 'W' );
        $signs_regex["EX"][$sign] = $value['pattern'];
    }

    
    $signs_regex["RX"] = [];
    require_once('./signatures.php');
    foreach(AMWScan\Signatures::getAll() as $key => $pattern) {
        $sign = "MAL:RX:{$key}";
        $signs_regex["RX"][$sign] = $pattern;
    }


    function sign_key($value) {
        #var_dump(preg_split('/(-|\.)/', $value)); die;
        #$value ="BIJA:333:3333:333";
        #var_dump($value);
        $value = preg_replace( '/\s+/', ':', ucwords(join(" ", preg_split('/(-|\.)/', $value))));
        $value = preg_replace_callback( '/(\d+)/', function($match){ var_dump($match[0]) ; return dechex($match[0]);} , $value);
        #var_dump($value);
        #die;
        #$value .= ":";
        return $value;
    };
    $f_seqdata = './v1/seqdata.dat';
    $seqdata = [];
    #if ( file_exists($f_seqdata))
    #    $seqdata = json_decode(file_get_contents($f_seqdata) , true);
    
    $seqhash = 1;
    #$signs_regex = [];
    $signs_def = [];
    foreach ($signs->_Mnemo as $key => $value) {

       

        $value = preg_replace( '/\s+/', ':', ucwords(join(" ", preg_split('/(-|\.)/', $value))));
        $signs_def[$key] = $value;
        continue;

        var_dump( hexdec('144c79b8'), $key, $value); die;


        $value = sign_key($value) ;
        var_dump($key , $value); die;
        if ( !isset($seqdata[$value])) {
            $_seqhash = ++$seqhash;
            $seqdata[$value] = [$_seqhash,  $key, dechex($_seqhash)] ;
        }
    }


   


    $susidx = [];

    foreach(['M' => $signs->_FlexDBShe, 'S' => $signs->_SusDB, 'A' => $signs->_AdwareSig, 'E' => $signs->_ExceptFlex,  'F' => $signs->_PhishingSig, 'J' => $signs->_JSVirSig ] as $prefix => $_signs) {
        $signs_regex[$prefix] = [];
        shuffle($_signs);
        if (1) {
            foreach($_signs as $key => $value) {  
                $signs_regex[$prefix][] =  $value ;
                continue; 
                $keys = null;
                if(preg_match_all("~\(\?\<(X[0-9a-z]{8})\>\)~", $value, $keys))
                {
                    foreach($keys[1] as $_key) {
                        $key = ltrim($_key, 'X');
                        if ( isset($signs->_Mnemo[$key])) {
                            $signkey = sign_key($signs->_Mnemo[$key]);
                            #var_dump($signkey);die;
                            if ( !isset($seqdata[$signkey])) {
                                die("Not found key.  $signkey ");
                            } else {
                                    $value = str_replace("<{$_key}>", "<{$prefix}{$seqdata[$signkey][2]}>",  $value);
                                    #print_r($value);die;
                            }
                        } else {
                            die("Not found key.  $key ");
                        }
        
                    }
                    #var_dump($keys, $value); die;
                    $signs_regex[$prefix][] =  $value ;
                    if (@preg_match( '~' . $value . '~smi', '') === false) {
                        die("error");
                    }


                    if ($prefix == "S")  $susidx[] = count($signs_regex)-1;
                }else{
                    var_dump($value);
                    die("not found  $prefix");
                }
        
            }
        }
    }



error_reporting(E_ALL | E_WARNING);
   
    $f_vdir_db = './v1/vdie/sigs.db';
    $vdie_signs = json_decode( file_get_contents($f_vdir_db), true);
    #print_r($vdie_signs); die;
    $vdb = CSApiAVScanner::Decode(file_get_contents('vdb.json'));
    #print_r(  ($vdb)); die;
    $signs_regex["VE"] = [];
    $vdie_def =[];
    $extensions =[""];

    error_reporting(E_ALL);
    $c = [];
    foreach($vdb as $key=>$value){

        #echo "\n" . ($value[1]);

        if ( stripos( $value[0], strtolower('5.7.1' )) !== false) {
           #die(print_r($value)); 
            
            # WP.PERMALINKMANAGERLITE.CVE GROUP.STR_ROT13

        }

        if (  in_array(strtolower($value[0]),  [ strtolower('CORE.5.7.1.CVE.EXC'), strtolower('DOM.IFRAME.HIDDEN.1.EXC'), strtolower('GROUP.POSIX'), strtolower('GROUP.STRREV'),  strtolower('Group.document[]'),  strtolower('Group.document.write'),  strtolower('GROUP.HEXSTR'), strtolower('GROUP.ASSERT'),  strtolower('GROUP.UPLOAD'),  strtolower('GROUP.HEXSTR'), strtolower('GROUP.CHARCODE'), strtolower('GROUP.SHELL'), strtolower('GROUP.CREATE_FUNCTION'), strtolower('GROUP.UNLINK'),  strtolower('GROUP.BASE64'), 'group.fopen', 'group.mysql', strtolower('GROUP.SOCK'),   strtolower('GROUP.URLDECODE'),  strtolower('GROUP.EXTRACT'),  ('group.function_exists'), strtolower('GROUP.FUNCTION_EXISTS'), 'group.exec', 'group.preg_replace',  'group.location', 'group.iframe',  'group.command', 'group.uname',  'group.document.write', strtolower('GROUP.STRIPSLASHES'), strtolower('GROUP.CHR'),  strtolower('GROUP.FORM'),  'group.eval', 'group.script', 'group.mail', 'group.global']))
        {

            

            #print_r($value);

            continue;
            #die("eee");
        }
        $pattern = $value[1];
        $ext_founds = array_filter(explode(",", $value[8]));
        $ext_founds = count($ext_founds) ? $ext_founds : null;
        $sign_key = "MAL:" . strtoupper($value[0]);
        if ( !in_array($sign_key, $vdie_def) )
        {
            $vdie_def[]= $sign_key;
        }
        $idx = array_search($sign_key, $vdie_def, true);
        if ( $idx === false) {
            die("NO Index found");
        }
        $idx = dechex($idx);
        if ( isset($value[1][0]) &&  ! in_array($value[1][0], ['/','~', '#', '=']) )
        {
           die("New Char found");
        }
        else if (!isset($value[1][0])) {
            $signs_regex["VE"]['signs'][":" . $value[3]] = [$ext_founds, $idx];
            #print_r( $signs_regex["VE"] ); die;
        }
        else {
            $pattern = str_replace('\if', 'if', $pattern);
            $signs_regex["VE"]['signs'][$pattern] = [$ext_founds, $idx];
            if ( $value[1][0] !== '=' )
            {
                error_clear_last();
                $m = @preg_match($pattern, '', $match, PREG_OFFSET_CAPTURE);
                $err =  (error_get_last());
                error_clear_last();
                $plr = preg_last_error();
                if ($plr) {
                    die("error");
                }
                if ($m === false  || !is_null($err)) {
                    print_r($pattern);
                    print_r(error_get_last());
                    die();
                }
            }

        }
    }
    $signs_regex["VE"]['def'] = $vdie_def;


    die(var_dump(json_encode(build_blacklisted())));
    $blacklist_sign = build_blacklisted();
    $signs_regex["BD"] = $blacklist_sign;


    #print_r( $signs_regex["VE"] ); die;
    #print_r($vdie_def); die;
    #print_r( count($patterns));
    #die;
    #CSApiAVScanner::setVDB($vdb);
    #$vdie_signs = CSApiAVScanner::$vdbTop;
    #print_r($vdie_signs); die;
   
    /*
    #print_r(  count( array_keys(  ($vdie_signs)))); die;
    echo "Virus Die Defination Found " . count($vdie_signs) . "\n";
    die;
    $unq = [];
    foreach ($vdie_signs as $key => $_value) {
        $value = $_value[0];
        $value = sign_key($value) ;
        $sign = $_value[1];
        if ( !isset($seqdata[$value])) {
            $_seqhash = ++$seqhash;
            if ( $sign[0] === "=") {
                die("here");
            }

VE
            if (@preg_match($sign, '') === false) {
                print_r(error_get_last());
                error_clear_last();
                var_dump($sign);
                die("error");
            }



            $sign = preg_replace_callback("/\/[imsxADSUXJu]{0,}$/im", function($match) use ($_seqhash) {return  "(?<I" . dechex($_seqhash). ">)" . $match[0] ;} , $sign);
            
            #var_dump($sign); die;
        
            
            $seqdata[$value] = [$_seqhash, null,   dechex($_seqhash) ];
            $signs_regex[] = $sign;
        } else {
            $_seqhash = $seqdata[$value][0];
            $sign = preg_replace_callback("/\/[imsxADSUXJu]{0,}$/im", function($match) use ($_seqhash) {return  "(?<I" . dechex($_seqhash). ">)" . $match[0] ;} , $sign);
            $signs_regex[] = $sign;
            #$seqdata[$value][3][]= $sign;
            #print_r($seqdata[$value]);
        }
    }


    */

   # (shuffle( $signs_regex));
    #print_r($signs_regex);
    #$signs_keys = [];
    #foreach($seqdata as $key=>$seqdat)
    #    $signs_keys[$seqdat[2]] = $key;

    #

    $sign_count = count($signs_regex['M']) +  count($signs_regex['S']) +  count($signs_regex['A']) +  count($signs_regex['E']) +  count($signs_regex['J'])  +  count($signs_regex['F'])  +  count($signs_regex['EX']) +  count($signs_regex['VE']); 
    echo "\nDefination Added " .  $sign_count . "\n";
   


    $sign_version = time();
    $app_version = '1.0.0';

    #$halt_compiler = gzdeflate(base64_encode(str_rot13(strrev(json_encode(array('_FlexDBShe'=> $signs_regex['M'], '_SusDB'=> $signs_regex['S'], '_AdwareSig'=> $signs_regex['A'], '_ExceptFlex'=> $signs_regex['E'], '_JSVirSig'=> $signs_regex['J'], '_PhishingSig'=> $signs_regex['F'], '_ExploitsSig'=> $signs_regex['EX'] ))))));
    #$halt_compiler = (((json_encode(array('_FlexDBShe'=> $signs_regex['M'], '_SusDB'=> $signs_regex['S'], '_AdwareSig'=> $signs_regex['A'], '_ExceptFlex'=> $signs_regex['E'], '_JSVirSig'=> $signs_regex['J'], '_PhishingSig'=> $signs_regex['F'], '_ExploitsSig'=> $signs_regex['EX'] )))));
    #$len=strlen(bin2hex($halt_compiler))/2;
    #var_dump($len); die;
   
    #print_r($signs_keys); die;

    $signs_hash  =  base64_encode(gzdeflate(serialize((array_keys($signs_def)))));
    $signs_def  =  base64_encode(gzdeflate(serialize(array_values($signs_def))));
    $signs_version  =  base64_encode(gzdeflate(serialize(($sign_version))));
    $signs_regex  =  base64_encode(gzdeflate(serialize((($signs_regex)))));
    
    #var_dump( unserialize(gzinflate(base64_decode($signs_keys)))); die;

    $static_data = [
    <<<BANNER
ZeroScan {$app_version} , Malware,Exploits Files Scanner for PHP Websites
Copyright: 2022-2022 ZeroScan Inc.
Signatures Verion: {$sign_version}
Signatures Loaded: {$sign_count}
BANNER,
 $app_version,
 $sign_version,
 $sign_count,
    ];


    $burls = (base64_encode(serialize(file_get_contents('./v1/aibolit/blacklistedUrls.db'))));
    $wurls = (base64_encode(serialize(file_get_contents('./v1/aibolit/whitelistUrls.db'))));
    #var_dump($wurls); die;
    $static_data  =  base64_encode(serialize($static_data));
    
    #$burls, $wurls, $static_data, $signs_regex, $signs_hash,  $signs_keys
    #var_dump(is_string($signs_regex)); die;


    


    #die;
    file_put_contents('./zeroscan.php', str_replace(array('[[BLACK_URLS]]', '[[WHITE_URLS]]', '[[STATIC_DATA]]', '[[SIGN_PATTERN]]', '[[SIGN_HASH]]', '[[SIGN_DEF]]'), array($burls, $wurls, $static_data, $signs_regex, $signs_hash,  $signs_def), file_get_contents('./zeroscan.php')));
    #file_put_contents('./bcap.php', str_replace(array('[[BLACK_URLS]]', '[[WHITE_URLS]]', '[[STATIC_DATA]]', '[[__halt_compiler]]'), array($burls, $wurls, $static_data, $halt_compiler), file_get_contents('./bcap.php')));
    

    #print_r($signs_regex); die;
    #print_r(count($signs_keys)); die;
    return [$app_version, $sign_version, $sign_count ];
}

 function optSigCheck(&$sigs, $debug)
{
    $result = true;

    foreach ($sigs as $k => $sig) {
        if (trim($sig) == "") {
            if ($debug) {
                echo ("************>>>>> EMPTY\n     pattern: " . $sig . "\n");
            }
            unset($sigs[$k]);
            $result = false;
        }

        if (@preg_match('~' . $sig . '~smiS', '') === false) {
            $error = error_get_last();
            if ($debug) {
                echo ("************>>>>> " . $error['message'] . "\n     pattern: " . $sig . "\n");
            }
            unset($sigs[$k]);
            $result = false;
        }
    }

    return $result;
}
die(build_db());

function wpscan() {
    
    $headers = array();
    $headers[] = 'Content-type: application/json';
    $headers[] = 'Authorization: OAuToken token=th nc0bzzUXVR8PQOW0wjARaJY5tWl2LVfpJzO8MgRFuAs';

    


    $url ="https://wpscan.com/api/v3/3.7.38";
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_HTTPHEADER,  $headers );
    print_r( curl_exec($ch) );
}



die(wpscan());






$extenstions = ['php','htaccess','cgi','pl','o','so','py','sh','phtml','php3','php4','php5','php6','php7','pht','shtml','susp','suspected','infected','vir','ico','js','json','com','', 'js','json','html','htm','suspicious', 'js',
'html',
'htm',
'suspected',
'php',
'phtml',
'pht',
'php7', 'tpl'] + array_keys(['htm' => 0, 'html' => 0, 'php' => 0, 'phps' => 0, 'phtml' => 0, 'php4' => 0, 'php5' => 0, 'php7' => 0, 'inc' => 0, 'tpl' => 0, 'class' => 0, 'js' => 0, 'pl' => 0, 'perl' => 0, 'py' => 0, 'asp' => 0, 'aspx' => 0, 'svg' => 0, 'xml' => 0]);
shuffle(($extenstions));
$extenstions = ( join("|",( array_unique($extenstions))));
#var_dump(  base64_encode( $extenstions)); die;

if (1) {
/**
 * Class FileHashMemoryDb.
 *
 * Implements operations to load the file hash database into memory and work with it.
 */
class FileHashMemoryDb
{
    const HEADER_SIZE = 1024;
    const ROW_SIZE = 20;

    /**
     * @var int
     */
    private $count;
    /**
     * @var array
     */
    private $header;
    /**
     * @var resource
     */
    private $fp;
    /**
     * @var array
     */
    private $data;

    /**
     * Creates a new DB file and open it.
     *
     * @param $filepath
     * @return FileHashMemoryDb
     * @throws Exception
     */
    public static function create($filepath)
    {
        if (file_exists($filepath)) {
            throw new Exception('File \'' . $filepath . '\' already exists.');
        }

        $value = pack('V', 0);
        $header = array_fill(0, 256, $value);
        file_put_contents($filepath, implode($header));

        return new self($filepath);
    }

    /**
     * Opens a particular DB file.
     *
     * @param $filepath
     * @return FileHashMemoryDb
     * @throws Exception
     */
    public static function open($filepath)
    {
        if (!file_exists($filepath)) {
            throw new Exception('File \'' . $filepath . '\' does not exist.');
        }

        return new self($filepath);
    }

    /**
     * FileHashMemoryDb constructor.
     *
     * @param mixed $filepath
     * @throws Exception
     */
    private function __construct($filepath)
    {
        $this->fp = fopen($filepath, 'rb');

        if (false === $this->fp) {
            throw new Exception('File \'' . $filepath . '\' can not be opened.');
        }

        try {
            $this->header = unpack('V256', fread($this->fp, self::HEADER_SIZE));
            $this->count = (int) (max(0, filesize($filepath) - self::HEADER_SIZE) / self::ROW_SIZE);
            foreach ($this->header as $chunk_id => $chunk_size) {
                if ($chunk_size > 0) {
                    $str = fread($this->fp, $chunk_size);
                } else {
                    $str = '';
                }
                $this->data[$chunk_id] = $str;
                ##print_r($this->data); die;

            }
        } catch (Exception $e) {
            throw new Exception('File \'' . $filepath . '\' is not a valid DB file. An original error: \'' . $e->getMessage() . '\'');
        }
    }

    /**
     * Calculates and returns number of hashes stored in a loaded database.
     *
     * @return int number of hashes stored in a DB
     */
    public function count()
    {
        return $this->count;
    }

    /**
     * Find hashes in a DB.
     *
     * @param array $list of hashes to find in a DB
     * @return array list of hashes from the $list parameter that are found in a DB
     */
    public function find($list)
    {
        sort($list);
        
        $hash = reset($list);

        $found = [];

        foreach ($this->header as $chunk_id => $chunk_size) {
            if ($chunk_size > 0) {
                $str = $this->data[$chunk_id];

                do {
                    $raw = pack("H*", $hash);
                    $id  = ord($raw[0]) + 1;

                    if ($chunk_id == $id AND $this->binarySearch($str, $raw)) {
                        $found[] = (string)$hash;
                    }

                } while ($chunk_id >= $id AND $hash = next($list));

                if ($hash === false) {
                    break;
                }
            }
        }

        return $found;
    }

    /**
     * Searches $item in the $str using an implementation of the binary search algorithm.
     *
     * @param $str
     * @param $item
     * @return bool
     */
    private function binarySearch($str, $item) {
        $item_size = strlen($item);
        if ($item_size == 0) {
            return false;
        }

        $first = 0;

        $last = floor(strlen($str) / $item_size);

        while ($first < $last) {
            $mid = $first + (($last - $first) >> 1);
            $b   = substr($str, $mid * $item_size, $item_size);
            if (strcmp($item, $b) <= 0) {
                $last = $mid;
            } else {
                $first = $mid + 1;
            }
        }

        $b = substr($str, $last * $item_size, $item_size);
        if ($b == $item) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * FileHashDB destructor.
     */
    public function __destruct()
    {
        fclose($this->fp);
    }
}

#$db = FileHashMemoryDb::open('v1/aibolit/AIBOLIT-WHITELIST.db');
#svar_dump($snum = $db->count());
die;


}


## https://www.broadnetme.com/cox_sym/root/opt/ai-bolit/


require_once('./bcap.php');
die("hello");

#php ImunifyAV.php --avdb   ./v1/description.json -p ./malwares_samples
#php vscaner.php --path=./malwares_samples      


class AVScanner {
    static private $signs=null;
    static function init(){
        if (self::$signs){
            return true;
        }
        #sself::$signs = 
    }
}
AVScanner::init();
die;