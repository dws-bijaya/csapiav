<?php

class AibolitHelpers
{
    /**
     * Format bytes to human readable
     *
     * @param int $bytes
     *
     * @return string
     */
    public static function bytes2Human($bytes)
    {
        if ($bytes < 1024) {
            return $bytes . ' b';
        } elseif (($kb = $bytes / 1024) < 1024) {
            return number_format($kb, 2) . ' Kb';
        } elseif (($mb = $kb / 1024) < 1024) {
            return number_format($mb, 2) . ' Mb';
        } elseif (($gb = $mb / 1024) < 1024) {
            return number_format($gb, 2) . ' Gb';
        } else {
            return number_format($gb / 1024, 2) . 'Tb';
        }
    }

    /**
     * Seconds to human readable
     * @param int $seconds
     * @return string
     */
    public static function seconds2Human($seconds)
    {
        $r        = '';
        $_seconds = floor($seconds);
        $ms       = $seconds - $_seconds;
        $seconds  = $_seconds;
        if ($hours = floor($seconds / 3600)) {
            $r .= $hours . ' h ';
            $seconds %= 3600;
        }

        if ($minutes = floor($seconds / 60)) {
            $r .= $minutes . ' m ';
            $seconds %= 60;
        }

        if ($minutes < 3) {
            $r .= ' ' . (string)($seconds + ($ms > 0 ? round($ms) : 0)) . ' s';
        }

        return $r;
    }

    /**
     * Get bytes from shorthand byte values (1M, 1G...)
     * @param int|string $val
     * @return int
     */
    public static function getBytes($val)
    {
        $val  = trim($val);
        $last = strtolower($val[strlen($val) - 1]);
        $val  = preg_replace('~\D~', '', $val);
        switch ($last) {
            case 't':
                $val *= 1024;
            case 'g':
                $val *= 1024;
            case 'm':
                $val *= 1024;
            case 'k':
                $val *= 1024;
        }
        return intval($val);
    }

    /**
     * Convert dangerous chars to html entities
     *
     * @param        $par_Str
     * @param string $addPrefix
     * @param string $noPrefix
     * @param bool   $replace_path
     *
     * @return string
     */
    public static function makeSafeFn($par_Str, $addPrefix = '', $noPrefix = '', $replace_path = false)
    {
        if ($replace_path) {
            $lines = explode("\n", $par_Str);
            array_walk($lines, static function(&$n) use ($addPrefix, $noPrefix) {
                $n = $addPrefix . str_replace($noPrefix, '', $n);
            });

            $par_Str = implode("\n", $lines);
        }

        return htmlspecialchars($par_Str, ENT_SUBSTITUTE | ENT_QUOTES);
    }


    public static function myCheckSum($str)
    {
        return hash('crc32b', $str);
    }

}

class LoadSignaturesForScan
{
    private $sig_db             = [];
    private $sig_db_meta_info   = [];
    private $sig_db_location    = 'internal';

    private $mode;
    private $debug;

    public $_DBShe;
    public $X_DBShe;
    public $_FlexDBShe;
    public $X_FlexDBShe;
    public $XX_FlexDBShe;
    public $_ExceptFlex;
    public $_AdwareSig;
    public $_PhishingSig;
    public $_JSVirSig;
    public $X_JSVirSig;
    public $_SusDB;
    public $_SusDBPrio;
    public $_DeMapper;
    public $_Mnemo;

    public $whiteUrls;
    public $blackUrls;
    public $ownUrl = null;

    private $count;
    private $count_susp;
    private $result = 0;
    private $last_error = '';

    const SIGN_INTERNAL = 1;
    const SIGN_EXTERNAL = 2;
    const SIGN_IMPORT = 3;
    const SIGN_ERROR = 9;

    public function __construct($avdb_file, $mode, $debug)
    {
        $this->mode = $mode;
        $this->debug = $debug;
        $this->sig_db_meta_info = [
            'build-date'    => 'n/a',
            'version'       => 'n/a',
            'release-type'  => 'n/a',
        ];

        if ($avdb_file && file_exists($avdb_file)) {
            $avdb = explode("\n", gzinflate(base64_decode(str_rot13(strrev(trim(file_get_contents($avdb_file)))))));
            #var_dump(base64_decode($avdb[2])); die;
            
            $this->sig_db_location  = 'external';

            $this->_DBShe       = explode("\n", base64_decode($avdb[0]));
            $this->X_DBShe      = explode("\n", base64_decode($avdb[1]));
            $this->_FlexDBShe   = explode("\n", base64_decode($avdb[2]));
            #print_r($this->_FlexDBShe); die;
            

            $this->X_FlexDBShe  = explode("\n", base64_decode($avdb[3]));
            $this->XX_FlexDBShe = explode("\n", base64_decode($avdb[4]));
            $this->_ExceptFlex  = explode("\n", base64_decode($avdb[5]));
            $this->_AdwareSig   = explode("\n", base64_decode($avdb[6]));
            $this->_PhishingSig = explode("\n", base64_decode($avdb[7]));
            $this->_JSVirSig    = explode("\n", base64_decode($avdb[8]));
            $this->X_JSVirSig   = explode("\n", base64_decode($avdb[9]));
            $this->_SusDB       = explode("\n", base64_decode($avdb[10]));
            $this->_SusDBPrio   = explode("\n", base64_decode($avdb[11]));
            $this->_DeMapper    = array_combine(explode("\n", base64_decode($avdb[12])), explode("\n", base64_decode($avdb[13])));
            $this->_Mnemo       = @array_flip(@array_combine(explode("\n", base64_decode($avdb[14])), explode("\n", base64_decode($avdb[15])))); //TODO: you need to remove array_flip and swap the keys and values in array_combine. Write a test: put the signature base in the tests folder and run a scan with this base on the VIRII folder - the result should not change, since the base is the same

            
            // get meta information
            $avdb_meta_info = json_decode(base64_decode($avdb[16]), true);

            $this->sig_db_meta_info['build-date'] = $avdb_meta_info ? $avdb_meta_info['build-date'] : 'n/a';
            $this->sig_db_meta_info['version'] = $avdb_meta_info ? $avdb_meta_info['version'] : 'n/a';
            $this->sig_db_meta_info['release-type'] = $avdb_meta_info ? $avdb_meta_info['release-type'] : 'n/a';

            

            if (count($this->_DBShe) <= 1) {
                $this->_DBShe = [];
            }

            if (count($this->X_DBShe) <= 1) {
                $this->X_DBShe = [];
            }

            if (count($this->_FlexDBShe) <= 1) {
                $this->_FlexDBShe = [];
            }

            if (count($this->X_FlexDBShe) <= 1) {
                $this->X_FlexDBShe = [];
            }

            if (count($this->XX_FlexDBShe) <= 1) {
                $this->XX_FlexDBShe = [];
            }

            if (count($this->_ExceptFlex) <= 1) {
                $this->_ExceptFlex = [];
            }

            if (count($this->_AdwareSig) <= 1) {
                $this->_AdwareSig = [];
            }

            if (count($this->_PhishingSig) <= 1) {
                $this->_PhishingSig = [];
            }

            if (count($this->X_JSVirSig) <= 1) {
                $this->X_JSVirSig = [];
            }

            if (count($this->_JSVirSig) <= 1) {
                $this->_JSVirSig = [];
            }

            if (count($this->_SusDB) <= 1) {
                $this->_SusDB = [];
            }

            if (count($this->_SusDBPrio) <= 1) {
                $this->_SusDBPrio = [];
            }

            $this->result = self::SIGN_EXTERNAL;

            
        } else {
            InternalSignatures::init();
            $this->_DBShe       = InternalSignatures::$_DBShe;
            $this->X_DBShe      = InternalSignatures::$X_DBShe;
            $this->_FlexDBShe   = InternalSignatures::$_FlexDBShe;
            $this->X_FlexDBShe  = InternalSignatures::$X_FlexDBShe;
            $this->XX_FlexDBShe = InternalSignatures::$XX_FlexDBShe;
            $this->_ExceptFlex  = InternalSignatures::$_ExceptFlex;
            $this->_AdwareSig   = InternalSignatures::$_AdwareSig;
            $this->_PhishingSig = InternalSignatures::$_PhishingSig;
            $this->_JSVirSig    = InternalSignatures::$_JSVirSig;
            $this->X_JSVirSig   = InternalSignatures::$X_JSVirSig;
            $this->_SusDB       = InternalSignatures::$_SusDB;
            $this->_SusDBPrio   = InternalSignatures::$_SusDBPrio;
            $this->_DeMapper    = InternalSignatures::$_DeMapper;
            $this->_Mnemo       = InternalSignatures::$_Mnemo;

            // get meta information
            $avdb_meta_info = InternalSignatures::$db_meta_info;

            $this->sig_db_meta_info['build-date'] = $avdb_meta_info ? $avdb_meta_info['build-date'] : 'n/a';
            $this->sig_db_meta_info['version'] = $avdb_meta_info ? $avdb_meta_info['version'] : 'n/a';
            $this->sig_db_meta_info['release-type'] = $avdb_meta_info ? $avdb_meta_info['release-type'] : 'n/a';

            $this->result = self::SIGN_INTERNAL;
        }

        // use only basic signature subset
        if ($mode < 2) {
            $this->X_FlexDBShe  = [];
            $this->XX_FlexDBShe = [];
            $this->X_JSVirSig   = [];
        }
        
        // Load custom signatures
        if (file_exists(__DIR__ . '/ai-bolit.sig')) {
            try {
                $s_file = new SplFileObject(__DIR__ . '/ai-bolit.sig');
                $s_file->setFlags(SplFileObject::READ_AHEAD | SplFileObject::SKIP_EMPTY | SplFileObject::DROP_NEW_LINE);
                foreach ($s_file as $line) {
                    $this->_FlexDBShe[] = preg_replace('#\G(?:[^~\\\\]+|\\\\.)*+\K~#', '\\~', $line); // escaping ~
                }

                $this->result = self::SIGN_IMPORT;
                $s_file = null; // file handler is closed
            }
            catch (Exception $e) {
                $this->result = self::SIGN_ERROR;
                $this->last_error = $e->getMessage();
            }
        }

        $this->count = count($this->_JSVirSig) + count($this->X_JSVirSig) + count($this->_DBShe) + count($this->X_DBShe) + count($this->_FlexDBShe) + count($this->X_FlexDBShe) + count($this->XX_FlexDBShe);
        $this->count_susp = $this->count + count($this->_SusDB);

        if (!$debug) {
            $this->OptimizeSignatures($debug);
        }

        #print_r([$avdb_file, $this->_FlexDBShe]);
        $this->_DBShe  = array_map('strtolower', $this->_DBShe);
        $this->X_DBShe = array_map('strtolower', $this->X_DBShe);


        
    }

    private function OptimizeSignatures($debug)
    {
        #var_dump($this->mode, $debug, '3'); die;

        ($this->mode == 2) && ($this->_FlexDBShe = array_merge($this->_FlexDBShe, $this->X_FlexDBShe, $this->XX_FlexDBShe));
        ($this->mode == 1) && ($this->_FlexDBShe = array_merge($this->_FlexDBShe, $this->X_FlexDBShe));
        $this->X_FlexDBShe = $this->XX_FlexDBShe = [];

        
        ($this->mode == 2) && ($this->_JSVirSig = array_merge($this->_JSVirSig, $this->X_JSVirSig));
        $this->X_JSVirSig = [];

        $count = count($this->_FlexDBShe);
    
        
        for ($i = 0; $i < $count; $i++) {
            if ($this->_FlexDBShe[$i] == '[a-zA-Z0-9_]+?\(\s*[a-zA-Z0-9_]+?=\s*\)')
                $this->_FlexDBShe[$i] = '\((?<=[a-zA-Z0-9_].)\s*[a-zA-Z0-9_]++=\s*\)';
            if ($this->_FlexDBShe[$i] == '([^\?\s])\({0,1}\.[\+\*]\){0,1}\2[a-z]*e')
                $this->_FlexDBShe[$i] = '(?J)\.[+*](?<=(?<d>[^\?\s])\(..|(?<d>[^\?\s])..)\)?\g{d}[a-z]*e';
            if ($this->_FlexDBShe[$i] == '$[a-zA-Z0-9_]\{\d+\}\s*\.$[a-zA-Z0-9_]\{\d+\}\s*\.$[a-zA-Z0-9_]\{\d+\}\s*\.')
                $this->_FlexDBShe[$i] = '\$[a-zA-Z0-9_]\{\d+\}\s*\.\$[a-zA-Z0-9_]\{\d+\}\s*\.\$[a-zA-Z0-9_]\{\d+\}\s*\.';

            $this->_FlexDBShe[$i] = str_replace('http://.+?/.+?\.php\?a', 'http://[^?\s]++(?<=\.php)\?a', $this->_FlexDBShe[$i]);
            $this->_FlexDBShe[$i] = preg_replace('~\[a-zA-Z0-9_\]\+\K\?~', '+', $this->_FlexDBShe[$i]);
            $this->_FlexDBShe[$i] = preg_replace('~^\\\\[d]\+&@~', '&@(?<=\d..)', $this->_FlexDBShe[$i]);
            $this->_FlexDBShe[$i] = str_replace('\s*[\'"]{0,1}.+?[\'"]{0,1}\s*', '.+?', $this->_FlexDBShe[$i]);
            $this->_FlexDBShe[$i] = str_replace('[\'"]{0,1}.+?[\'"]{0,1}', '.+?', $this->_FlexDBShe[$i]);
            $this->_FlexDBShe[$i] = preg_replace('~^\[\'"\]\{0,1\}\.?|^@\*|^\\\\s\*~', '', $this->_FlexDBShe[$i]);
        }
        self::optSig($this->_FlexDBShe,     $debug, 'AibolitHelpers::myCheckSum');
        
        self::optSig($this->_JSVirSig,      $debug, 'AibolitHelpers::myCheckSum');
        self::optSig($this->_AdwareSig,     $debug, 'AibolitHelpers::myCheckSum');
        self::optSig($this->_PhishingSig,   $debug, 'AibolitHelpers::myCheckSum');
        self::optSig($this->_SusDB,         $debug, 'AibolitHelpers::myCheckSum');
        //optSig($g_SusDBPrio);
        //optSig($g_ExceptFlex);

        // convert exception rules
        $cnt = count($this->_ExceptFlex);
        for ($i = 0; $i < $cnt; $i++) {
            $this->_ExceptFlex[$i] = trim(Normalization::normalize($this->_ExceptFlex[$i]));
            if ($this->_ExceptFlex[$i] == '')
                unset($this->_ExceptFlex[$i]);
        }

        $this->_ExceptFlex = array_values($this->_ExceptFlex);



    }

    public static function optSig(&$sigs, $debug = false, $func_id = null)
    {

        
    
        $sigs = array_unique($sigs);
        #var_dump(count($sigs));die;
        #

        // Add SigId
        foreach ($sigs as $k => &$s) {
            if ($func_id && is_callable($func_id)) {
                $id = $func_id($s);
            } else {
                $id = $k;
            }
            


            $s .= '(?<X' . $id . '>)';
            #var_dump($s);
        }
       
        #unset($s);


        
        $fix = [
            '([^\?\s])\({0,1}\.[\+\*]\){0,1}\2[a-z]*e' => '(?J)\.[+*](?<=(?<d>[^\?\s])\(..|(?<d>[^\?\s])..)\)?\g{d}[a-z]*e',
            'http://.+?/.+?\.php\?a' => 'http://[^?\s]++(?<=\.php)\?a',
            '\s*[\'"]{0,1}.+?[\'"]{0,1}\s*' => '.+?',
            '[\'"]{0,1}.+?[\'"]{0,1}' => '.+?'
        ];
        
        $sigs = str_replace(array_keys($fix), array_values($fix), $sigs);
        $fix = [
            '~^\\\\[d]\+&@~' => '&@(?<=\d..)',
            '~^((\[\'"\]|\\\\s|@)(\{0,1\}\.?|[?*]))+~' => ''
        ];

        $sigs = preg_replace(array_keys($fix), array_values($fix), $sigs);

        self::optSigCheck($sigs, $debug);
        $tmp = [];
        foreach ($sigs as $i => $s) {
            if (!preg_match('~^(?>(?!\.[*+]|\\\\\d)(?:\\\\.|\[.+?\]|.))+$~', $s)) {
                unset($sigs[$i]);
                $tmp[] = $s;
            }
        }
        #
    
        usort($sigs,  'strcasecmp');
        $txt = implode("\n", $sigs);
        for ($i = 24; $i >= 1; ($i > 4) ? $i -= 4 : --$i) {
            $txt = preg_replace_callback('#^((?>(?:\\\\.|\\[.+?\\]|[^(\n]|\((?:\\\\.|[^)(\n])++\))(?:[*?+]\+?|\{\d+(?:,\d*)?\}[+?]?|)){' . $i . ',})[^\n]*+(?:\\n\\1(?![{?*+]).+)+#im', 'LoadSignaturesForScan::optMergePrefixes', $txt);
        }
        $sigs = array_merge(explode("\n", $txt), $tmp);
        #print_r($sigs); die;

        self::optSigCheck($sigs, $debug);
    }

    private static function optMergePrefixes($m)
    {
        $limit = 8000;

        $prefix     = $m[1];
        $prefix_len = strlen($prefix);

        $len = $prefix_len;
        $r   = [];

        $suffixes = [];
        foreach (explode("\n", $m[0]) as $line) {

            if (strlen($line) > $limit) {
                $r[] = $line;
                continue;
            }

            $s = substr($line, $prefix_len);
            $len += strlen($s);
            if ($len > $limit) {
                if (count($suffixes) == 1) {
                    $r[] = $prefix . $suffixes[0];
                } else {
                    $r[] = $prefix . '(?:' . implode('|', $suffixes) . ')';
                }
                $suffixes = [];
                $len      = $prefix_len + strlen($s);
            }
            $suffixes[] = $s;
        }

        if (!empty($suffixes)) {
            if (count($suffixes) == 1) {
                $r[] = $prefix . $suffixes[0];
            } else {
                $r[] = $prefix . '(?:' . implode('|', $suffixes) . ')';
            }
        }

        return implode("\n", $r);
    }

    private function optMergePrefixes_Old($m)
    {
        $prefix     = $m[1];
        $prefix_len = strlen($prefix);

        $suffixes = [];
        foreach (explode("\n", $m[0]) as $line) {
            $suffixes[] = substr($line, $prefix_len);
        }

        return $prefix . '(?:' . implode('|', $suffixes) . ')';
    }

    /*
     * Checking errors in pattern
     */
    private static function optSigCheck(&$sigs, $debug)
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

    public static function getSigId($l_Found)
    {
        foreach ($l_Found as $key => &$v) {
            if (is_string($key) && $v[1] != -1 && strlen($key) == 9) {
                return substr($key, 1);
            }
        }

        return null;
    }

    public function setOwnUrl($url)
    {
        if (isset($this->blackUrls)) {
            foreach ($this->blackUrls->getDb() as $black) {
                if (preg_match('~' . $black . '~msi', $url)) {
                    $this->ownUrl = null;
                    return;
                }
            }
        }
        $this->ownUrl = $url;
    }

    public function getOwnUrl()
    {
        return $this->ownUrl;
    }

    public function getDBLocation()
    {
        return $this->sig_db_location;
    }

    public function getDB()
    {
        return $this->sig_db;
    }

    public function getDBMetaInfo()
    {
        return $this->sig_db_meta_info;
    }

    public function getDBMetaInfoVersion()
    {
        return $this->sig_db_meta_info['version'];
    }

    public function getDBCount()
    {
        return $this->count;
    }

    public function getDBCountWithSuspicious()
    {
        return $this->count_susp;
    }

    public function getResult()
    {
        return $this->result;
    }

    public function getLastError()
    {
        return $this->last_error;
    }
}