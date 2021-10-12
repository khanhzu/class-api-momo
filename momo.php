<?php

$m = new momo();


$imei = '';
$code = '';
$keySetup = '';
$pHash = '';
$REQUEST_ENCRYPT_KEY = '';
$AUTH_TOKEN = '';


echo $m->lichsu($AUTH_TOKEN, $keySetup, $REQUEST_ENCRYPT_KEY);


class momo {

    public $phone = '';
    public $password = '';



    function lichsu($AUTH_TOKEN, $keySetup, $REQUEST_ENCRYPT_KEY)
    {
        $action = 'QUERY_TRAN_HIS_MSG';

        $time   = $this->getTimeNow();

        $arrDataPost = array(
            'user'      => (string) $this->phone,
            'msgType'   => $action,
            'cmdId'     => (string) $time . '000000',
            'lang'      => 'vi',
            'channel'   => 'APP',
            'time'      => $time,
            'appVer'    => 30120,
            'appCode'   => '3.0.12',
            'deviceOS'  => 'Ios',
            'result'    => true,
            'errorCode' => 0,
            'errorDesc' => '',
            'extra' =>
            array(
                'checkSum' => $this->generateCheckSum($action, $time, $keySetup),
            ),
            'momoMsg' =>
            array(
                '_class'  => 'mservice.backend.entity.msg.QueryTranhisMsg',
                'begin'   => (time() - (3600 * 7)) * 1000,
                'end'     => $time,
            ),
        );
      
        $requestKeyRaw = $this->randomString(32);
        $requestKey = $this->_encodeRSA($requestKeyRaw, $REQUEST_ENCRYPT_KEY);
        $rqSendMoney  = $this->post_momo('https://owa.momo.vn/api/sync', $this->_encode(json_encode($arrDataPost), $requestKeyRaw), $action, $requestKey, $this->phone, $AUTH_TOKEN);
      
        return $this->_decode($rqSendMoney, $requestKeyRaw);

        $decodeRq = json_decode($this->_decode($rqSendMoney, $requestKeyRaw));

        if (@$decodeRq->result) {
            return json_encode([
                "error"    => 0,
                "tranList" => @$decodeRq->momoMsg->tranList,
                "finishTime" => @$decodeRq->momoMsg->end
            ]);
        } else {

            if (@$decodeRq->errorCode) {
                return json_encode([
                    "error" => $decodeRq->errorCode,
                    "msg"   => $decodeRq->errorDesc
                ]);
            } else {
                return json_encode([
                    "error" => 1,
                    "msg"   => "momo timeout"
                ]);
            }
        }
    }

    function dangnhap($pHash, $keySetup)
    {
        $action = 'USER_LOGIN_MSG';

        $time   = $this->getTimeNow();

        $arrDataPost = array(
            'user'      => $this->phone,
            'msgType'   => $action,
            'cmdId'     => $time . '000000',
            'lang'      => 'vi',
            'channel'   => 'APP',
            'time'      => $time,
            'appVer'    => 30120,
            'appCode'   => '3.0.12',
            'deviceOS'  => 'Ios',
            'result'    => true,
            'errorCode' => 0,
            'errorDesc' => '',
            'extra'     =>
            array(
                'checkSum'  => $this->generateCheckSum($action, $time, $keySetup),
                'pHash'     => $pHash,
                'AAID'      => '',
                'IDFA'      => '',
                'TOKEN'     => '',
                'SIMULATOR' => 'false',
                'SECUREID'  => $this->SECUREID(),
            ),
            'pass'      => $this->password,
            'momoMsg'   =>
            array(
                '_class'  => 'mservice.backend.entity.msg.LoginMsg',
                'isSetup' => true,
            ),
        );
        $rqLogin  = $this->post_momo('https://owa.momo.vn/public/login', json_encode($arrDataPost), $action);
        $decodeRq = json_decode($rqLogin);
      
        if (@$decodeRq->result) {

            $this->AUTH_TOKEN = $decodeRq->extra->AUTH_TOKEN;
            return json_encode([
                "error"   => 0,
                "balance" => $decodeRq->extra->BALANCE,
                'REQUEST_ENCRYPT_KEY' => $decodeRq->extra->REQUEST_ENCRYPT_KEY,
                "AUTH_TOKEN" => $decodeRq->extra->AUTH_TOKEN,
                "time"    => $decodeRq->time
            ]);
        } else {
            return json_encode([
                "error" => @$decodeRq->errorCode,
                "msg"   => @$decodeRq->errorDesc
            ]);
        }
    }

    function xacthuc_otp($imei, $code)
    {
        $oHash = hash('sha256', $this->phone . '12345678901234567890' . $code);
        $action = 'REG_DEVICE_MSG';
        $time   = $this->getTimeNow();
        $arrDataPost = array(
            'user' => $this->phone,
            'msgType' => $action,
            'cmdId' => $time . '000000',
            'lang' => 'vi',
            'channel' => 'APP',
            'time' => $time,
            'appVer' => 30120,
            'appCode' => '3.0.9',
            'deviceOS' => 'Ios',
            'result' => true,
            'errorCode' => 0,
            'errorDesc' => '',
            'extra' =>
            array(
                'ohash' => $oHash,
                'AAID' => '',
                'IDFA' => '',
                'TOKEN' => '',
                'SIMULATOR' => 'false',
                'SECUREID' => $this->SECUREID(),
            ),
            'momoMsg' =>
            array(
                '_class' => 'mservice.backend.entity.msg.RegDeviceMsg',
                'number' => $this->phone,
                'imei' => $imei,
                'cname' => 'Vietnam',
                'ccode' => '084',
                'device' => 'smrooter',
                'firmware' => '19',
                'hardware' => 'vbox86',
                'manufacture' => 'samsung',
                'csp' => '',
                'icc' => '',
                'mcc' => '',
                'device_os' => 'Ios',
                'secure_id' => $this->SECUREID(),
            ),
        );
        $rqVer  = $this->post_momo('https://owa.momo.vn/public', json_encode($arrDataPost), $action);
        $decodeRq = json_decode($rqVer);
        if (@$decodeRq->result) {
            $keySetup = $decodeRq->extra->setupKey;
            $key      = substr(@openssl_decrypt($keySetup, 'AES-256-CBC', substr($oHash, 0, 32), 0, ''), 0, 32);
            $pHash    = @openssl_encrypt($imei . '|' . $this->password, 'AES-256-CBC', $key, 0, '');
          
            return json_encode([
                "error" => 0,
                'keySetup' => $key,
                "pHash" => $pHash
            ]);
        } else {

            return json_encode([
                "error" => $decodeRq->errorCode,
                "msg"   => $decodeRq->errorDesc
            ]);
        }
    }

    function get_otp($imei)
    {

        $action = 'SEND_OTP_MSG';
        $time   = $this->getTimeNow();
        $arrDataPost = array(
            'user' => $this->phone,
            'msgType' => $action,
            'cmdId' => $time . '000000',
            'lang' => 'vi',
            'channel' => 'APP',
            'time' => $time,
            'appVer' => 30120,
            'appCode' => '3.0.9',
            'deviceOS' => 'Ios',
            'result' => true,
            'errorCode' => 0,
            'errorDesc' => '',
            'extra' =>
            array(
                'action' => 'SEND',
                'rkey' => '12345678901234567890',
                'isVoice' => false,
                'AAID' => '',
                'IDFA' => '',
                'TOKEN' => '',
                'SIMULATOR' => 'false',
                'SECUREID' => $this->SECUREID(),
            ),
            'momoMsg' =>
            array(
                '_class' => 'mservice.backend.entity.msg.RegDeviceMsg',
                'number' => $this->phone,
                'imei' => $imei,
                'cname' => 'Vietnam',
                'ccode' => '084',
                'device' => 'smrooter',
                'firmware' => '19',
                'hardware' => 'vbox86',
                'manufacture' => 'samsung',
                'csp' => '',
                'icc' => '',
                'mcc' => '',
                'device_os' => 'Ios',
                'secure_id' => $this->SECUREID(),
            ),
        );
        $rqReg  = $this->post_momo('https://owa.momo.vn/public', json_encode($arrDataPost), $action);
        $decodeRq = json_decode($rqReg);
        if (@$decodeRq->result) {
            return json_encode([
                "error"    => 0,
                "msg"      => 'Thành công'
            ]);
        } else {
            return json_encode([
                "error" => $decodeRq->errorCode,
                "msg"   => $decodeRq->errorDesc
            ]);
        }
    }
  
    function generateRandomString($length = 20)
    {
        $characters = '0123456789abcde';
        $charactersLength = strlen($characters);
        $randomString = '';

        for ($i = 0; $i < $length; $i++) {
            $randomString .= $characters[rand(0, $charactersLength - 1)];
        }
        return $randomString;
    }

    function get_imei()
    {
        return $this->generateRandomString(8) . '-' . $this->generateRandomString(4) . '-' . $this->generateRandomString(4) . '-' . $this->generateRandomString(4) . '-' . $this->generateRandomString(12);
    }

    function SECUREID($length = 17)
    {
        $characters = '0123456789abcde';
        $charactersLength = strlen($characters);
        $randomString = '';
        for ($i = 0; $i < $length; $i++) {
            $randomString .= $characters[rand(0, $charactersLength - 1)];
        }
        return $randomString;
    }

    function getTimeNow()
    {
        // return round(microtime(true) * 1000);
        $pieces = explode(" ", microtime());
        return bcadd(($pieces[0] * 1000), bcmul($pieces[1], 1000));
    }

    function generateCheckSum($msgType, $time, $keySetup)
    {
        $l = $time . '000000';
        $f = $this->phone . $l . $msgType . ($time / 1e12) . "E12";
        return @openssl_encrypt($f, 'AES-256-CBC',  substr($keySetup, 0, 32), 0, '');
    }

    function _encode($plaintext, $password)
    {
        $method = 'aes-256-cbc';
        $iv = chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0);
        $encrypted = base64_encode(openssl_encrypt($plaintext, $method, $password, OPENSSL_RAW_DATA, $iv));
        return $encrypted;
    }

    function _decode($encrypted, $password)
    {
        $method = 'aes-256-cbc';
        $iv = chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0);
        $decrypted = openssl_decrypt(base64_decode($encrypted), $method, $password, OPENSSL_RAW_DATA, $iv);
        return $decrypted;
    }

    function _encodeRSA($content, $key)
    {

        require_once('lib/RSA/Crypt/RSA.php');
        $rsa = new Crypt_RSA();
        $rsa->loadKey($key);
        $rsa->setEncryptionMode(CRYPT_RSA_ENCRYPTION_PKCS1);
        return base64_encode($rsa->encrypt($content));
    }

    function randomString($length = 10)
    {
        $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $charactersLength = strlen($characters);
        $randomString = '';
        for ($i = 0; $i < $length; $i++) {
            $randomString .= $characters[rand(0, $charactersLength - 1)];
        }
        return $randomString;
    }

    function post_momo($api, $dataPost, $MsgType, $requestKey = null, $phone = null, $Auth = false)
    {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $api);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $dataPost);
        curl_setopt($ch, CURLOPT_ENCODING, 'gzip, deflate');

        $headers = array();
        $headers[] = 'Accept: application/json';
        $headers[] = ($Auth == false) ? 'Authorization: Bearer' : 'Authorization: Bearer ' . $Auth;
        $headers[] = 'Userhash: null';
        $headers[] = 'Msgtype: ' . $MsgType;
        $headers[] = 'Content-Type: application/json';
        $headers[] = 'Host: owa.momo.vn';
        $headers[] = 'User-Agent: okhttp/3.12.1';
        if ($requestKey != null) {
            $headers[] = 'requestkey: ' . $requestKey;
        }
        if ($phone != null) {
            $headers[] = 'userid: ' . $phone;
        }
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

        $result = curl_exec($ch);
        curl_close($ch);
        return $result;
    }
}

