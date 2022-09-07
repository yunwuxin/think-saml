<?php

namespace think\saml;

use DateTime;
use DateTimeZone;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecEnc;

use DOMDocument;
use DOMElement;
use DOMNodeList;
use DomNode;
use DOMXPath;
use Exception;

/**
 * Utils of OneLogin PHP Toolkit
 *
 * Defines several often used methods
 */
class Utils
{
    const RESPONSE_SIGNATURE_XPATH  = "/samlp:Response/ds:Signature";
    const ASSERTION_SIGNATURE_XPATH = "/samlp:Response/saml:Assertion/ds:Signature";

    /**
     * This function load an XML string in a save way.
     * Prevent XEE/XXE Attacks
     *
     * @param DOMDocument $dom The document where load the xml.
     * @param string $xml The XML string to be loaded.
     *
     * @return DOMDocument|false $dom The result of load the XML at the DOMDocument
     *
     * @throws Exception
     */
    public static function loadXML(DOMDocument $dom, $xml)
    {
        assert($dom instanceof DOMDocument);
        assert(is_string($xml));

        $oldEntityLoader = null;
        if (PHP_VERSION_ID < 80000) {
            $oldEntityLoader = libxml_disable_entity_loader(true);
        }

        $res = $dom->loadXML($xml);

        if (PHP_VERSION_ID < 80000) {
            libxml_disable_entity_loader($oldEntityLoader);
        }

        foreach ($dom->childNodes as $child) {
            if ($child->nodeType === XML_DOCUMENT_TYPE_NODE) {
                throw new Exception(
                    'Detected use of DOCTYPE/ENTITY in XML, disabled to prevent XXE/XEE attacks'
                );
            }
        }

        if (!$res) {
            return false;
        } else {
            return $dom;
        }
    }

    /**
     * This function attempts to validate an XML string against the specified schema.
     *
     * It will parse the string into a DOMDocument and validate this document against the schema.
     *
     * @param string|DOMDocument $xml The XML string or document which should be validated.
     * @param string $schema The schema filename which should be used.
     *
     * @return string|DOMDocument $dom  string that explains the problem or the DOMDocument
     *
     * @throws Exception
     */
    public static function validateXML($xml, $schema)
    {
        assert(is_string($xml) || $xml instanceof DOMDocument);
        assert(is_string($schema));

        libxml_clear_errors();
        libxml_use_internal_errors(true);

        if ($xml instanceof DOMDocument) {
            $dom = $xml;
        } else {
            $dom = new DOMDocument;
            $dom = self::loadXML($dom, $xml);
            if (!$dom) {
                return 'unloaded_xml';
            }
        }

        $schemaFile = __DIR__ . '/schemas/' . $schema;

        $oldEntityLoader = null;
        if (PHP_VERSION_ID < 80000) {
            $oldEntityLoader = libxml_disable_entity_loader(false);
        }
        $res = $dom->schemaValidate($schemaFile);
        if (PHP_VERSION_ID < 80000) {
            libxml_disable_entity_loader($oldEntityLoader);
        }
        if (!$res) {
            return 'invalid_xml';
        }

        return $dom;
    }

    /**
     * Import a node tree into a target document
     * Copy it before a reference node as a sibling
     * and at the end of the copy remove
     * the reference node in the target document
     * As it were 'replacing' it
     * Leaving nested default namespaces alone
     * (Standard importNode with deep copy
     *  mangles nested default namespaces)
     *
     * The reference node must not be a DomDocument
     * It CAN be the top element of a document
     * Returns the copied node in the target document
     *
     * @param DomNode $targetNode
     * @param DomNode $sourceNode
     * @param bool $recurse
     * @return DOMNode
     * @throws Exception
     */
    public static function treeCopyReplace(DomNode $targetNode, DomNode $sourceNode, $recurse = false)
    {
        if ($targetNode->parentNode === null) {
            throw new Exception('Illegal argument targetNode. It has no parentNode.');
        }
        $clonedNode = $targetNode->ownerDocument->importNode($sourceNode, false);
        if ($recurse) {
            $resultNode = $targetNode->appendChild($clonedNode);
        } else {
            $resultNode = $targetNode->parentNode->insertBefore($clonedNode, $targetNode);
        }
        if ($sourceNode->childNodes !== null) {
            foreach ($sourceNode->childNodes as $child) {
                self::treeCopyReplace($resultNode, $child, true);
            }
        }
        if (!$recurse) {
            $targetNode->parentNode->removeChild($targetNode);
        }
        return $resultNode;
    }

    /**
     * Returns a x509 cert (adding header & footer if required).
     *
     * @param string $cert A x509 unformated cert
     * @param bool $heads True if we want to include head and footer
     *
     * @return string $x509 Formatted cert
     */
    public static function formatCert($cert, $heads = true)
    {
        $x509cert = str_replace(["\x0D", "\r", "\n"], "", $cert);
        if (!empty($x509cert)) {
            $x509cert = str_replace('-----BEGIN CERTIFICATE-----', "", $x509cert);
            $x509cert = str_replace('-----END CERTIFICATE-----', "", $x509cert);
            $x509cert = str_replace(' ', '', $x509cert);

            if ($heads) {
                $x509cert = "-----BEGIN CERTIFICATE-----\n" . chunk_split($x509cert, 64, "\n") . "-----END CERTIFICATE-----\n";
            }
        }
        return $x509cert;
    }

    /**
     * Returns a private key (adding header & footer if required).
     *
     * @param string $key A private key
     * @param bool $heads True if we want to include head and footer
     *
     * @return string $rsaKey Formatted private key
     */
    public static function formatPrivateKey($key, $heads = true)
    {
        $key = str_replace(["\x0D", "\r", "\n"], "", $key);
        if (!empty($key)) {
            if (strpos($key, '-----BEGIN PRIVATE KEY-----') !== false) {
                $key = Utils::getStringBetween($key, '-----BEGIN PRIVATE KEY-----', '-----END PRIVATE KEY-----');
                $key = str_replace(' ', '', $key);

                if ($heads) {
                    $key = "-----BEGIN PRIVATE KEY-----\n" . chunk_split($key, 64, "\n") . "-----END PRIVATE KEY-----\n";
                }
            } elseif (strpos($key, '-----BEGIN RSA PRIVATE KEY-----') !== false) {
                $key = Utils::getStringBetween($key, '-----BEGIN RSA PRIVATE KEY-----', '-----END RSA PRIVATE KEY-----');
                $key = str_replace(' ', '', $key);

                if ($heads) {
                    $key = "-----BEGIN RSA PRIVATE KEY-----\n" . chunk_split($key, 64, "\n") . "-----END RSA PRIVATE KEY-----\n";
                }
            } else {
                $key = str_replace(' ', '', $key);

                if ($heads) {
                    $key = "-----BEGIN RSA PRIVATE KEY-----\n" . chunk_split($key, 64, "\n") . "-----END RSA PRIVATE KEY-----\n";
                }
            }
        }
        return $key;
    }

    /**
     * Extracts a substring between 2 marks
     *
     * @param string $str The target string
     * @param string $start The initial mark
     * @param string $end The end mark
     *
     * @return string A substring or an empty string if is not able to find the marks
     *                or if there is no string between the marks
     */
    public static function getStringBetween($str, $start, $end)
    {
        $str = ' ' . $str;
        $ini = strpos($str, $start);

        if ($ini == 0) {
            return '';
        }

        $ini += strlen($start);
        $len = strpos($str, $end, $ini) - $ini;
        return substr($str, $ini, $len);
    }

    public static function strLreplace($search, $replace, $subject)
    {
        $pos = strrpos($subject, $search);

        if ($pos !== false) {
            $subject = substr_replace($subject, $replace, $pos, strlen($search));
        }

        return $subject;
    }

    /**
     * Generates an unique string (used for example as ID for assertions).
     *
     * @return string  A unique string
     */
    public static function generateUniqueID()
    {
        return 'ONELOGIN_' . sha1(uniqid((string) mt_rand(), true));
    }

    /**
     * Converts a UNIX timestamp to SAML2 timestamp on the form
     * yyyy-mm-ddThh:mm:ss(\.s+)?Z.
     *
     * @param string|int $time The time we should convert (DateTime).
     *
     * @return string $timestamp SAML2 timestamp.
     */
    public static function parseTime2SAML($time)
    {
        $date = new DateTime("@$time", new DateTimeZone('UTC'));
        return $date->format("Y-m-d\TH:i:s\Z");
    }

    /**
     * Converts a SAML2 timestamp on the form yyyy-mm-ddThh:mm:ss(\.s+)?Z
     * to a UNIX timestamp. The sub-second part is ignored.
     *
     * @param string $time The time we should convert (SAML Timestamp).
     *
     * @return int $timestamp  Converted to a unix timestamp.
     *
     * @throws Exception
     */
    public static function parseSAML2Time($time)
    {
        $matches = [];

        /* We use a very strict regex to parse the timestamp. */
        $exp1 = '/^(\\d\\d\\d\\d)-(\\d\\d)-(\\d\\d)';
        $exp2 = 'T(\\d\\d):(\\d\\d):(\\d\\d)(?:\\.\\d+)?Z$/D';
        if (preg_match($exp1 . $exp2, $time, $matches) == 0) {
            throw new Exception(
                'Invalid SAML2 timestamp passed to' .
                ' parseSAML2Time: ' . $time
            );
        }

        /* Extract the different components of the time from the
         * matches in the regex. int cast will ignore leading zeroes
         * in the string.
         */
        $year   = (int) $matches[1];
        $month  = (int) $matches[2];
        $day    = (int) $matches[3];
        $hour   = (int) $matches[4];
        $minute = (int) $matches[5];
        $second = (int) $matches[6];

        /* We use gmmktime because the timestamp will always be given
         * in UTC.
         */
        $ts = gmmktime($hour, $minute, $second, $month, $day, $year);

        return $ts;
    }

    /**
     * Interprets a ISO8601 duration value relative to a given timestamp.
     *
     * @param string $duration The duration, as a string.
     * @param int|null $timestamp The unix timestamp we should apply the
     *                            duration to. Optional, default to the
     *                            current time.
     *
     * @return int The new timestamp, after the duration is applied.
     *
     * @throws Exception
     */
    public static function parseDuration($duration, $timestamp = null)
    {
        assert(is_string($duration));
        assert(is_null($timestamp) || is_int($timestamp));

        $matches = [];

        /* Parse the duration. We use a very strict pattern. */
        $durationRegEx = '#^(-?)P(?:(?:(?:(\\d+)Y)?(?:(\\d+)M)?(?:(\\d+)D)?(?:T(?:(\\d+)H)?(?:(\\d+)M)?(?:(\\d+)S)?)?)|(?:(\\d+)W))$#D';
        if (!preg_match($durationRegEx, $duration, $matches)) {
            throw new Exception('Invalid ISO 8601 duration: ' . $duration);
        }

        $durYears   = (empty($matches[2]) ? 0 : (int) $matches[2]);
        $durMonths  = (empty($matches[3]) ? 0 : (int) $matches[3]);
        $durDays    = (empty($matches[4]) ? 0 : (int) $matches[4]);
        $durHours   = (empty($matches[5]) ? 0 : (int) $matches[5]);
        $durMinutes = (empty($matches[6]) ? 0 : (int) $matches[6]);
        $durSeconds = (empty($matches[7]) ? 0 : (int) $matches[7]);
        $durWeeks   = (empty($matches[8]) ? 0 : (int) $matches[8]);

        if (!empty($matches[1])) {
            /* Negative */
            $durYears   = -$durYears;
            $durMonths  = -$durMonths;
            $durDays    = -$durDays;
            $durHours   = -$durHours;
            $durMinutes = -$durMinutes;
            $durSeconds = -$durSeconds;
            $durWeeks   = -$durWeeks;
        }

        if ($timestamp === null) {
            $timestamp = time();
        }

        if ($durYears !== 0 || $durMonths !== 0) {
            /* Special handling of months and years, since they aren't a specific interval, but
             * instead depend on the current time.
             */

            /* We need the year and month from the timestamp. Unfortunately, PHP doesn't have the
             * gmtime function. Instead we use the gmdate function, and split the result.
             */
            $yearmonth = explode(':', gmdate('Y:n', $timestamp));
            $year      = (int) $yearmonth[0];
            $month     = (int) $yearmonth[1];

            /* Remove the year and month from the timestamp. */
            $timestamp -= gmmktime(0, 0, 0, $month, 1, $year);

            /* Add years and months, and normalize the numbers afterwards. */
            $year  += $durYears;
            $month += $durMonths;
            while ($month > 12) {
                $year  += 1;
                $month -= 12;
            }
            while ($month < 1) {
                $year  -= 1;
                $month += 12;
            }

            /* Add year and month back into timestamp. */
            $timestamp += gmmktime(0, 0, 0, $month, 1, $year);
        }

        /* Add the other elements. */
        $timestamp += $durWeeks * 7 * 24 * 60 * 60;
        $timestamp += $durDays * 24 * 60 * 60;
        $timestamp += $durHours * 60 * 60;
        $timestamp += $durMinutes * 60;
        $timestamp += $durSeconds;

        return $timestamp;
    }

    /**
     * Compares 2 dates and returns the earliest.
     *
     * @param string|null $cacheDuration The duration, as a string.
     * @param string|int|null $validUntil The valid until date, as a string or as a timestamp
     *
     * @return int|null $expireTime  The expiration time.
     *
     * @throws Exception
     */
    public static function getExpireTime($cacheDuration = null, $validUntil = null)
    {
        $expireTime = null;

        if ($cacheDuration !== null) {
            $expireTime = self::parseDuration($cacheDuration, time());
        }

        if ($validUntil !== null) {
            if (is_int($validUntil)) {
                $validUntilTime = $validUntil;
            } else {
                $validUntilTime = self::parseSAML2Time($validUntil);
            }
            if ($expireTime === null || $expireTime > $validUntilTime) {
                $expireTime = $validUntilTime;
            }
        }

        return $expireTime;
    }

    /**
     * Extracts nodes from the DOMDocument.
     *
     * @param DOMDocument $dom The DOMDocument
     * @param string $query \Xpath Expression
     * @param DOMElement|null $context Context Node (DOMElement)
     *
     * @return DOMNodeList The queried nodes
     */
    public static function query(DOMDocument $dom, $query, DOMElement $context = null)
    {
        $xpath = new DOMXPath($dom);
        $xpath->registerNamespace('samlp', Constants::NS_SAMLP);
        $xpath->registerNamespace('saml', Constants::NS_SAML);
        $xpath->registerNamespace('ds', Constants::NS_DS);
        $xpath->registerNamespace('xenc', Constants::NS_XENC);
        $xpath->registerNamespace('xsi', Constants::NS_XSI);
        $xpath->registerNamespace('xs', Constants::NS_XS);
        $xpath->registerNamespace('md', Constants::NS_MD);

        if (isset($context)) {
            $res = $xpath->query($query, $context);
        } else {
            $res = $xpath->query($query);
        }
        return $res;
    }

    /**
     * Calculates the fingerprint of a x509cert.
     *
     * @param string $x509cert x509 cert formatted
     * @param string $alg Algorithm to be used in order to calculate the fingerprint
     *
     * @return null|string Formatted fingerprint
     */
    public static function calculateX509Fingerprint($x509cert, $alg = 'sha1')
    {
        assert(is_string($x509cert));

        $arCert = explode("\n", $x509cert);
        $data   = '';
        $inData = false;

        foreach ($arCert as $curData) {
            if (!$inData) {
                if (strncmp($curData, '-----BEGIN CERTIFICATE', 22) == 0) {
                    $inData = true;
                } elseif ((strncmp($curData, '-----BEGIN PUBLIC KEY', 21) == 0) || (strncmp($curData, '-----BEGIN RSA PRIVATE KEY', 26) == 0)) {
                    /* This isn't an X509 certificate. */
                    return null;
                }
            } else {
                if (strncmp($curData, '-----END CERTIFICATE', 20) == 0) {
                    break;
                }
                $data .= trim($curData);
            }
        }

        if (empty($data)) {
            return null;
        }

        $decodedData = base64_decode($data);

        switch ($alg) {
            case 'sha512':
            case 'sha384':
            case 'sha256':
                $fingerprint = hash($alg, $decodedData, false);
                break;
            case 'sha1':
            default:
                $fingerprint = strtolower(sha1($decodedData));
                break;
        }
        return $fingerprint;
    }

    /**
     * Formates a fingerprint.
     *
     * @param string $fingerprint fingerprint
     *
     * @return string Formatted fingerprint
     */
    public static function formatFingerPrint($fingerprint)
    {
        $formatedFingerprint = str_replace(':', '', $fingerprint);
        return strtolower($formatedFingerprint);
    }

    /**
     * Generates a nameID.
     *
     * @param string $value fingerprint
     * @param string $spnq SP Name Qualifier
     * @param string|null $format SP Format
     * @param string|null $cert IdP Public cert to encrypt the nameID
     * @param string|null $nq IdP Name Qualifier
     * @param string|null $encAlg Encryption algorithm
     *
     * @return string $nameIDElement DOMElement | XMLSec nameID
     *
     * @throws Exception
     */
    public static function generateNameId($value, $spnq, $format = null, $cert = null, $nq = null, $encAlg = XMLSecurityKey::AES128_CBC)
    {

        $doc = new DOMDocument();

        $nameId = $doc->createElement('saml:NameID');
        if (isset($spnq)) {
            $nameId->setAttribute('SPNameQualifier', $spnq);
        }
        if (isset($nq)) {
            $nameId->setAttribute('NameQualifier', $nq);
        }
        if (isset($format)) {
            $nameId->setAttribute('Format', $format);
        }
        $nameId->appendChild($doc->createTextNode($value));

        $doc->appendChild($nameId);

        if (!empty($cert)) {
            if ($encAlg == XMLSecurityKey::AES128_CBC) {
                $seckey = new XMLSecurityKey(XMLSecurityKey::RSA_1_5, ['type' => 'public']);
            } else {
                $seckey = new XMLSecurityKey(XMLSecurityKey::RSA_OAEP_MGF1P, ['type' => 'public']);
            }
            $seckey->loadKey($cert);

            $enc = new XMLSecEnc();
            $enc->setNode($nameId);
            $enc->type = XMLSecEnc::Element;

            $symmetricKey = new XMLSecurityKey($encAlg);
            $symmetricKey->generateSessionKey();
            $enc->encryptKey($seckey, $symmetricKey);

            $encryptedData = $enc->encryptNode($symmetricKey);

            $newdoc = new DOMDocument();

            $encryptedID = $newdoc->createElement('saml:EncryptedID');

            $newdoc->appendChild($encryptedID);

            $encryptedID->appendChild($encryptedID->ownerDocument->importNode($encryptedData, true));

            return $newdoc->saveXML($encryptedID);
        } else {
            return $doc->saveXML($nameId);
        }
    }

    /**
     * Gets Status from a Response.
     *
     * @param DOMDocument $dom The Response as XML
     *
     * @return array $status The Status, an array with the code and a message.
     *
     * @throws ValidationError
     */
    public static function getStatus(DOMDocument $dom)
    {
        $status = [];

        $statusEntry = self::query($dom, '/samlp:Response/samlp:Status');
        if ($statusEntry->length != 1) {
            throw new ValidationError(
                "Missing Status on response",
                ValidationError::MISSING_STATUS
            );
        }

        $codeEntry = self::query($dom, '/samlp:Response/samlp:Status/samlp:StatusCode', $statusEntry->item(0));
        if ($codeEntry->length != 1) {
            throw new ValidationError(
                "Missing Status Code on response",
                ValidationError::MISSING_STATUS_CODE
            );
        }
        $code           = $codeEntry->item(0)->getAttribute('Value');
        $status['code'] = $code;

        $status['msg'] = '';
        $messageEntry  = self::query($dom, '/samlp:Response/samlp:Status/samlp:StatusMessage', $statusEntry->item(0));
        if ($messageEntry->length == 0) {
            $subCodeEntry = self::query($dom, '/samlp:Response/samlp:Status/samlp:StatusCode/samlp:StatusCode', $statusEntry->item(0));
            if ($subCodeEntry->length == 1) {
                $status['msg'] = $subCodeEntry->item(0)->getAttribute('Value');
            }
        } elseif ($messageEntry->length == 1) {
            $msg           = $messageEntry->item(0)->textContent;
            $status['msg'] = $msg;
        }

        return $status;
    }

    /**
     * Decrypts an encrypted element.
     *
     * @param DOMElement $encryptedData The encrypted data.
     * @param XMLSecurityKey $inputKey The decryption key.
     * @param bool $formatOutput Format or not the output.
     *
     * @return DOMElement  The decrypted element.
     *
     * @throws ValidationError
     */
    public static function decryptElement(DOMElement $encryptedData, XMLSecurityKey $inputKey, $formatOutput = true)
    {

        $enc = new XMLSecEnc();

        $enc->setNode($encryptedData);
        $enc->type = $encryptedData->getAttribute("Type");

        $symmetricKey = $enc->locateKey($encryptedData);
        if (!$symmetricKey) {
            throw new ValidationError(
                'Could not locate key algorithm in encrypted data.',
                ValidationError::KEY_ALGORITHM_ERROR
            );
        }

        $symmetricKeyInfo = $enc->locateKeyInfo($symmetricKey);
        if (!$symmetricKeyInfo) {
            throw new ValidationError(
                "Could not locate <dsig:KeyInfo> for the encrypted key.",
                ValidationError::KEYINFO_NOT_FOUND_IN_ENCRYPTED_DATA
            );
        }

        $inputKeyAlgo = $inputKey->getAlgorithm();
        if ($symmetricKeyInfo->isEncrypted) {
            $symKeyInfoAlgo = $symmetricKeyInfo->getAlgorithm();

            if ($symKeyInfoAlgo === XMLSecurityKey::RSA_OAEP_MGF1P && $inputKeyAlgo === XMLSecurityKey::RSA_1_5) {
                $inputKeyAlgo = XMLSecurityKey::RSA_OAEP_MGF1P;
            }

            if ($inputKeyAlgo !== $symKeyInfoAlgo) {
                throw new ValidationError(
                    'Algorithm mismatch between input key and key used to encrypt ' .
                    ' the symmetric key for the message. Key was: ' .
                    var_export($inputKeyAlgo, true) . '; message was: ' .
                    var_export($symKeyInfoAlgo, true),
                    ValidationError::KEY_ALGORITHM_ERROR
                );
            }

            $encKey                = $symmetricKeyInfo->encryptedCtx;
            $symmetricKeyInfo->key = $inputKey->key;
            $keySize               = $symmetricKey->getSymmetricKeySize();
            if ($keySize === null) {
                // To protect against "key oracle" attacks
                throw new ValidationError(
                    'Unknown key size for encryption algorithm: ' . var_export($symmetricKey->type, true),
                    ValidationError::KEY_ALGORITHM_ERROR
                );
            }

            $key = $encKey->decryptKey($symmetricKeyInfo);
            if (strlen($key) != $keySize) {
                $encryptedKey = $encKey->getCipherValue();
                $pkey         = openssl_pkey_get_details($symmetricKeyInfo->key);
                $pkey         = sha1(serialize($pkey), true);
                $key          = sha1($encryptedKey . $pkey, true);

                /* Make sure that the key has the correct length. */
                if (strlen($key) > $keySize) {
                    $key = substr($key, 0, $keySize);
                } elseif (strlen($key) < $keySize) {
                    $key = str_pad($key, $keySize);
                }
            }
            $symmetricKey->loadKey($key);
        } else {
            $symKeyAlgo = $symmetricKey->getAlgorithm();
            if ($inputKeyAlgo !== $symKeyAlgo) {
                throw new ValidationError(
                    'Algorithm mismatch between input key and key in message. ' .
                    'Key was: ' . var_export($inputKeyAlgo, true) . '; message was: ' .
                    var_export($symKeyAlgo, true),
                    ValidationError::KEY_ALGORITHM_ERROR
                );
            }
            $symmetricKey = $inputKey;
        }

        $decrypted = $enc->decryptNode($symmetricKey, false);

        $xml    = '<root xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">' . $decrypted . '</root>';
        $newDoc = new DOMDocument();
        if ($formatOutput) {
            $newDoc->preserveWhiteSpace = false;
            $newDoc->formatOutput       = true;
        }
        $newDoc = self::loadXML($newDoc, $xml);
        if (!$newDoc) {
            throw new ValidationError(
                'Failed to parse decrypted XML.',
                ValidationError::INVALID_XML_FORMAT
            );
        }

        $decryptedElement = $newDoc->firstChild->firstChild;
        if ($decryptedElement === null) {
            throw new ValidationError(
                'Missing encrypted element.',
                ValidationError::MISSING_ENCRYPTED_ELEMENT
            );
        }

        return $decryptedElement;
    }

    /**
     * Converts a XMLSecurityKey to the correct algorithm.
     *
     * @param XMLSecurityKey $key The key.
     * @param string $algorithm The desired algorithm.
     * @param string $type Public or private key, defaults to public.
     *
     * @return XMLSecurityKey The new key.
     *
     * @throws Exception
     */
    public static function castKey(XMLSecurityKey $key, $algorithm, $type = 'public')
    {
        assert(is_string($algorithm));
        assert($type === 'public' || $type === 'private');

        // do nothing if algorithm is already the type of the key
        if ($key->type === $algorithm) {
            return $key;
        }

        if (!Utils::isSupportedSigningAlgorithm($algorithm)) {
            throw new Exception('Unsupported signing algorithm.');
        }

        $keyInfo = openssl_pkey_get_details($key->key);
        if ($keyInfo === false) {
            throw new Exception('Unable to get key details from XMLSecurityKey.');
        }
        if (!isset($keyInfo['key'])) {
            throw new Exception('Missing key in public key details.');
        }
        $newKey = new XMLSecurityKey($algorithm, ['type' => $type]);
        $newKey->loadKey($keyInfo['key']);
        return $newKey;
    }

    /**
     * @param $algorithm
     *
     * @return bool
     */
    public static function isSupportedSigningAlgorithm($algorithm)
    {
        return in_array(
            $algorithm,
            [
                XMLSecurityKey::RSA_1_5,
                XMLSecurityKey::RSA_SHA1,
                XMLSecurityKey::RSA_SHA256,
                XMLSecurityKey::RSA_SHA384,
                XMLSecurityKey::RSA_SHA512,
            ]
        );
    }

    /**
     * Adds signature key and senders certificate to an element (Message or Assertion).
     *
     * @param string|DOMDocument $xml The element we should sign
     * @param string $key The private key
     * @param string $cert The public
     * @param string $signAlgorithm Signature algorithm method
     * @param string $digestAlgorithm Digest algorithm method
     *
     * @return string
     *
     * @throws Exception
     */
    public static function addSign($xml, $key, $cert, $signAlgorithm = XMLSecurityKey::RSA_SHA256, $digestAlgorithm = XMLSecurityDSig::SHA256)
    {
        if ($xml instanceof DOMDocument) {
            $dom = $xml;
        } else {
            $dom = new DOMDocument();
            $dom = self::loadXML($dom, $xml);
            if (!$dom) {
                throw new Exception('Error parsing xml string');
            }
        }

        /* Load the private key. */
        $objKey = new XMLSecurityKey($signAlgorithm, ['type' => 'private']);
        $objKey->loadKey($key, false);

        /* Get the EntityDescriptor node we should sign. */
        $rootNode = $dom->firstChild;

        /* Sign the metadata with our private key. */
        $objXMLSecDSig = new XMLSecurityDSig();
        $objXMLSecDSig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);

        $objXMLSecDSig->addReferenceList(
            [$rootNode],
            $digestAlgorithm,
            ['http://www.w3.org/2000/09/xmldsig#enveloped-signature', XMLSecurityDSig::EXC_C14N],
            ['id_name' => 'ID']
        );

        $objXMLSecDSig->sign($objKey);

        /* Add the certificate to the signature. */
        $objXMLSecDSig->add509Cert($cert, true);

        $insertBefore = $rootNode->firstChild;
        $messageTypes = ['AuthnRequest', 'Response', 'LogoutRequest', 'LogoutResponse'];
        if (in_array($rootNode->localName, $messageTypes)) {
            $issuerNodes = self::query($dom, '/' . $rootNode->tagName . '/saml:Issuer');
            if ($issuerNodes->length == 1) {
                $insertBefore = $issuerNodes->item(0)->nextSibling;
            }
        }

        /* Add the signature. */
        $objXMLSecDSig->insertSignature($rootNode, $insertBefore);

        /* Return the DOM tree as a string. */
        return $dom->saveXML();
    }

    /**
     * Validates a signature (Message or Assertion).
     *
     * @param string|\DomNode $xml The element we should validate
     * @param string|null $cert The public cert
     * @param string|null $fingerprint The fingerprint of the public cert
     * @param string|null $fingerprintalg The algorithm used to get the fingerprint
     * @param string|null $xpath The xpath of the signed element
     * @param array|null $multiCerts Multiple public certs
     *
     * @return bool
     *
     * @throws Exception
     */
    public static function validateSign($xml, $cert = null, $fingerprint = null, $fingerprintalg = 'sha1', $xpath = null, $multiCerts = null)
    {
        if ($xml instanceof DOMDocument) {
            $dom = clone $xml;
        } elseif ($xml instanceof DOMElement) {
            $dom = clone $xml->ownerDocument;
        } else {
            $dom = new DOMDocument();
            $dom = self::loadXML($dom, $xml);
        }

        $objXMLSecDSig         = new XMLSecurityDSig();
        $objXMLSecDSig->idKeys = ['ID'];

        if ($xpath) {
            $nodeset                = Utils::query($dom, $xpath);
            $objDSig                = $nodeset->item(0);
            $objXMLSecDSig->sigNode = $objDSig;
        } else {
            $objDSig = $objXMLSecDSig->locateSignature($dom);
        }

        if (!$objDSig) {
            throw new Exception('Cannot locate Signature Node');
        }

        $objKey = $objXMLSecDSig->locateKey();
        if (!$objKey) {
            throw new Exception('We have no idea about the key');
        }

        if (!Utils::isSupportedSigningAlgorithm($objKey->type)) {
            throw new Exception('Unsupported signing algorithm.');
        }

        $objXMLSecDSig->canonicalizeSignedInfo();

        try {
            $retVal = $objXMLSecDSig->validateReference();
        } catch (Exception $e) {
            throw $e;
        }

        XMLSecEnc::staticLocateKeyInfo($objKey, $objDSig);

        if (!empty($multiCerts)) {
            // If multiple certs are provided, I may ignore $cert and
            // $fingerprint provided by the method and just check the
            // certs on the array
            $fingerprint = null;
        } else {
            // else I add the cert to the array in order to check
            // validate signatures with it and the with it and the
            // $fingerprint value
            $multiCerts = [$cert];
        }

        $valid = false;
        foreach ($multiCerts as $cert) {
            if (!empty($cert)) {
                $objKey->loadKey($cert, false, true);
                if ($objXMLSecDSig->verify($objKey) === 1) {
                    $valid = true;
                    break;
                }
            } else {
                if (!empty($fingerprint)) {
                    $domCert            = $objKey->getX509Certificate();
                    $domCertFingerprint = Utils::calculateX509Fingerprint($domCert, $fingerprintalg);
                    if (Utils::formatFingerPrint($fingerprint) == $domCertFingerprint) {
                        $objKey->loadKey($domCert, false, true);
                        if ($objXMLSecDSig->verify($objKey) === 1) {
                            $valid = true;
                            break;
                        }
                    }
                }
            }
        }
        return $valid;
    }

}
