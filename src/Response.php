<?php

namespace think\saml;

use DOMDocument;
use DOMNode;
use DOMXPath;
use Exception;
use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityKey;

class Response
{
    protected $key;
    protected $idp;
    protected $security;

    protected $document;
    protected $encrypted;
    protected $decryptedDocument;

    public function __construct($xml, $key, $idp, $security)
    {
        $this->key      = $key;
        $this->idp      = $idp;
        $this->security = $security;
        $this->document = Utils::loadXML(new DOMDocument(), $xml);

        if (!$this->document) {
            throw new ValidationError(
                "SAML Response could not be processed",
                ValidationError::INVALID_XML_FORMAT
            );
        }

        $encryptedAssertionNodes = $this->document->getElementsByTagName('EncryptedAssertion');
        if ($encryptedAssertionNodes->length !== 0) {
            $this->decryptedDocument = clone $this->document;
            $this->encrypted         = true;
            $this->decryptedDocument = $this->decryptAssertion($this->decryptedDocument);
        }
    }

    protected function decryptAssertion(DOMDocument $dom)
    {
        $pem = $this->key;

        if (empty($pem)) {
            throw new Error(
                "No private key available, check settings",
                Error::PRIVATE_KEY_NOT_FOUND
            );
        }

        $objenc  = new XMLSecEnc();
        $encData = $objenc->locateEncryptedData($dom);
        if (!$encData) {
            throw new ValidationError(
                "Cannot locate encrypted assertion",
                ValidationError::MISSING_ENCRYPTED_ELEMENT
            );
        }

        $objenc->setNode($encData);
        $objenc->type = $encData->getAttribute("Type");
        if (!$objKey = $objenc->locateKey()) {
            throw new ValidationError(
                "Unknown algorithm",
                ValidationError::KEY_ALGORITHM_ERROR
            );
        }

        $key = null;
        if ($objKeyInfo = $objenc->locateKeyInfo($objKey)) {
            if ($objKeyInfo->isEncrypted) {
                $objencKey = $objKeyInfo->encryptedCtx;
                $objKeyInfo->loadKey($pem, false, false);
                $key = $objencKey->decryptKey($objKeyInfo);
            } else {
                // symmetric encryption key support
                $objKeyInfo->loadKey($pem, false, false);
            }
        }

        if (empty($objKey->key)) {
            $objKey->loadKey($key);
        }

        $decryptedXML = $objenc->decryptNode($objKey, false);
        $decrypted    = new DOMDocument();
        $check        = Utils::loadXML($decrypted, $decryptedXML);
        if ($check === false) {
            throw new Exception('Error: string from decrypted assertion could not be loaded into a XML document');
        }
        if ($encData->parentNode instanceof DOMDocument) {
            return $decrypted;
        } else {
            $decrypted          = $decrypted->documentElement;
            $encryptedAssertion = $encData->parentNode;
            $container          = $encryptedAssertion->parentNode;

            // Fix possible issue with saml namespace
            if (!$decrypted->hasAttributeNS('http://www.w3.org/2000/xmlns/', 'xmlns:saml')
                && !$decrypted->hasAttributeNS('http://www.w3.org/2000/xmlns/', 'xmlns:saml2')
                && !$decrypted->hasAttributeNS('http://www.w3.org/2000/xmlns/', 'xmlns')
                && !$container->hasAttributeNS('http://www.w3.org/2000/xmlns/', 'xmlns:saml')
                && !$container->hasAttributeNS('http://www.w3.org/2000/xmlns/', 'xmlns:saml2')
            ) {
                if (strpos($encryptedAssertion->tagName, 'saml2:') !== false) {
                    $ns = 'xmlns:saml2';
                } elseif (strpos($encryptedAssertion->tagName, 'saml:') !== false) {
                    $ns = 'xmlns:saml';
                } else {
                    $ns = 'xmlns';
                }
                $decrypted->setAttributeNS('http://www.w3.org/2000/xmlns/', $ns, Constants::NS_SAML);
            }

            Utils::treeCopyReplace($encryptedAssertion, $decrypted);

            // Rebuild the DOM will fix issues with namespaces as well
            $dom = new DOMDocument();
            return Utils::loadXML($dom, $container->ownerDocument->saveXML());
        }
    }

    protected function checkStatus()
    {
        $status = Utils::getStatus($this->document);

        if (isset($status['code']) && $status['code'] !== Constants::STATUS_SUCCESS) {
            $explodedCode  = explode(':', $status['code']);
            $printableCode = array_pop($explodedCode);

            $statusExceptionMsg = 'The status code of the Response was not Success, was ' . $printableCode;
            if (!empty($status['msg'])) {
                $statusExceptionMsg .= ' -> ' . $status['msg'];
            }
            throw new ValidationError(
                $statusExceptionMsg,
                ValidationError::STATUS_CODE_IS_NOT_SUCCESS
            );
        }
    }

    protected function validateNumAssertions()
    {
        $encryptedAssertionNodes = $this->document->getElementsByTagName('EncryptedAssertion');
        $assertionNodes          = $this->document->getElementsByTagName('Assertion');

        $valid = $assertionNodes->length + $encryptedAssertionNodes->length == 1;

        if ($this->encrypted) {
            $assertionNodes = $this->decryptedDocument->getElementsByTagName('Assertion');
            $valid          = $valid && $assertionNodes->length == 1;
        }

        return $valid;
    }

    private function query($query)
    {
        if ($this->encrypted) {
            return Utils::query($this->decryptedDocument, $query);
        } else {
            return Utils::query($this->document, $query);
        }
    }

    protected function validateSignedElements($signedElements)
    {
        if (count($signedElements) > 2) {
            return false;
        }

        $responseTag  = '{' . Constants::NS_SAMLP . '}Response';
        $assertionTag = '{' . Constants::NS_SAML . '}Assertion';

        $ocurrence = array_count_values($signedElements);
        if ((in_array($responseTag, $signedElements) && $ocurrence[$responseTag] > 1)
            || (in_array($assertionTag, $signedElements) && $ocurrence[$assertionTag] > 1)
            || !in_array($responseTag, $signedElements) && !in_array($assertionTag, $signedElements)
        ) {
            return false;
        }

        // Check that the signed elements found here, are the ones that will be verified
        // by Utils->validateSign()
        if (in_array($responseTag, $signedElements)) {
            $expectedSignatureNodes = Utils::query($this->document, Utils::RESPONSE_SIGNATURE_XPATH);
            if ($expectedSignatureNodes->length != 1) {
                throw new ValidationError(
                    "Unexpected number of Response signatures found. SAML Response rejected.",
                    ValidationError::WRONG_NUMBER_OF_SIGNATURES_IN_RESPONSE
                );
            }
        }

        if (in_array($assertionTag, $signedElements)) {
            $expectedSignatureNodes = $this->query(Utils::ASSERTION_SIGNATURE_XPATH);
            if ($expectedSignatureNodes->length != 1) {
                throw new ValidationError(
                    "Unexpected number of Assertion signatures found. SAML Response rejected.",
                    ValidationError::WRONG_NUMBER_OF_SIGNATURES_IN_ASSERTION
                );
            }
        }

        return true;
    }

    protected function processSignedElements()
    {
        $signedElements = [];
        $verifiedSeis   = [];
        $verifiedIds    = [];

        if ($this->encrypted) {
            $signNodes = $this->decryptedDocument->getElementsByTagName('Signature');
        } else {
            $signNodes = $this->document->getElementsByTagName('Signature');
        }
        foreach ($signNodes as $signNode) {
            $responseTag  = '{' . Constants::NS_SAMLP . '}Response';
            $assertionTag = '{' . Constants::NS_SAML . '}Assertion';

            $signedElement = '{' . $signNode->parentNode->namespaceURI . '}' . $signNode->parentNode->localName;

            if ($signedElement != $responseTag && $signedElement != $assertionTag) {
                throw new ValidationError(
                    "Invalid Signature Element $signedElement SAML Response rejected",
                    ValidationError::WRONG_SIGNED_ELEMENT
                );
            }

            // Check that reference URI matches the parent ID and no duplicate References or IDs
            $idValue = $signNode->parentNode->getAttribute('ID');
            if (empty($idValue)) {
                throw new ValidationError(
                    'Signed Element must contain an ID. SAML Response rejected',
                    ValidationError::ID_NOT_FOUND_IN_SIGNED_ELEMENT
                );
            }

            if (in_array($idValue, $verifiedIds)) {
                throw new ValidationError(
                    'Duplicated ID. SAML Response rejected',
                    ValidationError::DUPLICATED_ID_IN_SIGNED_ELEMENTS
                );
            }
            $verifiedIds[] = $idValue;

            $ref = $signNode->getElementsByTagName('Reference');
            if ($ref->length == 1) {
                $ref = $ref->item(0);
                $sei = $ref->getAttribute('URI');
                if (!empty($sei)) {
                    $sei = substr($sei, 1);

                    if ($sei != $idValue) {
                        throw new ValidationError(
                            'Found an invalid Signed Element. SAML Response rejected',
                            ValidationError::INVALID_SIGNED_ELEMENT
                        );
                    }

                    if (in_array($sei, $verifiedSeis)) {
                        throw new ValidationError(
                            'Duplicated Reference URI. SAML Response rejected',
                            ValidationError::DUPLICATED_REFERENCE_IN_SIGNED_ELEMENTS
                        );
                    }
                    $verifiedSeis[] = $sei;
                }
            } else {
                throw new ValidationError(
                    'Unexpected number of Reference nodes found for signature. SAML Response rejected.',
                    ValidationError::UNEXPECTED_REFERENCE
                );
            }
            $signedElements[] = $signedElement;
        }

        // Check SignedElements
        if (!empty($signedElements) && !$this->validateSignedElements($signedElements)) {
            throw new ValidationError(
                'Found an unexpected Signature Element. SAML Response rejected',
                ValidationError::UNEXPECTED_SIGNED_ELEMENTS
            );
        }
        return $signedElements;
    }

    public function valid()
    {
        // Check SAML version
        if ($this->document->documentElement->getAttribute('Version') != '2.0') {
            throw new ValidationError(
                "Unsupported SAML version",
                ValidationError::UNSUPPORTED_SAML_VERSION
            );
        }

        if (!$this->document->documentElement->hasAttribute('ID')) {
            throw new ValidationError(
                "Missing ID attribute on SAML Response",
                ValidationError::MISSING_ID
            );
        }

        $this->checkStatus();

        $singleAssertion = $this->validateNumAssertions();
        if (!$singleAssertion) {
            throw new ValidationError(
                "SAML Response must contain 1 assertion",
                ValidationError::WRONG_NUMBER_OF_ASSERTIONS
            );
        }

        $idpData = $this->idp;

        $signedElements = $this->processSignedElements();

        $responseTag  = '{' . Constants::NS_SAMLP . '}Response';
        $assertionTag = '{' . Constants::NS_SAML . '}Assertion';

        $hasSignedResponse  = in_array($responseTag, $signedElements);
        $hasSignedAssertion = in_array($assertionTag, $signedElements);

        // Detect case not supported
        if ($this->encrypted) {
            $encryptedIDNodes = Utils::query($this->decryptedDocument, '/samlp:Response/saml:Assertion/saml:Subject/saml:EncryptedID');
            if ($encryptedIDNodes->length > 0) {
                throw new ValidationError(
                    'SAML Response that contains an encrypted Assertion with encrypted nameId is not supported.',
                    ValidationError::NOT_SUPPORTED
                );
            }
        }

        if (empty($signedElements) || (!$hasSignedResponse && !$hasSignedAssertion)) {
            throw new ValidationError(
                'No Signature found. SAML Response rejected',
                ValidationError::NO_SIGNATURE_FOUND
            );
        } else {
            $cert           = $idpData['x509cert'];
            $fingerprint    = $idpData['certFingerprint'];
            $fingerprintalg = $idpData['certFingerprintAlgorithm'];

            $multiCerts          = null;
            $existsMultiX509Sign = isset($idpData['x509certMulti']) && isset($idpData['x509certMulti']['signing']) && !empty($idpData['x509certMulti']['signing']);

            if ($existsMultiX509Sign) {
                $multiCerts = $idpData['x509certMulti']['signing'];
            }

            // If find a Signature on the Response, validates it checking the original response
            if ($hasSignedResponse && !Utils::validateSign($this->document, $cert, $fingerprint, $fingerprintalg, Utils::RESPONSE_SIGNATURE_XPATH, $multiCerts)) {
                throw new ValidationError(
                    "Signature validation failed. SAML Response rejected",
                    ValidationError::INVALID_SIGNATURE
                );
            }

            // If find a Signature on the Assertion (decrypted assertion if was encrypted)
            $documentToCheckAssertion = $this->encrypted ? $this->decryptedDocument : $this->document;
            if ($hasSignedAssertion && !Utils::validateSign($documentToCheckAssertion, $cert, $fingerprint, $fingerprintalg, Utils::ASSERTION_SIGNATURE_XPATH, $multiCerts)) {
                throw new ValidationError(
                    "Signature validation failed. SAML Response rejected",
                    ValidationError::INVALID_SIGNATURE
                );
            }
        }
    }

    protected function queryAssertion($assertionXpath)
    {
        if ($this->encrypted) {
            $xpath = new DOMXPath($this->decryptedDocument);
        } else {
            $xpath = new DOMXPath($this->document);
        }

        $xpath->registerNamespace('samlp', Constants::NS_SAMLP);
        $xpath->registerNamespace('saml', Constants::NS_SAML);
        $xpath->registerNamespace('ds', Constants::NS_DS);
        $xpath->registerNamespace('xenc', Constants::NS_XENC);

        $assertionNode          = '/samlp:Response/saml:Assertion';
        $signatureQuery         = $assertionNode . '/ds:Signature/ds:SignedInfo/ds:Reference';
        $assertionReferenceNode = $xpath->query($signatureQuery)->item(0);
        if (!$assertionReferenceNode) {
            // is the response signed as a whole?
            $signatureQuery        = '/samlp:Response/ds:Signature/ds:SignedInfo/ds:Reference';
            $responseReferenceNode = $xpath->query($signatureQuery)->item(0);
            if ($responseReferenceNode) {
                $uri = $responseReferenceNode->attributes->getNamedItem('URI')->nodeValue;
                if (empty($uri)) {
                    $id = $responseReferenceNode->parentNode->parentNode->parentNode->attributes->getNamedItem('ID')->nodeValue;
                } else {
                    $id = substr($responseReferenceNode->attributes->getNamedItem('URI')->nodeValue, 1);
                }
                $nameQuery = "/samlp:Response[@ID='$id']/saml:Assertion" . $assertionXpath;
            } else {
                $nameQuery = "/samlp:Response/saml:Assertion" . $assertionXpath;
            }
        } else {
            $uri = $assertionReferenceNode->attributes->getNamedItem('URI')->nodeValue;
            if (empty($uri)) {
                $id = $assertionReferenceNode->parentNode->parentNode->parentNode->attributes->getNamedItem('ID')->nodeValue;
            } else {
                $id = substr($assertionReferenceNode->attributes->getNamedItem('URI')->nodeValue, 1);
            }
            $nameQuery = $assertionNode . "[@ID='$id']" . $assertionXpath;
        }

        return $xpath->query($nameQuery);
    }

    protected function getAttributesByKeyName($keyName = "Name")
    {
        $attributes = [];
        $entries    = $this->queryAssertion('/saml:AttributeStatement/saml:Attribute');

        $security                 = $this->security;
        $allowRepeatAttributeName = $security['allowRepeatAttributeName'];
        /** @var $entry DOMNode */
        foreach ($entries as $entry) {
            $attributeKeyNode = $entry->attributes->getNamedItem($keyName);
            if ($attributeKeyNode === null) {
                continue;
            }
            $attributeKeyName = $attributeKeyNode->nodeValue;
            if (in_array($attributeKeyName, array_keys($attributes))) {
                if (!$allowRepeatAttributeName) {
                    throw new ValidationError(
                        "Found an Attribute element with duplicated " . $keyName,
                        ValidationError::DUPLICATED_ATTRIBUTE_NAME_FOUND
                    );
                }
            }
            $attributeValues = [];
            foreach ($entry->childNodes as $childNode) {
                $tagName = ($childNode->prefix ? $childNode->prefix . ':' : '') . 'AttributeValue';
                if ($childNode->nodeType == XML_ELEMENT_NODE && $childNode->tagName === $tagName) {
                    $attributeValues[] = $childNode->nodeValue;
                }
            }

            if (in_array($attributeKeyName, array_keys($attributes))) {
                $attributes[$attributeKeyName] = array_merge($attributes[$attributeKeyName], $attributeValues);
            } else {
                $attributes[$attributeKeyName] = $attributeValues;
            }
        }
        return $attributes;
    }

    protected function getNameIdData()
    {
        $encryptedIdDataEntries = $this->queryAssertion('/saml:Subject/saml:EncryptedID/xenc:EncryptedData');

        if ($encryptedIdDataEntries->length == 1) {
            $encryptedData = $encryptedIdDataEntries->item(0);

            $key    = $this->key;
            $seckey = new XMLSecurityKey(XMLSecurityKey::RSA_1_5, ['type' => 'private']);
            $seckey->loadKey($key);

            $nameId = Utils::decryptElement($encryptedData, $seckey);
        } else {
            $entries = $this->queryAssertion('/saml:Subject/saml:NameID');
            if ($entries->length == 1) {
                $nameId = $entries->item(0);
            }
        }

        $nameIdData = [];

        if (!isset($nameId)) {
            $security = $this->security;
            if ($security['wantNameId']) {
                throw new ValidationError(
                    "NameID not found in the assertion of the Response",
                    ValidationError::NO_NAMEID
                );
            }
        } else {
            $nameIdData['Value'] = $nameId->nodeValue;

            foreach (['Format', 'SPNameQualifier', 'NameQualifier'] as $attr) {
                if ($nameId->hasAttribute($attr)) {
                    $nameIdData[$attr] = $nameId->getAttribute($attr);
                }
            }
        }

        return $nameIdData;
    }

    public function getId()
    {
        $id = null;
        if ($this->document->documentElement->hasAttribute('ID')) {
            $id = $this->document->documentElement->getAttribute('ID');
        }
        return $id;
    }

    public function getAttributes()
    {
        return $this->getAttributesByKeyName('Name');
    }

    public function getAttributesWithFriendlyName()
    {
        return $this->getAttributesByKeyName('FriendlyName');
    }

    public function getNameId()
    {
        $nameIdvalue = null;
        $nameIdData  = $this->getNameIdData();
        if (!empty($nameIdData) && isset($nameIdData['Value'])) {
            $nameIdvalue = $nameIdData['Value'];
        }
        return $nameIdvalue;
    }

    public function getNameIdFormat()
    {
        $nameIdFormat = null;
        $nameIdData   = $this->getNameIdData();
        if (!empty($nameIdData) && isset($nameIdData['Format'])) {
            $nameIdFormat = $nameIdData['Format'];
        }
        return $nameIdFormat;
    }

    public function getNameIdNameQualifier()
    {
        $nameIdNameQualifier = null;
        $nameIdData          = $this->getNameIdData();
        if (!empty($nameIdData) && isset($nameIdData['NameQualifier'])) {
            $nameIdNameQualifier = $nameIdData['NameQualifier'];
        }
        return $nameIdNameQualifier;
    }

    public function getNameIdSPNameQualifier()
    {
        $nameIdSPNameQualifier = null;
        $nameIdData            = $this->getNameIdData();
        if (!empty($nameIdData) && isset($nameIdData['SPNameQualifier'])) {
            $nameIdSPNameQualifier = $nameIdData['SPNameQualifier'];
        }
        return $nameIdSPNameQualifier;
    }

    public function getSessionIndex()
    {
        $sessionIndex = null;
        $entries      = $this->queryAssertion('/saml:AuthnStatement[@SessionIndex]');
        if ($entries->length !== 0) {
            $sessionIndex = $entries->item(0)->getAttribute('SessionIndex');
        }
        return $sessionIndex;
    }

    public function getSessionNotOnOrAfter()
    {
        $notOnOrAfter = null;
        $entries      = $this->queryAssertion('/saml:AuthnStatement[@SessionNotOnOrAfter]');
        if ($entries->length !== 0) {
            $notOnOrAfter = Utils::parseSAML2Time($entries->item(0)->getAttribute('SessionNotOnOrAfter'));
        }
        return $notOnOrAfter;
    }

    public function getAssertionId()
    {
        if (!$this->validateNumAssertions()) {
            throw new ValidationError("SAML Response must contain 1 Assertion.", ValidationError::WRONG_NUMBER_OF_ASSERTIONS);
        }
        $assertionNodes = $this->queryAssertion("");
        $id             = null;
        if ($assertionNodes->length == 1 && $assertionNodes->item(0)->hasAttribute('ID')) {
            $id = $assertionNodes->item(0)->getAttribute('ID');
        }
        return $id;
    }

}
