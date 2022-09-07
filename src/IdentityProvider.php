<?php

namespace think\saml;

use DOMDocument;
use Exception;

class IdentityProvider
{
    protected $data;

    public function __construct(array $data)
    {
        $this->data = $data;

        $this->addDefaultValues();
    }

    protected function addDefaultValues()
    {
        // Certificates / Private key /Fingerprint
        if (!isset($this->data['x509cert'])) {
            $this->data['x509cert'] = '';
        }
        if (!isset($this->data['certFingerprint'])) {
            $this->data['certFingerprint'] = '';
        }
        if (!isset($this->data['certFingerprintAlgorithm'])) {
            $this->data['certFingerprintAlgorithm'] = 'sha1';
        }
    }

    public function getData()
    {
        return $this->data;
    }

    public function getSSOUrl()
    {
        $ssoUrl = null;
        if (isset($this->data['singleSignOnService']) && isset($this->data['singleSignOnService']['url'])) {
            $ssoUrl = $this->data['singleSignOnService']['url'];
        }
        return $ssoUrl;
    }

    public static function parseXML($xml, $entityId = null, $desiredNameIdFormat = null, $desiredSSOBinding = Constants::BINDING_HTTP_REDIRECT, $desiredSLOBinding = Constants::BINDING_HTTP_REDIRECT)
    {
        $data = [];

        $dom = new DOMDocument();

        $dom->preserveWhiteSpace = false;
        $dom->formatOutput       = true;

        try {
            $dom = Utils::loadXML($dom, $xml);
            if (!$dom) {
                throw new Exception('Error parsing metadata');
            }

            $customIdPStr = '';
            if (!empty($entityId)) {
                $customIdPStr = '[@entityID="' . $entityId . '"]';
            }
            $idpDescryptorXPath = '//md:EntityDescriptor' . $customIdPStr . '/md:IDPSSODescriptor';

            $idpDescriptorNodes = Utils::query($dom, $idpDescryptorXPath);

            if (isset($idpDescriptorNodes) && $idpDescriptorNodes->length > 0) {

                $idpDescriptor = $idpDescriptorNodes->item(0);

                if (empty($entityId) && $idpDescriptor->parentNode->hasAttribute('entityID')) {
                    $entityId = $idpDescriptor->parentNode->getAttribute('entityID');
                }

                if (!empty($entityId)) {
                    $data['entityId'] = $entityId;
                }

                $ssoNodes = Utils::query($dom, './md:SingleSignOnService[@Binding="' . $desiredSSOBinding . '"]', $idpDescriptor);
                if ($ssoNodes->length < 1) {
                    $ssoNodes = Utils::query($dom, './md:SingleSignOnService', $idpDescriptor);
                }
                if ($ssoNodes->length > 0) {
                    $data['singleSignOnService'] = [
                        'url'     => $ssoNodes->item(0)->getAttribute('Location'),
                        'binding' => $ssoNodes->item(0)->getAttribute('Binding'),
                    ];
                }

                $sloNodes = Utils::query($dom, './md:SingleLogoutService[@Binding="' . $desiredSLOBinding . '"]', $idpDescriptor);
                if ($sloNodes->length < 1) {
                    $sloNodes = Utils::query($dom, './md:SingleLogoutService', $idpDescriptor);
                }
                if ($sloNodes->length > 0) {
                    $data['singleLogoutService'] = [
                        'url'     => $sloNodes->item(0)->getAttribute('Location'),
                        'binding' => $sloNodes->item(0)->getAttribute('Binding'),
                    ];

                    if ($sloNodes->item(0)->hasAttribute('ResponseLocation')) {
                        $data['singleLogoutService']['responseUrl'] = $sloNodes->item(0)
                            ->getAttribute('ResponseLocation');
                    }
                }

                $keyDescriptorCertSigningNodes = Utils::query($dom, './md:KeyDescriptor[not(contains(@use, "encryption"))]/ds:KeyInfo/ds:X509Data/ds:X509Certificate', $idpDescriptor);

                $keyDescriptorCertEncryptionNodes = Utils::query($dom, './md:KeyDescriptor[not(contains(@use, "signing"))]/ds:KeyInfo/ds:X509Data/ds:X509Certificate', $idpDescriptor);

                if (!empty($keyDescriptorCertSigningNodes) || !empty($keyDescriptorCertEncryptionNodes)) {
                    $data['x509certMulti'] = [];
                    if (!empty($keyDescriptorCertSigningNodes)) {
                        $idpInfo['x509certMulti']['signing'] = [];
                        foreach ($keyDescriptorCertSigningNodes as $keyDescriptorCertSigningNode) {
                            $data['x509certMulti']['signing'][] = Utils::formatCert($keyDescriptorCertSigningNode->nodeValue, false);
                        }
                    }
                    if (!empty($keyDescriptorCertEncryptionNodes)) {
                        $idpInfo['x509certMulti']['encryption'] = [];
                        foreach ($keyDescriptorCertEncryptionNodes as $keyDescriptorCertEncryptionNode) {
                            $data['x509certMulti']['encryption'][] = Utils::formatCert($keyDescriptorCertEncryptionNode->nodeValue, false);
                        }
                    }

                    $idpCertdata = $data['x509certMulti'];
                    if ((count($idpCertdata) == 1 and
                            ((isset($idpCertdata['signing']) and count($idpCertdata['signing']) == 1) or (isset($idpCertdata['encryption']) and count($idpCertdata['encryption']) == 1))) or
                        ((isset($idpCertdata['signing']) && count($idpCertdata['signing']) == 1) && isset($idpCertdata['encryption']) && count($idpCertdata['encryption']) == 1 && strcmp($idpCertdata['signing'][0], $idpCertdata['encryption'][0]) == 0)) {
                        if (isset($data['x509certMulti']['signing'][0])) {
                            $data['x509cert'] = $data['x509certMulti']['signing'][0];
                        } else {
                            $data['x509cert'] = $data['x509certMulti']['encryption'][0];
                        }
                        unset($data['x509certMulti']);
                    }
                }

                $nameIdFormatNodes = Utils::query($dom, './md:NameIDFormat', $idpDescriptor);
                if ($nameIdFormatNodes->length > 0) {
                    $data['NameIDFormat'] = $nameIdFormatNodes->item(0)->nodeValue;
                    if (!empty($desiredNameIdFormat)) {
                        foreach ($nameIdFormatNodes as $nameIdFormatNode) {
                            if (strcmp($nameIdFormatNode->nodeValue, $desiredNameIdFormat) == 0) {
                                $data['NameIDFormat'] = $nameIdFormatNode->nodeValue;
                                break;
                            }
                        }
                    }
                }
            }
        } catch (Exception $e) {
            throw new Exception('Error parsing metadata. ' . $e->getMessage());
        }

        return $data;
    }

    public static function fromXml($xml)
    {
        $data = self::parseXML($xml);

        return new static($data);
    }
}
