<?php

namespace think\saml;

use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

class Auth
{
    /** @var \think\saml\ServiceProvider */
    protected $sp;

    private $compress     = [];
    private $security     = [];
    private $contacts     = [];
    private $organization = [];

    public function __construct(ServiceProvider $sp, array $settings = [])
    {
        $this->sp = $sp;

        if (isset($settings['compress'])) {
            if (!is_array($settings['compress'])) {
                throw new Error("invalid_syntax");
            } elseif (isset($settings['compress']['requests'])
                && $settings['compress']['requests'] !== true
                && $settings['compress']['requests'] !== false
            ) {
                throw new Error("'compress'=>'requests' values must be true or false.");
            } elseif (isset($settings['compress']['responses'])
                && $settings['compress']['responses'] !== true
                && $settings['compress']['responses'] !== false
            ) {
                throw new Error("'compress'=>'responses' values must be true or false.");
            }
            $this->compress = $settings['compress'];
        }

        if (isset($settings['security'])) {
            $this->security = $settings['security'];
        }

        if (isset($settings['contactPerson'])) {
            $types      = array_keys($settings['contactPerson']);
            $validTypes = ['technical', 'support', 'administrative', 'billing', 'other'];
            foreach ($types as $type) {
                if (!in_array($type, $validTypes)) {
                    throw new Error('contact_type_invalid');
                }
            }

            foreach ($settings['contactPerson'] as $type => $contact) {
                if (!isset($contact['givenName']) || empty($contact['givenName'])
                    || !isset($contact['emailAddress']) || empty($contact['emailAddress'])
                ) {
                    throw new Error('contact_not_enought_data');
                }
            }
            $this->contacts = $settings['contactPerson'];
        }

        if (isset($settings['organization'])) {
            foreach ($settings['organization'] as $organization) {
                if (!isset($organization['name']) || empty($organization['name'])
                    || !isset($organization['displayname']) || empty($organization['displayname'])
                    || !isset($organization['url']) || empty($organization['url'])
                ) {
                    throw new Error('organization_not_enought_data');
                }
            }
            $this->organization = $settings['organization'];
        }

        $this->addDefaultValues();

        $this->checkSP();
    }

    protected function checkSP()
    {
        $sp       = $this->sp->getData();
        $security = $this->security;

        if (!isset($sp['entityId']) || empty($sp['entityId'])) {
            throw new Error('sp_entityId_not_found');
        }

        if (!isset($sp['assertionConsumerService'])
            || !isset($sp['assertionConsumerService']['url'])
            || empty($sp['assertionConsumerService']['url'])
        ) {
            throw new Error('sp_acs_not_found');
        } elseif (!filter_var($sp['assertionConsumerService']['url'], FILTER_VALIDATE_URL)) {
            throw new Error('sp_acs_url_invalid');
        }

        if (isset($sp['singleLogoutService'])
            && isset($sp['singleLogoutService']['url'])
            && !filter_var($sp['singleLogoutService']['url'], FILTER_VALIDATE_URL)
        ) {
            throw new Error('sp_sls_url_invalid');
        }

        if (isset($security['signMetadata']) && is_array($security['signMetadata'])) {
            if ((!isset($security['signMetadata']['keyFileName'])
                    || !isset($security['signMetadata']['certFileName'])) &&
                (!isset($security['signMetadata']['privateKey'])
                    || !isset($security['signMetadata']['x509cert']))
            ) {
                throw new Error('sp_signMetadata_invalid');
            }
        }

        if (((isset($security['authnRequestsSigned']) && $security['authnRequestsSigned'] == true)
                || (isset($security['logoutRequestSigned']) && $security['logoutRequestSigned'] == true)
                || (isset($security['logoutResponseSigned']) && $security['logoutResponseSigned'] == true)
                || (isset($security['wantAssertionsEncrypted']) && $security['wantAssertionsEncrypted'] == true)
                || (isset($security['wantNameIdEncrypted']) && $security['wantNameIdEncrypted'] == true))
            && !$this->checkSPCerts()
        ) {
            throw new Error('sp_certs_not_found_and_required');
        }
    }

    protected function checkSPCerts()
    {
        $key  = $this->sp->getKey();
        $cert = $this->sp->getCert();
        return (!empty($key) && !empty($cert));
    }

    protected function addDefaultValues()
    {
        if (!isset($this->compress['requests'])) {
            $this->compress['requests'] = true;
        }

        if (!isset($this->compress['responses'])) {
            $this->compress['responses'] = true;
        }
        if (!isset($this->security['nameIdEncrypted'])) {
            $this->security['nameIdEncrypted'] = false;
        }
        if (!isset($this->security['requestedAuthnContext'])) {
            $this->security['requestedAuthnContext'] = true;
        }

        // sign provided
        if (!isset($this->security['authnRequestsSigned'])) {
            $this->security['authnRequestsSigned'] = false;
        }
        if (!isset($this->security['logoutRequestSigned'])) {
            $this->security['logoutRequestSigned'] = false;
        }
        if (!isset($this->security['logoutResponseSigned'])) {
            $this->security['logoutResponseSigned'] = false;
        }
        if (!isset($this->security['signMetadata'])) {
            $this->security['signMetadata'] = false;
        }

        // sign expected
        if (!isset($this->security['wantMessagesSigned'])) {
            $this->security['wantMessagesSigned'] = false;
        }
        if (!isset($this->security['wantAssertionsSigned'])) {
            $this->security['wantAssertionsSigned'] = false;
        }

        // NameID element expected
        if (!isset($this->security['wantNameId'])) {
            $this->security['wantNameId'] = true;
        }

        // Relax Destination validation
        if (!isset($this->security['relaxDestinationValidation'])) {
            $this->security['relaxDestinationValidation'] = false;
        }

        // Strict Destination match validation
        if (!isset($this->security['destinationStrictlyMatches'])) {
            $this->security['destinationStrictlyMatches'] = false;
        }

        // Allow duplicated Attribute Names
        if (!isset($this->security['allowRepeatAttributeName'])) {
            $this->security['allowRepeatAttributeName'] = false;
        }

        // InResponseTo
        if (!isset($this->security['rejectUnsolicitedResponsesWithInResponseTo'])) {
            $this->security['rejectUnsolicitedResponsesWithInResponseTo'] = false;
        }

        // encrypt expected
        if (!isset($this->security['wantAssertionsEncrypted'])) {
            $this->security['wantAssertionsEncrypted'] = false;
        }
        if (!isset($this->security['wantNameIdEncrypted'])) {
            $this->security['wantNameIdEncrypted'] = false;
        }

        // XML validation
        if (!isset($this->security['wantXMLValidation'])) {
            $this->security['wantXMLValidation'] = true;
        }

        // SignatureAlgorithm
        if (!isset($this->security['signatureAlgorithm'])) {
            $this->security['signatureAlgorithm'] = XMLSecurityKey::RSA_SHA256;
        }

        // DigestAlgorithm
        if (!isset($this->security['digestAlgorithm'])) {
            $this->security['digestAlgorithm'] = XMLSecurityDSig::SHA256;
        }

        // EncryptionAlgorithm
        if (!isset($this->security['encryption_algorithm'])) {
            $this->security['encryption_algorithm'] = XMLSecurityKey::AES128_CBC;
        }

        if (!isset($this->security['lowercaseUrlencoding'])) {
            $this->security['lowercaseUrlencoding'] = false;
        }
    }

    public function getContacts()
    {
        return $this->contacts;
    }

    public function getOrganization()
    {
        return $this->organization;
    }

    public function getSPMetadata($alwaysPublishEncryptionCert = false, $validUntil = null, $cacheDuration = null)
    {
        $metadata = $this->sp->getMetadata($this->security['authnRequestsSigned'], $this->security['wantAssertionsSigned'], $validUntil, $cacheDuration, $this->getContacts(), $this->getOrganization());

        $certNew = $this->sp->getCertNew();
        if (!empty($certNew)) {
            $metadata = Metadata::addX509KeyDescriptors(
                $metadata,
                $certNew,
                $alwaysPublishEncryptionCert || $this->security['wantNameIdEncrypted'] || $this->security['wantAssertionsEncrypted']
            );
        }

        $cert = $this->sp->getCert();
        if (!empty($cert)) {
            $metadata = Metadata::addX509KeyDescriptors(
                $metadata,
                $cert,
                $alwaysPublishEncryptionCert || $this->security['wantNameIdEncrypted'] || $this->security['wantAssertionsEncrypted']
            );
        }

        //Sign Metadata
        if (isset($this->security['signMetadata']) && $this->security['signMetadata'] != false) {
            if ($this->security['signMetadata'] === true) {
                $keyMetadata  = $this->sp->getKey();
                $certMetadata = $cert;

                if (!$keyMetadata) {
                    throw new Error(
                        'SP Private key not found.',
                        Error::PRIVATE_KEY_FILE_NOT_FOUND
                    );
                }

                if (!$certMetadata) {
                    throw new Error(
                        'SP Public cert not found.',
                        Error::PUBLIC_CERT_FILE_NOT_FOUND
                    );
                }
            } elseif (isset($this->security['signMetadata']['privateKey']) &&
                isset($this->security['signMetadata']['x509cert'])) {
                $keyMetadata  = Utils::formatPrivateKey($this->security['signMetadata']['privateKey']);
                $certMetadata = Utils::formatCert($this->security['signMetadata']['x509cert']);
                if (!$keyMetadata) {
                    throw new Error(
                        'Private key not found.',
                        Error::PRIVATE_KEY_FILE_NOT_FOUND
                    );
                }

                if (!$certMetadata) {
                    throw new Error(
                        'Public cert not found.',
                        Error::PUBLIC_CERT_FILE_NOT_FOUND
                    );
                }
            } else {
                throw new Error(
                    'Invalid Setting: signMetadata value of the sp is not valid',
                    Error::SETTINGS_INVALID_SYNTAX
                );
            }

            $signatureAlgorithm = $this->security['signatureAlgorithm'];
            $digestAlgorithm    = $this->security['digestAlgorithm'];
            $metadata           = Metadata::sign($metadata, $keyMetadata, $certMetadata, $signatureAlgorithm, $digestAlgorithm);
        }
        return $metadata;
    }

    protected function buildAuthnRequest(IdentityProvider $idp, $forceAuthn, $isPassive, $setNameIdPolicy, $nameIdValueReq = null)
    {
        $spData   = $this->sp->getData();
        $security = $this->security;

        $id           = Utils::generateUniqueID();
        $issueInstant = Utils::parseTime2SAML(time());

        $subjectStr = "";
        if (isset($nameIdValueReq)) {
            $subjectStr = <<<SUBJECT

     <saml:Subject>
        <saml:NameID Format="{$spData['NameIDFormat']}">{$nameIdValueReq}</saml:NameID>
        <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"></saml:SubjectConfirmation>
    </saml:Subject>
SUBJECT;
        }

        $nameIdPolicyStr = '';
        if ($setNameIdPolicy) {
            $nameIDPolicyFormat = $spData['NameIDFormat'];
            if (isset($security['wantNameIdEncrypted']) && $security['wantNameIdEncrypted']) {
                $nameIDPolicyFormat = Constants::NAMEID_ENCRYPTED;
            }

            $nameIdPolicyStr = <<<NAMEIDPOLICY

    <samlp:NameIDPolicy
        Format="{$nameIDPolicyFormat}"
        AllowCreate="true" />
NAMEIDPOLICY;
        }

        $providerNameStr  = '';
        $organizationData = $this->getOrganization();
        if (!empty($organizationData)) {
            $langs = array_keys($organizationData);
            if (in_array('en-US', $langs)) {
                $lang = 'en-US';
            } else {
                $lang = $langs[0];
            }
            if (isset($organizationData[$lang]['displayname']) && !empty($organizationData[$lang]['displayname'])) {
                $providerNameStr = <<<PROVIDERNAME
    ProviderName="{$organizationData[$lang]['displayname']}"
PROVIDERNAME;
            }
        }

        $forceAuthnStr = '';
        if ($forceAuthn) {
            $forceAuthnStr = <<<FORCEAUTHN

    ForceAuthn="true"
FORCEAUTHN;
        }

        $isPassiveStr = '';
        if ($isPassive) {
            $isPassiveStr = <<<ISPASSIVE

    IsPassive="true"
ISPASSIVE;
        }

        $requestedAuthnStr = '';
        if (isset($security['requestedAuthnContext']) && $security['requestedAuthnContext'] !== false) {
            $authnComparison = 'exact';
            if (isset($security['requestedAuthnContextComparison'])) {
                $authnComparison = $security['requestedAuthnContextComparison'];
            }

            $authnComparisonAttr = '';
            if (!empty($authnComparison)) {
                $authnComparisonAttr = sprintf('Comparison="%s"', $authnComparison);
            }

            if ($security['requestedAuthnContext'] === true) {
                $requestedAuthnStr = <<<REQUESTEDAUTHN

    <samlp:RequestedAuthnContext $authnComparisonAttr>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
    </samlp:RequestedAuthnContext>
REQUESTEDAUTHN;
            } else {
                $requestedAuthnStr .= "    <samlp:RequestedAuthnContext $authnComparisonAttr>\n";
                foreach ($security['requestedAuthnContext'] as $contextValue) {
                    $requestedAuthnStr .= "        <saml:AuthnContextClassRef>" . $contextValue . "</saml:AuthnContextClassRef>\n";
                }
                $requestedAuthnStr .= '    </samlp:RequestedAuthnContext>';
            }
        }

        $spEntityId  = htmlspecialchars($spData['entityId'], ENT_QUOTES);
        $acsUrl      = htmlspecialchars($spData['assertionConsumerService']['url'], ENT_QUOTES);
        $destination = $idp->getSSOUrl();
        $request     = <<<AUTHNREQUEST
<samlp:AuthnRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="$id"
    Version="2.0"
{$providerNameStr}{$forceAuthnStr}{$isPassiveStr}
    IssueInstant="{$issueInstant}"
    Destination="{$destination}"
    ProtocolBinding="{$spData['assertionConsumerService']['binding']}"
    AssertionConsumerServiceURL="{$acsUrl}">
    <saml:Issuer>{$spEntityId}</saml:Issuer>{$subjectStr}{$nameIdPolicyStr}{$requestedAuthnStr}
</samlp:AuthnRequest>
AUTHNREQUEST;

        return $request;
    }

    public function checkIdp(IdentityProvider $idp)
    {
        $idp = $idp->getData();
        if (!isset($idp['entityId']) || empty($idp['entityId'])) {
            throw new Error('idp_entityId_not_found');
        }

        if (!isset($idp['singleSignOnService'])
            || !isset($idp['singleSignOnService']['url'])
            || empty($idp['singleSignOnService']['url'])
        ) {
            throw new Error('idp_sso_not_found');
        } elseif (!filter_var($idp['singleSignOnService']['url'], FILTER_VALIDATE_URL)) {
            throw new Error('idp_sso_url_invalid');
        }

        if (isset($idp['singleLogoutService'])
            && isset($idp['singleLogoutService']['url'])
            && !empty($idp['singleLogoutService']['url'])
            && !filter_var($idp['singleLogoutService']['url'], FILTER_VALIDATE_URL)
        ) {
            throw new Error('idp_slo_url_invalid');
        }

        if (isset($idp['singleLogoutService'])
            && isset($idp['singleLogoutService']['responseUrl'])
            && !empty($idp['singleLogoutService']['responseUrl'])
            && !filter_var($idp['singleLogoutService']['responseUrl'], FILTER_VALIDATE_URL)
        ) {
            throw new Error('idp_slo_response_url_invalid');
        }

        $existsX509          = isset($idp['x509cert']) && !empty($idp['x509cert']);
        $existsMultiX509Sign = isset($idp['x509certMulti']) && isset($idp['x509certMulti']['signing']) && !empty($idp['x509certMulti']['signing']);
        $existsFingerprint   = isset($idp['certFingerprint']) && !empty($idp['certFingerprint']);
        if (!($existsX509 || $existsFingerprint || $existsMultiX509Sign)
        ) {
            throw new Error('idp_cert_or_fingerprint_not_found_and_required');
        }

        $existsMultiX509Enc = isset($idp['x509certMulti']) && isset($idp['x509certMulti']['encryption']) && !empty($idp['x509certMulti']['encryption']);

        if ((isset($this->security['nameIdEncrypted']) && $this->security['nameIdEncrypted'] == true)
            && !($existsX509 || $existsMultiX509Enc)
        ) {
            throw new Error('idp_cert_not_found_and_required');
        }
    }

    public function login(IdentityProvider $idp, $returnTo = null, array $parameters = [], $forceAuthn = false, $isPassive = false, $setNameIdPolicy = true, $nameIdValueReq = null)
    {
        $authnRequest = $this->buildAuthnRequest($idp, $forceAuthn, $isPassive, $setNameIdPolicy, $nameIdValueReq);

        $deflate = $this->shouldCompressRequests();
        if ($deflate) {
            $authnRequest = gzdeflate($authnRequest);
        }
        $samlRequest = base64_encode($authnRequest);

        $parameters['SAMLRequest'] = $samlRequest;

        if (!empty($returnTo)) {
            $parameters['RelayState'] = $returnTo;
        }

        $security = $this->security;
        if (isset($security['authnRequestsSigned']) && $security['authnRequestsSigned']) {
            $signature               = $this->buildRequestSignature($samlRequest, $parameters['RelayState'], $security['signatureAlgorithm']);
            $parameters['SigAlg']    = $security['signatureAlgorithm'];
            $parameters['Signature'] = $signature;
        }

        return $this->redirectTo($idp->getSSOurl(), $parameters);
    }

    protected function redirectTo($url, $parameters = [])
    {
        assert(is_string($url));
        return redirect(url($url, $parameters));
    }

    protected function buildRequestSignature($samlRequest, $relayState, $signAlgorithm = XMLSecurityKey::RSA_SHA256)
    {
        return $this->buildMessageSignature($samlRequest, $relayState, $signAlgorithm, "SAMLRequest");
    }

    protected function buildMessageSignature($samlMessage, $relayState, $signAlgorithm = XMLSecurityKey::RSA_SHA256, $type = "SAMLRequest")
    {
        $key = $this->sp->getKey();
        if (empty($key)) {
            if ($type == "SAMLRequest") {
                $errorMsg = "Trying to sign the SAML Request but can't load the SP private key";
            } else {
                $errorMsg = "Trying to sign the SAML Response but can't load the SP private key";
            }

            throw new Error($errorMsg, Error::PRIVATE_KEY_NOT_FOUND);
        }

        $objKey = new XMLSecurityKey($signAlgorithm, ['type' => 'private']);
        $objKey->loadKey($key, false);

        $security = $this->security;
        if ($security['lowercaseUrlencoding']) {
            $msg = $type . '=' . rawurlencode($samlMessage);
            if (isset($relayState)) {
                $msg .= '&RelayState=' . rawurlencode($relayState);
            }
            $msg .= '&SigAlg=' . rawurlencode($signAlgorithm);
        } else {
            $msg = $type . '=' . urlencode($samlMessage);
            if (isset($relayState)) {
                $msg .= '&RelayState=' . urlencode($relayState);
            }
            $msg .= '&SigAlg=' . urlencode($signAlgorithm);
        }
        $signature = $objKey->signData($msg);
        return base64_encode($signature);
    }

    public function shouldCompressRequests()
    {
        return $this->compress['requests'];
    }
}
