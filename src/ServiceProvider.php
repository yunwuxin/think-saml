<?php

namespace think\saml;

class ServiceProvider
{
    protected $data;

    public function __construct(array $data)
    {
        $this->data = $data;

        $this->addDefaultValues();
    }

    public function getMetadata($authnsign = false, $wsign = false, $validUntil = null, $cacheDuration = null, $contacts = [], $organization = [], $attributes = [])
    {
        return Metadata::builder($this->data, $authnsign, $wsign, $validUntil, $cacheDuration, $contacts, $organization, $attributes);
    }

    public function getData()
    {
        return $this->data;
    }

    public function getCertNew()
    {
        $cert = null;

        if (isset($this->data['x509certNew']) && !empty($this->data['x509certNew'])) {
            $cert = $this->data['x509certNew'];
        }
        return $cert;
    }

    public function getCert()
    {
        $cert = null;

        if (isset($this->data['x509cert']) && !empty($this->data['x509cert'])) {
            $cert = $this->data['x509cert'];
        }
        return $cert;
    }

    public function getKey()
    {
        $key = null;
        if (isset($this->data['privateKey']) && !empty($this->data['privateKey'])) {
            $key = $this->data['privateKey'];
        }
        return $key;
    }

    protected function addDefaultValues()
    {
        if (!isset($this->data['assertionConsumerService']['binding'])) {
            $this->data['assertionConsumerService']['binding'] = Constants::BINDING_HTTP_POST;
        }
        if (isset($this->data['singleLogoutService']) && !isset($this->data['singleLogoutService']['binding'])) {
            $this->data['singleLogoutService']['binding'] = Constants::BINDING_HTTP_REDIRECT;
        }

        // Related to nameID
        if (!isset($this->data['NameIDFormat'])) {
            $this->data['NameIDFormat'] = Constants::NAMEID_UNSPECIFIED;
        }

        if (!isset($this->data['x509cert'])) {
            $this->data['x509cert'] = '';
        }
        if (!isset($this->data['privateKey'])) {
            $this->data['privateKey'] = '';
        }
    }
}
