<?php

namespace WsdlToPhp\WsSecurity;

class UsernameToken extends Element
{
    /**
     * Element name
     * @var string
     */
    const NAME = 'UsernameToken';
    /**
     * Attribute id name
     * @var string
     */
    const ATTRIBUTE_ID = 'Id';
    /**
     * Username element
     * @var Username
     */
    protected $username;
    /**
     * Password element
     * @var Password
     */
    protected $password;
    /**
     * Created element
     * @var Created
     */
    protected $created;
    /**
     * Nonce element
     * @var Nonce
     */
    protected $nonce;
    /**
     * Constructor for UsernameToken element
     * @see Element::__construct()
     * @param string $id
     * @param string $namespace the namespace
     */
    public function __construct($id = null, $namespace = self::NS_WSSE)
    {
        parent::__construct(self::NAME, $namespace, null, empty($id) ? array() : array(
            self::ATTRIBUTE_ID => $id,
        ));
    }
    /**
     * @return Username
     */
    public function getUsername()
    {
        return $this->username;
    }
    /**
     * @param Username $username
     * @return UsernameToken
     */
    public function setUsername(Username $username)
    {
        $this->username = $username;
        return $this;
    }
    /**
     * @return Password
     */
    public function getPassword()
    {
        return $this->password;
    }
    /**
     * @param Password $password
     * @return UsernameToken
     */
    public function setPassword($password)
    {
        $this->password = $password;
        return $this;
    }
    /**
     * @return Created
     */
    public function getCreated()
    {
        return $this->created;
    }
    /**
     * @param Created $created
     * @return UsernameToken
     */
    public function setCreated($created)
    {
        $this->created = $created;
        return $this;
    }
    /**
     * @return Nonce
     */
    public function getNonce()
    {
        return $this->nonce;
    }
    /**
     * @param Nonce $nonce
     * @return UsernameToken
     */
    public function setNonce($nonce)
    {
        $this->nonce = $nonce;
        return $this;
    }
    /**
     * Overrides method in order to add username, password and created values if they are set
     * @see Element::toSend()
     * @uses Element::setValue()
     * @uses UsernameToken::getUsername()
     * @uses UsernameToken::getPassword()
     * @uses UsernameToken::getCreated()
     * @uses UsernameToken::getNonce()
     * @param bool $asDomElement returns elements as a DOMElement or as a string
     * @return string
     */
    protected function __toSend($asDomElement = false)
    {
        $value = array();
        if ($this->getUsername() instanceof Username) {
            $value[] = $this->getUsername();
        }
        if ($this->getPassword() instanceof Password) {
            $value[] = $this->getPassword();
        }
        if ($this->getCreated() instanceof Created) {
            $value[] = $this->getCreated();
        }
        if ($this->getNonce() instanceof Nonce) {
            $value[] = $this->getNonce();
        }
        if (count($value) > 0) {
            $this->setValue($value);
        }
        return parent::__toSend($asDomElement);
    }
}
