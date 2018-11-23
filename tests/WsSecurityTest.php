<?php
namespace WsdlToPhp\WsSecurity\Tests;

use SoapHeader;
use WsdlToPhp\WsSecurity\WsSecurity;

class WsSecurityTest extends TestCase
{
    public function testCreateWithExpiresIn()
    {
        $header = WsSecurity::createWsSecuritySoapHeader('foo', 'bar', false, 1459451824, 600);
        $this->assertInstanceOf('\SoapHeader', $header);
        $this->assertMatches(self::innerTrim('
        <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <wsse:UsernameToken>
                <wsse:Username>foo</wsse:Username>
                <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">bar</wsse:Password>
                <wssu:Created xmlns:wssu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">2016-03-31T19:17:04Z</wssu:Created>
                <wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">([a-zA-Z0-9=]*)</wsse:Nonce>
            </wsse:UsernameToken>
            <wssu:Timestamp xmlns:wssu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
                <wssu:Created>2016-03-31T19:17:04Z</wssu:Created>
                <wssu:Expires>2016-03-31T19:27:04Z</wssu:Expires>
            </wssu:Timestamp>
        </wsse:Security>'), $header->data->enc_value);
    }
    public function testCreateWithoutExpiresIn()
    {
        $header = WsSecurity::createWsSecuritySoapHeader('foo', 'bar', false, 1459451824);
        $this->assertInstanceOf('\SoapHeader', $header);
        $this->assertMatches(self::innerTrim('
        <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <wsse:UsernameToken>
                <wsse:Username>foo</wsse:Username>
                <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">bar</wsse:Password>
                <wssu:Created xmlns:wssu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">2016-03-31T19:17:04Z</wssu:Created>
                <wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">([a-zA-Z0-9=]*)</wsse:Nonce>
            </wsse:UsernameToken>
        </wsse:Security>'), $header->data->enc_value);
    }
    public function testCreateWithMustUnderstand()
    {
        $header = WsSecurity::createWsSecuritySoapHeader('foo', 'bar', false, 1459451824, 0, true, true);
        $this->assertInstanceOf('\SoapHeader', $header);
        $this->assertMatches(self::innerTrim('
        <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" SOAP-ENV:mustunderstand="1">
            <wsse:UsernameToken>
                <wsse:Username>foo</wsse:Username>
                <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">bar</wsse:Password>
                <wssu:Created xmlns:wssu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">2016-03-31T19:17:04Z</wssu:Created>
                <wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">([a-zA-Z0-9=]*)</wsse:Nonce>
            </wsse:UsernameToken>
        </wsse:Security>'), $header->data->enc_value);
    }
    public function testCreateWithMustUnderstandAndActor()
    {
        $header = WsSecurity::createWsSecuritySoapHeader('foo', 'bar', false, 1459451824, 0, true, true, 'BAR');
        $this->assertInstanceOf('\SoapHeader', $header);
        $this->assertMatches(self::innerTrim('
        <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" SOAP-ENV:mustunderstand="1" SOAP-ENV:actor="BAR">
            <wsse:UsernameToken>
                <wsse:Username>foo</wsse:Username>
                <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">bar</wsse:Password>
                <wssu:Created xmlns:wssu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">2016-03-31T19:17:04Z</wssu:Created>
                <wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">([a-zA-Z0-9=]*)</wsse:Nonce>
            </wsse:UsernameToken>
        </wsse:Security>'), $header->data->enc_value);
    }
    public function testCreateSoapVar()
    {
        $header = WsSecurity::createWsSecuritySoapHeader('foo', 'bar', false, 1459451824, 0, false, true, 'BAR');
        $this->assertInstanceOf('\SoapVar', $header);
        $this->assertMatches(self::innerTrim('
        <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" SOAP-ENV:mustunderstand="1" SOAP-ENV:actor="BAR">
            <wsse:UsernameToken>
                <wsse:Username>foo</wsse:Username>
                <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">bar</wsse:Password>
                <wssu:Created xmlns:wssu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">2016-03-31T19:17:04Z</wssu:Created>
                <wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">([a-zA-Z0-9=]*)</wsse:Nonce>
            </wsse:UsernameToken>
        </wsse:Security>'), $header->enc_value);
    }
    public function testCreateWithPasswordDigest()
    {
        $header = WsSecurity::createWsSecuritySoapHeader('foo', 'bar', true, 1459451824, 0, false, true, 'BAR');
        $this->assertInstanceOf('\SoapVar', $header);
        $this->assertMatches(self::innerTrim('
        <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" SOAP-ENV:mustunderstand="1" SOAP-ENV:actor="BAR">
            <wsse:UsernameToken>
                <wsse:Username>foo</wsse:Username>
                <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">([a-zA-Z0-9=/+]*)</wsse:Password>
                <wssu:Created xmlns:wssu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">2016-03-31T19:17:04Z</wssu:Created>
                <wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">([a-zA-Z0-9=]*)</wsse:Nonce>
            </wsse:UsernameToken>
        </wsse:Security>'), $header->enc_value);
    }
    public function testCreateWithUsernameId()
    {
        $header = WsSecurity::createWsSecuritySoapHeader('foo', 'bar', false, 1459451824, 0, true, true, 'BAR', 'X90I3u8');
        $this->assertInstanceOf('\SoapHeader', $header);
        $this->assertMatches(self::innerTrim('
        <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" SOAP-ENV:mustunderstand="1" SOAP-ENV:actor="BAR">
            <wsse:UsernameToken wssu:Id="X90I3u8">
                <wsse:Username>foo</wsse:Username>
                <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">bar</wsse:Password>
                <wssu:Created xmlns:wssu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">2016-03-31T19:17:04Z</wssu:Created>
                <wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">([a-zA-Z0-9=]*)</wsse:Nonce>
            </wsse:UsernameToken>
        </wsse:Security>'), $header->data->enc_value);
    }

    public function testRuSetServer()
    {

        $soapClient = new \SoapClient('https://test-gw.ru-set.com/BusXmlService.svc?wsdl', [
            'soap_version' => SOAP_1_2,
            'trace' => true,
            'cache_wsdl' => WSDL_CACHE_NONE,
            'keep_alive' => false,
            'exceptions' => 1,
        ]);

        $headers = [];

        $headers[] = WsSecurity::createWsSecuritySoapHeader('Xml_be50afa3473140e0b799245656c588ad', 'fa$xq7A8');
        $headers[] = new SoapHeader('http://www.w3.org/2005/08/addressing', 'Action', 'http://tempuri.org/IBusXmlService/GetDispatch', false);

        $soapClient->__setSoapHeaders($headers);

        try {
            $result = $soapClient->__soapCall('GetDispatch', []);
        } catch (\SoapFault $exception) {
            die($exception);
        }

        $this->assertTrue(
            isset($result->GetDispatchResult),
            'Result not correct. GetDispatchResult not exists'
        );
    }

    public function testRuSetGetRuns()
    {
        /** @var \SoapClient $soapClient */
        $soapClient = new \SoapClient('https://test-gw.ru-set.com/BusXmlService.svc?wsdl', [
            'soap_version' => SOAP_1_2,
            'trace' => true,
            'cache_wsdl' => WSDL_CACHE_NONE,
            'keep_alive' => false,
            'exceptions' => 1,
        ]);

        $headers = [];

        $headers[] = WsSecurity::createWsSecuritySoapHeader('Xml_be50afa3473140e0b799245656c588ad', 'fa$xq7A8');
        $headers[] = new SoapHeader('http://www.w3.org/2005/08/addressing', 'Action', 'http://tempuri.org/IBusXmlService/GetRuns', false);

        $soapClient->__setSoapHeaders($headers);

        $getRuns = new \stdClass();
        $getRuns->parameters = new \stdClass();
        $getRuns->parameters->DepartureBusStopID = 23647;
        $getRuns->parameters->ArrivalBusStopID = 23650;
        $getRuns->parameters->DepartureDate = '2018-11-28';

        try {
            $result = $soapClient->__soapCall('GetRuns',  ['parameters' => $getRuns]);
        } catch (\SoapFault $exception) {
            die($exception);
        }


        $this->assertTrue(
            isset($result->GetRunsResult),
            'Result not correct. GetRunsResult not exists'
        );
    }
}
