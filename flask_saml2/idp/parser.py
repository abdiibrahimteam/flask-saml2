from typing import Optional

from flask_saml2.types import XmlNode
from flask_saml2.utils import cached_property
from flask_saml2.xml_parser import XmlParser


class AuthnRequestParser(XmlParser):
    """Parses an incoming ``<AuthnRequest>``
    and provides shortcuts to access common attributes."""

    def is_signed(self) -> bool:
        """Is the ``<AuthnRequest>`` signed?"""
        return bool(self._xpath_xml_tree('/samlp:AuthnRequest/ds:Signature'))

    @cached_property
    def issuer(self) -> str:
        """The content of the ``<Issuer>`` element."""
        return self._xpath_xml_tree('/samlp:AuthnRequest/saml:Issuer')[0].text

    @cached_property
    def request_id(self) -> str:
        """The ``<AuthnRequest>`` ID attribute."""
        return self._xpath_xml_tree('/samlp:AuthnRequest/@ID')[0]

    @cached_property
    def destination(self) -> str:
        """The ``<AuthnRequest>`` Destination attribute, if it has one."""
        try:
            return self._xpath_xml_tree('/samlp:AuthnRequest/@Destination')[0]
        except IndexError:
            return ''

    @cached_property
    def acs_url(self) -> str:
        """The AssertionConsumerServiceURL attribute."""
        switch = {
            "https://atlas.abdiibrahim.com.tr/auth/login/saml?client_id=32749fb2-5064-4796-bd03-8c8c3fb953b0":"https://srm.abdiibrahim.com.tr:8443/sap/saml2/sp/acs/100",
            "https://atlas.abdiibrahim.com.tr/auth/login/saml?client_id=f359bd2b-a025-4340-89f9-78fb539c864a":"https://srm.abdiibrahim.com.tr:443/saml2/sp/acs"
        }
        return switch[self._xpath_xml_tree('/samlp:AuthnRequest/@Destination')[0]]
    @cached_property
    def provider_name(self) -> str:
        """The ProviderName attribute, if it exists."""
        try:
            return self._xpath_xml_tree('/samlp:AuthnRequest/@ProviderName')[0]
        except IndexError:
            return ''

    @cached_property
    def version(self) -> str:
        """The Version attribute."""
        return self._xpath_xml_tree('/samlp:AuthnRequest/@Version')[0]

    @cached_property
    def issue_instant(self) -> str:
        """The IssueInstant attribute."""
        return self._xpath_xml_tree('/samlp:AuthnRequest/@IssueInstant')[0]

    @cached_property
    def protocol_binding(self) -> str:
        """The ProtocolBinding attribute."""
        return self._xpath_xml_tree('/samlp:AuthnRequest/@ProtocolBinding')[0]


class LogoutRequestParser(XmlParser):

    def is_signed(self):
        return bool(self._xpath_xml_tree('/samlp:LogoutRequest/ds:Signature'))

    @cached_property
    def issuer(self) -> str:
        return self._xpath_xml_tree('/samlp:LogoutRequest/saml:Issuer')[0].text

    @cached_property
    def request_id(self) -> str:
        return self._xpath_xml_tree('/samlp:LogoutRequest/@ID')[0]

    @cached_property
    def destination(self) -> Optional[str]:
        try:
            return self._xpath_xml_tree('/samlp:LogoutRequest/@Destination')[0]
        except IndexError:
            return None

    @cached_property
    def version(self) -> str:
        return self._xpath_xml_tree('/samlp:LogoutRequest/@Version')[0]

    @cached_property
    def issue_instant(self) -> str:
        return self._xpath_xml_tree('/samlp:LogoutRequest/@IssueInstant')[0]

    @cached_property
    def nameid_el(self) -> XmlNode:
        return self._xpath_xml_tree('/samlp:LogoutRequest/saml:NameID')[0]

    @cached_property
    def nameid(self) -> XmlNode:
        return self.nameid_el.text

    @cached_property
    def nameid_format(self) -> XmlNode:
        return self._xpath(self.nameid_el, '@Format')[0]
