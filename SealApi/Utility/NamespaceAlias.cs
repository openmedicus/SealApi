/*
 * Copyright (C) 2008 Digital Sundhed 
 *
 * The source code Seal.net is released under dual licenses,
 * i.e. you may choose either license for your use.
 *
 * It is released under the Common Public License 1.0, a copy of which can
 * be found at the following link:
 * http://www.opensource.org/licenses/cpl.php
 *
 * It is released under the LGPL (GNU Lesser General Public License) 
 * version 2.1, a copy of which can be found at the following link:
 * http://www.gnu.org/copyleft/lesser.html
 */
namespace Medcom
{
    /// <summary>
    /// klasse som indeholder kortere skrivemåde og giver mere typesikker brug af udvalgte xml-namespaces
    /// </summary>
    class NamespaceAlias
    {
        public const string dgws10 = "http://www.medcom.dk/dgws/2006/04/dgws-1.0.xsd";
        public const string xsi = "http://www.w3.org/2001/XMLSchema-instance";
        public const string saml = "urn:oasis:names:tc:SAML:2.0:assertion";
        public const string wsse = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
        public const string ds = "http://www.w3.org/2000/09/xmldsig#";
        public const string soap = "http://schemas.xmlsoap.org/soap/envelope/";
        public const string wsu = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
        public const string dgws11 = "http://www.dgws.dk/dgws/2007/12/dgws-1.1";
        public const string wst = "http://schemas.xmlsoap.org/ws/2005/02/trust";
        public const string wsa04 = "http://schemas.xmlsoap.org/ws/2004/08/addressing";
        public const string wsa = "http://www.w3.org/2005/08/addressing/";
    }
}