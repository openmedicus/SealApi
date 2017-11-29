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
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace SDSD.SealApi
{
    public class XNsMap : Dictionary<string, string>, IXmlNamespaceResolver
    {
        public XNsMap()
        {
        }

        public XNsMap(IDictionary<string, string> dic):base( dic)
        {
        }

        #region IXmlNamespaceResolver Members

        public IDictionary<string, string> GetNamespacesInScope(XmlNamespaceScope scope)
        {
            return this;
        }
 
        public string LookupNamespace(string prefix)
        {
            return base[prefix];
        }

        public string LookupPrefix(string namespaceName)
        {
            foreach (var key in Keys)
            {
                if (base[key] == namespaceName) return key;
            }
            return "";
        }

        #endregion

    }

    public class NA
    {
        public static XNamespace dgws10 = "http://www.medcom.dk/dgws/2006/04/dgws-1.0.xsd";
        public static XNamespace xsi = "http://www.w3.org/2001/XMLSchema-instance";
        public static XNamespace saml = "urn:oasis:names:tc:SAML:2.0:assertion";
        public static XNamespace wsse = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
        public static XNamespace ds = "http://www.w3.org/2000/09/xmldsig#";
        public static XNamespace soap = "http://schemas.xmlsoap.org/soap/envelope/";
        public static XNamespace wsu = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
        public static XNamespace dgws11 = "http://www.dgws.dk/dgws/2007/12/dgws-1.1";
        public static XNamespace wst = "http://schemas.xmlsoap.org/ws/2005/02/trust";
        public static XNamespace wsa04 = "http://schemas.xmlsoap.org/ws/2004/08/addressing";
        public static XNamespace wsa = "http://www.w3.org/2005/08/addressing";
        public static XNamespace medcom = "http://www.medcom.dk/dgws/2006/04/dgws-1.0.xsd";
    }

}
