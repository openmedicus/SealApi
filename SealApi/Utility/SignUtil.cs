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
using System.Xml;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Security.Cryptography.X509Certificates;


namespace Medcom
{

	public class SignedXmlCustom : SignedXml
	{
		XmlNamespaceManager nsmgr;
		public SignedXmlCustom(XmlElement e, XmlNamespaceManager nsmgr) : base(e) {
			this.nsmgr = nsmgr;
			//this.Signature.GetXml().RemoveAttribute("xmlns");
		}

		public override XmlElement GetIdElement(XmlDocument document, string idValue)
		{
			if ((document == null) || (idValue == null))
				return null;
			
			// this works only if there's a DTD or XSD available to define the ID
			XmlElement xel = document.GetElementById (idValue);
			if (xel == null) {
				// search an "undefined" ID
				xel = (XmlElement) document.SelectSingleNode ("//*[@wsu:Id='" + idValue + "']", nsmgr);
				if (xel == null) {
					xel = (XmlElement) document.SelectSingleNode ("//*[@wsu:ID='" + idValue + "']", nsmgr);
					if (xel == null) {
						xel = (XmlElement) document.SelectSingleNode ("//*[@wsu:id='" + idValue + "']", nsmgr);
					}
				}
			}
			return xel;
		}
	}

  	// delegate void ErrorMessageReporter( Exception ex );
    /// <summary>
    /// Indeholder operationer til signering af xml og valiering af underskrevet xml
    /// </summary>
    public class Signering
    {
        /// <summary>
        /// Underskriver flere dele af et xmldokument med medfølgende certifikat og indlejrer underskriften i dokumentet
        /// </summary>
        /// <param name="envelope">Dokument som skal underskrives</param>
        /// <param name="refnames">Udpeger de underelementer hvorfra underskriften skal gælde</param>
        /// <param name="parentname">Angiver tagnavnet på det element hvorunder underskriften skal indlejres</param>
        /// <param name="parentnamespace">Angiver namespacet på det element hvorunder underskriften skal indlejres</param>
        /// <param name="name">Angiver vavnet på id af underskriftern f.eks. IDCard hvis id = "IDCard"</param>
        /// <param name="Certificate">Certificatet som underskriver</param>
		public static void Sign(XmlElement envelope, string[] refnames, string parentname, string parentnamespace, string name, X509Certificate2 Certificate, XmlNamespaceManager nsmgr)
        {
			SignedXml signedXml = new SignedXmlCustom(envelope, nsmgr);
            signedXml.SigningKey = Certificate.PrivateKey;
			signedXml.SignedInfo.CanonicalizationMethod = "http://www.w3.org/2001/10/xml-exc-c14n#";

            foreach (string s in refnames)
            {
                Reference reference = new Reference();
                reference.Uri = s;
				//reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
				reference.AddTransform(new XmlDsigExcC14NTransform());

				signedXml.AddReference(reference);
            }
            

            KeyInfo keyInfo = new KeyInfo();
            KeyInfoX509Data data = new KeyInfoX509Data(Certificate);
            keyInfo.AddClause(data);

            signedXml.KeyInfo = keyInfo;
            signedXml.ComputeSignature();

            XmlNode n = envelope.GetElementsByTagName(parentname, parentnamespace)[0];
            XmlElement signaelm = signedXml.GetXml();
			XmlAttribute at = envelope.OwnerDocument.CreateAttribute("Id", nsmgr.LookupNamespace("wsu"));
            at.Value = name;

			n.Attributes.Append(at);

			var node = n.OwnerDocument.ImportNode(signaelm, true);
			//signedXml.Signature.GetXml().RemoveAttribute("xmlns");
			//signedXml.Signature.GetXml().SetAttribute("xmlns", null);
			n.AppendChild(node);
        }

		public static void Sign(XmlElement envelope, string[] refnames, string parentname, string parentnamespace, string name, X509Certificate2 Certificate)
		{
			SignedXml signedXml = new SignedXml(envelope);
			signedXml.SigningKey = Certificate.PrivateKey;
			foreach (string s in refnames)
			{
				Reference reference = new Reference();
				reference.Uri = s;
				reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
				reference.AddTransform(new XmlDsigC14NTransform());
				signedXml.AddReference(reference);
			}

			KeyInfo keyInfo = new KeyInfo();
			KeyInfoX509Data data = new KeyInfoX509Data(Certificate);
			keyInfo.AddClause(data);

			signedXml.KeyInfo = keyInfo;
			signedXml.ComputeSignature();

			XmlNode n = envelope.GetElementsByTagName(parentname, parentnamespace)[0];
			XmlElement signaelm = signedXml.GetXml();
			XmlAttribute at = signaelm.OwnerDocument.CreateAttribute("Id");
			at.Value = name;

			signaelm.Attributes.Append(at);

			var node = n.OwnerDocument.ImportNode(signaelm, true);

			n.AppendChild(node);
		}
        
		//public XmlDocument Sign(X509Certificate2 cert)
		//{
		//	var refnames = new string[] { "#timestamp", "#messageID", "#action", "#body" };
		//	foreach (string s in refnames)
		//	{
		//		var reference = new Reference();
		//		reference.Uri = s;
		//		reference.AddTransform(new XmlDsigExcC14NTransform());
		//		AddReference(reference);
		//	}

		//	SigningKey = cert.PrivateKey;
		//	SignedInfo.CanonicalizationMethod = new XmlDsigExcC14NTransform().Algorithm;
		//	KeyInfo = new KeyInfo();
		//	KeyInfo.AddClause(new KeyInfoX509Data(cert));

		//	ComputeSignature();

		//	XmlElement signaelm = GetXml();
		//	var XSecurity = xml.SelectSingleNode("/soap:Envelope/soap:Header/wsse:Security", ns.MakeNsManager(xml.NameTable)) as XmlElement;
		//	XSecurity.AppendChild(signaelm);

		//	return xml;
		//}

        static X509Certificate2 GetCertificate(SignedXml sx)
        {
            foreach (KeyInfoX509Data d in sx.KeyInfo)
            {
                X509Certificate2 cer = d.Certificates[0] as X509Certificate2;
                if (cer != null) return cer;
            }
            return null;
        }

        static XmlElement FindSignature(XmlElement e, string id)
        {
            foreach (XmlElement elm in e.GetElementsByTagName("Signature", NamespaceAlias.ds))
            {
                var aid = elm.Attributes["id"] ?? elm.Attributes["Id"];

                if (aid.Value == id)
                {
                    return elm;
                }
            }
            return null;
        }
        
        /// <summary>
        /// Kontrollerer om et underskrevet xmldokument er ok. Certifikatet returneres hvis alt er ok
        /// </summary>
        /// <param name="envelope">Det underskrevne xmldokument</param>
        /// <param name="id">identen på det xmlelement der indeholder underskriften</param>
        /// <param name="elmid">identen på elementet hvorfra underskriften gælder, hvis null gælder hele xmldokumentet</param>
        /// <param name="ns">namespacet på elementet hvorfra underskriften gælder</param>
        /// <param name="RemoveSignature">angiver om certifikatet skal fjernes fra xmldokumentet</param>
        /// <returns>certifikatet der har underskrevet</returns>
        public static X509Certificate2 validateSignature(XmlElement envelope, string id, string elmid, string ns, bool RemoveSignature)
        {
            try
            {
                XmlElement doc;

                if (string.IsNullOrEmpty(elmid))
                {
                    doc = envelope;
                }
                else
                {
                    XmlElement tag = envelope.Name == elmid && envelope.NamespaceURI == ns ? envelope :
                                                      envelope.GetElementsByTagName(elmid, ns)[0] as XmlElement;
                    if (tag == null) return null;

                    var d = new XmlDocument();
                    d.LoadXml(tag.OuterXml);
                    doc = d.DocumentElement;
                }

                SignedXml signedXml = new SignedXml(doc);

                // Load the signature node.
                XmlElement xmlsignature = FindSignature(doc, id);
                if (xmlsignature == null) return null;

                signedXml.LoadXml(xmlsignature);
                X509Certificate2 certificate = Signering.GetCertificate(signedXml);
                // Check the signature and return the result.
                if (!signedXml.CheckSignature(certificate, true)) return null;

                if (RemoveSignature)
                {
                    xmlsignature.ParentNode.RemoveChild(xmlsignature);
                }
                return certificate;
            }
            catch (Exception )
            {
                //ErrorHandler.ErrorMessage(ex);
            }
            return null;
        }

        
        /// <summary>
        /// Henter værdierne af ClientMOCESHash og ClientVOCESHash
        /// </summary>
        /// <param name="envelope">Xmldokumentet</param>
        /// <returns>værdierne af ClientMOCESHash og ClientVOCESHash</returns>
        public static HashValues GetHashValues(XmlDocument envelope)
        {
            HashValues hv = new HashValues();
            
            XmlNamespaceManager nms = new XmlNamespaceManager(envelope.NameTable);
            nms.AddNamespace("soap", NamespaceAlias.soap);
            nms.AddNamespace("wsse", NamespaceAlias.wsse);
            nms.AddNamespace("saml", NamespaceAlias.saml);

            XmlElement e = envelope.SelectSingleNode("/soap:Envelope/soap:Header/wsse:Security/saml:Assertion[@id='IDCard']/saml:AttributeStatement[@id='IDCardData']/saml:Attribute[@Name='dgws:ClientMOCESHash']", nms) as XmlElement;
            if (e != null) hv.ClientMOCESHash = e.InnerText.Trim();
            e = envelope.SelectSingleNode("/soap:Envelope/soap:Header/wsse:Security/saml:Assertion[@id='IDCard']/saml:AttributeStatement[@id='IDCardData']/saml:Attribute[@Name='dgws:ClientVOCESHash']", nms) as XmlElement;
            if (e != null) hv.ClientVOCESHash = e.InnerText.Trim();
            return hv;
        }
        
        //static ErrorMessageReporter emr = (e) => { };
    }

    /// <summary>
    /// Indeholder værdierne af ClientMOCESHash og ClientVOCESHash fra et IKDCard
    /// </summary>
    public class HashValues
    {
        public string ClientMOCESHash;
        public string ClientVOCESHash;

        /// <summary>
        /// Hvis både ClientVOCESHash er tom er IsSingleSignOn true
        /// </summary>
        public bool IsSingleSignOn
        { 
            get
            {
                return !string.IsNullOrEmpty(ClientVOCESHash);
            }
        }
    }
}