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

/*
    På enkelte punkter overholder DGWS ikke Saml 2.0 
    Nedenstående klasser gør Saml-typerne DGWS kompatible
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using System.Xml.Linq;
using System.Web.Services.Protocols;
using SDSD.SealApi;

namespace SDSD.SealApi.Saml20
{
    public class DGWSAssertionType : AssertionType
    {
        public override XElement ToXml()
        {
            XElement SignatureXml = null;
            if (Signature != null)
            {
                var sigid = Signature.Id;
                Signature.Id = null;

                using (var nr = new XmlNodeReader(Signature.GetXml()))
                {
                    SignatureXml = XElement.Load(nr);
                    if (sigid != null)
                    {
                        SignatureXml.Add(new XAttribute("Id", sigid)); //specielt for DGWS
                    }
                }
            }

            return new XElement(
                NA.saml + "Assertion",
                    new XAttribute("Id", ID), //specielt for DGWS
                    IssueInstant.MakeXAttribute("IssueInstant"),
                    new XAttribute("Version", Version),
                    Issuer.ToXml(),
                    Subject == null ? null : Subject.ToXml(),
                    Conditions == null ? null : Conditions.ToXml(),
                    //Advice == null ? null : Advice.ToXml(),
                    from x in Statements where x != null select x.ToXml(),
                    SignatureXml
                );
        }
    }

    public class DGWSAttributeStatementType : AttributeStatementType
    {
        public string id;

        public DGWSAttributeStatementType(params object[] c)
            : base(c)
        {
        }

        public override XElement ToXml()
        {
            return new XElement(
                NA.saml + "AttributeStatement",
                    id == null ? null : new XAttribute("Id", id), //specielt for DGWS
                    from e in StatementList where e != null select e.ToXml()
                );
        }
    }

    public class DGWSSubjectConfirmationType : SubjectConfirmationType
    {
        public DGWSSubjectConfirmationType(XElement SubjectConfirmation)
            : base(SubjectConfirmation)
        {
        }

        public override XElement ToXml()
        {
            return new XElement(
                NA.saml + "SubjectConfirmation",
                    new XElement(NA.saml + "ConfirmationMethod", SamlIDs.HolderOfKey), //specielt for DGWS
                    //BaseID == null ? null : BaseID.ToXml(),
                    NameID == null ? null : NameID.ToXml(),
                    //EncryptedID == null ? null : EncryptedID.ToXml(),
                    SubjectConfirmationData == null ? null : SubjectConfirmationData.ToXml()
                );
        }
    }
}
