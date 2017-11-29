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
    /// <summary>
    /// Contains a collection of known Saml Id's
    /// </summary>
    public class SamlIDs
    { 
        public static Uri HolderOfKey = new Uri("urn:oasis:names:tc:SAML:2.0:cm:holder-of-key");
        public static Uri SenderVouches = new Uri("urn:oasis:names:tc:SAML:2.0:cm:sender-vouches");
        public static Uri Bearer = new Uri("urn:oasis:names:tc:SAML:2.0:cm:bearer");

        public static Uri ACRwedc = new Uri("urn:oasis:names:tc:SAML:1.0:action:rwedc");
        public static Uri ACNegation = new Uri("urn:oasis:names:tc:SAML:1.0:action:rwedc-negation");
        public static Uri ACGhpp = new Uri("urn:oasis:names:tc:SAML:1.0:action:ghpp");
        public static Uri ACUnix = new Uri("urn:oasis:names:tc:SAML:1.0:action:unix");
        
        public static Uri ANunspecified = new Uri("urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified");
        public static Uri ANUri = new Uri("urn:oasis:names:tc:SAML:2.0:attrname-format:uri");
        public static Uri ANBasic = new Uri("urn:oasis:names:tc:SAML:2.0:attrname-format:basic");
        
        public static Uri NIunspecified = new Uri("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");
        public static Uri NIEmailAddress = new Uri("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
        public static Uri NIX509SubjectName = new Uri("urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName");
        public static Uri NIWindowsDomainQualifiedName = new Uri("urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName");
        public static Uri NIKerberos = new Uri("urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos");
        public static Uri NIEntity = new Uri("urn:oasis:names:tc:SAML:2.0:nameid-format:entity");
        public static Uri NIPersistent = new Uri("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");
        public static Uri NITransient = new Uri("urn:oasis:names:tc:SAML:2.0:nameid-format:transient");

        public static Uri CIUnspecified = new Uri("urn:oasis:names:tc:SAML:2.0:consent:unspecified");
        public static Uri CIObtained = new Uri("urn:oasis:names:tc:SAML:2.0:consent:obtained");
        public static Uri CIPrior = new Uri("urn:oasis:names:tc:SAML:2.0:consent:prior");
        public static Uri CIImplicit = new Uri("urn:oasis:names:tc:SAML:2.0:consent:current-implicit");
        public static Uri CIExplicit = new Uri("urn:oasis:names:tc:SAML:2.0:consent:current-explicit");
        public static Uri CIUnavailable = new Uri("urn:oasis:names:tc:SAML:2.0:consent:unavailable");
        public static Uri CIInapplicable = new Uri("urn:oasis:names:tc:SAML:2.0:consent:inapplicable");

        public static Uri CLPassword = new Uri("urn:oasis:names:tc:SAML:2.0:ac:classes:Password");
        public static Uri CLX509 = new Uri("urn:oasis:names:tc:SAML:2.0:ac:classes:X509");

        static Uri[] Fields = (from f in typeof(SamlIDs).GetFields()
                               where f.FieldType.Name == "Uri" && f.IsPublic == true
                               select f.GetValue(null) as Uri).ToArray();
        
        public static Uri GetUriFromId(string id)
        {
            return Fields.FirstOrDefault( u => u.ToString() == id);
        }

        public static bool KnownSamlId(string id)
        {
            return Fields.Contains(new Uri(id));
        }
    }

    /// <summary>
    /// Implementation of Saml Assertion
    /// </summary>
    public class AssertionType 
    {
        public IssuerType Issuer;
        public Signature Signature;
        public SubjectType Subject;
        public ConditionsType Conditions;
        //public AdviceType Advice;
        public string Version="2.0";
        public string ID = "IDCard";
        public DateTime IssueInstant;
        public List<StatementAbstractType> Statements = new List<StatementAbstractType>();

        public IEnumerable<AttributeType> AllAttributes()
        {
            return from sat in Statements
                   let att = sat as AttributeStatementType
                   where att != null
                   from a in att.AllAttributes()
                   select a;
        }

        public static AssertionType Load(XElement AssertionElement)
        {
            var at = new AssertionType();

            foreach (var a in AssertionElement.Attributes() )
            {
                switch (a.Name.LocalName)
                {
                    case "Id": at.ID = a.Value; break;
                    case "Version": at.Version = a.Value; break;
                    case "IssueInstant": at.IssueInstant = (DateTime)a; break;
                }
            }
            
            foreach (var e in AssertionElement.Elements())
            {
                switch (e.Name.LocalName)
                {
                    case "Issuer": at.Issuer = IssuerType.Load(e); break;
                    case "Signature":
                    {
                        XmlDocument doc = new XmlDocument();
                        using( var rd = e.CreateReader() )
                        {
                            doc.Load( rd );
                        }
                        at.Signature = new Signature();
                        at.Signature.LoadXml(doc.DocumentElement);

                        if (at.Signature.Id == null && e.Attribute("Id") != null)
                        {
                            at.Signature.Id = e.Attribute("Id").Value;
                        }
                    } 
                    break;
                    case "Subject": at.Subject = SubjectType.Load(e); break;
                    case "Conditions": at.Conditions = ConditionsType.Load(e); break;
                    //case "Advice": at.Advice = AdviceType.Load(e); break;
                    case "AuthnStatement": at.Statements.Add(AuthnStatementType.Load(e)); break;
                    case "AttributeStatement": at.Statements.Add(AttributeStatementType.Load(e)); break;
                    //case "AuthzDecisionStatement": at.Statements.Add(AuthzDecisionStatementType.Load(e)); break;
                    case "Statement": at.Statements.Add(StatementType.Load(e)); break;
                }
            }
            return at;
        }
        
        public virtual XElement ToXml()
        {
            XElement SignatureXml=null;
            if (Signature != null)
            {
                using (var nr = new XmlNodeReader(Signature.GetXml()))
                {
                    SignatureXml = XElement.Load(nr);
                }
            }
            
            return new XElement(
                NA.saml + "Assertion", 
                    new XAttribute("Id", ID ),
                    IssueInstant.MakeXAttribute("IssueInstant"),
                    new XAttribute("Version", Version),
                    Issuer.ToXml(),
                    SignatureXml,
                    Subject == null ? null:Subject.ToXml(),
                    Conditions == null ? null : Conditions.ToXml(),
                    //Advice == null ? null : Advice.ToXml(),
                    from x in Statements where x != null select x.ToXml()
                );
        }
    }

    /*
    public class AdviceType 
    {
        public static AdviceType Load(XElement AdviceElement)
        {
            var at = new AdviceType();
            //TODO
            return at;
        }

        public XElement ToXml()
        {
            return null;
        }
    }
    */

    public class IssuerType 
    {
        public string Value;

        public static IssuerType Load (XElement IssuerElement)
        {
            return new IssuerType{ Value = (string)IssuerElement };
        }

        public XElement ToXml()
        {
            return new XElement(NA.saml + "Issuer", Value);
        }
    }

    public class SubjectType 
    {
        //public BaseIDType BaseID;
        public NameIDType NameID;
        //public EncryptedIDType EncryptedID;
        public List<SubjectConfirmationType> SubjectConfirmations = new List<SubjectConfirmationType>();

        public SubjectType()
        { }

        public SubjectType(string NameID, Uri NameIDFormat, SubjectConfirmationType st)
        {
            this.NameID = new NameIDType
            {
                Value = NameID,
                Format = NameIDFormat
            };

            SubjectConfirmations.Add(st);
        }

        public static SubjectType Load (XElement SubjectElement)
        {
            var st = new SubjectType();
            foreach (var e in SubjectElement.Elements())
            {
                switch (e.Name.LocalName)
                {
                    //case "BaseID": st.BaseID = BaseIDType.Load(e); break;
                    case "NameID": st.NameID = NameIDType.Load(e); break;
                    //case "EncryptedID": st.EncryptedID = EncryptedIDType.Load(e); break;
                    //case "SubjectConfirmation": st.SubjectConfirmations.Add(new SubjectConfirmationType(e)); break;
                    case "SubjectConfirmation": st.SubjectConfirmations.Add(SubjectConfirmationType.Load(e)); break;
                }
            }

            if (st.NameID == null && st.SubjectConfirmations.Count == 0)
            {
                throw new Exception("SubjectType error");
            }

            return st;
        }
        
        public XElement ToXml()
        {
            return new XElement(
                NA.saml + "Subject",
                    //BaseID == null ? null : BaseID.ToXml(),
                    NameID == null ? null : NameID.ToXml(),
                    //EncryptedID== null ? null : EncryptedID.ToXml(),
                    SubjectConfirmations == null ? null : from x in SubjectConfirmations where x!= null select x.ToXml()
                );
        }
    }
    /*
    public class BaseIDType 
    {
        public string NameQualifier;
        public string SPNameQualifier;

        public static BaseIDType Load(XElement BaseIDElement)
        {
            var bt = new BaseIDType();
            foreach (var a in BaseIDElement.Attributes())
            {
                switch (a.Name.LocalName)
                {
                    case "NameQualifier": bt.NameQualifier = a.Value; break;
                    case "SPNameQualifier": bt.SPNameQualifier = a.Value; break;
                }
            }
            return bt;
        }

        public XElement ToXml()
        {
            return new XElement(
                NA.saml + "BaseID",
                    string.IsNullOrEmpty(NameQualifier) ? null : new XAttribute("NameQualifier", NameQualifier),
                    string.IsNullOrEmpty(SPNameQualifier) ? null : new XAttribute("SPNameQualifier", SPNameQualifier)
                );
        }
    }
    */
    public class NameIDType 
    {
        public string NameQualifier;
        public string SPNameQualifier;
        public Uri Format;
        public string SPProvidedID;
        public string Value;

        public static NameIDType Load(XElement NameIDElement)
        {
            var bt = new NameIDType();
            foreach (var a in NameIDElement.Attributes())
            {
                switch (a.Name.LocalName)
                {
                    case "NameQualifier": bt.NameQualifier = a.Value; break;
                    case "SPNameQualifier": bt.SPNameQualifier = a.Value; break;
                    case "Format": bt.Format = new Uri(a.Value); break;
                    case "SPProvidedID": bt.SPProvidedID = a.Value; break;
                }
            }
            bt.Value = (string)NameIDElement;
            return bt;
        }

        public XElement ToXml()
        {
            return new XElement( 
                NA.saml+ "NameID", 
                    string.IsNullOrEmpty( NameQualifier ) ?null: new XAttribute( "NameQualifier", NameQualifier),
                    string.IsNullOrEmpty(SPNameQualifier) ? null : new XAttribute("SPNameQualifier", SPNameQualifier),
                    Format == null ? null : new XAttribute("Format", Format.ToString() ),
                    string.IsNullOrEmpty(SPProvidedID) ? null : new XAttribute("SPProvidedID", SPProvidedID),
                Value);
        }
    }

    /*
    public class EncryptedIDType 
    {
        public static EncryptedIDType Load(XElement EncryptedIDElement )
        {
            var ei = new EncryptedIDType();
            //TODO
            return ei;
        }

        public XElement ToXml()
        {
            return null;
        }
    }
    */
    public class SubjectConfirmationType 
    {
        //public BaseIDType BaseID;
        public NameIDType NameID;
        //public EncryptedIDType EncryptedID;
        public SubjectConfirmationDataType SubjectConfirmationData;
        public Uri Method = SamlIDs.HolderOfKey;

        public SubjectConfirmationType()
        { 
        }

        public SubjectConfirmationType(XElement SubjectConfirmation)
        {
            SubjectConfirmationData = new SubjectConfirmationDataType
            {
                Data = new List<XElement> { SubjectConfirmation }
            };
        }

        public static SubjectConfirmationType Load(XElement SubjectConfirmationElement)
        {
            var sc = new SubjectConfirmationType();
            foreach (var a in SubjectConfirmationElement.Attributes())
            {
                switch (a.Name.LocalName)
                {
                    case "Method": sc.Method = new Uri(a.Value); break;
                }
            }

            foreach (var e in SubjectConfirmationElement.Elements())
            {
                switch (e.Name.LocalName)
                {
                    //case "BaseID": sc.BaseID = BaseIDType.Load(e); break;
                    case "NameID": sc.NameID = NameIDType.Load(e); break;
                    //case "EncryptedID": sc.EncryptedID = EncryptedIDType.Load(e); break;
                    case "ConfirmationMethod": sc.Method = new Uri(e.Value); break;
                    case "SubjectConfirmationData": sc.SubjectConfirmationData = SubjectConfirmationDataType.Load(e); break;
                }
            }
            return sc;
        }
        
        public virtual XElement ToXml()
        {
            return new XElement(
                NA.saml + "SubjectConfirmation",
                    new XAttribute( "Method", Method ),
                    //BaseID == null ? null : BaseID.ToXml(),
                    NameID == null ? null : NameID.ToXml(),
                    //EncryptedID == null ? null : EncryptedID.ToXml(),
                    SubjectConfirmationData == null ? null : SubjectConfirmationData.ToXml()
                );
        }
    }

    public class SubjectConfirmationDataType 
    {
        public DateTime? NotBefore;
        public DateTime? NotOnOrAfter;
        public Uri Recipient;
        public string InResponseTo;
        public string Address;

        public List<XElement> Data = new List<XElement>();

        public SubjectConfirmationDataType()
        { }

        public static SubjectConfirmationDataType Load(XElement SubjectConfirmationDataTypeElement)
        {
            var sc = new SubjectConfirmationDataType();
            foreach (var a in SubjectConfirmationDataTypeElement.Attributes())
            {
                switch (a.Name.LocalName)
                {
                    case "NotBefore": sc.NotBefore = (DateTime)a; break;
                    case "NotOnOrAfter": sc.NotOnOrAfter = (DateTime)a; break;
                    case "Recipient": sc.Recipient = new Uri(a.Value); break;
                    case "InResponseTo": sc.InResponseTo = (string)a; break;
                    case "Address": sc.Address = (string)a; break;
                }
            }

            sc.Data.AddRange( SubjectConfirmationDataTypeElement.Elements() );
            return sc;
        }

        public XElement ToXml()
        {
            return new XElement(
                NA.saml + "SubjectConfirmationData",
                    NotBefore == null ? null : NotBefore.Value.MakeXAttribute( "NotBefore"),
                    NotOnOrAfter == null ? null : NotOnOrAfter.Value.MakeXAttribute("NotOnOrAfter"),
                    Recipient == null ? null : new XAttribute("Recipient", Recipient),
                    InResponseTo == null ? null : new XAttribute("InResponseTo", InResponseTo),
                    Address == null ? null : new XAttribute("Address", Address),
                    from x in Data where x!= null select x
                );
        }
    }

    public class ConditionsType 
    {
        public DateTime? NotBefore;
        public DateTime? NotOnOrAfter;
        //public List<ConditionAbstractType> Conditions = new List<ConditionAbstractType>();

        public static ConditionsType Load(XElement ConditionsTypeElement)
        {
            var ct = new ConditionsType();
            foreach (var a in ConditionsTypeElement.Attributes())
            {
                switch (a.Name.LocalName)
                {
                    case "NotBefore": ct.NotBefore = (DateTime)a; break;
                    case "NotOnOrAfter": ct.NotOnOrAfter = (DateTime)a;  break;
                }
            }
            /*
            foreach (var e in ConditionsTypeElement.Elements())
            {
                switch (e.Name.LocalName)
                {
                    case "Condition": ct.Conditions.Add(ConditionType.Load(e));  break;
                    case "AudienceRestriction": ct.Conditions.Add(AudienceRestrictionType.Load(e));break;
                    case "OneTimeUse": ct.Conditions.Add(OneTimeUseType.Load(e));break;
                    case "ProxyRestriction": ct.Conditions.Add(ProxyRestrictionType.Load(e));break;
                }
            }
            */
            return ct;
        }
        
        public XElement ToXml()
        {
            return new XElement(
                NA.saml + "Conditions",
                    NotBefore == null ? null :  NotBefore.Value.MakeXAttribute("NotBefore"),
                    NotOnOrAfter == null ? null : NotOnOrAfter.Value.MakeXAttribute( "NotOnOrAfter")
                    //,from x in Conditions select x.ToXml()
                );
        }
    }
/*
    public abstract class ConditionAbstractType
    {
        public abstract XElement ToXml();
    }

    public class ConditionType : ConditionAbstractType
    {
        public static ConditionType Load(XElement ConditionElement)
        { 
            return new ConditionType();
        }

        public override XElement ToXml()
        {
            return new XElement(NA.saml + "Condition");
        }
    }
*/
    public class StatementType : StatementAbstractType
    {
        public static StatementType Load(XElement ConditionElement)
        {
            return new StatementType();
        }

        public override XElement ToXml()
        {
            return new XElement(NA.saml + "Statement");
        }
    }
/*
    public class AudienceType
    {
        public Uri Value;

        public static AudienceType Load(XElement AudienceElement)
        {
            return new AudienceType();
        }

        public XElement ToXml()
        {
            return new XElement(NA.saml + "Audience", Value);
        }
    }
    
    public class AudienceRestrictionType : ConditionAbstractType
    {
        public List<AudienceType> Audience = new List<AudienceType>();

        public static AudienceRestrictionType Load(XElement AudienceRestrictionElement)
        {
            return new AudienceRestrictionType
                {
                    Audience = (from e in AudienceRestrictionElement.Elements(NA.saml + "Audience")
                                select AudienceType.Load(e)).ToList()
                };
        }
        
        public override XElement ToXml()
        {
            return new XElement(
                NA.saml + "AudienceRestriction",
                    from a in Audience where a!= null select a.ToXml()
                ); 
        }
    }
    
    public class OneTimeUseType : ConditionAbstractType
    {
        public static OneTimeUseType Load(XElement OneTimeUseElement)
        {
            return new OneTimeUseType();
        }

        public override XElement ToXml()
        {
            return new XElement(NA.saml + "OneTimeUse");
        }
    }
    
    public class ProxyRestrictionType : ConditionAbstractType
    {
        //public List<AudienceType> Audience = new List<AudienceType>();
        public int? Count;

        public static ProxyRestrictionType Load(XElement ProxyRestrictionElement)
        {
            return new ProxyRestrictionType 
            {
                //Audience = (from e in ProxyRestrictionElement.Elements(NA.saml + "Audience") 
                //           select AudienceType.Load(e)).ToList(),
                Count = (from a in ProxyRestrictionElement.Attributes( "Count" ) 
                         select (int)a).FirstOrDefault()
            };
        }

        public override XElement ToXml()
        {
            return new XElement(
                NA.saml + "ProxyRestriction",
                    Count == default(int?) ? null : new XAttribute("Count", Count)
                    //,from a in Audience select a.ToXml()
                );
        }
    }
    */

    public abstract class StatementAbstractType
    {
        public virtual XElement ToXml( )
        {
            return null;
        }
    }

    /*
    public class SubjectLocalityType
    {
        public string Address;
        public string DNSName;

        public static SubjectLocalityType Load(XElement SubjectLocalityElement)
        {
            var ct = new SubjectLocalityType();
            foreach (var a in SubjectLocalityElement.Attributes())
            {
                switch (a.Name.LocalName)
                {
                    case "Address": ct.Address = (string)a; break;
                    case "DNSName": ct.DNSName = (string)a; break;
                }
            }
            return ct;
        }

        public XElement ToXml()
        {
            return new XElement(
                NA.saml + "SubjectLocality",
                    Address == null ? null : new XAttribute("Address", Address),
                    DNSName == null ? null : new XAttribute("DNSName", DNSName)
                );
        }
    }
    */

    public class AuthnContextType
    {
        public Uri AuthnContextClassRef;
        public Uri AuthnContextDecl;
        public Uri AuthnContextDeclRef;

        //public List<Uri> AuthenticatingAuthorities = new List<Uri>();
        public List<string> AuthenticatingAuthorities = new List<string>();

        public static AuthnContextType Load(XElement AuthnContextElement)
        {
            var ct = new AuthnContextType
                { 
                    //AuthenticatingAuthorities = (from e in AuthnContextElement.Elements( NA.saml + "AuthenticatingAuthority" ) 
                    //                            select new Uri( e.Value)).ToList()
                    AuthenticatingAuthorities = (from e in AuthnContextElement.Elements( NA.saml + "AuthenticatingAuthority" ) 
                                                select e.Value).ToList()

                };
            
            foreach (var a in AuthnContextElement.Elements())
            {
                switch (a.Name.LocalName)
                {
                    case "AuthnContextClassRef": ct.AuthnContextClassRef = new Uri(a.Value ); break;
                    case "AuthnContextDecl": ct.AuthnContextDecl = new Uri(a.Value); break;
                    case "AuthnContextDeclRef": ct.AuthnContextDeclRef = new Uri(a.Value); break;
                }
            }
            
            return ct;
        }

        public XElement ToXml()
        {
            return new XElement(
                NA.saml + "AuthnContext",
                    AuthnContextDecl == null ? null : new XElement(NA.saml + "AuthnContextDecl", AuthnContextDecl),
                    AuthnContextDeclRef == null ? null : new XElement(NA.saml + "AuthnContextDeclRef", AuthnContextDeclRef),
                    AuthnContextClassRef == null ? null : new XElement(NA.saml+"AuthnContextClassRef", AuthnContextClassRef),
                    from a in AuthenticatingAuthorities where a != null select new XElement(NA.saml + "AuthenticatingAuthority", a)
                );
        }
    }

    public class AuthnStatementType : StatementAbstractType
    {
        //public SubjectLocalityType SubjectLocality;
        public DateTime AuthnInstant;
        public string SessionIndex;
        public DateTime? SessionNotOnOrAfter;
        public AuthnContextType AuthnContext;

        public static AuthnStatementType Load(XElement AuthnStatementElement)
        {
            var ct = new AuthnStatementType();

            foreach (var a in AuthnStatementElement.Attributes())
            {
                switch (a.Name.LocalName)
                {
                    case "AuthnInstant": ct.AuthnInstant = (DateTime)a; break;
                    case "SessionIndex": ct.SessionIndex = (string)a; break;
                    case "SessionNotOnOrAfter": ct.SessionNotOnOrAfter = (DateTime)a; break;
                }
            }

            foreach (var e in AuthnStatementElement.Elements())
            {
                switch (e.Name.LocalName)
                {
                    //case "SubjectLocality": ct.SubjectLocality = SubjectLocalityType.Load(e); break;
                    case "AuthnContext": ct.AuthnContext = AuthnContextType.Load(e); break;
                }
            }
            return ct;
        }

        public override XElement ToXml()
        {
            return new XElement(
                NA.saml + "AuthnStatement",
                    AuthnInstant.MakeXAttribute("AuthnInstant"),
                    SessionIndex == null ? null : new XAttribute("SessionIndex", SessionIndex),
                    SessionNotOnOrAfter == null ? null : SessionNotOnOrAfter.Value.MakeXAttribute("SessionNotOnOrAfter"),
                    //SubjectLocality == null ? null : SubjectLocality.ToXml(),
                    AuthnContext.ToXml()
                );
        }
    }

    public class AttributeStatementType : StatementAbstractType
    {
        protected class ChoiceAttributeTypeOrEncryptedElementType
        {
            public AttributeType Attribute;
            //public EncryptedElementType EncryptedAttribute;

            public XElement ToXml()
            {
                if (Attribute != null) return Attribute.ToXml();
                return null;
                //return EncryptedAttribute.ToXml();
            }
        }
        protected List<ChoiceAttributeTypeOrEncryptedElementType> StatementList = new List<ChoiceAttributeTypeOrEncryptedElementType>();

        public AttributeStatementType(params object[] c)
        {
            foreach (var o in c)
            {
                if (o is AttributeType) Add(o as AttributeType);
                //else if (o is EncryptedElementType) Add(o as EncryptedElementType);
                else if (o is AttributeType[] )
                    foreach (var a in (o as AttributeType[]))
                        Add(a);
            }
        }
        
        public void Add(AttributeType at)
        { 
            StatementList.Add( new ChoiceAttributeTypeOrEncryptedElementType{ Attribute = at});
        }
        /*
        public void Add(EncryptedElementType et)
        {
            StatementList.Add( new ChoiceAttributeTypeOrEncryptedElementType{ EncryptedAttribute = et});
        }
        */
        public IEnumerable<AttributeType> AllAttributes()
        {
            return from s in StatementList where s.Attribute != null select s.Attribute;
        }

        public static AttributeStatementType Load(XElement AttributeStatementElement)
        {
            var ct = new AttributeStatementType();
            
            foreach (var e in AttributeStatementElement.Elements())
            {
                switch (e.Name.LocalName)
                {
                    case "Attribute": ct.Add( AttributeType.Load(e)); break;
                    //case "EncryptedAttribute": ct.Add( EncryptedElementType.Load(e)); break;
                }
            }
            return ct;
        }

        public override XElement ToXml()
        {
            return new XElement(
                NA.saml + "AttributeStatement",
                    from e in StatementList where e != null select e.ToXml()
                );
        }
    }

    public class AttributeType 
    {
        public List<AttributeValueType> AttributeValues = new List<AttributeValueType>();
        public string Name;
        public Uri NameFormat;
        public string FriendlyName;

        public AttributeType()
        { 
        }

        public AttributeType(string Name, string Value)
        {
            this.Name = Name;
            AttributeValues.Add(new AttributeValueType { Value = Value });
        }

        public AttributeType(string Name, Uri NameFormat, string Value)
        {
            this.Name = Name;
            this.NameFormat = NameFormat;
            AttributeValues.Add(new AttributeValueType { Value = Value });
        }

        public static AttributeType Load(XElement AttributeElement)
        {
            return new AttributeType 
            {
                Name = (string)AttributeElement.Attribute("Name"),
                NameFormat = (from a in AttributeElement.Attributes("NameFormat") 
                              select new Uri(a.Value) ).FirstOrDefault(),
                FriendlyName = (from a in AttributeElement.Attributes("FriendlyName")
                                select (string)a ).FirstOrDefault(),
                AttributeValues = (from e in AttributeElement.Elements(NA.saml+"AttributeValue")
                                  select AttributeValueType.Load(e)).ToList()
            };
        }

        public XElement ToXml()
        {
            return new XElement(
                NA.saml + "Attribute",
                    new XAttribute( "Name", Name),
                    NameFormat == null ? null : new XAttribute("NameFormat", NameFormat),
                    FriendlyName == null ? null : new XAttribute("FriendlyName", FriendlyName),
                    from av in AttributeValues select av.ToXml()
                );
        }
    }

    public class AttributeValueType
    {
        public string Value;

        public static AttributeValueType Load(XElement AttributeValueElement)
        {
            return new AttributeValueType 
            {
                Value = AttributeValueElement.Value
            };
        }

        public XElement ToXml()
        {
            return new XElement(
                NA.saml + "AttributeValue", Value
                );
        }
    }

    /*
    public class AuthzDecisionStatementType : StatementAbstractType
    {
        public List<ActionType> Actions = new List<ActionType>();
        public EvidenceType Evidence;
        public Uri Resource;
        public DecisionType Decision;

        public static AuthzDecisionStatementType Load(XElement AuthzDecisionStatementElement)
        {
            var ct = new AuthzDecisionStatementType();
            switch ((string)AuthzDecisionStatementElement.Attribute("Decision"))
            {
                case "Permit": ct.Decision = DecisionType.Permit; break;
                case "Deny": ct.Decision = DecisionType.Deny; break;
                case "Indeterminate": ct.Decision = DecisionType.Indeterminate; break;
            }

            foreach (var e in AuthzDecisionStatementElement.Elements())
            {
                switch (e.Name.LocalName)
                {
                    case "Action": ct.Actions.Add( ActionType.Load(e)); break;
                    case "Evidence": ct.Evidence = EvidenceType.Load(e); break;
                }
            }
            return ct;
        }

        public override XElement ToXml()
        {
            return new XElement(
                NA.saml + "AuthzDecisionStatement",
                    from a in Actions select a.ToXml(),
                    Evidence == null ? null : new XElement("Evidence", Evidence),
                    Resource == null ? null : new XAttribute("Resource", Resource),
                    new XAttribute("Decision", Decision.ToString() )
                );
        }
    }
    

    public enum DecisionType
    { 
        Permit,
        Deny,
        Indeterminate
    }

    
    public class ActionType
    {
        public Uri Namespace;

        public static ActionType Load(XElement ActionElement)
        {
            return new ActionType 
            {
                Namespace = new Uri(ActionElement.Attribute("Namespace").Value)
            };
        }

        public XElement ToXml()
        {
            return new XElement(
                NA.saml + "Action",
                    new XAttribute("Namespace", Namespace)
            );
        }
    }
    
    
    public class EvidenceType
    {
        public string AssertionIDRef;
        public Uri AssertionURIRef;
        public AssertionType Assertion;
        //public EncryptedElementType EncryptedAssertion;

        public static EvidenceType Load(XElement EvidenceElement)
        {
            var ct = new EvidenceType();
            foreach (var e in EvidenceElement.Elements())
            {
                switch (e.Name.LocalName)
                {
                    case "AssertionIDRef": ct.AssertionIDRef = e.Value; break;
                    case "AssertionURIRef": ct.AssertionURIRef = new Uri(e.Value); break;
                    case "Assertion": ct.Assertion = AssertionType.Load(e); break;
                    //case "EncryptedAssertion": ct.EncryptedAssertion = EncryptedElementType.Load(e); break;
                }
            }
            return ct;
        }

        public XElement ToXml()
        {
            if (AssertionIDRef != null) return new XElement(NA.saml + "AssertionIDRef", AssertionIDRef);
            if (AssertionURIRef != null) return new XElement(NA.saml + "AssertionURIRef", AssertionURIRef);
            if (Assertion != null) return Assertion.ToXml();
            //if (EncryptedAssertion != null) return EncryptedAssertion.ToXml();
            return null;
        }
    }

    
    public class EncryptedElementType
    {
        public EncryptedData EncryptedData;
        public List<EncryptedKey> EncryptedKeys = new List<EncryptedKey>();

        public static EncryptedElementType Load(XElement EncryptedElement)
        {
            var ct = new EncryptedElementType();
            //TODO
            return ct;
        }
        
        public XElement ToXml()
        {
            return null;
        }
    }
    */
}