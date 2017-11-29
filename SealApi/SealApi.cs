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

namespace SDSD.SealApi
{
    using Saml20;
    using Microsoft.Web.Services3.Design;

    class UsedPaths
    {
        public static XName[] BodyAssertion = new XName[] { NA.soap + "Body", NA.wst + "RequestSecurityTokenResponse", NA.wst + "RequestedSecurityToken", NA.saml + "Assertion" };
        public static XName[] HeaderAttributeStatement = new XName[] { NA.soap + "Header", NA.wsse + "Security", NA.saml + "Assertion", NA.saml + "AttributeStatement" };
        public static XName[] HeaderAssertion = new XName[] { NA.soap + "Header", NA.wsse + "Security", NA.saml + "Assertion" };
        public static XName[] MedcomHeader = new XName[] { NA.soap + "Header", NA.medcom + "Header" };
        public static XName[] AttributeStatementPath = new XName[] { NA.soap + "Header", NA.wsse + "Security", NA.saml + "Assertion", NA.saml + "AttributeStatement" };
    }

    public class FormatIds
    {
        public const string cprnumber = "http://rep.oio.dk/cpr.dk/xml/schemas/core/2005/03/18/CPR_PersonCivilRegistrationIdentifier.xsd";
        public const string cvrnumber = "medcom:cvrnumber";
        public const string ynumber = "medcom:ynumber";
        public const string pnumber = "medcom:pnumber";
        public const string skscode = "medcom:skscode";
        public const string sorcode = "medcom:sor";
    }

    public enum CardLifeTimeType
    {
        FiveMinutes,
        HalfHour,
        Hours8,
        Hours24
    }

    public enum CardType
    {
        user,
        system
    }

    public class CardFactory
    {
        public static DGWSCard10Type Load(XElement AssertionElement)
        {
            var v = CardVersion(AssertionElement);
            if (v == null) return null;

            DGWSCard10Type card = null;
            switch (v)
            {
                case "1.0": card = new DGWSCard10Type(); break;
                case "1.0.1": card = new DGWSCard101Type(); break;
                case "1.1": card = new DGWSCard11Type(); break;
            }

            if (card != null)
            {
                card.Load(AssertionElement);
            }
            return card;
        }

        public static string CardVersion(XElement AssertionElement)
        {
            if (AssertionElement == null) return null;

            return (from e in AssertionElement.Descendants(NA.saml + "Attribute")
                    from a in e.Attributes("Name")
                    where a.Value.EndsWith(":IDCardVersion")
                    from p in e.Elements(NA.saml + "AttributeValue")
                    select p.Value).FirstOrDefault();
        }
    }

    public class DGWSCard10Type
    {
        public string Issuer;
        public CardLifeTimeType CardLifeTime;
        public string NameID;
        public string NameIDFormat = FormatIds.cprnumber;

		public string IDCardID = Guid.NewGuid().ToString();
        protected string iDCardVersion = "1.0";
        public virtual string IDCardVersion
        {
            get { return iDCardVersion; }
        }
        public CardType IDCardType = CardType.system;
        public int AuthenticationLevel = 1;
        public string OCESCertHash;

        //UserLogType
        public string CivilRegistrationNumber;
        public string GivenName;
        public string SurName;
        public string Occupation;
        public string EmailAddress;
        public string Role;
        public string AuthorizationCode;

        //SystemLog
        public string ITSystemName;
        public string OrganisationID;
        public string OrganisationIDFormat = FormatIds.cvrnumber;
        public string OrganisationName;

        DateTime cardCreationTime;
        public virtual DateTime CardCreationTime
        {
            get
            {
                return cardCreationTime;
            }

            set
            {
                var t = new DateTime(value.Year, value.Month, value.Day, value.Hour, value.Minute, value.Second, value.Kind);
                cardCreationTime = t - TimeSpan.FromMinutes(5);
            }
        }

        protected string signatureID;
        public virtual string SignatureID
        {
            get { return signatureID; }
            set { signatureID = value; }
        }

        Signature signature;
        public Signature Signature
        {
            get
            {
                return signature;
            }
            set
            {
                XmlAssertion = null;
                signature = value;
            }
        }

        public string Username;
        public string Password;

        public DGWSCard10Type()
        {
            signatureID = "OCESSignature";
			CardCreationTime = DateTime.Now;
		}

        protected XElement XmlAssertion;

        public virtual bool TooOld()
        {
            if (DateTime.Now < CardCreationTime) return true;
            return DateTime.Now > CardCreationTime + Api.ToTimeSpan(CardLifeTime);
        }

        public virtual bool SignatureIsNeeded()
        {
            switch (AuthenticationLevel)
            {
                case 1: return false;
                case 2: return string.IsNullOrEmpty(Username) || string.IsNullOrEmpty(Password) || TooOld();
                case 3: return (Signature == null) || TooOld();
                case 4: return (Signature == null) || TooOld();
            }
            return true;
        }

        public virtual void Sign(X509Certificate2 cert)
        {
            Signature = null; //Remove old Signature before making Xml
            Signature = CertificateUtil.Sign(ToXml(), cert);
            Signature.Id = SignatureID;
        }

        public virtual bool CheckSignature(XElement e)
        {
            if (Signature == null) return false;
            return CertificateUtil.validateSignature(e, SignatureID) != null;
        }

        public virtual bool CheckSignature()
        {
            if (Signature == null) return false;
            return CertificateUtil.validateSignature(ToXml(), SignatureID) != null;
        }

        public virtual XElement ToXml()
        {
            XmlAssertion = XmlAssertion ?? new DGWSAssertionType
            {
                Issuer = new IssuerType
                {
                    Value = Issuer,
                },
                Signature = Signature,
                IssueInstant = CardCreationTime,
                Subject = new SubjectType(
                            NameID,
                            new Uri(NameIDFormat),
                            AuthenticationLevel == 1 ? null : new DGWSSubjectConfirmationType(
                                AuthenticationLevel > 2 ? new XElement(NA.ds + "KeyInfo",
                                    new XElement(NA.ds + "KeyName", SignatureID)
                                 ) :
                                new XElement(NA.wsse + "UsernameToken",
                                            new XElement(NA.wsse + "Username", Username),
                                            new XElement(NA.wsse + "Password", Password)
                                ) ) ),
                Conditions = new ConditionsType
                {
					NotBefore = CardCreationTime,
					NotOnOrAfter = CardCreationTime + Api.ToTimeSpan(CardLifeTime)
                },
                Statements = new List<StatementAbstractType>() 
                { 
                    new DGWSAttributeStatementType(
                        new AttributeType("sosi:IDCardID",IDCardID),
                        new AttributeType("sosi:IDCardVersion", IDCardVersion),
                        new AttributeType("sosi:IDCardType", IDCardType.ToString() ),
                        new AttributeType("sosi:AuthenticationLevel", AuthenticationLevel.ToString() ),
                        OCESCertHash == null ? null : new AttributeType("sosi:OCESCertHash", OCESCertHash )
                    ){ id="IDCardData"}, 
                    IDCardType == CardType.system ? null :
                    new DGWSAttributeStatementType(
                        new AttributeType("medcom:UserCivilRegistrationNumber",CivilRegistrationNumber),
                        new AttributeType("medcom:UserGivenName", GivenName),
                        new AttributeType("medcom:UserSurName", SurName ),
                        new AttributeType("medcom:UserEmailAddress", EmailAddress ),
                        new AttributeType("medcom:UserRole", Role ),
                        string.IsNullOrEmpty(AuthorizationCode)?null: new AttributeType("medcom:UserAuthorizationCode", AuthorizationCode ),
                        Occupation == null ? null: new AttributeType("medcom:UserOccupation", Occupation )
                    ){ id="UserLog"},
                    new DGWSAttributeStatementType(
                        new AttributeType("medcom:ITSystemName", ITSystemName ),
                        new AttributeType("medcom:CareProviderID", new Uri(OrganisationIDFormat), OrganisationID ),
                        new AttributeType("medcom:CareProviderName", OrganisationName )
                    ){id="SystemLog"}
                }
            }.ToXml();
			//Console.WriteLine (XmlAssertion);
            return XmlAssertion;
        }
        
        public bool Load(XElement Assertion)
        {
            if (Assertion == null) return false;
            if (Assertion.Name != NA.saml + "Assertion") return false;
            this.XmlAssertion = Assertion;

            var Ass = AssertionType.Load(Assertion);
            if (Ass.Version != "2.0") return false;

            Issuer = Ass.Issuer.Value;
            NameID = Ass.Subject.NameID.Value;
            NameIDFormat = Ass.Subject.NameID.Format.ToString();

            var scdList = (from sc in Ass.Subject.SubjectConfirmations
                           where sc.Method == SamlIDs.HolderOfKey && sc.SubjectConfirmationData != null && sc.SubjectConfirmationData.Data != null
                           from data in sc.SubjectConfirmationData.Data
                           select data).ToList();

            var qSig = from e in scdList
                       where e.Name == NA.ds + "KeyInfo"
                       select e.Elements(NA.ds + "KeyName").Select(elm => elm.Value).FirstOrDefault();

            SignatureID = qSig.FirstOrDefault();

            if (!string.IsNullOrEmpty(SignatureID) && Ass.Signature != null)
            {
                Signature = Ass.Signature.Id == SignatureID ? Ass.Signature : null;
            }
            
            var qUP = (from e in scdList
                       where e.Name == NA.wsse + "UsernameToken"
                       select new
                       {
                           Username = e.Elements(NA.wsse + "Username").Select(elm => elm.Value).FirstOrDefault(),
                           Password = e.Elements(NA.wsse + "Password").Select(elm => elm.Value).FirstOrDefault()
                       }).FirstOrDefault();

            if (qUP != null)
            {
                Username = qUP.Username;
                Password = qUP.Password;
            }

            CardCreationTime = Ass.IssueInstant;
            CardLifeTime = Api.ToCardLifeTimeType(Ass.Conditions.NotOnOrAfter.Value - Ass.Conditions.NotBefore.Value);
            foreach (var a in Ass.AllAttributes())
            {
                ReadAttribute(a);
            }
            return true;
        }

        protected virtual bool ReadAttribute(AttributeType a)
        {
            var ar = a.Name.Split(':');
            if (ar.Length != 2) return false;
            if (ar[0] != "sosi" && ar[0] != "medcom" && ar[0] != "dgws") return false;

            var v = a.AttributeValues[0].Value;

            switch (ar[1])
            {
                case "IDCardID": IDCardID = v; return true;
                case "IDCardVersion":
                    //at.IDCardVersion = (string)e.Element(NA.saml + "AttributeValue");
                    break;
                case "IDCardType":
                    switch (v)
                    {
                        case "user": IDCardType = CardType.user; return true;
                        case "system": IDCardType = CardType.system; return true;
                    }
                    return true;
                case "AuthenticationLevel": AuthenticationLevel = int.Parse(v); return true;
                case "OCESCertHash": OCESCertHash = v; return true;
                case "UserCivilRegistrationNumber": CivilRegistrationNumber = v; return true;
                case "UserGivenName": GivenName = v; return true;
                case "UserSurName": SurName = v; return true;
                case "UserEmailAddress": EmailAddress = v; return true;
                case "UserRole": Role = v; return true;
                case "UserOccupation": Occupation = v; return true;
                case "UserAuthorizationCode": AuthorizationCode = v; return true;
                case "ITSystemName": ITSystemName = v; return true;
                case "CareProviderID":
                    OrganisationID = v;
                    OrganisationIDFormat = a.NameFormat.ToString();
                    return true;
                case "CareProviderName": OrganisationName = v; return true;
                case "OrganisationID":
                    OrganisationID = v;
                    OrganisationIDFormat = a.NameFormat.ToString();
                    return true;
                case "OrganisationName": OrganisationName = v; return true;
            }
            return false;
        }

        public virtual ErrorType VerificerKonsistens(bool CheckCertificate)
        {
            if (string.IsNullOrEmpty(Issuer)) return new ErrorType(ErrorCode.InvalidHeader, "Data fejl i kort (Issuer mangler)");
            if (string.IsNullOrEmpty(NameID)) return new ErrorType(ErrorCode.InvalidHeader, "Data fejl i kort (NameID mangler)");
            if (string.IsNullOrEmpty(NameIDFormat)) return new ErrorType(ErrorCode.InvalidHeader, "Data fejl i kort ( NameIDFormat mangler)");
            if (IDCardID == null) return new ErrorType(ErrorCode.InvalidHeader, "Data fejl i kort ( IDCardID mangler)");
            if (string.IsNullOrEmpty(IDCardVersion)) return new ErrorType(ErrorCode.InvalidHeader, "Data fejl i kort (IDCardVersion mangler)");
            if (!(IDCardVersion == "1.0.1" || IDCardVersion == "1.0")) return new ErrorType(ErrorCode.InvalidHeader, "Data fejl i kort (forkert kortversion)");
            if (AuthenticationLevel < 1 || AuthenticationLevel > 4) return new ErrorType(ErrorCode.AuthenticationLevel, "Data fejl i kort (forkert AuthenticationLevel)");

            if (string.IsNullOrEmpty(ITSystemName)) return new ErrorType(ErrorCode.InvalidHeader, "Data fejl i kort ( mangler ITSystemName)");
            if (string.IsNullOrEmpty(OrganisationID)) return new ErrorType(ErrorCode.InvalidHeader, "Data fejl i kort ( mangler OrganisationID)");
            if (string.IsNullOrEmpty(OrganisationIDFormat)) return new ErrorType(ErrorCode.InvalidHeader, "Data fejl i kort (OrganisationIDFormat mangler)");
            if (string.IsNullOrEmpty(OrganisationName)) return new ErrorType(ErrorCode.InvalidHeader, "Data fejl i kort (OrganisationName mangler )");

            if (IDCardType == CardType.user)
            {
                if (string.IsNullOrEmpty(CivilRegistrationNumber)) return new ErrorType(ErrorCode.InvalidHeader, "Data fejl i kort (CivilRegistrationNumber mangler)");
                if (string.IsNullOrEmpty(GivenName)) return new ErrorType(ErrorCode.InvalidHeader, "Data fejl i kort ( GivenName mangler)");
                if (string.IsNullOrEmpty(SurName)) return new ErrorType(ErrorCode.InvalidHeader, "Data fejl i kort ( SurName mangler)");
                if (string.IsNullOrEmpty(EmailAddress)) return new ErrorType(ErrorCode.InvalidHeader, "Data fejl i kort (EmailAddress mangler)");
                if (string.IsNullOrEmpty(Role)) return new ErrorType(ErrorCode.InvalidHeader, "Data fejl i kort ( Role mangler)");
            }

            switch (AuthenticationLevel)
            {
                case 1: return null;
                case 2:
                    {
                        if (string.IsNullOrEmpty(Username)) return new ErrorType(ErrorCode.InvalidHeader, "Data fejl i kort ( Username mangler)");
                        if (string.IsNullOrEmpty(Password)) return new ErrorType(ErrorCode.InvalidHeader, "Data fejl i kort ( Password mangler)");
                        break;
                    }
                case 3:
                    {
                        if (!CheckCertificate) break;
                        if (Signature == null) return new ErrorType(ErrorCode.InvalidCertificate, "Data fejl i kort ( Signature mangler)");
                        if (SignatureID != Signature.Id) return new ErrorType(ErrorCode.InvalidCertificate, "Data fejl i kort ( Forkert Signatur ID)");
                        var cert = CertificateUtil.GetCertificate(Signature);
                        if (cert == null) return new ErrorType(ErrorCode.InvalidHeader, "Data fejl i kort ( Certifikat i signatur mangler)");
                        if (!CertificateUtil.IsVOCES(cert)) return new ErrorType(ErrorCode.InvalidHeader, "Data fejl i kort ( Certifikat i er ikke VOCES)");
                    }
                    break;

                case 4:
                    {
                        if (!CheckCertificate) break;
                        if (Signature == null) return new ErrorType(ErrorCode.InvalidHeader, "Data fejl i kort ( Signature mangler)");
                        if (SignatureID != Signature.Id) return new ErrorType(ErrorCode.InvalidCertificate, "Data fejl i kort ( Forkert Signatur ID)");
                        var cert = CertificateUtil.GetCertificate(Signature);
                        if (cert == null) return new ErrorType(ErrorCode.InvalidHeader, "Data fejl i kort ( Certifikat i signatur mangler)");
                        if (!CertificateUtil.IsMOCES(cert)) return new ErrorType(ErrorCode.InvalidHeader, "Data fejl i kort ( Certifikat i er ikke MOCES)");
                    };
                    break;
                default:
					{
					return new ErrorType(ErrorCode.InvalidHeader, "Data fejl i kort ( AuthenticationLevel ligger ikke melle 1 og 4)");
				}
            }

            return null;
        }


        public virtual ErrorType HandleIncommingRequest(XElement envelope, IDCardCheck CheckIDCard)
        {
            SDSD.SealApi.Assertion.SericeUtil.ServiceSessionData.Card = this;

            var res = VerificerKonsistens(false);
            if (res != null) return res;
            if (TooOld()) return new ErrorType(ErrorCode.IdCardTooOld, "Perioden for IDKortet er udløbet");

            return CheckIDCard(this, envelope);
        }

        public virtual ErrorType HandleIncommingResponse(XElement envelope, IDCardCheck CheckIDCard)
        {
            var err = VerificerKonsistens(false);
            if (err != null) return err;
            if (TooOld()) return new ErrorType(ErrorCode.IdCardTooOld, "Perioden for IDKortet er udløbet");
            return CheckIDCard(this, envelope);
        }

        public virtual ErrorType HandleOutgoingRequest(XElement envelope)
        {
			//This will probably fail and fuck everything up.
            //var err = VerificerKonsistens(false);
            //if (err != null) return err;

            var hd = envelope.Element(NA.soap + "Header");
            hd.Add(new SecurityType { Assertion = this }.ToXml());

            return null;
        }

        public virtual ErrorType HandleOutgoingResponse(XElement envelope)
        {
            var err = VerificerKonsistens(false);
            if (err != null) return err;

            var hd = envelope.Element(NA.soap + "Header");
            hd.Add(new SecurityType { Assertion = this }.ToXml());
            return null;
        }

        public virtual ErrorType HandleOutgoingMedcomHeaderResponse(XElement envelope, MedcomHeaderReceiver GetMedcomHeader)
        {
            var hd = envelope.Element(NA.soap + "Header");
            hd.Add(GetMedcomHeader().ToXml());
            return null;
        }

        public virtual ErrorType HandleIncommingMedcomHeaderResponse(XElement envelope, MedcomHeaderCheck CheckMedcomHeader)
        {
            var mh = envelope.Element(UsedPaths.MedcomHeader);
            if (mh == null) return new ErrorType(ErrorCode.InvalidHeader, "MedCom header mangler i response");
            mh.Remove();

            var mhd = MedcomHeaderType.Load(mh);
            if (mhd == null) return new ErrorType(ErrorCode.InvalidHeader, "Kunne ikke parse MedCom header");

            var err = CheckMedcomHeader(mhd);
            if (err != null) return err;
            return null;
        }

        public virtual ErrorType HandleIncommingMedcomHeaderRequest(XElement envelope, MedcomHeaderCheck CheckMedcomHeader)
        {
            var tag = envelope.Element(UsedPaths.MedcomHeader);
            if (tag == null) return new ErrorType(ErrorCode.InvalidHeader, "MedCom header mangler");
            tag.Remove();
            var m = MedcomHeaderType.Load(tag);
            if (m == null) return new ErrorType(ErrorCode.InvalidHeader, "Kunne ikke læse Medcom Header");
            var res = CheckMedcomHeader(m);
            if (res != null) return new ErrorType(ErrorCode.InvalidHeader, "Medcom Header ikke accepteret");
            return null;
        }

        public virtual ErrorType HandleOutgoingMedcomHeaderRequest(XElement envelope, MedcomHeaderReceiver GetMedcomHeader)
        {
            var m = GetMedcomHeader();
            var hd = envelope.Element(NA.soap + "Header");
            hd.Add(m.ToXml());
            SDSD.SealApi.Assertion.SericeUtil.ClientSessionData.MedcomHeader = m;
            return null;
        }
    }

    public class DGWSCard101Type : DGWSCard10Type
    {
        public override DateTime CardCreationTime
        {
            get
            {
                return base.CardCreationTime;
            }

            set
            {
                base.CardCreationTime = value.MinSecUnivesial();
            }
        }

        public DGWSCard101Type() : base()
        {
            iDCardVersion = "1.0.1";
        }

        public override bool TooOld()
        {
            if (DateTime.Now.ToUniversalTime() < CardCreationTime) return true;
            return DateTime.Now.ToUniversalTime() > CardCreationTime + Api.ToTimeSpan(CardLifeTime);
        }
    }

    public class DGWSCard11Type : DGWSCard101Type
    {
        public string MOCESHash;
        public string VOCESHash;
        public string AuthenticatingAuthority;

        public DGWSCard11Type() : base()
        {
            signatureID = "IdCardSignature";
            iDCardVersion = "1.1";
        }

        public override bool SignatureIsNeeded()
        {
            switch (AuthenticationLevel)
            {
                case 1: return false;
                case 2: return string.IsNullOrEmpty(Username) || string.IsNullOrEmpty(Password) || TooOld();
                case 3: return (Signature == null) || TooOld();
            }
            return true;
        }

        public override XElement ToXml()
        {
            XmlAssertion = XmlAssertion ?? new DGWSAssertionType
            {
                Issuer = new IssuerType
                {
                    Value = Issuer,
                },
                Signature = Signature,
                IssueInstant = CardCreationTime,
                Subject = new SubjectType(
                            NameID,
                            new Uri(NameIDFormat),
                            AuthenticationLevel == 1 ? null : new DGWSSubjectConfirmationType(
                                AuthenticationLevel > 2 ? new XElement(NA.ds + "KeyInfo",
                                    new XElement(NA.ds + "KeyName", SignatureID)
                                ) :
                                new XElement(NA.wsse + "UsernameToken",
                                            new XElement(NA.wsse + "Username", Username),
                                            new XElement(NA.wsse + "Password", Password)
                                )
                            )
                        )
                ,
                Conditions = new ConditionsType
                {
					NotBefore = CardCreationTime,
					NotOnOrAfter = CardCreationTime + Api.ToTimeSpan(CardLifeTime)
                },
                Statements = new List<StatementAbstractType>() 
                    { 
                        AuthenticatingAuthority == null ? null :
                        new AuthnStatementType
                        {
                          AuthnInstant = CardCreationTime,
                          AuthnContext = new AuthnContextType
                          {
                            AuthnContextClassRef = AuthenticationLevel > 2 ? SamlIDs.CLX509:SamlIDs.CLPassword,
                            //AuthenticatingAuthorities = new List<Uri>{ AuthenticatingAuthority }
                            AuthenticatingAuthorities = new List<string>{ AuthenticatingAuthority }
                          }
                        },

                        new DGWSAttributeStatementType(
                            new AttributeType("dgws:IDCardID",IDCardID),
                            new AttributeType("dgws:IDCardVersion", IDCardVersion),
                            new AttributeType("dgws:IDCardType", IDCardType.ToString() ),
                            new AttributeType("dgws:AuthenticationLevel", AuthenticationLevel.ToString() ), 
                            IDCardType == CardType.system ? null : new AttributeType[]
                            {
                                new AttributeType("dgws:UserCivilRegistrationNumber",CivilRegistrationNumber),
                                new AttributeType("dgws:UserGivenName", GivenName),
                                new AttributeType("dgws:UserSurName", SurName ),
                                Occupation == null ? null: new AttributeType("dgws:UserOccupation", Occupation ),
                                new AttributeType("dgws:UserEmailAddress", EmailAddress ),
                                new AttributeType("dgws:UserRole", Role ),
                                string.IsNullOrEmpty(AuthorizationCode )?null : new AttributeType("dgws:UserAuthorizationCode", AuthorizationCode )
                            },
                            new AttributeType("dgws:ITSystemName", ITSystemName ),
                            new AttributeType("dgws:OrganisationID", new Uri(OrganisationIDFormat), OrganisationID ),
                            new AttributeType("dgws:OrganisationName", OrganisationName ),

                            MOCESHash == null ? null: new AttributeType("dgws:ClientMOCESHash", MOCESHash ),
                            VOCESHash == null ? null: new AttributeType("dgws:ClientVOCESHash", VOCESHash )
                       ){ id = "IDCardData"}
                    }
            }.ToXml();
            return XmlAssertion;
        }

        protected override bool ReadAttribute(AttributeType a)
        {
            if (base.ReadAttribute(a)) return true;
            var v = a.AttributeValues[0].Value;

            switch (a.Name)
            {
                case "dgws:ClientMOCESHash": MOCESHash = v; return true;
                case "dgws:ClientVOCESHash": VOCESHash = v; return true;
            }
            return false;
        }

        public override ErrorType VerificerKonsistens(bool CheckCertificate)
        {
            if (string.IsNullOrEmpty(Issuer)) return new ErrorType(ErrorCode.InvalidHeader, "Data fejl i kort (Issuer mangler)");
            if (string.IsNullOrEmpty(NameID)) return new ErrorType(ErrorCode.InvalidHeader, "Data fejl i kort (NameID mangler)");
            if (string.IsNullOrEmpty(NameIDFormat)) return new ErrorType(ErrorCode.InvalidHeader, "Data fejl i kort ( NameIDFormat mangler)");
            if (IDCardID == null) return new ErrorType(ErrorCode.InvalidHeader, "Data fejl i kort ( IDCardID mangler)");
            if (string.IsNullOrEmpty(IDCardVersion)) return new ErrorType(ErrorCode.InvalidHeader, "Data fejl i kort (IDCardVersion mangler)");
            if (AuthenticationLevel < 1 || AuthenticationLevel > 3) return new ErrorType(ErrorCode.InvalidHeader, "Data fejl i kort (forkert AuthenticationLevel)");

            if (string.IsNullOrEmpty(ITSystemName)) return new ErrorType(ErrorCode.InvalidHeader, "Data fejl i kort ( mangler ITSystemName)");
            if (string.IsNullOrEmpty(OrganisationID)) return new ErrorType(ErrorCode.InvalidHeader, "Data fejl i kort ( mangler OrganisationID)");
            if (string.IsNullOrEmpty(OrganisationIDFormat)) return new ErrorType(ErrorCode.InvalidHeader, "Data fejl i kort (OrganisationIDFormat mangler)");
            if (string.IsNullOrEmpty(OrganisationName)) return new ErrorType(ErrorCode.InvalidHeader, "Data fejl i kort (OrganisationName mangler )");

            if (IDCardType == CardType.user)
            {
                if (string.IsNullOrEmpty(CivilRegistrationNumber)) return new ErrorType(ErrorCode.InvalidHeader, "Data fejl i kort (CivilRegistrationNumber mangler)");
                if (string.IsNullOrEmpty(GivenName)) return new ErrorType(ErrorCode.InvalidHeader, "Data fejl i kort ( GivenName mangler)");
                if (string.IsNullOrEmpty(SurName)) return new ErrorType(ErrorCode.InvalidHeader, "Data fejl i kort ( SurName mangler)");
                if (string.IsNullOrEmpty(EmailAddress)) return new ErrorType(ErrorCode.InvalidHeader, "Data fejl i kort (EmailAddress mangler)");
                if (string.IsNullOrEmpty(Role)) return new ErrorType(ErrorCode.InvalidHeader, "Data fejl i kort ( Role mangler)");
                //if (string.IsNullOrEmpty( )) return "Data fejl i kort ( mangler)";
            }

            switch (AuthenticationLevel)
            {
                case 1: return null;
                case 2:
                    {
                        if (string.IsNullOrEmpty(Username)) return new ErrorType(ErrorCode.InvalidHeader, "Data fejl i kort ( Username mangler)");
                        if (string.IsNullOrEmpty(Password)) return new ErrorType(ErrorCode.InvalidHeader, "Data fejl i kort ( Password mangler)");
                        break;
                    }
                case 3:
                    {
                        if (!CheckCertificate) break;
                        if (Signature == null) return new ErrorType(ErrorCode.InvalidHeader, "Data fejl i kort ( Signature mangler)");
                        var cert = CertificateUtil.GetCertificate(Signature);
                        if (cert == null) return new ErrorType(ErrorCode.InvalidHeader, "Data fejl i kort ( Certifikat i signatur mangler)");
                        if (!CertificateUtil.IsVOCES(cert) && !CertificateUtil.IsMOCES(cert)) return new ErrorType(ErrorCode.InvalidHeader, "Data fejl i kort ( Certifikat i er ikke VOCES)");
                    }
                    break;

                default: return new ErrorType(ErrorCode.InvalidHeader, "Data fejl i kort ( AuthenticationLevel ligger ikke melle 1 og 4)");
            }
            return null;
        }


        public override ErrorType HandleIncommingResponse(XElement envelope, IDCardCheck CheckIDCard)
        {
            var b = base.HandleIncommingResponse(envelope, CheckIDCard);
            if (b != null) return b;
            RequestResponse.RemoveIds(envelope);
            return null;
        }

        public override ErrorType HandleIncommingRequest(XElement envelope, IDCardCheck CheckIDCard)
        {
            var b = base.HandleIncommingRequest(envelope, CheckIDCard);
            if (b != null) return b;
            RequestResponse.RemoveIds(envelope);
            return null;
        }

        public override ErrorType HandleOutgoingRequest(XElement envelope)
        {
            var r = base.HandleOutgoingRequest(envelope);
            if (r != null) return r;
            RequestResponse.SetIds(envelope);
            return null;
        }

        public override ErrorType HandleOutgoingResponse(XElement envelope)
        {
            var r = base.HandleOutgoingResponse(envelope);
            if (r != null) return r;
            RequestResponse.SetIds(envelope);
            return null;
        }


        public override ErrorType HandleOutgoingMedcomHeaderResponse(XElement envelope, MedcomHeaderReceiver GetMedcomHeader)
        {
            return null;
        }

        public override ErrorType HandleIncommingMedcomHeaderResponse(XElement envelope, MedcomHeaderCheck CheckMedcomHeader)
        {
            return null;
        }

        public override ErrorType HandleIncommingMedcomHeaderRequest(XElement envelope, MedcomHeaderCheck CheckMedcomHeader)
        {
            return null;
        }

        public override ErrorType HandleOutgoingMedcomHeaderRequest(XElement envelope, MedcomHeaderReceiver GetMedcomHeader)
        {
            return null;
        }

    }

    public enum MedcomTimeOut
    {
        min5,
        min30,
        min480,
        min1440,
        unbounded
    }

    public enum MedcomPriority
    {
        AKUT,
        HASTER,
        RUTINE
    }

    public enum MedcomFlowStatus
    {
        flow_running,
        flow_finalized_succesfully,
        syntax_error,
        missing_required_header,
        security_level_failed,
        invalid_username_password,
        invalid_signature,
        invalid_idcard,
        invalid_certificate,
        expired_idcard,
        not_authorized,
        illegal_http_method,
        processing_problem,
        signature_not_supported,
        nonrepudiation_not_supported,
    }

    public class MedcomHeaderType
    {
        public int SecurityLevel = 1;
        public MedcomTimeOut TimeOut = MedcomTimeOut.min1440;
        public string FlowID;
        public string MessageID;
        public MedcomPriority Priority = MedcomPriority.RUTINE;
        public MedcomFlowStatus FlowStatus = MedcomFlowStatus.flow_running;
        public bool? RequireNonRepudiationReceipt;

        public virtual XElement ToXml()
        {
            string Timeout = "unbound";
            switch (TimeOut)
            {
                case MedcomTimeOut.min5: Timeout = "5"; break;
                case MedcomTimeOut.min30: Timeout = "30"; break;
                case MedcomTimeOut.min480: Timeout = "480"; break;
                case MedcomTimeOut.min1440: Timeout = "1440"; break;
            }

            XElement xml = new XElement(NA.medcom + "Header",
                new XElement(NA.medcom + "SecurityLevel", SecurityLevel),
                new XElement(NA.medcom + "TimeOut", Timeout),
                new XElement(NA.medcom + "Linking",
                    new XElement(NA.medcom + "FlowID", FlowID),
                    new XElement(NA.medcom + "MessageID", MessageID)
                ),
                new XElement(NA.medcom + "FlowStatus", FlowStatus),
                new XElement(NA.medcom + "Priority", Priority),
                RequireNonRepudiationReceipt.HasValue
                    ? new XElement(NA.medcom + "RequireNonRepudiationReceipt", (RequireNonRepudiationReceipt.Value ? "yes" : "no"))
                    : null
            );
            return xml;
        }

        public static MedcomHeaderType Load(XElement Header)
        {
            var mht = new MedcomHeaderType();
            foreach (var e in Header.Descendants())
            {
                if (e.Name.Namespace != NA.medcom) throw new Exception("Fejl i Medcom header");
                switch (e.Name.LocalName)
                {
                    case "SecurityLevel": mht.SecurityLevel = int.Parse(e.Value); break;
                    case "TimeOut": mht.TimeOut = Api.MedcomTimeOutParse(e.Value.Trim()); break;
                    case "FlowID": mht.FlowID = e.Value; break;
                    case "MessageID": mht.MessageID = e.Value; break;
                    case "FlowStatus": mht.FlowStatus = Api.MedcomFlowStatusParse(e.Value.Trim()); break;
                    case "Priority": mht.Priority = Api.MedcomPriorityParse(e.Value.Trim()); break;
                    case "RequireNonRepudiationReceipt": mht.RequireNonRepudiationReceipt = e.Value == "yes"; break;
                }
            }
            return mht;
        }
    }

    public class SecurityType
    {
        DateTime created = DateTime.Now.MinSecUnivesial();
        public DateTime Created
        {
            get
            {
                return created;
            }
            set
            {
                created = value.MinSecUnivesial();
            }
        }

        public DGWSCard10Type Assertion;

        public XElement ToXml()
        {
            return new XElement(NA.wsse + "Security",
                            new XElement(NA.wsu + "Timestamp",
                                new XElement(NA.wsu + "Created", Created)
                            ),
                            Assertion != null ? XElement.Parse(Assertion.ToXml().ToString()) : null
                        );
        }
    }

    public class RequestSecurityTokenType
    {
        public string Issuer;
        public XElement Assertion;

        public XElement ToXml()
        {
            return new XElement(NA.wst + "RequestSecurityToken",
                new XAttribute("Context", "www.sosi.dk"),
                new XElement(NA.wst + "TokenType", "urn:oasis:names:tc:SAML:2.0:assertion"),
                new XElement(NA.wst + "RequestType", "http://schemas.xmlsoap.org/ws/2005/02/security/trust/Issue"),
                new XElement(NA.wst + "Claims", Assertion),
                new XElement(NA.wst + "Issuer",
                    new XElement(NA.wsa04 + "Address", Issuer)
                )
            );
        }
    }

    static class XElementEx
    {
        public static XElement Element(this XElement e, IEnumerable<XName> names)
        {
            if (e == null) return null;
			foreach (var n in names)
            {
                e = e.Element(n);
                if (e == null) return null;
            }
            return e;
        }

        public static IEnumerable<XElement> Elements(this XElement e, IEnumerable<XName> names)
        {
            if (e == null) return new XElement[0];
            foreach (var n in names)
            {
                e = e.Element(n);
                if (e == null) return new XElement[0];
            }
            return e.Elements();
        }

        public static long GetUTF8TextLength(this XElement e)
        {
            var sc = new StreamCounter();
            using (var w = new XmlTextWriter(sc, UTF8Encoding.UTF8)) e.Save(w);
            return sc.Count;
        }
    }

    public class IDP
    {
        public static XElement MakeSTSEnvelope(XElement RequestSecurityToken)
        {
            var sec = new SecurityType
            {
                Created = DateTime.Now.MinSecUnivesial()
            };

            return MakeEnvelope(sec.ToXml(), RequestSecurityToken);
        }

        public static XElement MakeEnvelope(XElement SecurityElement, XElement RequestSecurityToken)
        {
            return new XElement(NA.soap + "Envelope",
                            new XElement(NA.soap + "Header", SecurityElement),
                            new XElement(NA.soap + "Body", RequestSecurityToken)
                           );
        }



        public static SoapException MakeSoapException(XElement Envelope)
        {
            var a = Envelope.Element(new XName[] { NA.soap + "Body", NA.soap + "Fault" });
            if (a == null) return new SoapException();
            var e = a.Element("faultcode");
            var faultcode = e == null ? ":" : e.Value;
            e = a.Element("faultstring");
            var faultstring = e == null ? "" : e.Value;
            e = a.Element("faultactor");
            var faultactor = e == null ? "" : e.Value;

            var fa = faultcode.Split(':');
            var ns = fa[0];
            var nm = fa.Length > 1 ? fa[1] : "";

            return new SoapException(faultstring, new XmlQualifiedName(nm, ns), faultactor);
        }

        public static XElement CallIdp(DGWSCard10Type Ass, string issuer, string url)
        {
            var rr = new RequestSecurityTokenType
            {
                Assertion = Ass.ToXml(),
                Issuer = issuer
            };

            var card = IDP.CallIdp(IDP.MakeSTSEnvelope(rr.ToXml()), url);

            var a = card.Element(UsedPaths.BodyAssertion);
            if (a == null) throw MakeSoapException(card);

            //var c = CertificateUtil.validateSignature(a, "");
            //if (c == null) throw new Exception("fejl i signatur fra STS");
            return a;
        }

        public static XElement CallIdp(XElement request, string url)
        {
            return WebPost(request, url, "http://sosi.org/webservices/sts/1.0/stsService/RequestSecurityToken");
        }

		public static XElement WebPost(XElement request, string url, string action)
        {
			try
			{
				var wr = WebRequest.Create (url) as HttpWebRequest;
				wr.Method = "POST";
				wr.ContentType = "text/xml; charset=utf-8";
				wr.Headers.Add ("SOAPAction", action);
				wr.ContentLength = request.GetUTF8TextLength ();
				wr.Timeout = 6000;

				using (var w = new XmlTextWriter (wr.GetRequestStream (), Encoding.UTF8))
				{
					request.Save (w);

					//Console.WriteLine ("\n-");
					//Console.WriteLine("WebPost to " + url);
					//Console.WriteLine("-");
					//request.Save (Console.Out);
				}

				WebResponse response = wr.GetResponse ();

				XElement res;
				using (var rd = XmlReader.Create (response.GetResponseStream ()))
				{
					res = XElement.Load (rd);
				}

				//Console.WriteLine ("\n-");
				//Console.WriteLine("Response from " + url);
				//Console.WriteLine("-");
				//res.Save(Console.Out);

				return res;
			}
			catch (WebException ex)
            {
				if (ex.Response.GetResponseStream () != null)
				{
					var sr = new StreamReader (ex.Response.GetResponseStream ());
					var str = sr.ReadToEnd ();

					throw new SoapException (str, XmlQualifiedName.Empty);
				}

				Console.WriteLine (ex.Message);
				Console.WriteLine (ex.StackTrace);
            }

			return null;
        }
    }

    public enum ErrorCode
    {
        AuthenticationLevel,
        IdCardTooOld,
        IDCardType,
        InternalError,
        InvalidCertificate,
        InvalidHeader,
        InvalidInput,
        InvalidSignature,
        InvalidUserPass,
        MissingHeader,
        NotAuthorized,
        DuplicateMessageId
    }

    public class ErrorType
    {
        public ErrorCode Errorcode;
        public string Message;

        public ErrorType(ErrorCode Errorcode, string Message)
        {
            this.Errorcode = Errorcode;
            this.Message = Message;
        }
    }

    public class ParseException : Exception
    {
        public ParseException(string s)
            : base(s)
        { }
    }

    public static class Api
    {
        public static TimeSpan ToTimeSpan(CardLifeTimeType CardLifeTime)
        {
            switch (CardLifeTime)
            {
                case CardLifeTimeType.FiveMinutes: return new TimeSpan(0, 5, 0);
                case CardLifeTimeType.HalfHour: return new TimeSpan(0, 30, 0);
                case CardLifeTimeType.Hours8: return new TimeSpan(8, 0, 0);
                case CardLifeTimeType.Hours24: return new TimeSpan(24, 0, 0);
            }
            return new TimeSpan(0, 5, 0);
        }

        public static CardLifeTimeType ToCardLifeTimeType(TimeSpan ts)
        {
            if (ts.TotalMinutes <= 5) return CardLifeTimeType.FiveMinutes;
            if (ts.TotalMinutes <= 30) return CardLifeTimeType.HalfHour;
            if (ts.TotalMinutes <= 480) return CardLifeTimeType.Hours8;
            return CardLifeTimeType.Hours24;
        }

        public static DateTime MinSecUnivesial(this DateTime t)
        {
            var tt = new DateTime(t.Year, t.Month, t.Day, t.Hour, t.Minute, t.Second, t.Kind);
            return tt.Kind == DateTimeKind.Utc ? tt : tt.ToUniversalTime();
        }

        public static XAttribute MakeXAttribute(this DateTime t, string name)
        {
            return t.Kind == DateTimeKind.Utc ? new XAttribute(name, t) : new XAttribute(name, t.ToString("s"));
        }

        public static MedcomTimeOut MedcomTimeOutParse(string v)
        {
            switch (v.Trim())
            {
                case "5": return MedcomTimeOut.min5;
                case "30": return MedcomTimeOut.min30;
                case "480": return MedcomTimeOut.min480;
                case "1440": return MedcomTimeOut.min1440;
                case "unbounded": return MedcomTimeOut.unbounded;
            }
            throw new ParseException("MedcomTimeOut parse fejl");
        }

        public static MedcomFlowStatus MedcomFlowStatusParse(string v)
        {
            switch (v)
            {
                case "flow_running": return MedcomFlowStatus.flow_running;
                case "flow_finalized_succesfully": return MedcomFlowStatus.flow_finalized_succesfully;
                case "syntax_error": return MedcomFlowStatus.syntax_error;
                case "missing_required_header": return MedcomFlowStatus.missing_required_header;
                case "security_level_failed": return MedcomFlowStatus.security_level_failed;
                case "invalid_username_password": return MedcomFlowStatus.invalid_username_password;
                case "invalid_signature": return MedcomFlowStatus.invalid_signature;
                case "invalid_idcard": return MedcomFlowStatus.invalid_idcard;
                case "invalid_certificate": return MedcomFlowStatus.invalid_certificate;
                case "expired_idcard": return MedcomFlowStatus.expired_idcard;
                case "not_authorized": return MedcomFlowStatus.not_authorized;
                case "illegal_http_method": return MedcomFlowStatus.illegal_http_method;
                case "processing_problem": return MedcomFlowStatus.processing_problem;
                case "signature_not_supported": return MedcomFlowStatus.signature_not_supported;
                case "nonrepudiation_not_supported": return MedcomFlowStatus.nonrepudiation_not_supported;
            }
            throw new ParseException("MedcomFlowStatusParse parse fejl");
        }

        public static MedcomPriority MedcomPriorityParse(string v)
        {
            switch (v)
            {
                case "AKUT": return MedcomPriority.AKUT;
                case "HASTER": return MedcomPriority.HASTER;
                case "RUTINE": return MedcomPriority.RUTINE;
            }
            throw new ParseException("MedcomPriorityParse parse fejl");
        }
    }

    public class CertificateUtil
    {
        public static XElement AsXml(Signature s)
        {
            if (s == null) return null;
            using (var rd = new XmlNodeReader(s.GetXml()))
            {
                return XElement.Load(rd);
            }
        }

        public static XElement AsXml(Signature s, string id)
        {
            var x = AsXml(s);
            if (x == null) return null;
            x.Add(new XAttribute("Id", id));
            return x;
        }

        public static Signature CreateSignature(XElement e)
        {
            XmlDocument doc = new XmlDocument();
            using (var rd = e.CreateReader())
            {
                doc.Load(rd);
            }

            var s = new Signature();
            s.LoadXml(doc.DocumentElement);
            return s;
        }

        public static X509Certificate2 GetCertificate(Signature s)
        {
            foreach (KeyInfoX509Data kid in s.KeyInfo)
            {
                foreach (var cert in kid.Certificates)
                {
                    if (cert is X509Certificate2) return cert as X509Certificate2;
                }
            }
            return null;
        }

        public static Signature Sign(XElement envelope, X509Certificate2 Certificate)
        {
            return Sign(envelope, "#IDCard", Certificate);
        }

        public static Signature Sign(XElement e, string refname, X509Certificate2 Certificate)
        {
            var envelope = new XmlDocument();
            using (var rd = e.CreateReader()) envelope.Load(rd);
            SignedXml signedXml = new SignedXml(envelope);        
            signedXml.SigningKey = Certificate.PrivateKey;
            signedXml.SignedInfo.CanonicalizationMethod = "http://www.w3.org/2001/10/xml-exc-c14n#";

            Reference reference = new Reference();
            reference.Uri = refname;
			reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
			reference.AddTransform(new XmlDsigExcC14NTransform());
            signedXml.AddReference(reference);

            KeyInfo keyInfo = new KeyInfo();
			KeyInfoX509Data data = new KeyInfoX509Data(Certificate);
            keyInfo.AddClause(data);

            signedXml.KeyInfo = keyInfo;
            signedXml.ComputeSignature();

            return signedXml.Signature;
            //using (var nr = new XmlNodeReader(signedXml.GetXml())) return XElement.Load(nr);
        }

        public static string SSN(X509Certificate2 certificate)
        {
            Regex rx = new Regex(@"=\w{3}:[^,]+");
            Match m = rx.Match(certificate.Subject);
            if (string.IsNullOrEmpty(m.Value)) return "";
            return m.Value.Substring(1);
        }
        //SERIALNUMBER = PID:9208-2002-2-497532055832
        //SERIALNUMBER = CVR:28143605-RID:1144914074106
        //SERIALNUMBER = CVR:25444832-UID:1181822216987
        public static bool IsPOCES(X509Certificate2 certificate)
        {
            Regex rx = new Regex(@"=PID:\d{4}-\d{4}-\d-\d{12}");
            Match m = rx.Match(certificate.Subject);
            return !string.IsNullOrEmpty(m.Value);
        }

        public static bool IsMOCES(X509Certificate2 certificate)
        {
            Regex rx = new Regex(@"=CVR:\d{8}-RID:\d{13}");
            Match m = rx.Match(certificate.Subject);
            return !string.IsNullOrEmpty(m.Value);
        }

        public static bool IsVOCES(X509Certificate2 certificate)
        {
            Regex rx = new Regex(@"=CVR:\d{8}-UID:\d{13}");
            Match m = rx.Match(certificate.Subject);
            return !string.IsNullOrEmpty(m.Value);
        }

        public static bool Validate(X509Certificate2 certificate)
        {
            if (certificate == null) return false;
            if (DateTime.Now > certificate.NotAfter || DateTime.Now < certificate.NotBefore) return false;
			return true;
            //return certificate.IssuerName.Name.StartsWith("CN=TDC OCES");
        }

        public static bool IsAccepted(X509Certificate2 certificate, IEnumerable<string> AcceptedCertificates)
        {
            if (!Validate(certificate)) return false;
            string ssn = SSN(certificate);
            if (string.IsNullOrEmpty(ssn)) return false;
            if (AcceptedCertificates == null) return false;

            foreach (string s in AcceptedCertificates)
            {
                if (s == "*") return true;
                if (s == ssn) return true;
            }
            return false;
        }

        public static X509Certificate2 GetCertificate(string CertificatePointer, string password)
        {
            if (string.IsNullOrEmpty(CertificatePointer)) return null;
            Uri filuri = new Uri(CertificatePointer, UriKind.RelativeOrAbsolute);

            if (!filuri.IsAbsoluteUri)
            {
                CertificatePointer = Path.Combine((AppDomain.CurrentDomain.RelativeSearchPath ?? AppDomain.CurrentDomain.BaseDirectory), CertificatePointer);
            }

            if (!string.IsNullOrEmpty(password))
            {
                return new X509Certificate2(CertificatePointer, password);
            }
            return new X509Certificate2(CertificatePointer);
        }

        public static X509Certificate2 validateSignature(XElement envl)
        {
            string KeyName = (from a in envl.Descendants(NA.ds + "KeyName") select a.Value).FirstOrDefault();
            if (KeyName == null) return null;
            return validateSignature(envl, KeyName);
        }

        public static X509Certificate2 validateSignature(XElement envl, string id)
        {
            try
            {
                var d = new XmlDocument();
                using (var rd = envl.CreateReader())
                {
                    d.Load(rd);
                }

                XmlElement xmlsignature = FindSignature(d.DocumentElement, id);
                if (xmlsignature == null) return null;
                xmlsignature.ParentNode.RemoveChild(xmlsignature);

                SignedXml signedXml = new SignedXml(d);
                signedXml.LoadXml(xmlsignature);
                X509Certificate2 certificate = GetCertificate(signedXml.KeyInfo);
                // Check the signature and return the result.
                if (!signedXml.CheckSignature(certificate, true)) return null;
                return certificate;
            }
            catch (Exception)
            {
            }
            return null;
        }

        static XmlElement FindSignature(XmlElement e, string id)
        {
            XmlElement secelm = null;
            foreach (XmlElement elm in e.GetElementsByTagName("Signature", NA.ds.NamespaceName))
            {
                secelm = elm;
                var a = elm.Attributes["Id"] ?? elm.Attributes["id"];
                if (a != null && a.Value == id)
                {
                    return elm;
                }
            }
            return secelm;
        }


        public static X509Certificate2 GetCertificate(KeyInfo ki)
        {
            foreach (KeyInfoX509Data d in ki)
            {
                X509Certificate2 cer = d.Certificates[0] as X509Certificate2;
                if (cer != null) return cer;
            }
            return null;
        }
    }

    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("wsdl", "2.0.50727.3038")]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Web.Services.WebServiceBindingAttribute(Name = "SosiGWSoapBinding", Namespace = "http://sosi.dk/gw/2007.09.01")]
    public partial class SosiGWFacadeService : Microsoft.Web.Services3.WebServicesClientProtocol
    {
        public SosiGWFacadeService()
        {
            this.Url = "http://localhost:8080/sosigw/service/sosigw";
        }

        [System.Web.Services.Protocols.SoapDocumentMethodAttribute("http://sosi.dk/gw/2007.09.01#requestIdCardDigestForSigning", Use = System.Web.Services.Description.SoapBindingUse.Literal, ParameterStyle = System.Web.Services.Protocols.SoapParameterStyle.Bare)]
        [return: System.Xml.Serialization.XmlElementAttribute("requestIdCardDigestForSigningResponse", Namespace = "http://sosi.dk/gw/2007.09.01")]
        public requestIdCardDigestForSigningResponse requestIdCardDigestForSigning([System.Xml.Serialization.XmlElementAttribute(Namespace = "http://sosi.dk/gw/2007.09.01")] string requestIdCardDigestForSigningRequestBody)
        {
            object[] results = this.Invoke("requestIdCardDigestForSigning", new object[] {
                    requestIdCardDigestForSigningRequestBody});
            return ((requestIdCardDigestForSigningResponse)(results[0]));
        }

        [System.Web.Services.Protocols.SoapDocumentMethodAttribute("http://sosi.dk/gw/2007.09.01#logout", OneWay = true, Use = System.Web.Services.Description.SoapBindingUse.Literal, ParameterStyle = System.Web.Services.Protocols.SoapParameterStyle.Bare)]
        public void logout([System.Xml.Serialization.XmlElementAttribute(Namespace = "http://sosi.dk/gw/2007.09.01")] string logoutRequestBody)
        {
            this.Invoke("logout", new object[] {
                    logoutRequestBody});
        }
    }

    [System.CodeDom.Compiler.GeneratedCodeAttribute("wsdl", "2.0.50727.3038")]
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(AnonymousType = true, Namespace = "http://sosi.dk/gw/2007.09.01")]
    public partial class requestIdCardDigestForSigningResponse
    {
        private byte[] digestValueField;
        private string browserUrlField;

        [System.Xml.Serialization.XmlElementAttribute(Namespace = "http://www.w3.org/2000/09/xmldsig#", DataType = "base64Binary")]
        public byte[] DigestValue
        {
            get
            {
                return this.digestValueField;
            }
            set
            {
                this.digestValueField = value;
            }
        }

        [System.Xml.Serialization.XmlElementAttribute(DataType = "anyURI")]
        public string BrowserUrl
        {
            get
            {
                return this.browserUrlField;
            }
            set
            {
                this.browserUrlField = value;
            }
        }
    }


    public class SOSIGW
    {
        public static Uri GetSosiUrl(DGWSCard10Type card, Uri SOSIGWUrl, IDCardReceiver idcr, IDCardCheck idcc)
        {
            var p = new Policy(new PolicyAssertion[]
                    { 
                        new SDSD.SealApi.Assertion.DGWSAssertion
                        {
                            CheckIDCard = idcc,
                            GetIDCard = idcr
                        }
                    });

            var ws = new SosiGWFacadeService();
            ws.SetPolicy(p);
            if (SOSIGWUrl != null)
            {
                ws.Url = SOSIGWUrl.AbsoluteUri;
            }
            var s = ws.requestIdCardDigestForSigning("");
            return new Uri(s.BrowserUrl);
        }

        public static Uri GetSosiUrl(DGWSCard10Type card, Uri SOSIGWUrl)
        {
            return GetSosiUrl(card, SOSIGWUrl, (v) => card, (s, e) => null);
        }

        public static Uri GetSosiUrl(DGWSCard10Type card)
        {
            return GetSosiUrl(card, null);
        }
    }


    class StreamCounter : Stream
    {
        public long Count = 0;

        public override bool CanRead { get { return false; } }
        public override bool CanSeek { get { return false; } }
        public override bool CanWrite { get { return true; } }
        public override long Length { get { return Count; } }
        public override long Position { get { return Count; } set { } }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) { return 0; }
        public override long Seek(long offset, SeekOrigin origin) { return 0; }
        public override void SetLength(long value) { }
        public override void Write(byte[] buffer, int offset, int count)
        {
            Count += count;
        }
        public override void WriteByte(byte value)
        {
            Count++;
        }
    }
}
