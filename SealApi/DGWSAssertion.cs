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
using System.Xml.Linq;
using Microsoft.Web.Services3.Design;
using Microsoft.Web.Services3;
using System.Web.Services.Protocols;
using System.Xml;
using SDSD.SealApi;
using System.Security.Cryptography.Xml;
using System.Security.Cryptography.X509Certificates;

namespace SDSD.SealApi.Assertion
{
    public delegate SoapFilterResult ProcessEnvelopeDelegate(XElement envelope);

    public class DGWSAssertion : PolicyAssertion
    {
        public IDCardReceiver GetIDCard = (v) => null;
        public IDCardCheck CheckIDCard = (c,e) => null;

        public MedcomHeaderReceiver GetMedcomHeader = () => new MedcomHeaderType
        {
            SecurityLevel = 3,
            FlowID = "AMRRMD",
            MessageID = Guid.NewGuid().ToString("N"),
            RequireNonRepudiationReceipt = false
        };

        public MedcomHeaderCheck CheckMedcomHeader = (m) => null;

		public override SoapFilter CreateClientInputFilter(FilterCreationContext context)
        {
            return new DelegateFilter
            {
                ProcessEnvelope = (envelope) =>
                {
                    ErrorType err = null;
                    var AssertionTag = envelope.Element(UsedPaths.HeaderAssertion);
                    if (AssertionTag == null)
                    {
                        err = CheckIDCard(null, envelope);
                    }
                    else
                    {
                        var serviceCard = CardFactory.Load(AssertionTag);
                        err = serviceCard.HandleIncommingResponse(envelope, CheckIDCard);
                        AssertionTag.Parent.Remove();
                        if (err != null) throw new Exception(err.Message);
                        err = serviceCard.HandleIncommingMedcomHeaderResponse(envelope, CheckMedcomHeader);
                    }

                    if (err != null) throw new Exception(err.Message);
                    return SoapFilterResult.Continue;
                }
            };
        }

        public override SoapFilter CreateClientOutputFilter(FilterCreationContext context)
        {
            return new DelegateFilter
            {
                ProcessEnvelope = (envelope) =>
                {
                    var card = GetIDCard(null);
                    var err = card.HandleOutgoingRequest(envelope);
                    if (err != null) return errorhandler.makeClientError(err);
                    err = card.HandleOutgoingMedcomHeaderRequest(envelope, GetMedcomHeader);
                    if (err != null) return errorhandler.makeClientError(err);
                    return SoapFilterResult.Continue;
                }
            };
        }

        public override SoapFilter CreateServiceInputFilter(FilterCreationContext context)
        {
            return new DelegateFilter
            {
                ProcessEnvelope = (envelope) =>
                {
                    try
                    {
                        var hd = envelope.Element(NA.soap + "Header");
                        if (hd == null) return errorhandler.makeServiceError(new ErrorType(ErrorCode.MissingHeader, "Soap header mangler"));

                        var AssertionTag = envelope.Element(UsedPaths.HeaderAssertion); 
                        if (AssertionTag == null) return errorhandler.makeServiceError( new ErrorType(ErrorCode.InvalidHeader, "Assertion tag mangler"));

                        var card = CardFactory.Load(AssertionTag);
                        var msg = card.HandleIncommingRequest(envelope, CheckIDCard);
                        AssertionTag.Parent.Remove();
                        if (msg != null) return errorhandler.makeServiceError(msg);

                        msg = card.HandleIncommingMedcomHeaderRequest(envelope, CheckMedcomHeader);
                        if (msg != null) return errorhandler.makeServiceError(msg);
                    }
                    catch (Exception ex)
                    {
                        return errorhandler.makeServiceError(new ErrorType(ErrorCode.InternalError, "DGWSAssertionServiceInFilter " + ex.Message));
                    }

                    return SoapFilterResult.Continue;
                }
            };
        }

        public override SoapFilter CreateServiceOutputFilter(FilterCreationContext context)
        {
            return new DelegateFilter
            {
                ProcessEnvelope = (envelope) =>
                {
                    var fault = envelope.Element(NA.soap + "Body").Element(NA.soap + "Fault"); ;                    
                    if (fault != null)
                    {
                        RequestResponse.DGWSServiceResponseFaultHandle11(fault, SericeUtil.ServiceSessionData.error);
                        SericeUtil.ServiceSessionData.error = null;
                    }

                    var clientCard = SericeUtil.ServiceSessionData.Card;
                    if (clientCard == null) return SoapFilterResult.Continue;
                    var serviceCard = GetIDCard(clientCard.IDCardVersion);
                    if (serviceCard != null)
                    {
                        serviceCard.HandleOutgoingResponse(envelope);
                        serviceCard.HandleOutgoingMedcomHeaderResponse(envelope, GetMedcomHeader);
                    }
                    return SoapFilterResult.Continue;
                }
            };
        }
    }

    public class AddressingConverterAssertion : PolicyAssertion
    {
        DelegateFilter old2new = new DelegateFilter
        {
            ProcessEnvelope = (envelope) =>
            {
                if (SericeUtil.versionsnummer(envelope) != "1.1") return SoapFilterResult.Continue;
                
                var hd = envelope.Element(NA.soap + "Header");

                var q = (from a in envelope.Attributes()
                         where a.Value == NA.wsa04.NamespaceName && a.Name.Namespace == XNamespace.Xmlns
                         select a).Concat(
                        from e in hd.Descendants()
                        from a in e.Attributes()
                        where a.Value == NA.wsa04.NamespaceName
                        select a);

                foreach (var a in q)
                {
                    a.Value = NA.wsa.NamespaceName;
                }

                var q2 = from e in hd.Descendants()
                         where e.Name.Namespace == NA.wsa04
                         select e;

                foreach (var e in q2)
                {
                    e.Name = NA.wsa + e.Name.LocalName;
                    if (e.Name.LocalName == "Address")
                    {
                        e.Value = "http://www.w3.org/2005/08/addressing/anonymous";
                    }
                }
                return SoapFilterResult.Continue;
            }
        };

        DelegateFilter new2old = new DelegateFilter
        {
            ProcessEnvelope = (envelope) =>
            {
                if (SericeUtil.versionsnummer(envelope) != "1.1") return SoapFilterResult.Continue;

                var hd = envelope.Element(NA.soap + "Header");

                var q = (from a in envelope.Attributes()
                         where a.Value == NA.wsa.NamespaceName && a.Name.Namespace == XNamespace.Xmlns
                         select a).Concat(
                        from e in hd.Descendants()
                        from a in e.Attributes()
                        where a.Value == NA.wsa.NamespaceName
                        select a);

                foreach (var a in q)
                {
                    a.Value = NA.wsa04.NamespaceName;
                }

                var q2 = from e in hd.Descendants()
                         where e.Name.Namespace == NA.wsa
                         select e;

                foreach (var e in q2)
                {
                    e.Name = NA.wsa04 + e.Name.LocalName;
                    if (e.Name.LocalName == "RelatesTo")
                    {
                        var a = e.Attribute("RelationShip");
                        if (a != null) a.Remove();
                    }
                }

                return SoapFilterResult.Continue;
            }
        };
        
        public override SoapFilter CreateClientInputFilter(FilterCreationContext context)
        {
            return new2old;
        }

        public override SoapFilter CreateClientOutputFilter(FilterCreationContext context)
        {
            return old2new;
        }

        public override SoapFilter CreateServiceInputFilter(FilterCreationContext context)
        {
            return new2old;
        }

        public override SoapFilter CreateServiceOutputFilter(FilterCreationContext context)
        {
            return old2new;
        }
    }

    public class DelegateFilter : SoapFilter
    {
        [System.Diagnostics.DebuggerStepThroughAttribute()]
        public override SoapFilterResult ProcessMessage(SoapEnvelope envelope)
        {
            var env = XElement.Load(envelope.GetDocumentReader());

            var r = ProcessEnvelope(env);
            using (var rd = env.CreateReader())
            {
                envelope.Load(rd);
            }
            return r;
        }

        public ProcessEnvelopeDelegate ProcessEnvelope = (e) =>
        {
            return SoapFilterResult.Continue;
        };
    }

    class DGWSSessionData
    {
        public DGWSCard10Type Card;
        public MedcomHeaderType MedcomHeader;
        public ErrorType error;
    }

    class SericeUtil
    {
        public static string versionsnummer(SoapEnvelope envelope)
        {
            try
            {
                var q1 = from e in envelope.DocumentElement.Elements(UsedPaths.AttributeStatementPath)
                         from a in e.Attributes("Name")
                         where a.Value.EndsWith(":IDCardVersion") 
                         select e.Element("AttributeValue", NA.saml.NamespaceName);

                var atv = q1.FirstOrDefault();
                if (atv == null) return "";
                return atv.InnerText;
            }
            catch
            { }
            return "";
        }

        public static string versionsnummer(XElement envelope)
        {
            try
            {
                var q1 = from e in envelope.Elements(UsedPaths.AttributeStatementPath)
                         from a in e.Attributes("Name")
                         where a.Value.EndsWith (":IDCardVersion") 
                         select e.Element(NA.saml+"AttributeValue" );

                var atv = q1.FirstOrDefault();
                if (atv == null) return "";
                return atv.Value;
            }
            catch
            { }
            return "";
        }

        
        static StateManager clientSessionState;
        static StateManager ClientSessionState
        {
            get
            {
                if (SoapContext.Current != null) return SoapContext.Current.SessionState;
                if (clientSessionState == null)
                {
                    clientSessionState = new StateManager();
                }
                return clientSessionState;
            }

            set
            {
                clientSessionState = value;
            }
        }

        static StateManager serviceSessionState;
        static StateManager ServiceSessionState
        {
            get
            {
                if (SoapContext.Current != null) return SoapContext.Current.SessionState;
                if (serviceSessionState == null)
                {
                    serviceSessionState = new StateManager();
                }
                return serviceSessionState;
            }

            set
            {
                serviceSessionState = value;
            }
        }

        public static DGWSSessionData ServiceSessionData
        {
            get
            {
                var ses = ServiceSessionState.Get<DGWSSessionData>();
                if (ses != null) return ses;
                ses = new DGWSSessionData();
                ServiceSessionState.Set(ses);
                return ses;
            }
        }

        public static DGWSSessionData ClientSessionData
        {
            get
            {
                var ses = ClientSessionState.Get<DGWSSessionData>();
                if (ses != null) return ses;
                ses = new DGWSSessionData();
                ClientSessionState.Set(ses);
                return ses;
            }
        }
    }

    public class errorhandler
    {
        static errorhandler ers = new errorhandler();
        static Type s = typeof(errorhandler);
        static SoapServerMethod method1 = new SoapServerMethod(s, new LogicalMethodInfo(s.GetMethod("error")));

        static public SoapFilterResult makeClientError(ErrorType error)
        {
            throw new SoapException(error.Message, new XmlQualifiedName("dgws", error.Errorcode.ToString()));
        }

        static public SoapFilterResult makeServiceError(ErrorType error)
        {
            if (SericeUtil.ServiceSessionData.error == null)
            {
                SericeUtil.ServiceSessionData.error = error;
            }
            return new SoapFilterResult(method1);
        }

        public static void Invoke(SoapFilterResult sfr)
        {
            sfr.TargetMethod.MethodInfo.Invoke(ers, null);
        }

        public void error()
        {
            throw new Exception("");
        }
    }

    static class XmlNodeExt
    {
        public static IEnumerable<XmlAttribute> Attributes(this XmlElement xe)
        {
            foreach (var a in xe.Attributes)
            {
                if (a is XmlAttribute) yield return a as XmlAttribute;
            }
        }

        public static IEnumerable<XmlAttribute> Attributes(this XmlElement xe, string localName)
        {
            return from a in xe.Attributes()
                   where a.LocalName == localName
                   select a;
        }
        
        public static IEnumerable<XmlElement> Elements(this XmlElement xe)
        {
            foreach (var n in xe.ChildNodes)
            {
                if (n is XmlElement) yield return n as XmlElement;
            }
        }

        public static IEnumerable<XmlElement> Elements(this XmlElement xe, string localName, string Namepace)
        {
            return from e in xe.Elements()
                   where e.LocalName == localName && e.NamespaceURI == Namepace
                   select e;
        }

        public static XmlElement Element(this XmlElement xe, string localName, string Namepace)
        {
            return (from e in xe.Elements()
                    where e.LocalName == localName && e.NamespaceURI == Namepace
                    select e).FirstOrDefault();
        }

        public static IEnumerable< XmlElement> Elements(this XmlElement e, IEnumerable<XName> names)
        {
            if (e == null) return new XmlElement[]{};
            foreach (var n in names)
            {
                e = e.Element(n.LocalName,n.NamespaceName);
                if (e == null) return new XmlElement[] { };
            }
            return e.Elements();
        }
    }
}
