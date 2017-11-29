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
using System.Reflection;
using System.Collections.Generic;
using System.Text;
using Microsoft.Web.Services3;
using Microsoft.Web.Services3.Design;
using Microsoft.Web.Services3.Addressing;
using System.Xml;
using System.Xml.Serialization;
using Medcom;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Security.Cryptography.X509Certificates;

namespace SDSD.SealApi.Assertion
{
    //using ErrorHandler;
    public delegate bool CheckCertificate(X509Certificate2 certificate);

    public class MessageSignAssertion : PolicyAssertion
    {
        public X509Certificate2 certificate;
        public string[] acceptedcartificates;
        public CheckCertificate CertificateChecker;
        public bool ServiceAcceptOtherThan11 = true;

        public MessageSignAssertion()
        {
            CertificateChecker = CheckCertificate;
        }

        public MessageSignAssertion(string CertificatePointer, string Password, string[] acceptedcartificates)
        {
            this.acceptedcartificates = acceptedcartificates;
            certificate = new X509Certificate2(CertificatePointer, Password);
        }

        bool CheckCertificate(X509Certificate2 certificate)
        {
            if (certificate == null) return false;
            if (acceptedcartificates == null) return false;
            return CertificateUtil.IsAccepted(certificate, acceptedcartificates);
        }

        public override SoapFilter CreateClientInputFilter(FilterCreationContext context)
        {
            return new MessageSignClientInFilter(CertificateChecker);
        }

        public override SoapFilter CreateClientOutputFilter(FilterCreationContext context)
        {
            return new MessageSignClientOutFilter(certificate);
        }

        public override SoapFilter CreateServiceInputFilter(FilterCreationContext context)
        {
            return new MessageSignServiceInFilter(CertificateChecker, ServiceAcceptOtherThan11);
        }

        public override SoapFilter CreateServiceOutputFilter(FilterCreationContext context)
        {
            return new MessageSignServiceOutFilter(certificate);
        }
        /*
        public override IEnumerable<KeyValuePair<string, Type>> GetExtensions()
        {
            return new KeyValuePair<string, Type>[] { new KeyValuePair<string, Type>("DGWS", typeof(DGWSAssertion)) };
        }

        public override void ReadXml(XmlReader xreader, IDictionary<string, Type> extensions)
        {
            var Msa = XmlConvertering<global::DgwsWse.HeaderTypes.MessageSignAssertion>.Deserialize(xreader);

            if (string.IsNullOrEmpty( Msa.CertificatePointer )) return;
            if (string.IsNullOrEmpty( Msa.Password )) return;

            certificate = CertificateUtil.GetCertificate(Msa.CertificatePointer, Msa.Password);

            acceptedcartificates = Msa.AcceptedCertificates;
        }
        */
    }

    class MessageSignClientOutFilter : SoapFilter
    {
        static string[] reqrefs = { "#wsamessageid", "#wsareplyto", "#wsato", "#wsaaction", "#body", "#IDCard" };
        X509Certificate2 cert;

        public MessageSignClientOutFilter(X509Certificate2 cert)
        {
            this.cert = cert;
        }

        public override SoapFilterResult ProcessMessage(SoapEnvelope envelope)
        {
            try
            {
                if (cert != null)
                {
                    Signering.Sign(envelope.DocumentElement, reqrefs, "Security", NamespaceAlias.wsse, "MessageSignature", cert);
                }
                return SoapFilterResult.Continue;
            }
            catch
            { }
            return errorhandler.makeClientError( new ErrorType(ErrorCode.InternalError,  ""));
        }
    }

    class MessageSignClientInFilter : SoapFilter
    {
        CheckCertificate cf;

        public MessageSignClientInFilter(CheckCertificate cf)
        {
            this.cf = cf;
        }
        
        public override SoapFilterResult ProcessMessage(SoapEnvelope envelope)
        {
            var certificate = Signering.validateSignature(envelope.DocumentElement, "MessageSignature", "", NamespaceAlias.wsse, true);
            HashValues hv = Signering.GetHashValues(envelope);

            if (hv.IsSingleSignOn)
            {
                if (certificate.GetCertHashString() == hv.ClientVOCESHash) return SoapFilterResult.Continue;
            }
            else
            {
                if (CertificateUtil.Validate(certificate))
                {
                    if (cf(certificate)) return SoapFilterResult.Continue;
                }
                throw new Exception("certifikat ikke accepteret");
            }
            return SoapFilterResult.Terminate;
        }
    }

    class MessageSignServiceOutFilter : SoapFilter
    {
        static string[] resrefs = { "#wsamessageid", "#wsarelatesto", "#wsato", "#wsaaction", "#body", "#IDCard" };

        X509Certificate2 cert;

        public MessageSignServiceOutFilter(X509Certificate2 cert)
        {
            this.cert = cert;
        }
        
        public override SoapFilterResult ProcessMessage(SoapEnvelope envelope)
        {
            if (SericeUtil.versionsnummer(envelope) == "1.1")
            {
                if (cert != null)
                {
                    Signering.Sign(envelope.DocumentElement, resrefs, "Security", NamespaceAlias.wsse, "MessageSignature", cert);
                }
            }
            return SoapFilterResult.Continue;
        }
    }

    class MessageSignServiceInFilter : SoapFilter
    {
        CheckCertificate cf;
        bool ServiceAcceptOtherThan11 = true;
        public MessageSignServiceInFilter(CheckCertificate cf, bool ServiceAcceptOtherThan11 )
        {
            this.cf = cf;
            this.ServiceAcceptOtherThan11 = ServiceAcceptOtherThan11;
        }
        
        public override SoapFilterResult ProcessMessage(SoapEnvelope envelope)
        {
            try
            {
                if (SericeUtil.versionsnummer(envelope) != "1.1" && ServiceAcceptOtherThan11 ) return SoapFilterResult.Continue;

                var certificate = Signering.validateSignature(envelope.DocumentElement, "MessageSignature", "", NamespaceAlias.wsse, true);
                if (certificate == null)
                {
                    return errorhandler.makeServiceError(new ErrorType(ErrorCode.InvalidInput, "Fejl i MessageSignature"));
                }

                HashValues hv = Signering.GetHashValues(envelope);

                if (hv.IsSingleSignOn)
                {
                    if (certificate.GetCertHashString() == hv.ClientVOCESHash) return SoapFilterResult.Continue;
                }
                else
                {
                    if (cf(certificate)) return SoapFilterResult.Continue;
                }
                return errorhandler.makeServiceError(new ErrorType(ErrorCode.NotAuthorized, "MessageSignature ikke accepteret"));
            }
            catch (Exception ex)
            {
                return errorhandler.makeServiceError(new ErrorType(ErrorCode.InternalError, "MessageSignServiceInFilter "+ex.Message));
            }
        }
    }
}