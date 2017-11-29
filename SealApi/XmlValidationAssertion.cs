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
using System.Security.Cryptography.X509Certificates;
using Microsoft.Web.Services3.Design;
using Microsoft.Web.Services3;
using System.Xml;
using System.Xml.Schema;
using System.Web.Services.Description;
using System.Web.Services.Protocols;
using System.IO;

namespace SDSD.SealApi.Assertion
{
    /// <summary>
    /// Kontrollerer om body af et soap request/response overholderer skmaer tilhørende en wsdl
    /// Filtrene sættes afhængig af hvad der skal kontrolleres. 
    /// F.eks: ClientInputFilter = new ValidatorFilter(), hvis en klient ønsker at kontrollere request SOAP
    /// </summary>
    public class SoapBodyVailidator : PolicyAssertion
    {
        /// <summary>
        /// Kontrollerer soap response til en klient, hvis null, udføres ingen kontrol
        /// </summary>
        public SoapFilter ClientInputFilter = null;
        /// <summary>
        /// Kontrollerer soap request ud af en klient, hvis null, udføres ingen kontrol
        /// </summary>
        public SoapFilter ClientOutputFilter = null;
        /// <summary>
        /// Kontrollerer soap request fra en klient, hvis null, udføres ingen kontrol
        /// </summary>
        public SoapFilter ServiceInputFilter = null;
        /// <summary>
        /// Kontrollerer soap responset ud af en service, hvis null, udføres ingen kontrol
        /// </summary>
        public SoapFilter ServiceOutputFilter = null;

        /// <summary>
        /// Aktiverer ClientInputFilter
        /// </summary>
        /// <param name="context"></param>
        /// <returns>ClientInputFilter</returns>
        public override SoapFilter CreateClientInputFilter(FilterCreationContext context)
        {
            return ClientInputFilter;
        }
        /// <summary>
        /// Aktiverer ClientOutputFilter
        /// </summary>
        /// <param name="context"></param>
        /// <returns>ClientOutputFilter</returns>
        public override SoapFilter CreateClientOutputFilter(FilterCreationContext context)
        {
            return ClientOutputFilter;
        }
        /// <summary>
        /// AKtiverer
        /// </summary>
        /// <param name="context"></param>
        /// <returns>ServiceInputFilter</returns>
        public override SoapFilter CreateServiceInputFilter(FilterCreationContext context)
        {
            return ServiceInputFilter;
        }
        /// <summary>
        /// Aktiverer ServiceOutputFilter
        /// </summary>
        /// <param name="context"></param>
        /// <returns>ServiceOutputFilter</returns>
        public override SoapFilter CreateServiceOutputFilter(FilterCreationContext context)
        {
            return ServiceOutputFilter;
        }
    }
    /// <summary>
    /// Kontrollerer body af SoapEnvelope, mod XmlSkemaerne i loaded ind i Schemas.
    /// Hvis ikke Schemas er initieret manuelt, hentes den tilhørende Wsdl udpeget af Wsdlfile,
    /// første gang skemavalidering skal aktiveres.
    /// </summary>
    public class ValidatorFilter : SoapFilter
    {
        XmlSchemaSet _Schemas;
        /// <summary>
        /// Skemaer til validering af body i SoapEnvelope
        /// </summary>
        public XmlSchemaSet Schemas
        {
            get
            {
                if (_Schemas != null) return _Schemas;
                if (!string.IsNullOrEmpty(Wsdlfile))
                {
                    using (var rd = XmlReader.Create(Wsdlfile))
                    {
                        _Schemas = ReadSchemasFromWsdl(ServiceDescription.Read(rd));
                    }
                }
                else if (Wsdl != null)
                {
                    _Schemas = ReadSchemasFromWsdl(ServiceDescription.Read(Wsdl));
                }

                return _Schemas;
            }

            set
            {
                _Schemas = value;
            }
        }

        /// <summary>
        /// Hvis Schemas ikke er aktiveret manuelt, så hentes den tilhørende Wsdl udpeget af Wsdlfile,
        /// første gang skemavalidering skal aktiveres.  
        /// </summary>
        public string Wsdlfile;
        public TextReader Wsdl;

        /// <summary>
        /// Udtrækker alle skemaer fra en wsdl-fil.
        /// </summary>
        /// <param name="wsdlfilename">En uri som udpeger en wsdlfil </param>
        /// <returns></returns>
        
        public XmlSchemaSet ReadSchemasFromWsdl(ServiceDescription sd)
        {
            var schemas = new XmlSchemaSet();
            foreach (XmlSchema s in sd.Types.Schemas)
            {
                schemas.Add(s);
            }
            schemas.ValidationEventHandler += (o, e) => { throw e.Exception; };
            schemas.Compile();
            return schemas;
        }

        /// <summary>
        /// Validerer Xml i rd, mode XmlSkemaerne i Schemas.
        /// Hvis ingen fejl returneres en tom streng, ellers en fejlbesked
        /// </summary>
        /// <param name="Schemas">XmlSkemaerne som skal kontrolleres mod rd</param>
        /// <param name="rd">Xml</param>
        /// <returns>Hvis ingen fejl en tom streng, ellers en fejlbesked</returns>
        public string Scan(XmlSchemaSet Schemas, XmlReader rd)
        {
            string errormessage = string.Empty;
            bool error = false;

            XmlReaderSettings validatorsettings = new XmlReaderSettings();
            validatorsettings.Schemas = Schemas;
            validatorsettings.ValidationType = ValidationType.Schema;
            validatorsettings.ValidationEventHandler += (o, e) =>
            {
                errormessage += e.Message;
                error = true;
            };

            XmlReader data = XmlReader.Create(rd, validatorsettings);
            while (data.Read() && !error) ;
            return errormessage;
        }

        /// <summary>
        /// Udfører skemavalidereing.
        /// </summary>
        /// <param name="envelope">Xml</param>
        /// <returns>SoapFilterResult.Continue hvis ok ellers andet SoapFilterResult indeholdende en fejlbesked</returns>
        public override SoapFilterResult ProcessMessage(SoapEnvelope envelope)
        {
            using (var nr = new XmlNodeReader(envelope.Body.FirstChild))
            {
                string errormessage = Scan(Schemas, nr);
                if (!string.IsNullOrEmpty(errormessage))
                {
                    return errorhandler.makeServiceError(new ErrorType(ErrorCode.InvalidInput, errormessage));
                }
            }
            return SoapFilterResult.Continue;
        }
    }

    public class ValidatorFilterException : ValidatorFilter
    {
        public override SoapFilterResult ProcessMessage(SoapEnvelope envelope)
        {
            using (var nr = new XmlNodeReader(envelope.Body.FirstChild))
            {
                string errormessage = Scan(Schemas, nr);
                if (!string.IsNullOrEmpty(errormessage))
                {
                    throw new Exception(errormessage);
                }
            }
            return SoapFilterResult.Continue;
        }
    }
}
