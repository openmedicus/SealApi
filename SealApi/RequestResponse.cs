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
using System.Xml;

namespace SDSD.SealApi
{
    public delegate DGWSCard10Type IDCardReceiver(string version);
    public delegate ErrorType IDCardCheck(DGWSCard10Type a, XElement envelope);
    public delegate ErrorType MedcomHeaderCheck(MedcomHeaderType m);
    public delegate MedcomHeaderType MedcomHeaderReceiver();

    public class RequestResponse
    {
        static Dictionary<XName, string> ids = new Dictionary<XName, string>
        {
            { NA.wsa04+"MessageID", "wsamessageid" },
            { NA.wsa04+"Action", "wsaaction" },
            { NA.wsa04+"To", "wsato" },
            { NA.wsa04+"RelatesTo", "wsarelatesto" },
            { NA.wsa04+"ReplyTo", "wsareplyto" },
            { NA.wsa+"MessageID", "wsamessageid" },
            { NA.wsa+"Action", "wsaaction" },
            { NA.wsa+"To", "wsato" },
            { NA.wsa+"RelatesTo", "wsarelatesto" },
            { NA.wsa+"ReplyTo", "wsareplyto" },
            { NA.soap+"Body", "body" }
        };

        public static void SetIds(XElement envelope)
        {
            var hd = envelope.Element(NA.soap + "Header");

            var q = from e in hd.Elements().Concat(envelope.Elements(NA.soap + "Body"))
                    join i in ids.Keys on e.Name equals i
                    select new { e, i };

            foreach (var n in q)
            {
                n.e.Add(new XAttribute("Id", ids[n.i]));
            }
        }

        public static void RemoveIds(XElement envelope)
        {
            var hd = envelope.Element(NA.soap + "Header");

            var q = from e in
                        (from e in hd.Elements().Concat(envelope.Elements(NA.soap + "Body"))
                         join i in ids.Keys on e.Name equals i
                         select e)
                    from a in e.Attributes()
                    where a.Name == "Id"
                    select a;

            foreach (var a in q)
            {
                a.Remove();
            }
        }

        /*
        public static string VersionNumber(XElement envelope)
        {
            try
            {
                var ats = envelope.Element(UsedPaths.HeaderAttributeStatement);
                if (ats == null) return "";

                var q = (from a in ats.Elements(NA.saml + "Attribute")
                         let at = a.Attribute("Name")
                         where at != null && (at.Value == "sosi:IDCardVersion" || at.Value == "dgws:IDCardVersion")
                         select a.Element(NA.saml + "AttributeValue")).FirstOrDefault();

                if (q == null) return "";
                return q.Value;
            }
            catch
            { }
            return "";
        }
        
        public static ErrorType DGWSClientRequestHandle(XElement envelope, IDCardReceiver cr, MedcomHeaderReceiver mhc)
        {
            var hd = envelope.Element(NA.soap + "Header");

            var a = cr(null);
            var err = a.VerificerKonsistens(false);
            if (err != null) return err;

            hd.Add(new SecurityType { Assertion = a }.ToXml());

            if (a.IDCardVersion != "1.1") return DGWSClientMedcomHeaderHandle(envelope, mhc);
            SetIds(envelope);

            return null;
        }

        public static ErrorType DGWSC101lientResponseHandle(XElement envelope, IDCardCheck cr, MedcomHeaderCheck mhc)
        {
            var mh = envelope.Element(UsedPaths.MedcomHeader);
            if (mh == null) return new ErrorType(ErrorCode.InvalidHeader, "MedCom header mangler i response");
            mh.Remove();
            var AssertionTag = envelope.Element(UsedPaths.HeaderAssertion);
            //if (AssertionTag == null) return new ErrorType(ErrorCode.InvalidHeader, "IDKort mangler i response");

            DGWSCard101Type card = null;
            if (AssertionTag != null)
            {
                AssertionTag.Parent.Remove();
                card = new DGWSCard101Type(AssertionTag);
            }
            var err = cr(card, envelope);
            if (err != null) return err;

            var mhd = MedcomHeaderType.Load(mh);
            if (mhd == null) return new ErrorType(ErrorCode.InvalidHeader, "Kunne ikke parse MedCom header");

            err = mhc(mhd);
            if (err != null) return err;

            return null;
        }

        public static ErrorType DGWSC11lientResponseHandle(XElement envelope, IDCardCheck cr)
        {
            var AssertionTag = envelope.Element(UsedPaths.HeaderAssertion);
            if (AssertionTag == null) return new ErrorType(ErrorCode.InvalidHeader, "IDKort mangler i response");

            var card = new DGWSCard11Type(AssertionTag);
            //if (!card.Load( AssertionTag) ) return new ErrorType(ErrorCode.InvalidHeader, "Kunne ikke parse IDKort");

            var err = cr(card, envelope);
            if (err != null) return err;
            AssertionTag.Parent.Remove();

            return null;
        }

        public static ErrorType DGWSClientMedcomHeaderHandle(XElement envelope, MedcomHeaderReceiver mhc)
        {
            var hd = envelope.Element(NA.soap + "Header");
            var m = mhc();
            hd.Add(m.ToXml());
            return null;
        }

        public static ErrorType DGWSServiceRequestHandle(XElement envelope, IDCardCheck cr, MedcomHeaderCheck mhc)
        {
            var ver = RequestResponse.VersionNumber(envelope);
            switch (ver)
            {
                case "1.0.1":
                    {
                        var err = DGWS101ServiceRequestHandle(envelope, cr);
                        if (err != null) return err;
                        return DGWS101MedcomHeaderServiceRequestHandle(envelope, mhc);
                    }
                case "1.1": return DGWS11ServiceRequestHandle(envelope, cr);
            }
            return new ErrorType(ErrorCode.InvalidInput, "Ukendt version:" + ver);
        }

        public static ErrorType DGWS101ServiceRequestHandle(XElement envelope, IDCardCheck cr)
        {
            var AssertionTag = envelope.Element(UsedPaths.HeaderAssertion); ;
            if (AssertionTag == null) return new ErrorType(ErrorCode.InvalidHeader, "Assertion tag mangler");

            var card = new DGWSCard101Type(AssertionTag);
            
            var res = card.VerificerKonsistens(false);
            if (res != null) return res;
            if (card.TooOld()) return new ErrorType(ErrorCode.IdCardTooOld, "Perioden for IDKortet er udløbet");

            res = cr(card, envelope);
            if (res != null) return res;

            AssertionTag.Parent.Remove();
            return null;
        }

        public static ErrorType DGWS101MedcomHeaderServiceRequestHandle(XElement envelope, MedcomHeaderCheck mhc)
        {
            var tag = envelope.Element(UsedPaths.MedcomHeader);
            if (tag == null) return new ErrorType(ErrorCode.InvalidHeader, "MedCom header mangler");
            tag.Remove();
            var m = MedcomHeaderType.Load(tag);
            if (m == null) return new ErrorType(ErrorCode.InvalidHeader, "Kunne ikke læse Medcom Header");
            var res = mhc(m);
            if (res != null) return new ErrorType(ErrorCode.InvalidHeader, "Medcom Header ikke accepteret");
            return null;
        }

        public static ErrorType DGWS11ServiceRequestHandle(XElement envelope, IDCardCheck cr)
        {
            var AssertionTag = envelope.Element(UsedPaths.HeaderAssertion); ;
            if (AssertionTag == null) return new ErrorType(ErrorCode.InvalidHeader, "Assertion tag mangler");

            DGWSCard11Type card = new DGWSCard11Type(AssertionTag);
            //if ( !card.Load(AssertionTag) ) return new ErrorType(ErrorCode.InvalidHeader, "Kunne ikke læse IDKort");
            var res = card.VerificerKonsistens(true);
            if (res != null) return res;
            if (card.TooOld()) return new ErrorType(ErrorCode.IdCardTooOld, "Perioden for IDKortet er udløbet");

            res = cr(card, envelope);
            if (res != null) return res;

            RemoveIds(envelope);
            AssertionTag.Parent.Remove();
            return null;
        }

        public static ErrorType DGWSServiceResponseHandle10(XElement envelope, IDCardReceiver cr, MedcomHeaderReceiver mhc)
        {
            var a = cr("1.0");
            var hd = envelope.Element(NA.soap + "Header");

            if (a != null)
            {
                hd.Add(new SecurityType { Assertion = a }.ToXml());
            }
            hd.Add(mhc().ToXml());
            return null;
        }


        public static ErrorType DGWSServiceResponseHandle101(XElement envelope, IDCardReceiver cr, MedcomHeaderReceiver mhc)
        {
            var a = cr("1.0.1");
            var hd = envelope.Element(NA.soap + "Header");

            if (a != null)
            {
                hd.Add(new SecurityType { Assertion = a }.ToXml());
            }
            hd.Add(mhc().ToXml());
            return null;
        }

        public static ErrorType DGWSServiceResponseHandle11(XElement envelope, IDCardReceiver cr)
        {
            var a = cr("1.1");
            var hd = envelope.Element(NA.soap + "Header");

            hd.Add(new SecurityType { Assertion = a }.ToXml());

            SetIds(envelope);
            return null;
        }
        */
        public static void DGWSServiceResponseFaultHandle11(XElement FaultTag, ErrorType error)
        {
            FaultTag.Add(new XAttribute(XNamespace.Xmlns + "dgws", NA.dgws11.NamespaceName));
            if (error != null)
            {
                FaultTag.SetElementValue("faultcode", "dgws:" + error.Errorcode.ToString());
                FaultTag.SetElementValue("faultstring", error.Message);
            }
            else
            {
                FaultTag.SetElementValue("faultcode", ErrorCode.InternalError.ToString());
            }
        }
    }
}