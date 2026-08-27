// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.test;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.DirectoryString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.OtherName;
import org.bouncycastle.asn1.x509.SubjectDirectoryAttributes;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.qualified.BiometricData;
import org.bouncycastle.asn1.x509.qualified.Iso4217CurrencyCode;
import org.bouncycastle.asn1.x509.qualified.MonetaryValue;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.bouncycastle.asn1.x509.qualified.TypeOfBiometricData;
import org.xipki.security.HashAlgo;
import org.xipki.security.OIDs;
import org.xipki.security.asn1.ccc.EndpointCertificateExtensionSchema;
import org.xipki.security.asn1.ccc.InstanceCACertificateExtensionSchema;
import org.xipki.security.asn1.ccc.SBxDKisCertificateExtensionSchema;
import org.xipki.security.asn1.rfc4108.HardwareModuleName;
import org.xipki.security.asn1.rpki.*;
import org.xipki.security.asn1.stir.TNAuthorizationList;
import org.xipki.security.asn1.stir.TNEntry;
import org.xipki.security.asn1.stir.TelephoneNumberRange;
import org.xipki.security.asn1.tcg.*;
import org.xipki.security.util.KeyUtil;
import org.xipki.util.codec.ipadress.IPAddress;
import org.xipki.util.codec.ipadress.IPAddressFamily;
import org.xipki.util.io.IoUtil;
import org.xipki.util.misc.StringUtil;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Vector;

/**
 * Generate file containing the DER-encoded Extensions.
 *
 * @author Lijun Liao (xipki)
 */
public class GenerateExtensions {

  public static void main(String[] args) {
    try {
      KeyUtil.addProviders();
      saveExtensions("ccc-e.der", generateCCC_E_Instance_CA());
      saveExtensions("ccc-h.der", generateCCC_H_Endpoint());
      saveExtensions("ccc-t.der", generateCCC_T_SBxDKis_Endpoint());
      saveExtensions("spdm.der",  generateSPDM());
      saveExtensions("stir.der",  generateSTIR());
      saveExtensions("rpki.der",  generateRPKI());
      saveExtensions("rfc3739.der", generateRfc3739());
      saveExtensions("tcg.der",   generateTCG());
      saveExtensions("caliptra.der", generateCaliptra());
      saveExtensions("ee-complex.der", generateEeComplex());
      saveExtensions("gmt0015.der", generateGmt0015());
      saveExtensions("microsoft.der", generateMicrosoft());
      saveExtensions("othernames.der", generateOthernames());
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  private static void saveExtensions(String filename, Extensions extns) throws IOException {
    IoUtil.save("target/extensions/" + filename, extns.getEncoded());
  }

  private static byte[] fixedBytes(int len, int value) {
    byte[] ret = new byte[len];
    Arrays.fill(ret, (byte) value);
    return ret;
  }

  private static Extensions generateCCC_E_Instance_CA() throws IOException {
    InstanceCACertificateExtensionSchema schema = new InstanceCACertificateExtensionSchema(
        1, fixedBytes(4, 0x12), null);
    return new Extensions(new Extension(OIDs.Extn.id_ccc_E_Instance_CA_Cert, true,
        schema.getEncoded()));
  }

  private static Extensions generateCCC_H_Endpoint() throws Exception {
    KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", "BC");
    kpGen.initialize(new ECGenParameterSpec("P-256"));
    SubjectPublicKeyInfo vehiclePK = SubjectPublicKeyInfo.getInstance(
        kpGen.generateKeyPair().getPublic().getEncoded());
    EndpointCertificateExtensionSchema schema = new EndpointCertificateExtensionSchema(
        1, fixedBytes(8, 0x23), (byte) 3, (byte) 4,
        fixedBytes(2, 11), vehiclePK, fixedBytes(2, 0x45));
    return new Extensions(new Extension(OIDs.Extn.id_ccc_H_Endpoint_Cert, true,
        schema.getEncoded()));
  }

  private static Extensions generateCCC_T_SBxDKis_Endpoint() throws IOException {
    SBxDKisCertificateExtensionSchema schema = new SBxDKisCertificateExtensionSchema(
        fixedBytes(4, 0x12),  fixedBytes(4, 0x34),  fixedBytes(4, 0x56));
    return new Extensions(new Extension(OIDs.Extn.id_ccc_T_SBxDKis_Endpoint_Cert, true,
        schema.getEncoded()));
  }

  private static Extensions generateSPDM() throws IOException {
    OtherName otherName = new OtherName(OIDs.Spdm.id_DMTF_device_info,
        new DERUTF8String("my-manufacturer:my-product:my-serialNumber"));
    GeneralName altName = new GeneralName(GeneralName.otherName, otherName);
    GeneralNames altNames = new GeneralNames(altName);
    return new Extensions(new Extension(OIDs.Extn.subjectAlternativeName, false,
        altNames.getEncoded()));
  }

  private static Extensions generateSTIR() throws IOException {
    List<TNEntry> entries = new LinkedList<>();
    entries.add(TNEntry.ofSpc("my-spc"));
    entries.add(TNEntry.ofOne("1234"));

    entries.add(TNEntry.ofRange(new TelephoneNumberRange("2345", BigInteger.valueOf(10))));
    TNAuthorizationList tnAuthList = new TNAuthorizationList(entries);
    return new Extensions(new Extension(OIDs.Extn.id_pe_TNAuthList, false,
        tnAuthList.getEncoded()));
  }

  private static Extensions generateRPKI() throws IOException {
    List<Extension> extensions = new LinkedList<>();
    extensions.add(new Extension(OIDs.Extn.ASIdentifiers, false,
        buildASIdentifiers().getEncoded()));

    ASIdentifierChoice asnum = new ASIdentifierChoice(null);
    extensions.add(new Extension(OIDs.Extn.ASIdentifiersV2, false,
        new ASIdentifiers(asnum, null).getEncoded()));

    extensions.add(new Extension(OIDs.Extn.IPAddrBlocks, false,
        buildIPAddrBlocks(true, null, false).getEncoded()));

    extensions.add(new Extension(OIDs.Extn.IPAddrBlocksV2, false,
        buildIPAddrBlocks(false, IPAddressFamily.SAFI_unicast, true).getEncoded()));

    return new Extensions(extensions.toArray(new Extension[0]));
  }

  static ASIdentifiers buildASIdentifiers() {
    ASIdentifierChoice asnum = new ASIdentifierChoice(List.of(
        new ASIdOrRange(BigInteger.valueOf(2))));
    ASIdentifierChoice rdi = new ASIdentifierChoice(List.of(
        new ASIdOrRange(new ASRange(BigInteger.valueOf(3), BigInteger.valueOf(6)))));
    return new ASIdentifiers(asnum, rdi);
  }

  static IPAddrBlocks buildIPAddrBlocks(
      boolean inherit, Byte safi, boolean withLongIPv6Bytes) {
    if (inherit) {
      IPAddressChoice ioAddrChoice = new IPAddressChoice(null);
      return new IPAddrBlocks(Arrays.asList(
          new ASN1IPAddressFamily(new IPAddressFamily(IPAddressFamily.AFI_IPv6, safi),
              ioAddrChoice),
          new ASN1IPAddressFamily(new IPAddressFamily(IPAddressFamily.AFI_IPv4, safi),
              ioAddrChoice)));
    }

    List<ASN1IPAddressFamily> families = new ArrayList<>(2);

    List<IPAddressOrRange> ipv4List = new LinkedList<>();
    ipv4List.add(buildIPAddressOrRange(true, "192.0.2.0/24"));
    ipv4List.add(buildIPAddressOrRange(true, "198.51.100.0/28"));
    ipv4List.add(buildIPAddressOrRange(true, "203.0.113.0/24"));

    // https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml
    List<IPAddressOrRange> ipv6List = new LinkedList<>();
    ipv6List.add(buildIPAddressOrRange(false, "2001:0db8:1234/48"));
    if (withLongIPv6Bytes) {
      ipv6List.add(buildIPAddressOrRange(false,
          "3fff:0003::-3fff:0122::2233:3344:5566:ffff:ffff"));
    } else {
      ipv6List.add(buildIPAddressOrRange(false,
          "3fff:0600::-3fff:0fff:ffff:ffff:ffff:ffff:ffff:ffff"));
    }

    families.add(
        new ASN1IPAddressFamily(new IPAddressFamily(IPAddressFamily.AFI_IPv6, safi),
        new IPAddressChoice(ipv6List)));

    families.add(
        new ASN1IPAddressFamily(new IPAddressFamily(IPAddressFamily.AFI_IPv4, safi),
        new IPAddressChoice(ipv4List)));

    return new IPAddrBlocks(families);
  }

  private static IPAddressOrRange buildIPAddressOrRange(boolean ipv4, String addr) {
    if (addr.contains("-")) {
      String[] tokens = addr.split("-");
      IPAddress min = IPAddress.getInstance(ipv4, tokens[0], IPAddress.Context.RANGE_MIN);
      IPAddress max = IPAddress.getInstance(ipv4, tokens[1], IPAddress.Context.RANGE_MAX);

      return new IPAddressOrRange(new IPAddressRange(
          new ASN1IPAddress(min.value(), min.unusedBits()),
          new ASN1IPAddress(max.value(), max.unusedBits())));
    } else {
      IPAddress prefix = IPAddress.getInstance(ipv4, addr, IPAddress.Context.PREFIX);
      return new IPAddressOrRange(new ASN1IPAddress(prefix.value(), prefix.unusedBits()));
    }
  }

  private static Extensions generateRfc3739() throws Exception {
    Vector<Attribute> attrs = new Vector<>();
    attrs.add(new Attribute(OIDs.DN.title,
        new DERSet(new DERPrintableString("Dr."))));
    attrs.add(new Attribute(OIDs.DN.countryOfResidence,
        new DERSet(new DERPrintableString("DE"))));
    attrs.add(new Attribute(OIDs.DN.countryOfCitizenship,
        new DERSet(new DERPrintableString("FR"))));
    attrs.add(new Attribute(OIDs.DN.gender,
        new DERSet(new DERPrintableString("M"))));
    attrs.add(new Attribute(OIDs.DN.placeOfBirth,
        new DERSet(DirectoryString.getInstance(new DERUTF8String("DummyCity")))));
    attrs.add(new Attribute(OIDs.DN.dateOfBirth,
        new DERSet(new DERGeneralizedTime("198012180000Z"))));

    SubjectDirectoryAttributes sdAttrs = new SubjectDirectoryAttributes(attrs);

    List<Extension> extensions = new ArrayList<>();
    extensions.add(new Extension(OIDs.Extn.subjectDirectoryAttributes, false,
            sdAttrs.getEncoded()));

    TypeOfBiometricData bioType = new TypeOfBiometricData(0);
    HashAlgo hashAlgo = HashAlgo.SHA256;
    byte[] bioHash = fixedBytes(hashAlgo.length(), 0x12);
    String biometricUri = "https://myorg.org/?id=123";
    BiometricData bioData = new BiometricData(
        bioType, hashAlgo.algorithmIdentifier(), new DEROctetString(bioHash),
        new DERIA5String(biometricUri));
    extensions.add(new Extension(OIDs.Extn.biometricInfo, false,
        new DERSequence(bioData).getEncoded()));

    return new Extensions(extensions.toArray(new Extension[0]));
  }

  private static Extensions generateGmt0015() throws Exception {
    List<Extension> extensions = new ArrayList<>();

    String cnResidentIdCardNumber = "110101199001011234";
    String cnPassportNumber = "E12345678";
    String cnSocialInsuranceNumber = "110101199001013456";
    String cnUnifiedSocialCreditCode = "91310000MA1K12345X";

    // GM/T 0015
    if (StringUtil.isNotBlank(cnResidentIdCardNumber)) {
      extensions.add(new Extension(OIDs.Extn.id_cn_residentIdCardNumber, false,
          new DERPrintableString(cnResidentIdCardNumber).getEncoded()));
    }

    if (StringUtil.isNotBlank(cnPassportNumber)) {
      extensions.add(new Extension(OIDs.Extn.id_cn_passportNumber, false,
          new DERUTF8String(cnPassportNumber).getEncoded()));
    }

    if (StringUtil.isNotBlank(cnSocialInsuranceNumber)) {
      extensions.add(new Extension(OIDs.Extn.id_cn_socialInsuranceNumber, false,
          new DERUTF8String(cnSocialInsuranceNumber).getEncoded()));
    }

    if (StringUtil.isNotBlank(cnUnifiedSocialCreditCode)) {
      extensions.add(new Extension(OIDs.Extn.id_cn_UnifiedSocialCreditCode, false,
          new DERUTF8String(cnUnifiedSocialCreditCode).getEncoded()));
    }

    return new Extensions(extensions.toArray(new Extension[0]));
  }

  private static Extensions generateMicrosoft() throws Exception {
    // Microsoft SID, e.g. S-1-5-...
    String microsoftSid = "S-1-5-123456-234567-1234";
    List<Extension> extensions = new ArrayList<>();
    OtherName on = new OtherName(OIDs.Extn.id_microsoft_objectSid,
        new DEROctetString(microsoftSid.getBytes(StandardCharsets.US_ASCII)));
    GeneralName gn = new GeneralName(GeneralName.otherName, on);
    GeneralNames gns = new GeneralNames(gn);
    extensions.add(new Extension(OIDs.Extn.id_microsoft_SID, false, gns.getEncoded()));

    return new Extensions(extensions.toArray(new Extension[0]));
  }

  private static Extensions generateEeComplex() throws Exception {
    ASN1EncodableVector vec = new ASN1EncodableVector();

    MonetaryValue mv = new MonetaryValue(new Iso4217CurrencyCode("EUR"), 150, 15);
    vec.add(new QCStatement(OIDs.QCS.id_etsi_qcs_QcLimitValue, mv));

    return new Extensions(new Extension(OIDs.Extn.qCStatements, false,
        new DERSequence(vec).getEncoded()));
  }

  private static Extensions generateCaliptra() throws Exception {
    return new Extensions(new Extension(OIDs.DICE.tcg_dice_ueid, false,
        new DEROctetString(fixedBytes(4, 0x12)).getEncoded()));
  }

  private static Extensions generateOthernames() throws Exception {
    List<OtherName> otherNames = new LinkedList<>();

    // macAddress
    otherNames.add(new OtherName(
        OIDs.X509.id_on_MACAddress, new DEROctetString(fixedBytes(8, 12))));

    // smtpUtf8Mailbox
    otherNames.add(new OtherName(
            OIDs.X509.id_on_SmtpUTF8Mailbox, new DERUTF8String("学生@school.example.org")));

    // smtpUtf8Mailbox
    HardwareModuleName hwmName = new HardwareModuleName(
        new ASN1ObjectIdentifier("1.2.3.5"), fixedBytes(16, 0x45));
    otherNames.add(new OtherName(
            OIDs.X509.id_on_hardwareModuleName, hwmName));

    // any otherName
    ASN1Sequence dummySeq = new DERSequence(new ASN1Encodable[]
        {new DERUTF8String("first"), new DERUTF8String("second")});
    otherNames.add(new OtherName(
            new ASN1ObjectIdentifier("1.2.3.4.5"), dummySeq));

    List<GeneralName> gns = new ArrayList<>(otherNames.size());
    for (OtherName otherName : otherNames) {
      gns.add(new GeneralName(GeneralName.otherName, otherName));
    }

    return new Extensions(new Extension(OIDs.Extn.subjectAlternativeName, false,
        new GeneralNames(gns.toArray(new GeneralName[0])).getEncoded()));
  }

  private static Extensions generateTCG() throws Exception {
    // extension SubjectAltName
    Extension otherNameExt = generateTcgOtherNameExt();

    // extension SubjectDirectoryAttributes
    Vector<Attribute> attrs = new Vector<>();

    // tcg_at_tcgPlatformSpecification
    TCGPlatformSpecification platformSpec = new TCGPlatformSpecification(
        new TCGSpecificationVersion(1, 2, 3),
        fixedBytes(4, 0x34));
    attrs.add(new Attribute(OIDs.TCG.tcg_at_tcgPlatformSpecification,
            new DERSet(platformSpec)));

    // tcg_at_tcgCredentialSpecification
    TCGSpecificationVersion specVersion = new TCGSpecificationVersion(1, 2, 3);
    attrs.add(new Attribute(OIDs.TCG.tcg_at_tcgCredentialSpecification,
            new DERSet(specVersion)));

    // tcg_at_tcgCredentialType
    TCGCredentialType credentialType =
        new TCGCredentialType(OIDs.TCG.tcg_kp_PlatformKeyCertificate);
    attrs.add(new Attribute(OIDs.TCG.tcg_at_tcgCredentialType,
            new DERSet(credentialType)));

    // tcg_at_platformConfiguration_v3
    ASN1ObjectIdentifier attrType = OIDs.TCG.tcg_at_platformConfiguration_v3;
    List<Property> props = new ArrayList<>();
    props.add(new Property("prop-name", "prop-value", AttributeStatus.added));
    PlatformConfigurationV3 confV3 = new PlatformConfigurationV3(
        generateTraitsForPlatformConfiguration(), new Properties(props));
    attrs.add(new Attribute(attrType, new DERSet(confV3)));

    // tcg_at_platformConfigUri_v3
    attrType = OIDs.TCG.tcg_at_platformConfigUri_v3;
    attrs.add(new Attribute(attrType, new DERSet(generateTraitsForPlatformConfigUriV3())));

    // tcg_at_previousPlatformCertificates
    attrType = OIDs.TCG.tcg_at_previousPlatformCertificates;
    attrs.add(new Attribute(attrType, new DERSet(generateTraitsForPreviousPlatformCertificates())));

    // tcg_at_tbbSecurityAssertions_v3
    attrType = OIDs.TCG.tcg_at_tbbSecurityAssertions_v3;
    attrs.add(new Attribute(attrType, new DERSet(generateTraitsForTbbSecurityAssertions_v3())));

    // tcg_at_cryptographicAnchors
    attrType = OIDs.TCG.tcg_at_cryptographicAnchors;
    attrs.add(new Attribute(attrType, new DERSet(generateTraitsForCryptographicAnchors())));

    // tcg_at_platformOwnership
    attrType = OIDs.TCG.tcg_at_platformOwnership;
    attrs.add(new Attribute(attrType, new DERSet(generateTraitsForPlatformOwnership())));

    // tcg_at_manufacturingAssertions
    attrType = OIDs.TCG.tcg_at_manufacturingAssertions;
    attrs.add(new Attribute(attrType, new DERSet(generateTraitsForManufacturingAssertions())));

    Extension subjectDirectoryAttributesExt = new Extension(
        OIDs.Extn.subjectDirectoryAttributes, false,
        new SubjectDirectoryAttributes(attrs).getEncoded());
    return new Extensions(new Extension[] {otherNameExt, subjectDirectoryAttributesExt});
  }

  private static Extension generateTcgOtherNameExt() throws IOException {
    List<Trait> traits = new LinkedList<>();
    traits.add(new Trait(
        OIDs.TCG.tcg_tr_ID_UTF8String,
        OIDs.TCG.tcg_tr_cat_platformManufacturer,
        OIDs.TCG.tcg_tr_reg_none,
        "description cat platformManufacturer",
        "http://example.com/platformManufacturer",
        new DERUTF8String("my platformManufacturer")));

    traits.add(new Trait(
        OIDs.TCG.tcg_tr_ID_IA5String,
        OIDs.TCG.tcg_tr_cat_platformModel,
        OIDs.TCG.tcg_tr_reg_none,
        "description cat platformModel",
        "http://example.com/platformModel",
        new DERIA5String("my platformModel")));

    traits.add(new Trait(
        OIDs.TCG.tcg_tr_ID_UTF8String,
        OIDs.TCG.tcg_tr_cat_platformVersion,
        OIDs.TCG.tcg_tr_reg_none,
        "description cat platformVersion",
        "http://example.com/platformVersion",
        new DERUTF8String("my platformVersion")));

    traits.add(new Trait(
        OIDs.TCG.tcg_tr_ID_UTF8String,
        OIDs.TCG.tcg_tr_cat_platformSerial,
        OIDs.TCG.tcg_tr_reg_none,
        "description cat platformSerial",
        "http://example.com/platformSerial",
        new DERUTF8String("my platformSerial")));

    traits.add(new Trait(
        OIDs.TCG.tcg_tr_ID_PEN,
        OIDs.TCG.tcg_tr_cat_platformManufacturerIdentifier,
        OIDs.TCG.tcg_tr_reg_none,
        "description cat platformManufacturerIdentifier",
        "http://example.com/platformManufacturerIdentifier",
        new ASN1ObjectIdentifier("1.3.6.1.4.1.45522.1234")));

    OtherName otherName = new OtherName(OIDs.TCG.tcg_at_platformIdentifier,
        new DERSequence(traits.toArray(new ASN1Encodable[0])));

    return new Extension(OIDs.Extn.subjectAlternativeName, false,
        new GeneralNames(new GeneralName(GeneralName.otherName, otherName)).getEncoded());
  }

  private static Traits generateTraitsForPlatformConfigUriV3()
      throws Exception {
    List<Trait> traits = new LinkedList<>();

    // tcg_tr_ID_URI
    traits.add(new Trait(OIDs.TCG.tcg_tr_ID_URI,
        OIDs.TCG.tcg_tr_cat_PlatformCertificate, OIDs.TCG.tcg_tr_reg_none, null, null,
        new URIReference("http://example.org/platform-configuri-v3", null, null)));

    return new Traits(traits);
  }

  private static Traits generateTraitsForPlatformConfiguration()
      throws Exception {
    List<Trait> traits = new LinkedList<>();

    traits.add(new Trait(
        OIDs.TCG.tcg_tr_ID_UTF8String,
        OIDs.TCG.tcg_tr_cat_platformManufacturer,
        OIDs.TCG.tcg_tr_reg_none,
        "description cat platformManufacturer",
        "http://example.com/platformManufacturer",
        new DERUTF8String("my platformManufacturer")));

    traits.add(new Trait(
        OIDs.TCG.tcg_tr_ID_IA5String,
        OIDs.TCG.tcg_tr_cat_platformModel,
        OIDs.TCG.tcg_tr_reg_none,
        "description cat platformModel",
        "http://example.com/platformModel",
        new DERIA5String("my platformModel")));

    traits.add(new Trait(
        OIDs.TCG.tcg_tr_ID_UTF8String,
        OIDs.TCG.tcg_tr_cat_platformVersion,
        OIDs.TCG.tcg_tr_reg_none,
        "description cat platformVersion",
        "http://example.com/platformVersion",
        new DERUTF8String("my platformVersion")));

    traits.add(new Trait(
        OIDs.TCG.tcg_tr_ID_UTF8String,
        OIDs.TCG.tcg_tr_cat_platformSerial,
        OIDs.TCG.tcg_tr_reg_none,
        "description cat platformSerial",
        "http://example.com/platformSerial",
        new DERUTF8String("my platformSerial")));

    traits.add(new Trait(
        OIDs.TCG.tcg_tr_ID_PEN,
        OIDs.TCG.tcg_tr_cat_platformManufacturerIdentifier,
        OIDs.TCG.tcg_tr_reg_none,
        "description cat platformManufacturerIdentifier",
        "http://example.com/platformManufacturerIdentifier",
        new ASN1ObjectIdentifier("1.3.6.1.4.1.45522.1234")));

    return new Traits(traits);
  }

  private static Traits generateTraitsForPreviousPlatformCertificates()
      throws Exception {
    List<Trait> traits = new LinkedList<>();

    // tcg_tr_ID_Boolean
    traits.add(new Trait(OIDs.TCG.tcg_tr_ID_Boolean,
        OIDs.TCG.tcg_tr_cat_PlatformCertificate, OIDs.TCG.tcg_tr_reg_none, null, null,
        ASN1Boolean.TRUE));

    // tcg_tr_ID_certificateIdentifier
    CertificateIdentifier certId = new CertificateIdentifier(
        new HashedCertificateIdentifier(
            HashAlgo.SHA256.algorithmIdentifier(), fixedBytes(32, 0x12)),
        new IssuerSerial(new GeneralNames(new GeneralName(new X500Name("CN=issuer"))),
            BigInteger.TEN));
    traits.add(new Trait(OIDs.TCG.tcg_tr_ID_certificateIdentifier,
        OIDs.TCG.tcg_tr_cat_PlatformCertificate, OIDs.TCG.tcg_tr_reg_none, null, null,
        certId));

    // tcg_tr_ID_componentClass
    traits.add(new Trait(OIDs.TCG.tcg_tr_ID_componentClass,
        OIDs.TCG.tcg_tr_cat_PlatformCertificate, OIDs.TCG.tcg_tr_reg_none, null, null,
        new DEROctetString(fixedBytes(4, 0x22))));

    // tcg_tr_ID_componentIdentifierV11
    ComponentClass componentClass = new ComponentClass(
        OIDs.TCG.tcg_registry_componentClass_tcg, fixedBytes(4, 0x33));
    ComponentIdentifierV11 idV11 = new ComponentIdentifierV11(componentClass,
        "my component manufacturer", "my component model");
    traits.add(new Trait(OIDs.TCG.tcg_tr_ID_componentIdentifierV11,
        OIDs.TCG.tcg_tr_cat_PlatformCertificate, OIDs.TCG.tcg_tr_reg_none, null, null,
        idV11));

    // tcg_tr_ID_networkMAC
    ComponentAddress componentAddress = new ComponentAddress(OIDs.TCG.tcg_address_ethernetmac,
        "02:1A:2B:3C:4D:5E");
    traits.add(new Trait(OIDs.TCG.tcg_tr_ID_networkMAC,
        OIDs.TCG.tcg_tr_cat_PlatformCertificate, OIDs.TCG.tcg_tr_reg_none, null, null,
        componentAddress));

    // tcg_tr_ID_OID
    traits.add(new Trait(OIDs.TCG.tcg_tr_ID_OID,
        OIDs.TCG.tcg_tr_cat_PlatformCertificate, OIDs.TCG.tcg_tr_reg_none, null, null,
        new ASN1ObjectIdentifier("1.2.3.4.5")));

    // tcg_tr_ID_status
    traits.add(new Trait(OIDs.TCG.tcg_tr_ID_status,
        OIDs.TCG.tcg_tr_cat_PlatformCertificate, OIDs.TCG.tcg_tr_reg_none, null, null,
        AttributeStatus.added));

    // tcg_tr_ID_PEMCertString
    traits.add(new Trait(OIDs.TCG.tcg_tr_ID_PEMCertString,
        OIDs.TCG.tcg_tr_cat_PlatformCertificate, OIDs.TCG.tcg_tr_reg_none, null, null,
        new DERUTF8String("-----BEGIN CERTIFICATE-----\r\nMIIA\r\n-----END CERTIFICATE-----")));

    return new Traits(traits);
  }

  private static Traits generateTraitsForPlatformOwnership()
      throws Exception {
    List<Trait> traits = new LinkedList<>();

    // tcg_tr_ID_UTF8String
    traits.add(new Trait(OIDs.TCG.tcg_tr_ID_UTF8String,
        OIDs.TCG.tcg_tr_cat_platformOwnership, OIDs.TCG.tcg_tr_reg_none, null, null,
        new DERUTF8String("my PlatformOwnership")));

    return new Traits(traits);
  }

  private static Traits generateTraitsForManufacturingAssertions()
      throws Exception {
    List<Trait> traits = new LinkedList<>();

    // tcg_tr_ID_UTF8String
    traits.add(new Trait(OIDs.TCG.tcg_tr_ID_UTF8String,
        OIDs.TCG.tcg_tr_cat_platformOwnership, OIDs.TCG.tcg_tr_reg_none, null, null,
        new DERUTF8String("my ManufacturingAssertions")));

    return new Traits(traits);
  }

  private static Traits generateTraitsForCryptographicAnchors()
      throws Exception {
    List<Trait> traits = new LinkedList<>();

    KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", "BC");
    kpGen.initialize(new NamedParameterSpec("P-256"));
    KeyPair keyPair = kpGen.generateKeyPair();
    SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
    traits.add(new Trait(OIDs.TCG.tcg_tr_ID_PublicKey,
        OIDs.TCG.tcg_tr_cat_PlatformCertificate, OIDs.TCG.tcg_tr_reg_none, null, null,
        spki));

    return new Traits(traits);
  }

  private static Traits generateTraitsForTbbSecurityAssertions_v3()
      throws Exception {
    List<Trait> traits = new LinkedList<>();

    // tcg_tr_ID_CommonCriteria
    CommonCriteriaMeasures ccMeasures = new CommonCriteriaMeasures(
        "3.1", EvaluationAssuranceLevel.level4, EvaluationStatus.evaluationCompleted, false,
        StrengthOfFunction.medium, null, null, null, null);
    CommonCriteriaEvaluation cce = new CommonCriteriaEvaluation(
        ccMeasures, "CC-Number", "CC-CertificateAuthority",
        "CC-Schema", null, null);
    traits.add(new Trait(OIDs.TCG.tcg_tr_ID_CommonCriteria,
        OIDs.TCG.tcg_tr_cat_PlatformCertificate, OIDs.TCG.tcg_tr_reg_none, null, null,
        cce));

    // tcg_tr_ID_FIPSLevel
    traits.add(new Trait(OIDs.TCG.tcg_tr_ID_FIPSLevel,
        OIDs.TCG.tcg_tr_cat_PlatformCertificate, OIDs.TCG.tcg_tr_reg_none, null, null,
        new FIPSLevel("140-3", SecurityLevel.level3, false)));

    // tcg_tr_ID_ISO9000Level
    traits.add(new Trait(OIDs.TCG.tcg_tr_ID_ISO9000Level,
        OIDs.TCG.tcg_tr_cat_PlatformCertificate, OIDs.TCG.tcg_tr_reg_none, null, null,
        new ISO9000Certification(true, "https://example.org/ISO9000Certification")));

    // tcg_tr_ID_platformFirmwareUpdateCompliance
    traits.add(new Trait(OIDs.TCG.tcg_tr_ID_platformFirmwareUpdateCompliance,
        OIDs.TCG.tcg_tr_cat_PlatformCertificate, OIDs.TCG.tcg_tr_reg_none, null, null,
        new PlatformFirmwareUpdateCompliance(
                PlatformFirmwareUpdateCompliance.sp800_147)));

    // tcg_tr_ID_platformHardwareCapabilities
    traits.add(new Trait(OIDs.TCG.tcg_tr_ID_platformHardwareCapabilities,
        OIDs.TCG.tcg_tr_cat_PlatformCertificate, OIDs.TCG.tcg_tr_reg_none, null, null,
        new PlatformHardwareCapabilities(
                PlatformHardwareCapabilities.firmwareFlashWP)));

    // tcg_tr_ID_platformFirmwareCapabilities
    traits.add(new Trait(OIDs.TCG.tcg_tr_ID_platformFirmwareCapabilities,
        OIDs.TCG.tcg_tr_cat_PlatformCertificate, OIDs.TCG.tcg_tr_reg_none, null, null,
        new PlatformFirmwareCapabilities(
                PlatformFirmwareCapabilities.fwSetupAuthLocal)));

    // tcg_tr_ID_platformFirmwareSignatureVerification
    traits.add(new Trait(OIDs.TCG.tcg_tr_ID_platformFirmwareSignatureVerification,
        OIDs.TCG.tcg_tr_cat_PlatformCertificate, OIDs.TCG.tcg_tr_reg_none, null, null,
        new PlatformFirmwareSignatureVerification(
                PlatformFirmwareSignatureVerification.secureBoot)));

    // tcg_tr_ID_RTM
    traits.add(new Trait(OIDs.TCG.tcg_tr_ID_RTM,
        OIDs.TCG.tcg_tr_cat_PlatformCertificate, OIDs.TCG.tcg_tr_reg_none, null, null,
        new RTMTypes(RTMTypes.dynamic)));

    // tcg_tr_ID_URI
    traits.add(new Trait(OIDs.TCG.tcg_tr_ID_URI,
        OIDs.TCG.tcg_tr_cat_PlatformCertificate, OIDs.TCG.tcg_tr_reg_none, null, null,
        new URIReference("http://example.org/id", null, null)));

    return new Traits(traits);
  }

}
