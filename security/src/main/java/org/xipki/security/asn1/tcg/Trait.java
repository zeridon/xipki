// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.asn1.tcg;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.xipki.security.OIDs;
import org.xipki.security.util.Asn1Util;
import org.xipki.util.codec.Args;

import java.io.IOException;

/**
 * <pre>
 * Trait ::= SEQUENCE {
 *     traitId        TRAIT.&id({TraitSet}), -- Specifies the traitValue encoding
 *     traitCategory  OBJECT IDENTIFIER, -- Identifies the information category
 *                                       -- contained in traitValue
 *     traitRegistry  OBJECT IDENTIFIER, -- Identifies the registry used to match
 *                                       -- against the traitValue
 *     description    [0] IMPLICIT UTF8String (SIZE (1..STRMAX)) OPTIONAL,
 *     descriptionURI [1] IMPLICIT IA5String  (SIZE (1..URIMAX)) OPTIONAL,
 *     traitValue     OCTET STRING
 *                ( CONTAINING TRAIT.&TraitValueType({TraitSet}{@traitId}) ENCODED BY der) }
 * }
 *
 * TRAIT ::= CLASS {
 *     &id OBJECT IDENTIFIER UNIQUE,
 *     &TraitValueType }
 * WITH SYNTAX {
 *     SYNTAX &TraitValueType
 *     IDENTIFIED BY &id }
 *
 * TraitSet TRAIT ::= {...}
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class Trait extends ASN1Object {

  private final ASN1ObjectIdentifier traitId;

  private final ASN1ObjectIdentifier traitCategory;

  private final ASN1ObjectIdentifier traitRegistry;

  private final String description;

  private final String descriptionURI;

  private final byte[] traitValue;

  private ASN1Object parsedTraitValue;

  public Trait(ASN1ObjectIdentifier traitId, ASN1ObjectIdentifier traitCategory,
               ASN1ObjectIdentifier traitRegistry, String description,
               String descriptionURI, ASN1Encodable traitValue) throws IOException {
    this(traitId, traitCategory, traitRegistry, description, descriptionURI,
        Args.notNull(traitValue, "traitValue").toASN1Primitive().getEncoded());
  }

  private Trait(ASN1ObjectIdentifier traitId, ASN1ObjectIdentifier traitCategory,
                ASN1ObjectIdentifier traitRegistry, String description,
                String descriptionURI, byte[] traitValue) {
    this.traitId = Args.notNull(traitId, "traitId");
    this.traitCategory = Args.notNull(traitCategory, "traitCategory");
    this.traitRegistry = Args.notNull(traitRegistry, "traitRegistry");
    this.description = description;
    if (description != null) {
      Args.lengthRange(description, "description", 1, TcgConstants.STRMAX);
    }

    this.descriptionURI = descriptionURI;
    if (descriptionURI != null) {
      Args.lengthRange(descriptionURI, "descriptionURI", 1, TcgConstants.STRMAX);
    }

    this.traitValue = Args.notEmpty(traitValue, "traitValue");
  }

  public ASN1ObjectIdentifier traitId() {
    return traitId;
  }

  public ASN1ObjectIdentifier traitCategory() {
    return traitCategory;
  }

  public ASN1ObjectIdentifier traitRegistry() {
    return traitRegistry;
  }

  public String description() {
    return description;
  }

  public String descriptionURI() {
    return descriptionURI;
  }

  public byte[] traitValue() {
    return traitValue;
  }

  public synchronized ASN1Object parsedTraitValue() {
    if (parsedTraitValue != null) {
      return parsedTraitValue;
    }

    if (traitId.equals(OIDs.TCG.tcg_tr_ID_Boolean)) {
      parsedTraitValue = ASN1Boolean.getInstance(traitValue);
    } else if (traitId.equals(OIDs.TCG.tcg_tr_ID_certificateIdentifier)) {
      parsedTraitValue = CertificateIdentifier.getInstance(traitValue);
    } else if (traitId.equals(OIDs.TCG.tcg_tr_ID_CommonCriteria)) {
      parsedTraitValue = CommonCriteriaEvaluation.getInstance(traitValue);
    } else if (traitId.equals(OIDs.TCG.tcg_tr_ID_componentClass)) {
      parsedTraitValue = DEROctetString.getInstance(traitValue);
      int len = Asn1Util.getOctetStringOctets(parsedTraitValue).length;
      if (len != 4) {
        throw new IllegalArgumentException("length of traitValue (OCTET STRING) != 4");
      }
    } else if (traitId.equals(OIDs.TCG.tcg_tr_ID_componentIdentifierV11)) {
      parsedTraitValue = ComponentIdentifierV11.getInstance(traitValue);
    } else if (traitId.equals(OIDs.TCG.tcg_tr_ID_FIPSLevel)) {
      parsedTraitValue = FIPSLevel.getInstance(traitValue);
    } else if (traitId.equals(OIDs.TCG.tcg_tr_ID_ISO9000Level)) {
      parsedTraitValue = ISO9000Certification.getInstance(traitValue);
    } else if (traitId.equals(OIDs.TCG.tcg_tr_ID_networkMAC)) {
      parsedTraitValue = ComponentAddress.getInstance(traitValue);
    } else if (traitId.equals(OIDs.TCG.tcg_tr_ID_OID)) {
      parsedTraitValue = ASN1ObjectIdentifier.getInstance(traitValue);
    } else if (traitId.equals(OIDs.TCG.tcg_tr_ID_PEN)) {
      parsedTraitValue = ASN1ObjectIdentifier.getInstance(traitValue);
      String id = ((ASN1ObjectIdentifier) parsedTraitValue).getId();
      if (!id.startsWith("1.3.6.1.4.1.")) {
        throw new IllegalArgumentException(id + " is not a PEN OID");
      }
    } else if (traitId.equals(OIDs.TCG.tcg_tr_ID_platformFirmwareCapabilities)) {
      parsedTraitValue = PlatformFirmwareCapabilities.getInstance(traitValue);
    } else if (traitId.equals(OIDs.TCG.tcg_tr_ID_platformFirmwareSignatureVerification)) {
      parsedTraitValue = PlatformFirmwareSignatureVerification.getInstance(traitValue);
    } else if (traitId.equals(OIDs.TCG.tcg_tr_ID_platformFirmwareUpdateCompliance)) {
      parsedTraitValue = PlatformFirmwareUpdateCompliance.getInstance(traitValue);
    } else if (traitId.equals(OIDs.TCG.tcg_tr_ID_platformHardwareCapabilities)) {
      parsedTraitValue = PlatformHardwareCapabilities.getInstance(traitValue);
    } else if (traitId.equals(OIDs.TCG.tcg_tr_ID_RTM)) {
      parsedTraitValue = RTMTypes.getInstance(traitValue);
    } else if (traitId.equals(OIDs.TCG.tcg_tr_ID_status)) {
      parsedTraitValue = AttributeStatus.getInstance(traitValue);
    } else if (traitId.equals(OIDs.TCG.tcg_tr_ID_URI)) {
      parsedTraitValue = URIReference.getInstance(traitValue);
    } else if (traitId.equals(OIDs.TCG.tcg_tr_ID_UTF8String)) {
      parsedTraitValue = DERUTF8String.getInstance(traitValue);
      int len = Asn1Util.getUTF8String(parsedTraitValue).length();
      if (len == 0) {
        throw new IllegalArgumentException("string length not in [1..MAX]");
      }
    } else if (traitId.equals(OIDs.TCG.tcg_tr_ID_IA5String)) {
      parsedTraitValue = DERIA5String.getInstance(traitValue);
      int len = Asn1Util.getIA5String(parsedTraitValue).length();
      if (len == 0) {
        throw new IllegalArgumentException("string length not in [1..MAX]");
      }
    } else if (traitId.equals(OIDs.TCG.tcg_tr_ID_PEMCertString)) {
      parsedTraitValue = DERUTF8String.getInstance(traitValue);
      int len = Asn1Util.getUTF8String(parsedTraitValue).length();
      if (len == 0 || len > TcgConstants.CERTSTRMAX) {
        throw new IllegalArgumentException(
            "string length not in [1.." + TcgConstants.CERTSTRMAX + "]");
      }
    } else if (traitId.equals(OIDs.TCG.tcg_tr_ID_PublicKey)) {
      parsedTraitValue = SubjectPublicKeyInfo.getInstance(traitValue);
    } else {
      throw new IllegalArgumentException("unknown trait ID " + traitId.getId());
    }

    return parsedTraitValue;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector v = new ASN1EncodableVector();
    v.add(traitId);
    v.add(traitCategory);
    v.add(traitRegistry);
    if (description != null) {
      v.add(new DERTaggedObject(false, 0, new DERUTF8String(description)));
    }

    if (descriptionURI != null) {
      v.add(new DERTaggedObject(false, 1, new DERIA5String(descriptionURI)));
    }

    v.add(new DEROctetString(traitValue));
    return new DERSequence(v);
  }

  public static Trait getInstance(Object  obj) {
    if (obj instanceof Trait) {
      return (Trait) obj;
    } else if (obj instanceof ASN1Sequence) {
      ASN1Sequence seq = (ASN1Sequence) obj;
      int size = seq.size();
      if (size < 4 || size > 6) {
        throw new IllegalArgumentException("invalid sequence.size() " + seq.size());
      }

      ASN1ObjectIdentifier traitId = (ASN1ObjectIdentifier) seq.getObjectAt(0);
      ASN1ObjectIdentifier traitCategory = (ASN1ObjectIdentifier) seq.getObjectAt(1);
      ASN1ObjectIdentifier traitRegistry = (ASN1ObjectIdentifier) seq.getObjectAt(2);

      String description = null;
      String descriptionURI = null;

      int index = 3;
      ASN1Encodable item = seq.getObjectAt(index++);

      while (item instanceof ASN1TaggedObject) {
        int tag = ((ASN1TaggedObject) item).getTagNo();
        if (tag == 0) {
          if (description != null) {
            throw new IllegalArgumentException("duplicated tag " + tag);
          }

          if (descriptionURI != null) {
            throw new IllegalArgumentException("incorrect position of tag " + tag);
          }

          description = Asn1Util.getUTF8String(
              Asn1Util.getImplicitBaseObject((ASN1TaggedObject) item, BERTags.UTF8_STRING));
          item = index < size ? seq.getObjectAt(index++) : null;
        } else if (tag == 1) {
          if (descriptionURI != null) {
            throw new IllegalArgumentException("duplicated tag " + tag);
          }
          descriptionURI = Asn1Util.getIA5String(
              Asn1Util.getImplicitBaseObject((ASN1TaggedObject) item, BERTags.IA5_STRING));
          item = index < size ? seq.getObjectAt(index++) : null;
        }
      }

      byte[] traitValue = ((ASN1OctetString) item).getOctets();
      return new Trait(traitId, traitCategory, traitRegistry,
          description, descriptionURI, traitValue);
    } else {
      return getInstance(ASN1Sequence.getInstance(obj));
    }
  }

}
