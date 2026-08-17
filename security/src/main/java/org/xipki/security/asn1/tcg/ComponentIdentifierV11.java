// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.asn1.tcg;

import org.bouncycastle.asn1.*;
import org.xipki.security.util.Asn1Util;
import org.xipki.util.codec.Args;

/**
 * <pre>
 * ComponentIdentifierV11 ::= SEQUENCE {
 *     componentClass           ComponentClass,
 *     componentManufacturer    UTF8String (SIZE (1..STRMAX)),
 *     componentModel           UTF8String (SIZE (1..STRMAX)),
 *     componentSerial          [0] IMPLICIT UTF8String (SIZE (1..STRMAX)) OPTIONAL,
 *     componentRevision        [1] IMPLICIT UTF8String (SIZE (1..STRMAX)) OPTIONAL,
 *     componentManufacturerId  [2] IMPLICIT PrivateEnterpriseNumber OPTIONAL,
 *     fieldReplaceable         [3] IMPLICIT BOOLEAN OPTIONAL,
 *     componentAddresses       [4] IMPLICIT SEQUENCE(SIZE(1.. MAX)) OF ComponentAddress OPTIONAL,
 *     componentPlatformCert    [5] IMPLICIT CertificateIdentifier OPTIONAL,
 *     componentPlatformCertUri [6] IMPLICIT URIReference OPTIONAL,
 *     status                   [7] IMPLICIT AttributeStatus OPTIONAL
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class ComponentIdentifierV11 extends ASN1Object {

  private final ComponentClass componentClass;

  private final String componentManufacturer;

  private final String componentModel;

  private final String componentSerial;

  private final String componentRevision;

  private final ASN1ObjectIdentifier componentManufacturerId;

  private final Boolean fieldReplaceable;

  private final ComponentAddresses componentAddresses;

  private final CertificateIdentifier componentPlatformCert;

  private final URIReference componentPlatformCertUri;

  private final AttributeStatus status;

  public ComponentIdentifierV11(
      ComponentClass componentClass, String componentManufacturer, String componentModel) {
    this(componentClass, componentManufacturer, componentModel,
        null, null, null, null, null, null, null, null);
  }

  public ComponentIdentifierV11(
      ComponentClass componentClass, String componentManufacturer,
      String componentModel, String componentSerial,
      String componentRevision, ASN1ObjectIdentifier componentManufacturerId,
      Boolean fieldReplaceable, ComponentAddresses componentAddresses,
      CertificateIdentifier componentPlatformCert,
      URIReference componentPlatformCertUri, AttributeStatus status) {
    this.componentClass = Args.notNull(componentClass, "componentClass");
    this.componentManufacturer = Args.lengthRange(componentManufacturer,
        "componentManufacturer", 1, TcgConstants.STRMAX);
    this.componentModel = Args.lengthRange(componentModel,
        "componentModel", 1, TcgConstants.STRMAX);

    if (componentSerial != null) {
      Args.lengthRange(componentSerial,
              "componentSerial", 1, TcgConstants.STRMAX);
    }
    this.componentSerial = componentSerial;

    if (componentRevision != null) {
      Args.lengthRange(componentRevision,
              "componentRevision", 1, TcgConstants.STRMAX);
    }
    this.componentRevision = componentRevision;

    this.componentManufacturerId = componentManufacturerId;
    this.fieldReplaceable = fieldReplaceable;
    this.componentAddresses = componentAddresses;
    this.componentPlatformCert = componentPlatformCert;
    this.componentPlatformCertUri = componentPlatformCertUri;
    this.status = status;
  }

  public ComponentClass componentClass() {
    return componentClass;
  }

  public String componentManufacturer() {
    return componentManufacturer;
  }

  public String componentModel() {
    return componentModel;
  }

  public String componentSerial() {
    return componentSerial;
  }

  public String componentRevision() {
    return componentRevision;
  }

  public ASN1ObjectIdentifier componentManufacturerId() {
    return componentManufacturerId;
  }

  public Boolean fieldReplaceable() {
    return fieldReplaceable;
  }

  public ComponentAddresses componentAddresses() {
    return componentAddresses;
  }

  public CertificateIdentifier componentPlatformCert() {
    return componentPlatformCert;
  }

  public URIReference componentPlatformCertUri() {
    return componentPlatformCertUri;
  }

  public AttributeStatus status() {
    return status;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector v = new ASN1EncodableVector(11);
    v.add(componentClass);
    v.add(new DERUTF8String(componentManufacturer));
    v.add(new DERUTF8String(componentModel));
    if (componentSerial != null) { // tag 0
      v.add(new DERTaggedObject(false, 0,  new DERUTF8String(componentSerial)));
    }

    if (componentRevision != null) { // tag 1
      v.add(new DERTaggedObject(false, 1,  new DERUTF8String(componentRevision)));
    }

    if (componentManufacturerId != null) { // tag 2
      v.add(new DERTaggedObject(false, 2,  componentManufacturerId));
    }

    if (fieldReplaceable != null) { // tag 3
      v.add(new DERTaggedObject(false, 3,  ASN1Boolean.getInstance(fieldReplaceable)));
    }

    if (componentAddresses != null) { // tag 4
      v.add(new DERTaggedObject(false, 4,  componentAddresses));
    }

    if (componentPlatformCert != null) { // tag 5
      v.add(new DERTaggedObject(false, 5,  componentPlatformCert));
    }

    if (componentPlatformCertUri != null) { // tag 6
      v.add(new DERTaggedObject(false, 6,  componentPlatformCertUri));
    }

    if (status != null) { // tag 7
      v.add(new DERTaggedObject(false, 7,  status));
    }

    return new DERSequence(v);
  }

  public static ComponentIdentifierV11 getInstance(Object  obj) {
    if (obj instanceof ComponentIdentifierV11) {
      return (ComponentIdentifierV11) obj;
    } else if (obj instanceof ASN1Sequence) {
      ASN1Sequence seq = (ASN1Sequence) obj;
      int size = seq.size();
      if (size < 3 || size > 11) {
        throw new IllegalArgumentException("invalid sequence.size() " + seq.size());
      }

      ComponentClass _class = ComponentClass.getInstance(seq.getObjectAt(0));
      String manufacturer = Asn1Util.getUTF8String(seq.getObjectAt(1));
      String model = Asn1Util.getUTF8String(seq.getObjectAt(2));

      String serial = null;
      String revision = null;
      ASN1ObjectIdentifier manufacturerId = null;
      Boolean fieldReplaceable = null;
      ComponentAddresses addresses = null;
      CertificateIdentifier platformCert = null;
      URIReference platformCertUri = null;
      AttributeStatus status = null;

      int index = 3;
      int minTagNo = 0;
      for (; index < size; index++) {
        ASN1TaggedObject tagObj = (ASN1TaggedObject) seq.getObjectAt(index);
        int tagNo = tagObj.getTagNo();
        if (tagNo < minTagNo) {
          throw new IllegalArgumentException("invalid occurrence of element with tag " + tagNo);
        }

        if (tagNo == 0) {
          serial = Asn1Util.getUTF8String(
              Asn1Util.getImplicitBaseObject(tagObj, BERTags.UTF8_STRING));
        } else if (tagNo == 1) {
          revision = Asn1Util.getUTF8String(
              Asn1Util.getImplicitBaseObject(tagObj, BERTags.UTF8_STRING));
        } else if (tagNo == 2) {
          manufacturerId = (ASN1ObjectIdentifier)
              Asn1Util.getImplicitBaseObject(tagObj, BERTags.OBJECT_IDENTIFIER);
        } else if (tagNo == 3) {
          fieldReplaceable = ((ASN1Boolean)
              Asn1Util.getImplicitBaseObject(tagObj, BERTags.BOOLEAN)).isTrue();
        } else if (tagNo == 4) {
          addresses = ComponentAddresses.getInstance(
              Asn1Util.getImplicitBaseObject(tagObj, BERTags.SEQUENCE));
        } else if (tagNo == 5) {
          platformCert = CertificateIdentifier.getInstance(
              Asn1Util.getImplicitBaseObject(tagObj, BERTags.SEQUENCE));
        } else if (tagNo == 6) {
          platformCertUri = URIReference.getInstance(
              Asn1Util.getImplicitBaseObject(tagObj, BERTags.SEQUENCE));
        } else if (tagNo == 7) {
          status = AttributeStatus.getInstance(
              Asn1Util.getImplicitBaseObject(tagObj, BERTags.ENUMERATED));
        } else {
          throw new IllegalArgumentException("invalid tagNo " + tagNo);
        }

        minTagNo = tagNo + 1;
      }

      return new ComponentIdentifierV11(_class, manufacturer, model, serial, revision,
          manufacturerId, fieldReplaceable, addresses, platformCert, platformCertUri, status);
    } else {
      return getInstance(ASN1Sequence.getInstance(obj));
    }
  }

}
