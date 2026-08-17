// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.asn1.tcg;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.xipki.security.util.Asn1Util;

/**
 * <pre>
 * PlatformConfiguration-v3 ::= SEQUENCE {
 *     platformComponents [0] IMPLICIT SEQUENCE(SIZE(1..MAX)) OF ComponentIdentifier-v2 OPTIONAL,
 *     platformProperties [1] IMPLICIT SEQUENCE(SIZE(1..MAX)) OF Property OPTIONAL }
 *
 * ComponentIdentifier-v2 ::= SEQUENCE(SIZE(1..MAX)) OF Trait
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class PlatformConfigurationV3 extends ASN1Object {

  private final Traits platformComponents;

  private final Properties platformProperties;

  public PlatformConfigurationV3(Traits platformComponents, Properties platformProperties) {
    if (platformComponents == null && platformProperties != null) {
      throw new IllegalArgumentException(
          "platformComponents and platformProperties must not be both null");
    }
    this.platformComponents = platformComponents;
    this.platformProperties = platformProperties;
  }

  public Traits platformComponents() {
    return platformComponents;
  }

  public Properties platformProperties() {
    return platformProperties;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector v = new ASN1EncodableVector(2);
    if (platformComponents != null) {
      v.add(new DERTaggedObject(false, 0, platformComponents));
    }

    if (platformProperties != null) {
      v.add(new DERTaggedObject(false, 1, platformProperties));
    }
    return new DERSequence(v);
  }

  public static PlatformConfigurationV3 getInstance(Object  obj) {
    if (obj instanceof PlatformConfigurationV3) {
      return (PlatformConfigurationV3) obj;
    } else if (obj instanceof ASN1Sequence) {
      ASN1Sequence seq = (ASN1Sequence) obj;
      int size = seq.size();
      if (size < 1 || size > 2) {
        throw new IllegalArgumentException("invalid sequence.size() " + seq.size());
      }

      int index = 0;

      Traits components = null;
      Properties properties = null;

      int minTagNo = 0;
      for (; index < size; index++) {
        ASN1TaggedObject tagObj = (ASN1TaggedObject) seq.getObjectAt(index);
        int tagNo = tagObj.getTagNo();
        if (tagNo < minTagNo) {
          throw new IllegalArgumentException("invalid occurrence of element with tag " + tagNo);
        }

        if (tagNo == 0) {
          components = Traits.getInstance(
              Asn1Util.getImplicitBaseObject(tagObj, BERTags.SEQUENCE));
        } else if (tagNo == 1) {
          properties = Properties.getInstance(
              Asn1Util.getImplicitBaseObject(tagObj, BERTags.SEQUENCE));
        } else {
          throw new IllegalArgumentException("invalid tagNo " + tagNo);
        }

        minTagNo = tagNo + 1;
      }

      return new PlatformConfigurationV3(components, properties);
    } else {
      return getInstance(ASN1Sequence.getInstance(obj));
    }
  }

}
