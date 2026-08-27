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
import org.bouncycastle.asn1.DERUTF8String;
import org.xipki.security.util.Asn1Util;
import org.xipki.util.codec.Args;

/**
 * <pre>
 * Property ::= SEQUENCE {
 *     propertyName  UTF8String (SIZE (1..STRMAX)),
 *     propertyValue UTF8String (SIZE (1..STRMAX)),
 *     status        [0] IMPLICIT AttributeStatus OPTIONAL
 * }
 * </pre>
 * issuerUID is not allowed in this class, since it is forbidden in the v3 certificates.
 *
 * @author Lijun Liao (xipki)
 */
public class Property extends ASN1Object {

  private final String propertyName;

  private final String propertyValue;

  private final AttributeStatus status;

  public Property(String propertyName, String propertyValue, AttributeStatus status) {
    this.propertyName = Args.lengthRange(propertyName, "propertyName", 1, TcgConstants.STRMAX);
    this.propertyValue = Args.lengthRange(propertyValue, "propertyValue", 1, TcgConstants.STRMAX);
    this.status = status;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector v = new ASN1EncodableVector(3);
    v.add(new DERUTF8String(propertyName));
    v.add(new DERUTF8String(propertyValue));
    if (status != null) {
      v.add(new DERTaggedObject(false, 0, status));
    }
    return new DERSequence(v);
  }

  public static Property getInstance(Object  obj) {
    if (obj instanceof Property) {
      return (Property) obj;
    } else if (obj instanceof ASN1Sequence) {
      ASN1Sequence seq = (ASN1Sequence) obj;
      int size = seq.size();
      if (size < 2 || size > 3) {
        throw new IllegalArgumentException("invalid sequence.size() " + seq.size());
      }

      String name = Asn1Util.getUTF8String(seq.getObjectAt(0));
      String value = Asn1Util.getUTF8String(seq.getObjectAt(1));
      AttributeStatus status = null;
      if (size > 2) {
        status = AttributeStatus.getInstance(
            Asn1Util.getImplicitBaseObject(
                (ASN1TaggedObject) seq.getObjectAt(2), BERTags.ENUMERATED));
      }
      return new Property(name, value, status);
    } else {
      return getInstance(ASN1Sequence.getInstance(obj));
    }
  }

}
