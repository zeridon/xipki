// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.asn1.tcg;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.xipki.util.codec.Args;

/**
 * <pre>
 * OriginComposition SEQUENCE ::= Sequence {
 *     location      EntityGeoLocation,
 *     hasComponents [0] BOOLEAN DEFAULT TRUE OPTIONAL
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class OriginComposition extends ASN1Object {

  private final EntityGeoLocation location;

  private final boolean hasComponents;

  public OriginComposition(EntityGeoLocation location, boolean hasComponents) {
    this.location = Args.notNull(location, "location");
    this.hasComponents = hasComponents;
  }

  public EntityGeoLocation location() {
    return location;
  }

  public boolean hasComponents() {
    return hasComponents;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector v = new ASN1EncodableVector(2);
    v.add(location);
    if (!hasComponents) {
      v.add(ASN1Boolean.FALSE);
    }

    return new DERSequence(v);
  }

  public static OriginComposition getInstance(Object  obj) {
    if (obj instanceof OriginComposition) {
      return (OriginComposition) obj;
    } else if (obj instanceof ASN1Sequence) {
      ASN1Sequence seq = (ASN1Sequence) obj;
      int size = seq.size();
      if (size != 1 && size != 2) {
        throw new IllegalArgumentException("invalid sequence.size() " + seq.size());
      }

      EntityGeoLocation location = EntityGeoLocation.getInstance(seq.getObjectAt(0));
      boolean hasComponents = true;
      if (size == 2) {
        hasComponents = ((ASN1Boolean) seq.getObjectAt(2)).isTrue();
      }

      return new OriginComposition(location, hasComponents);
    } else {
      return getInstance(ASN1Sequence.getInstance(obj));
    }
  }

}
