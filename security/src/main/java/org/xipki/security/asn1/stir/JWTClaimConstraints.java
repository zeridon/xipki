// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.asn1.stir;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.xipki.security.util.Asn1Util;

/**
 * RFC 8226:
 * <pre>
 * JWTClaimConstraints ::= SEQUENCE {
 *   mustInclude [0] JWTClaimNames OPTIONAL,
 *     -- The listed claim names MUST appear in the PASSporT
 *     -- in addition to iat, orig, and dest.  If absent, iat, orig,
 *     -- and dest MUST appear in the PASSporT.
 *   permittedValues [1] JWTClaimPermittedValuesList OPTIONAL }
 *     -- If the claim name is present, the claim MUST contain one of
 *     -- the listed values.
 *   ( WITH COMPONENTS { ..., mustInclude PRESENT } |
 *   WITH COMPONENTS { ..., permittedValues PRESENT } )
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class JWTClaimConstraints extends ASN1Object {

  private final JWTClaimNames mustInclude;

  private final JWTClaimPermittedValuesList permittedValues;

  public JWTClaimConstraints(JWTClaimNames mustInclude,
                             JWTClaimPermittedValuesList permittedValues) {
    if (mustInclude == null && permittedValues == null) {
      throw new IllegalArgumentException("mustInclude and permittedValues must no be both null");
    }
    this.mustInclude = mustInclude;
    this.permittedValues = permittedValues;
  }

  public JWTClaimNames getMustInclude() {
    return mustInclude;
  }

  public JWTClaimPermittedValuesList getPermittedValues() {
    return permittedValues;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector v = new ASN1EncodableVector();
    if (mustInclude != null) {
      v.add(new DERTaggedObject(true, 0, mustInclude));
    }

    if (permittedValues != null) {
      v.add(new DERTaggedObject(true, 1, permittedValues));
    }
    return new DERSequence(v);
  }

  public static JWTClaimConstraints getInstance(Object  obj) {
    if (obj instanceof JWTClaimConstraints) {
      return (JWTClaimConstraints)obj;
    } else if (obj != null) {
      ASN1Sequence seq = ASN1Sequence.getInstance(obj);
      int seqSize = seq.size();
      if (seqSize != 1 && seqSize != 2) {
        throw new IllegalArgumentException("Bad sequence size: " + seqSize);
      }

      JWTClaimNames mustInclude = null;
      JWTClaimPermittedValuesList permittedValues = null;
      for (int i = 0; i < seqSize; i++) {
        ASN1TaggedObject tagO = (ASN1TaggedObject) seq.getObjectAt(i);
        int tagNo = tagO.getTagNo();
        ASN1Encodable baseO = Asn1Util.getBaseObject(tagO);
        if (tagNo == 0) {
          if (permittedValues != null) {
            throw new IllegalArgumentException("invalid order of object at index " + i);
          } else {
            mustInclude = JWTClaimNames.getInstance(baseO);
          }
        } else if (tagNo == 1) {
          permittedValues = JWTClaimPermittedValuesList.getInstance(baseO);
        } else {
          throw new IllegalArgumentException("invalid tag " + tagNo);
        }
      }
      return new JWTClaimConstraints(mustInclude, permittedValues);
    } else {
      throw new IllegalArgumentException("invalid object null");
    }
  }

}
