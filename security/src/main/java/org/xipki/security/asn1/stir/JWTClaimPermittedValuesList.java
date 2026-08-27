// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.asn1.stir;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.xipki.util.codec.Args;

import java.util.ArrayList;
import java.util.List;

/**
 * RFC 8226:
 * <pre>
 * JWTClaimPermittedValuesList ::= SEQUENCE SIZE (1..MAX) Of
 *                                       JWTClaimPermittedValues
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class JWTClaimPermittedValuesList extends ASN1Object {

  private final List<JWTClaimPermittedValues> values;

  public JWTClaimPermittedValuesList(List<JWTClaimPermittedValues> values) {
    this.values = Args.notEmpty(values, "values");
  }

  public List<JWTClaimPermittedValues> getValues() {
    return values;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector v = new ASN1EncodableVector();
    for (JWTClaimPermittedValues m : values) {
      v.add(m);
    }
    return new DERSequence(v);
  }

  public static JWTClaimPermittedValuesList getInstance(Object  obj) {
    if (obj instanceof JWTClaimPermittedValuesList) {
      return (JWTClaimPermittedValuesList)obj;
    } else if (obj != null) {
      ASN1Sequence seq = ASN1Sequence.getInstance(obj);
      int seqSize = seq.size();
      if (seqSize == 0) {
        throw new IllegalArgumentException("Bad sequence size: " + seqSize);
      }

      List<JWTClaimPermittedValues> values = new ArrayList<>(seqSize);
      for (int i = 0; i < seqSize; i++) {
        values.add(JWTClaimPermittedValues.getInstance(seq.getObjectAt(i)));
      }
      return new JWTClaimPermittedValuesList(values);
    } else {
      throw new IllegalArgumentException("invalid object null");
    }
  }

}
