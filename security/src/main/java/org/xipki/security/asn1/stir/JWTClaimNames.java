// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.asn1.stir;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSequence;
import org.xipki.security.util.Asn1Util;
import org.xipki.util.codec.Args;

import java.util.ArrayList;
import java.util.List;

/**
 * RFC 8226:
 * <pre>
 * JWTClaimNames ::= SEQUENCE SIZE (1..MAX) OF JWTClaimName
 *
 * JWTClaimName ::= IA5String
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class JWTClaimNames extends ASN1Object {

  private final List<DERIA5String> values;

  public JWTClaimNames(List<String> values) {
    Args.notEmpty(values, "values");
    this.values = new ArrayList<>(values.size());
    for (String value : values) {
      this.values.add(new DERIA5String(value));
    }
  }

  public List<DERIA5String> getValues() {
    return values;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector v = new ASN1EncodableVector();
    for (ASN1Encodable m : values) {
      v.add(m);
    }
    return new DERSequence(v);
  }

  public static JWTClaimNames getInstance(Object  obj) {
    if (obj instanceof JWTClaimNames) {
      return (JWTClaimNames)obj;
    } else if (obj != null) {
      ASN1Sequence seq = ASN1Sequence.getInstance(obj);
      int seqSize = seq.size();
      if (seqSize == 0) {
        throw new IllegalArgumentException("Bad sequence size: " + seqSize);
      }

      List<String> values = new ArrayList<>(seqSize);
      for (int i = 0; i < seqSize; i++) {
        values.add(Asn1Util.getIA5String(seq.getObjectAt(i)));
      }
      return new JWTClaimNames(values);
    } else {
      throw new IllegalArgumentException("invalid object null");
    }
  }

}
