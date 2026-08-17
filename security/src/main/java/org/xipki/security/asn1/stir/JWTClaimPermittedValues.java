// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.asn1.stir;

import org.bouncycastle.asn1.*;
import org.xipki.security.util.Asn1Util;
import org.xipki.util.codec.Args;

import java.util.ArrayList;
import java.util.List;

/**
 * RFC 8226:
 * <pre>
 * JWTClaimPermittedValues ::= SEQUENCE {
 *    claim      JWTClaimName,
 *    permitted  SEQUENCE SIZE (1..MAX) OF UTF8String
 * }
 *
 * JWTClaimName ::= IA5String
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class JWTClaimPermittedValues extends ASN1Object {

  private final DERIA5String claim;

  private final List<DERUTF8String> permitted;

  public JWTClaimPermittedValues(String claim, List<String> permitted) {
    this.claim = new DERIA5String(Args.notNull(claim, "claim"));

    Args.notEmpty(permitted, "permitted");
    this.permitted = new ArrayList<>(permitted.size());
    for (String value : permitted) {
      this.permitted.add(new DERUTF8String(value));
    }
  }

  public DERIA5String getClaim() {
    return claim;
  }

  public List<DERUTF8String> getPermitted() {
    return permitted;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector v = new ASN1EncodableVector();
    v.add(claim);
    v.add(new DERSequence(permitted.toArray(new ASN1Encodable[0])));
    return new DERSequence(v);
  }

  public static JWTClaimPermittedValues getInstance(Object  obj) {
    if (obj instanceof JWTClaimPermittedValues) {
      return (JWTClaimPermittedValues)obj;
    } else if (obj != null) {
      ASN1Sequence seq = ASN1Sequence.getInstance(obj);
      int seqSize = seq.size();
      if (seqSize == 2) {
        throw new IllegalArgumentException("Bad sequence size: " + seqSize);
      }

      String claim = Asn1Util.getIA5String(seq.getObjectAt(0));
      ASN1Sequence seq1 = (ASN1Sequence) seq.getObjectAt(1);
      int seq1Size = seq1.size();
      List<String> permitted = new ArrayList<>(seq1Size);
      for (int i = 0; i < seq1Size; i++) {
        permitted.add(Asn1Util.getIA5String(seq1.getObjectAt(i)));
      }
      return new JWTClaimPermittedValues(claim, permitted);
    } else {
      throw new IllegalArgumentException("invalid object null");
    }
  }

}
