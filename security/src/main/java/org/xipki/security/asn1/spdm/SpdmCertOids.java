// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.asn1.spdm;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.xipki.util.codec.Args;

import java.util.ArrayList;
import java.util.List;

/**
 * <pre>
 * id-spdm-cert-oids ::= SEQUENCE SIZE (1..MAX) OF id-spdm-cert-oid
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class SpdmCertOids extends ASN1Object {

  private final List<SpdmCertOid> values;

  public SpdmCertOids(List<SpdmCertOid> values) {
    this.values = Args.notEmpty(values, "values");
  }

  public List<SpdmCertOid> getValues() {
    return values;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector v = new ASN1EncodableVector();
    for (SpdmCertOid m : values) {
      v.add(m);
    }
    return new DERSequence(v);
  }

  public static SpdmCertOids getInstance(Object  obj) {
    if (obj instanceof SpdmCertOids) {
      return (SpdmCertOids)obj;
    } else if (obj != null) {
      ASN1Sequence seq = ASN1Sequence.getInstance(obj);
      int seqSize = seq.size();
      if (seqSize == 0) {
        throw new IllegalArgumentException("Bad sequence size: " + seqSize);
      }

      List<SpdmCertOid> values = new ArrayList<>(seqSize);
      for (int i = 0; i < seqSize; i++) {
        values.add(SpdmCertOid.getInstance(seq.getObjectAt(i)));
      }
      return new SpdmCertOids(values);
    } else {
      throw new IllegalArgumentException("invalid object null");
    }
  }

}
