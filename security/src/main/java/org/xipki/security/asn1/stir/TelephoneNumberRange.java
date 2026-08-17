// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.asn1.stir;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSequence;
import org.xipki.security.util.Asn1Util;
import org.xipki.util.codec.Args;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * RFC 8226: TelephoneNumberRange
 * <pre>
 *  TelephoneNumberRange ::= SEQUENCE {
 *     start TelephoneNumber,
 *     count INTEGER (2..MAX),
 *     ...
 *  }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class TelephoneNumberRange extends ASN1Object {

  private final DERIA5String start;

  private final ASN1Integer count;

  private final List<ASN1Encodable> extraFields;

  public TelephoneNumberRange(String start, BigInteger count) {
    this(start, count, null);
  }

  public TelephoneNumberRange(String start, BigInteger count, List<ASN1Encodable> extraFields) {
    this.start = new DERIA5String(TNEntry.assertValidTelephoneNumber(start, "start"));
    Args.notNull(count, "count");
    if (count.compareTo(BigInteger.TWO) < 0) {
      throw new IllegalArgumentException("count not in (2..MAX)");
    }
    this.count = new ASN1Integer(count);
    this.extraFields = extraFields;
  }

  public DERIA5String getStart() {
    return start;
  }

  public ASN1Integer getCount() {
    return count;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    if (extraFields == null || extraFields.isEmpty()) {
      return new DERSequence(new ASN1Encodable[] {start, count});
    } else {
      ASN1EncodableVector vec = new ASN1EncodableVector(2 + extraFields.size());
      vec.add(start);
      vec.add(count);
      for (ASN1Encodable m : extraFields) {
        vec.add(m);
      }
      return new DERSequence(vec);
    }
  }

  public static TelephoneNumberRange getInstance(Object  obj) {
    if (obj instanceof TelephoneNumberRange) {
      return (TelephoneNumberRange)obj;
    } else if (obj != null) {
      ASN1Sequence seq = ASN1Sequence.getInstance(obj);
      int seqSize = seq.size();
      if (seqSize < 2) {
        throw new IllegalArgumentException("Bad sequence size: " + seqSize);
      }

      String start = Asn1Util.getIA5String(seq.getObjectAt(0));
      ASN1Integer count = (ASN1Integer) seq.getObjectAt(1);
      List<ASN1Encodable> extraFields = null;
      if (seqSize > 2) {
        extraFields = new ArrayList<>(seqSize - 2);
        for (int i = 2; i < seqSize; i++) {
          extraFields.add(seq.getObjectAt(i));
        }
      }
      return new TelephoneNumberRange(start, count.getValue(), extraFields);
    } else {
      throw new IllegalArgumentException("invalid object null");
    }
  }

}
