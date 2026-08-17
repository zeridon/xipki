// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.asn1.tcg;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSequence;
import org.xipki.security.util.Asn1Util;
import org.xipki.util.codec.Args;

/**
 * <pre>
 * ISO9000Certification ::= SEQUENCE {
 *     iso9000Certified BOOLEAN DEFAULT FALSE,
 *     iso9000Uri       IA5String (SIZE (1..URIMAX)) OPTIONAL
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class ISO9000Certification extends ASN1Object {

  private final boolean iso9000Certified;

  private final String iso9000Uri;

  public ISO9000Certification(boolean iso9000Certified, String iso9000Uri) {
    this.iso9000Certified = iso9000Certified;
    this.iso9000Uri = Args.lengthRange(iso9000Uri, "iso9000Uri", 1, TcgConstants.URIMAX);
  }

  public String iso9000Uri() {
    return iso9000Uri;
  }

  public boolean iso9000Certified() {
    return iso9000Certified;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector v = new ASN1EncodableVector(9);
    if (iso9000Certified) {
      v.add(ASN1Boolean.TRUE);
    }
    v.add(new DERIA5String(iso9000Uri));

    return new DERSequence(v);
  }

  public static ISO9000Certification getInstance(Object  obj) {
    if (obj instanceof ISO9000Certification) {
      return (ISO9000Certification) obj;
    } else if (obj instanceof ASN1Sequence) {
      ASN1Sequence seq = (ASN1Sequence) obj;
      int size = seq.size();
      if (size != 1 && size != 2) {
        throw new IllegalArgumentException("invalid sequence.size() " + seq.size());
      }

      boolean certified = false;
      if (size == 2) {
        certified = ((ASN1Boolean) seq.getObjectAt(0)).isTrue();
      }
      String uri = Asn1Util.getIA5String(seq.getObjectAt(size - 1));

      return new ISO9000Certification(certified, uri);
    } else {
      return getInstance(ASN1Sequence.getInstance(obj));
    }
  }

}
