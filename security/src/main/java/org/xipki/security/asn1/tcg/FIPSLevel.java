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
 * FIPSLevel ::= SEQUENCE {
 *     version IA5String (SIZE (1..STRMAX)), -- “140-1”, “140-2”, or “140-3”
 *     level   SecurityLevel,
 *     plus    BOOLEAN DEFAULT FALSE
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class FIPSLevel extends ASN1Object {

  private final String version;

  private final SecurityLevel level;

  private final boolean plus;

  public FIPSLevel(String version, SecurityLevel level, boolean plus) {
    this.version = Args.lengthRange(version, "version", 1, TcgConstants.STRMAX);
    this.level = Args.notNull(level, "level");
    this.plus = plus;
  }

  public String version() {
    return version;
  }

  public SecurityLevel level() {
    return level;
  }

  public boolean plus() {
    return plus;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector v = new ASN1EncodableVector(3);
    v.add(new DERIA5String(version));
    v.add(level);
    if (plus) {
      v.add(ASN1Boolean.TRUE);
    }

    return new DERSequence(v);
  }

  public static FIPSLevel getInstance(Object  obj) {
    if (obj instanceof FIPSLevel) {
      return (FIPSLevel) obj;
    } else if (obj instanceof ASN1Sequence) {
      ASN1Sequence seq = (ASN1Sequence) obj;
      int size = seq.size();
      if (size != 2 && size != 3) {
        throw new IllegalArgumentException("invalid sequence.size() " + seq.size());
      }

      String version = Asn1Util.getIA5String(seq.getObjectAt(0));
      SecurityLevel level = SecurityLevel.getInstance(seq.getObjectAt(1));
      boolean plus = false;
      if (size > 2) {
        plus = ((ASN1Boolean) seq.getObjectAt(2)).isTrue();
      }

      return new FIPSLevel(version, level, plus);
    } else {
      return getInstance(ASN1Sequence.getInstance(obj));
    }
  }

}
