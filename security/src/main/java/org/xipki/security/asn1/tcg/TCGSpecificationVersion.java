// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.asn1.tcg;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.xipki.util.codec.Args;

import java.math.BigInteger;

/**
 * <pre>
 * tCGCredentialSpecification ATTRIBUTE ::= {
 *     WITH SYNTAX TCGSpecificationVersion
 *     ID tcg-at-tcgCredentialSpecification }
 *
 * TCGSpecificationVersion ::= SEQUENCE {
 *     majorVersion  INTEGER,
 *     minorVersion  INTEGER,
 *     revision      INTEGER }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class TCGSpecificationVersion extends ASN1Object {

  private final long majorVersion;

  private final long minorVersion;

  private final long revision;

  public TCGSpecificationVersion(long majorVersion, long minorVersion, long revision) {
    this.majorVersion = Args.notNegative(majorVersion, "majorVersion");
    this.minorVersion = Args.notNegative(minorVersion, "minorVersion");
    this.revision     = Args.notNegative(revision, "revision");
  }

  public long majorVersion() {
    return majorVersion;
  }

  public long minorVersion() {
    return minorVersion;
  }

  public long revision() {
    return revision;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    return new DERSequence(new ASN1Encodable[] {
        new ASN1Integer(BigInteger.valueOf(majorVersion)),
        new ASN1Integer(BigInteger.valueOf(minorVersion)),
        new ASN1Integer(BigInteger.valueOf(revision))
    });
  }

  public static TCGSpecificationVersion getInstance(Object  obj) {
    if (obj instanceof TCGSpecificationVersion) {
      return (TCGSpecificationVersion) obj;
    } else if (obj instanceof ASN1Sequence) {
      ASN1Sequence seq = (ASN1Sequence) obj;
      if (seq.size() != 3) {
        throw new IllegalArgumentException("invalid sequence.size() " + seq.size());
      }

      return new TCGSpecificationVersion(
          ((ASN1Integer) seq.getObjectAt(0)).longValueExact(),
          ((ASN1Integer) seq.getObjectAt(0)).longValueExact(),
          ((ASN1Integer) seq.getObjectAt(0)).longValueExact());
    } else {
      return getInstance(ASN1Sequence.getInstance(obj));
    }
  }

}
