// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.asn1.tcg;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.xipki.util.codec.Args;

/**
 * <pre>
 * tCGPlatformSpecification ATTRIBUTE ::= {
 *     WITH SYNTAX TCGPlatformSpecification
 *     ID tcg-at-tcgPlatformSpecification }
 *
 * TCGPlatformSpecification ::= SEQUENCE {
 *     version TCGSpecificationVersion,
 *     platformClass OCTET STRING (SIZE(4)) }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class TCGPlatformSpecification extends ASN1Object {

  private final TCGSpecificationVersion version;

  private final byte[] platformClass;

  public TCGPlatformSpecification(TCGSpecificationVersion version, byte[] platformClass) {
    this.version = Args.notNull(version, "version");
    this.platformClass = Args.notNull(platformClass, "platformClass");
    Args.equals(platformClass.length, "platformClass.length", 4);
  }

  public TCGSpecificationVersion getVersion() {
    return version;
  }

  public byte[] getPlatformClass() {
    return platformClass;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    return new DERSequence(new ASN1Encodable[] {version, new DEROctetString(platformClass)});
  }

  public static TCGPlatformSpecification getInstance(Object  obj) {
    if (obj instanceof TCGPlatformSpecification) {
      return (TCGPlatformSpecification) obj;
    } else if (obj instanceof ASN1Sequence) {
      ASN1Sequence seq = (ASN1Sequence) obj;
      if (seq.size() != 2) {
        throw new IllegalArgumentException("invalid sequence.size() " + seq.size());
      }

      return new TCGPlatformSpecification(
          TCGSpecificationVersion.getInstance(seq.getObjectAt(0)),
          ((ASN1OctetString) seq.getObjectAt(1)).getOctets());
    } else {
      return getInstance(ASN1Sequence.getInstance(obj));
    }
  }

}
