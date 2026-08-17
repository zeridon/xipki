// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.asn1.tcg;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.xipki.util.codec.Args;

import java.math.BigInteger;

/**
 * <pre>
 * IssuerSerial ::= SEQUENCE {
 *     issuer     GeneralNames,
 *     serial     CertificateSerialNumber,
 *     issuerUID  UniqueIdentifier OPTIONAL
 * }
 * </pre>
 * issuerUID is not allowed in this class, since it is forbidden in the v3 certificates.
 *
 * @author Lijun Liao (xipki)
 */
public class IssuerSerial extends ASN1Object {

  private final GeneralNames issuer;

  private final BigInteger serial;

  public IssuerSerial(GeneralNames issuer, BigInteger serial) {
    this.issuer = Args.notNull(issuer, "issuer");
    this.serial = Args.notNull(serial, "serial");
  }

  public GeneralNames issuer() {
    return issuer;
  }

  public BigInteger serial() {
    return serial;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    return new DERSequence(new ASN1Encodable[] {issuer, new ASN1Integer(serial)});
  }

  public static IssuerSerial getInstance(Object  obj) {
    if (obj instanceof IssuerSerial) {
      return (IssuerSerial) obj;
    } else if (obj instanceof ASN1Sequence) {
      ASN1Sequence seq = (ASN1Sequence) obj;
      int size = seq.size();
      if (size != 6) {
        throw new IllegalArgumentException("invalid sequence.size() " + seq.size());
      }

      return new IssuerSerial(GeneralNames.getInstance(seq.getObjectAt(0)),
          ASN1Integer.getInstance(seq.getObjectAt(1)).getValue());
    } else {
      return getInstance(ASN1Sequence.getInstance(obj));
    }
  }

}
