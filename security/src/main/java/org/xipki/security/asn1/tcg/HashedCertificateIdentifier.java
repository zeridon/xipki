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
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.xipki.util.codec.Args;

/**
 * <pre>
 * HashedCertificateIdentifier ::= SEQUENCE {
 *     hashAlgorithm AlgorithmIdentifier,
 *     hashOverSignatureValue OCTET STRING
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class HashedCertificateIdentifier extends ASN1Object {

  private final AlgorithmIdentifier hashAlgorithm;

  private final byte[] hashOverSignatureValue;

  public HashedCertificateIdentifier(AlgorithmIdentifier hashAlgorithm,
                                     byte[] hashOverSignatureValue) {
    this.hashAlgorithm = Args.notNull(hashAlgorithm, "hashAlgorithm");
    this.hashOverSignatureValue = Args.notEmpty(hashOverSignatureValue, "hashOverSignatureValue");
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    return new DERSequence(new ASN1Encodable[] {
        hashAlgorithm, new DEROctetString(hashOverSignatureValue) });
  }

  public static HashedCertificateIdentifier getInstance(Object  obj) {
    if (obj instanceof HashedCertificateIdentifier) {
      return (HashedCertificateIdentifier) obj;
    } else if (obj instanceof ASN1Sequence) {
      ASN1Sequence seq = (ASN1Sequence) obj;
      int size = seq.size();
      if (size != 2) {
        throw new IllegalArgumentException("invalid sequence.size() " + seq.size());
      }

      return new HashedCertificateIdentifier(AlgorithmIdentifier.getInstance(seq.getObjectAt(0)),
          ((ASN1OctetString) seq.getObjectAt(1)).getOctets());
    } else {
      return getInstance(ASN1Sequence.getInstance(obj));
    }
  }

}
