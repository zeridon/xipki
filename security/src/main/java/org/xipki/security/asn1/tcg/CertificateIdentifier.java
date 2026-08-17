// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.asn1.tcg;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.xipki.security.util.Asn1Util;

/**
 * <pre>
 * CertificateIdentifierTrait TRAIT ::= {
 *     SYNTAX CertificateIdentifier
 *     IDENTIFIED BY tcg-tr-ID-certificateIdentifier
 * }
 *
 * CertificateIdentifier ::= SEQUENCE {
 *     hashedCertIdentifier  [0] IMPLICIT HashedCertificateIdentifier OPTIONAL,
 *     genericCertIdentifier [1] IMPLICIT IssuerSerial OPTIONAL
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class CertificateIdentifier extends ASN1Object {

  private final HashedCertificateIdentifier hashedCertIdentifier;

  private final IssuerSerial genericCertIdentifier;

  public CertificateIdentifier(HashedCertificateIdentifier hashedCertIdentifier,
                               IssuerSerial genericCertIdentifier) {
    if (hashedCertIdentifier == null && genericCertIdentifier == null) {
      throw new IllegalArgumentException(
          "hashedCertIdentifier and genericCertIdentifier must not be both null");
    }

    this.hashedCertIdentifier = hashedCertIdentifier;
    this.genericCertIdentifier = genericCertIdentifier;
  }

  public HashedCertificateIdentifier hashedCertIdentifier() {
    return hashedCertIdentifier;
  }

  public IssuerSerial genericCertIdentifier() {
    return genericCertIdentifier;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector v = new ASN1EncodableVector();
    if (hashedCertIdentifier != null) {
      v.add(new DERTaggedObject(false, 0, hashedCertIdentifier));
    }

    if (genericCertIdentifier != null) {
      v.add(new DERTaggedObject(false, 1, genericCertIdentifier));
    }
    return new DERSequence(v);
  }

  public static CertificateIdentifier getInstance(Object  obj) {
    if (obj instanceof CertificateIdentifier) {
      return (CertificateIdentifier) obj;
    } else if (obj instanceof ASN1Sequence) {
      ASN1Sequence seq = (ASN1Sequence) obj;
      int size = seq.size();
      if (size < 1 || size > 2) {
        throw new IllegalArgumentException("invalid sequence.size() " + seq.size());
      }

      HashedCertificateIdentifier hashedCertIdentifier = null;
      IssuerSerial genericCertIdentifier = null;

      int index = 0;
      ASN1Encodable item = seq.getObjectAt(index++);

      while (item instanceof ASN1TaggedObject) {
        int tag = ((ASN1TaggedObject) item).getTagNo();
        if (tag == 0) {
          if (hashedCertIdentifier != null) {
            throw new IllegalArgumentException("duplicated tag " + tag);
          }

          if (genericCertIdentifier != null) {
            throw new IllegalArgumentException("incorrect position of tag " + tag);
          }

          hashedCertIdentifier = HashedCertificateIdentifier.getInstance(
              Asn1Util.getImplicitBaseObject((ASN1TaggedObject) item, BERTags.SEQUENCE));
          item = index < size ? seq.getObjectAt(index++) : null;
        } else if (tag == 1) {
          if (genericCertIdentifier != null) {
            throw new IllegalArgumentException("duplicated tag " + tag);
          }

          genericCertIdentifier = IssuerSerial.getInstance(
              Asn1Util.getImplicitBaseObject((ASN1TaggedObject) item, BERTags.SEQUENCE));
          item = index < size ? seq.getObjectAt(index++) : null;
        }
      }

      return new CertificateIdentifier(hashedCertIdentifier, genericCertIdentifier);
    } else {
      return getInstance(ASN1Sequence.getInstance(obj));
    }
  }

}
