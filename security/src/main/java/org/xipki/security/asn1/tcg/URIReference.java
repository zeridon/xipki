// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.asn1.tcg;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.xipki.security.util.Asn1Util;
import org.xipki.util.codec.Args;

/**
 * <pre>
 * -- Reference to external document containing information relevant to this subject.
 * -- The hashAlgorithm and hashValue MUST both exist in each reference if either
 * -- is present.
 * URIReference ::= SEQUENCE {
 *     uniformResourceIdentifier  IA5String (SIZE (1..URIMAX)),
 *     hashAlgorithm              AlgorithmIdentifier OPTIONAL,
 *     hashValue                  BIT STRING OPTIONAL
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class URIReference extends ASN1Object {

  private final String uri;

  private final AlgorithmIdentifier hashAlgorithm;

  private final byte[] hashValue;

  public URIReference(String uri, AlgorithmIdentifier hashAlgorithm, byte[] hashValue) {
    this.uri = Args.lengthRange(uri, "uri", 1, TcgConstants.STRMAX);
    if (hashAlgorithm == null && hashValue != null) {
      throw new IllegalArgumentException("hashAlgorithm is null but hashValue is not present");
    }
    if (hashAlgorithm != null && hashValue == null) {
      throw new IllegalArgumentException("hashAlgorithm is present but hashValue is null");
    }
    this.hashAlgorithm = hashAlgorithm;
    this.hashValue = hashValue;
  }

  public String uri() {
    return uri;
  }

  public AlgorithmIdentifier hashAlgorithm() {
    return hashAlgorithm;
  }

  public byte[] hashValue() {
    return hashValue;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector v = new ASN1EncodableVector();
    v.add(new DERIA5String(uri));
    if (hashAlgorithm != null) {
      v.add(hashAlgorithm);
      v.add(new DERBitString(hashValue));
    }
    return new DERSequence(v);
  }

  public static URIReference getInstance(Object  obj) {
    if (obj instanceof URIReference) {
      return (URIReference) obj;
    } else if (obj instanceof ASN1Sequence) {
      ASN1Sequence seq = (ASN1Sequence) obj;
      int size = seq.size();
      if (size != 1 && size != 3) {
        throw new IllegalArgumentException("invalid sequence.size() " + seq.size());
      }

      String uri = Asn1Util.getIA5String(seq.getObjectAt(0));
      AlgorithmIdentifier hashAlg = null;
      byte[] hashValue = null;
      if (size == 3) {
        hashAlg = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
        hashValue = ((ASN1BitString) seq.getObjectAt(2)).getOctets();
      }

      return new URIReference(uri, hashAlg, hashValue);
    } else {
      return getInstance(ASN1Sequence.getInstance(obj));
    }
  }

}
