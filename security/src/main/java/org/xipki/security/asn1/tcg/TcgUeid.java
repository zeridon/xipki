// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.asn1.tcg;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.xipki.util.codec.Args;

/**
 * Defined in
 * https://trustedcomputinggroup.org/wp-content/uploads/DICE-Attestation-Architecture-v1.2_pub.pdf
 *
 * 6.1.4 UEID Extension
 * This extension contains a UEID [9] that identifies the device containing
 * the private key and is identified by the ertificate’s subjectPublicKey. In
 * the case of its inclusion as a CRL extension, the device containing the
 * private key is identified by the certificate serial number, which
 * identifies the certificate containing the subjectPublicKey.
 *
 * The OID declaration of DiceUeid is as follows:
 * <pre>
 * tcg-dice-Ueid OBJECT IDENTIFIER ::= {tcg-dice ueid(4) }
 * </pre>
 *
 * The ASN.1 definition is as follows:
 *
 * <pre>
 * TcgUeid ::= SEQUENCE {
 *     ueid OCTET STRING
 * }
 * </pre>
 *
 * When filling in the UEID extension, the issuer must ensure that the content
 * of this extension contributes to the CDI which generated the subject key
 * (such that a change in the field value will cause a change in the CDI).
 *
 * @author Lijun Liao (xipki)
 */
public class TcgUeid extends ASN1Object {

  private final byte[] ueid;

  public TcgUeid(byte[] ueid) {
    this.ueid = Args.notEmptyBytes(ueid, "ueid");
  }

  public byte[] ueid() {
    return ueid;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector v = new ASN1EncodableVector();
    v.add(new DEROctetString(ueid));
    return new DERSequence(v);
  }

  public static TcgUeid getInstance(Object  obj) {
    if (obj instanceof TcgUeid) {
      return (TcgUeid) obj;
    } else if (obj instanceof ASN1Sequence) {
      ASN1Sequence seq = (ASN1Sequence) obj;
      int size = seq.size();
      if (size != 1) {
        throw new IllegalArgumentException("invalid sequence.size() " + seq.size());
      }

      byte[] ueid = ((ASN1BitString) seq.getObjectAt(0)).getOctets();
      return new TcgUeid(ueid);
    } else {
      return getInstance(ASN1Sequence.getInstance(obj));
    }
  }

}
