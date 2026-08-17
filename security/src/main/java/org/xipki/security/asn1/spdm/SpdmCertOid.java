// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.asn1.spdm;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.xipki.security.OIDs;
import org.xipki.util.codec.Args;

/**
 * https://www.dmtf.org/sites/default/files/standards/documents/DSP0274_1.4.1.pdf
 *
 * <pre>
 * id-spdm-cert-oid ::= SEQUENCE {
 *    spdmOID           OBJECT IDENTIFIER,
 *    spdmOIDdefinition OCTET STRING OPTIONAL
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class SpdmCertOid extends ASN1Object {

  private final ASN1ObjectIdentifier spdmOID;

  private final ASN1OctetString spdmOIDdefinition;

  public SpdmCertOid(ASN1ObjectIdentifier spdmOID) {
    this(spdmOID, null);
  }

  public SpdmCertOid(ASN1ObjectIdentifier spdmOID, byte[] spdmOIDdefinition) {
    this.spdmOID = Args.notNull(spdmOID, "spdmOID");
    if (spdmOID.equals(OIDs.Spdm.id_DMTF_hardware_identity)
        || spdmOID.equals(OIDs.Spdm.id_DMTF_mutable_certificate)) {
      if (spdmOIDdefinition != null) {
        throw new IllegalArgumentException("spdmOIDdefinition shall not be non-null");
      }
    }

    this.spdmOIDdefinition = spdmOIDdefinition == null ? null
        : new DEROctetString(spdmOIDdefinition);
  }

  public ASN1ObjectIdentifier getSpdmOID() {
    return spdmOID;
  }

  public ASN1OctetString getSpdmOIDdefinition() {
    return spdmOIDdefinition;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector v = new ASN1EncodableVector();
    v.add(spdmOID);
    if (spdmOIDdefinition != null) {
      v.add(spdmOID);
    }
    return new DERSequence(v);
  }

  public static SpdmCertOid getInstance(Object  obj) {
    if (obj instanceof SpdmCertOid) {
      return (SpdmCertOid)obj;
    } else if (obj != null) {
      ASN1Sequence seq = ASN1Sequence.getInstance(obj);
      int seqSize = seq.size();
      if (!(seqSize >= 1 && seqSize <= 2)) {
        throw new IllegalArgumentException("Bad sequence size: " + seqSize);
      }

      ASN1ObjectIdentifier spdmOID = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
      byte[] spdmOIDdefinition = null;
      if (seqSize > 1) {
        spdmOIDdefinition = ((ASN1OctetString) seq.getObjectAt(1)).getOctets();
      }
      return new SpdmCertOid(spdmOID, spdmOIDdefinition);
    } else {
      throw new IllegalArgumentException("invalid object null");
    }
  }

}
