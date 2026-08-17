// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.asn1.tcg;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.xipki.security.OIDs;
import org.xipki.util.codec.Args;

/**
 * <pre>
 * TCGCredentialType::= SEQUENCE {
 *     certificateType CredentialType}
 *
 * CredentialType ::= OBJECT IDENTIFIER (tcg-kp-PlatformAttributeCertificate |
 *     tcg-kp-PlatformKeyCertificate |
 *     tcg-kp-AdditionalPlatformAttributeCertificate |
 *     tcg-kp-AdditionalPlatformKeyCertificate |
 *     tcg-kp-DeltaPlatformAttributeCertificate |
 *     tcg-kp-DeltaPlatformKeyCertificate )
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class TCGCredentialType extends ASN1Object {

  private final ASN1ObjectIdentifier certificateType;

  public TCGCredentialType(ASN1ObjectIdentifier certificateType) {
    this.certificateType = Args.notNull(certificateType, "certificateType");

    if (!(OIDs.TCG.tcg_kp_PlatformAttributeCertificate.equals(certificateType) ||
        OIDs.TCG.tcg_kp_PlatformKeyCertificate.equals(certificateType) ||
        OIDs.TCG.tcg_kp_AdditionalPlatformAttributeCertificate.equals(certificateType) ||
        OIDs.TCG.tcg_kp_DeltaPlatformAttributeCertificate.equals(certificateType) ||
        OIDs.TCG.tcg_kp_DeltaPlatformKeyCertificate.equals(certificateType))) {
      throw new IllegalArgumentException("invalid certificateType " + certificateType.getId());
    }
  }

  public ASN1ObjectIdentifier certificateType() {
    return certificateType;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    return new DERSequence(certificateType);
  }

  public static TCGCredentialType getInstance(Object  obj) {
    if (obj instanceof TCGCredentialType) {
      return (TCGCredentialType) obj;
    } else if (obj instanceof ASN1Sequence) {
      ASN1Sequence seq = (ASN1Sequence) obj;
      int size = seq.size();
      if (size != 1) {
        throw new IllegalArgumentException("invalid sequence.size() " + seq.size());
      }

      ASN1ObjectIdentifier type = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
      return new TCGCredentialType(type);
    } else {
      return getInstance(ASN1Sequence.getInstance(obj));
    }
  }

}
