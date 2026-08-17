// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.asn1.tcg;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.x509.OtherName;
import org.xipki.security.OIDs;
import org.xipki.security.exception.BadCertTemplateException;

/**
 * TCG Parser with utility methods.
 *
 * @author Lijun Liao (xipki)
 */
public class TcgParser {

  public static ASN1Object parseTcgAttributeValue(
      ASN1ObjectIdentifier attrType, ASN1Set attrValue) {
    int size = attrValue.size();
    if (size != 1) {
      throw new IllegalArgumentException("invalid attrValue.size() " + size);
    }

    ASN1Primitive sAttrValue = attrValue.getObjectAt(0).toASN1Primitive();
    if (OIDs.TCG.tcg_at_tcgPlatformSpecification.equals(attrType)) {
      return TCGPlatformSpecification.getInstance(sAttrValue);
    } else if (OIDs.TCG.tcg_at_tcgCredentialSpecification.equals(attrType)) {
      return TCGSpecificationVersion.getInstance(sAttrValue);
    } else if (OIDs.TCG.tcg_at_tcgCredentialType.equals(attrType)) {
      return TCGCredentialType.getInstance(sAttrValue);
    } else if (OIDs.TCG.tcg_at_platformConfiguration_v3.equals(attrType)) {
      return PlatformConfigurationV3.getInstance(sAttrValue);
    } else if (OIDs.TCG.tcg_at_platformConfigUri_v3.equals(attrType)) {
      return Traits.getInstance(sAttrValue);
    } else if (OIDs.TCG.tcg_at_previousPlatformCertificates.equals(attrType)) {
      return Traits.getInstance(sAttrValue);
    } else if (OIDs.TCG.tcg_at_tbbSecurityAssertions_v3.equals(attrType)) {
      return Traits.getInstance(sAttrValue);
    } else if (OIDs.TCG.tcg_at_cryptographicAnchors.equals(attrType)) {
      return Traits.getInstance(sAttrValue);
    } else if (OIDs.TCG.tcg_at_platformOwnership.equals(attrType)) {
      return Traits.getInstance(sAttrValue);
    } else if (OIDs.TCG.tcg_at_manufacturingAssertions.equals(attrType)) {
      return Traits.getInstance(sAttrValue);
    } else {
      return sAttrValue;
    }
  }

  public static ASN1Encodable parseTcgOtherName(OtherName otherName)
      throws BadCertTemplateException {
    ASN1ObjectIdentifier type = otherName.getTypeID();
    ASN1Encodable value = otherName.getValue();
    if (OIDs.TCG.tcg_at_platformIdentifier.equals(type)) {
      try {
        return Traits.getInstance(value);
      } catch (RuntimeException e) {
        throw new BadCertTemplateException(
            "invalid tcg_at_platformIdentifier, message=" + e.getMessage());
      }
    } else {
      return value;
    }
  }

}
