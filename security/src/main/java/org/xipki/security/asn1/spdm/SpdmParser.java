// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.asn1.spdm;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.OtherName;
import org.xipki.security.OIDs;
import org.xipki.security.exception.BadCertTemplateException;
import org.xipki.security.util.Asn1Util;

/**
 * SPDM Parser with utility methods.
 *
 * @author Lijun Liao (xipki)
 */
public class SpdmParser {

  public static ASN1Encodable parseSpdmOtherName(OtherName otherName)
      throws BadCertTemplateException {
    ASN1ObjectIdentifier type = otherName.getTypeID();
    ASN1Encodable value = otherName.getValue();
    if (OIDs.Spdm.id_DMTF_device_info.equals(type)) {
      String str = Asn1Util.getUTF8String(value);
      int[] indexes = new int[3];
      int j = 0;
      for (int i = 0; i < str.length(); i++) {
        char c = str.charAt(i);
        if (c == ':') {
          if (j > 2) {
            throw new BadCertTemplateException("invalid DMTF_device_info: '" + str + "'");
          }
          indexes[j++] = i;
        }
      }

      if (j != 2) {
        throw new BadCertTemplateException("invalid DMTF_device_info: '" + str + "'");
      }

      if (indexes[0] + 1 == indexes[1] || indexes[1] + 1 == indexes[2]) {
        throw new BadCertTemplateException("invalid DMTF_device_info: '" + str + "'");
      }
      return value;
    } else {
      return value;
    }
  }

}
