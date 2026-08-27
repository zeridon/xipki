// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.util;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1PrintableString;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1UTF8String;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

/**
 * Asn1 Util.
 *
 * @author Lijun Liao (xipki)
 */
public class Asn1Util {

  public static ASN1Encodable getImplicitBaseObject(
      ASN1TaggedObject taggedObject, int baseObjTagNo) {
    return taggedObject.getBaseUniversal(false, baseObjTagNo);
  }

  public static byte[] getPublicKeyData(SubjectPublicKeyInfo ski) {
    return ski.getPublicKeyData().getOctets();
  }

  public static String getIA5String(ASN1Encodable str) {
    return ASN1IA5String.getInstance(str).getString();
  }

  public static String getPrintableString(ASN1Encodable str) {
    return ASN1PrintableString.getInstance(str).getString();
  }

  public static String getUTF8String(ASN1Encodable str) {
    return ASN1UTF8String.getInstance(str).getString();
  }

  public static byte[] getOctetStringOctets(Object obj) {
    return ASN1OctetString.getInstance(obj).getOctets();
  }

}
