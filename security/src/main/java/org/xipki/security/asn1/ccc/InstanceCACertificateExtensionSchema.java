// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.security.asn1.ccc;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.xipki.util.codec.Args;

import java.math.BigInteger;

/**
 * CCC InstanceCACertificateExtensionSchema.
 * <pre>
 * InstanceCACertificateExtensionSchema ::= SEQUENCE {
 *     extension_version    INTEGER (1..255),
 *     applet_version       OCTET STRING (SIZE (4)),
 *     platform_information OCTET STRING (SIZE (1..20)) OPTIONAL
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class InstanceCACertificateExtensionSchema extends ASN1Object {

  private final ASN1Integer extensionVersion;

  private final ASN1OctetString appletVersion;

  private final ASN1OctetString platformInformation;

  public InstanceCACertificateExtensionSchema(
      int extensionVersion, byte[] appletVersion, byte[] platformInformation) {
    Args.range(extensionVersion, "extensionVersion", 1, 255);
    this.extensionVersion = new ASN1Integer(BigInteger.valueOf(extensionVersion));
    Args.fixedLen(appletVersion, "appletVersion", 4);
    this.appletVersion = new DEROctetString(appletVersion);

    if (platformInformation == null) {
      this.platformInformation = null;
    } else {
      Args.variableLen(platformInformation, "platformInformation", 1, 20);
      this.platformInformation = new DEROctetString(platformInformation);
    }
  }

  public ASN1Integer getExtensionVersion() {
    return extensionVersion;
  }

  public ASN1OctetString getAppletVersion() {
    return appletVersion;
  }

  public ASN1OctetString getPlatformInformation() {
    return platformInformation;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector vec = new ASN1EncodableVector(platformInformation == null ? 2 : 3);
    vec.add(extensionVersion);
    vec.add(appletVersion);
    if (platformInformation != null) {
      vec.add(platformInformation);
    }
    return new DERSequence(vec);
  }

  public static InstanceCACertificateExtensionSchema getInstance(Object  obj) {
    if (obj instanceof InstanceCACertificateExtensionSchema) {
      return (InstanceCACertificateExtensionSchema)obj;
    } else if (obj != null) {
      ASN1Sequence seq = ASN1Sequence.getInstance(obj);
      int seqSize = seq.size();
      if (seqSize != 2 && seqSize != 3) {
        throw new IllegalArgumentException("Bad sequence size: " + seqSize);
      }

      int extensionVersion = ASN1Integer.getInstance(seq.getObjectAt(0)).intValueExact();
      byte[] appletVersion = DEROctetString.getInstance(seq.getObjectAt(1)).getOctets();
      byte[] platformInformation = seqSize == 2 ? null
          : DEROctetString.getInstance(seq.getObjectAt(2)).getOctets();
      return new InstanceCACertificateExtensionSchema(extensionVersion, appletVersion,
          platformInformation);
    } else {
      throw new IllegalArgumentException("invalid object null");
    }
  }

}
