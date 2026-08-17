// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.asn1.ccc;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.xipki.util.codec.Args;

/**
 * CCC InstanceCACertificateExtensionSchema.
 * <pre>
 * SBxDKisCertificateExtensionSchema ::= SEQUENCE {
 *     key_server_provider_identifier UTF8String (SIZE (1..32)),
 *     service_provider_identifier    UTF8String (SIZE (1..32)),
 *     service_identifier             UTF8String (SIZE (1..32))
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class SBxDKisCertificateExtensionSchema extends ASN1Object {

  private final ASN1OctetString keyServerProviderIdentifier;

  private final ASN1OctetString serviceProvideIdentifier;

  private final ASN1OctetString serviceIdentifier;

  public SBxDKisCertificateExtensionSchema(
      byte[] keyServerProviderIdentifier, byte[] serviceProvideIdentifier,
      byte[] serviceIdentifier) {
    Args.variableLen(keyServerProviderIdentifier, "keyServerProviderIdentifier", 1, 32);
    Args.variableLen(serviceProvideIdentifier, "serviceProvideIdentifier", 1, 32);
    Args.variableLen(serviceIdentifier, "serviceIdentifier", 1, 32);

    this.keyServerProviderIdentifier = new DEROctetString(keyServerProviderIdentifier);
    this.serviceProvideIdentifier = new DEROctetString(serviceProvideIdentifier);
    this.serviceIdentifier = new DEROctetString(serviceIdentifier);
  }

  public ASN1OctetString getKeyServerProviderIdentifier() {
    return keyServerProviderIdentifier;
  }

  public ASN1OctetString getServiceProvideIdentifier() {
    return serviceProvideIdentifier;
  }

  public ASN1OctetString getServiceIdentifier() {
    return serviceIdentifier;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector vec = new ASN1EncodableVector(3);
    vec.add(keyServerProviderIdentifier);
    vec.add(serviceProvideIdentifier);
    vec.add(serviceIdentifier);
    return new DERSequence(vec);
  }

  public static SBxDKisCertificateExtensionSchema getInstance(Object  obj) {
    if (obj instanceof SBxDKisCertificateExtensionSchema) {
      return (SBxDKisCertificateExtensionSchema)obj;
    } else if (obj != null) {
      ASN1Sequence seq = ASN1Sequence.getInstance(obj);
      int seqSize = seq.size();
      if (seqSize != 3) {
        throw new IllegalArgumentException("Bad sequence size: " + seqSize);
      }

      byte[] keyServerProviderIdentifier =
          DEROctetString.getInstance(seq.getObjectAt(0)).getOctets();
      byte[] serviceProvideIdentifier = DEROctetString.getInstance(seq.getObjectAt(1)).getOctets();
      byte[] serviceIdentifier = DEROctetString.getInstance(seq.getObjectAt(2)).getOctets();
      return new SBxDKisCertificateExtensionSchema(keyServerProviderIdentifier,
          serviceProvideIdentifier, serviceIdentifier);
    } else {
      throw new IllegalArgumentException("invalid object null");
    }
  }

}
