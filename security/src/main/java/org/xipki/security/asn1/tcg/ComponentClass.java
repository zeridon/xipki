// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.asn1.tcg;

import org.bouncycastle.asn1.ASN1Encodable;
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
 * <pre>
 * ComponentClass ::= SEQUENCE {
 *     componentClassRegistry ComponentClassRegistry,
 *     componentClassValue    OCTET STRING (SIZE(4))
 * }
 *
 * ; tcg-registry-componentClass-storage is renamed to tcg-registry-componentClass-disk.
 * ComponentClassRegistry ::= OBJECT IDENTIFIER ( tcg-registry-componentClass-tcg
 *                 | tcg-registry-componentClass-dmtf
 *                 | tcg-registry-componentClass-pcie
 *                 | tcg-registry-componentClass-disk )
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class ComponentClass extends ASN1Object {

  private final ASN1ObjectIdentifier componentClassRegistry;

  private final byte[] componentClassValue;

  public ComponentClass(ASN1ObjectIdentifier componentClassRegistry, byte[] componentClassValue) {
    this.componentClassRegistry = Args.notNull(componentClassRegistry, "componentClassRegistry");
    this.componentClassValue = Args.notNull(componentClassValue, "componentClassValue");
    Args.equals(componentClassValue.length, "componentClassValue.length", 4);

    if (!(OIDs.TCG.tcg_registry_componentClass_tcg.equals(componentClassRegistry) ||
        OIDs.TCG.tcg_registry_componentClass_dmtf.equals(componentClassRegistry) ||
        OIDs.TCG.tcg_registry_componentClass_pcie.equals(componentClassRegistry) ||
        OIDs.TCG.tcg_registry_componentClass_disk.equals(componentClassRegistry))) {
      throw new IllegalArgumentException(
          "invalid componentClassRegistry " + componentClassRegistry.getId());
    }
  }

  public ASN1ObjectIdentifier componentClassRegistry() {
    return componentClassRegistry;
  }

  public byte[] componentClassValue() {
    return componentClassValue;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    return new DERSequence(new ASN1Encodable[] {
        componentClassRegistry, new DEROctetString(componentClassValue)});
  }

  public static ComponentClass getInstance(Object  obj) {
    if (obj instanceof ComponentClass) {
      return (ComponentClass) obj;
    } else if (obj instanceof ASN1Sequence) {
      ASN1Sequence seq = (ASN1Sequence) obj;
      int size = seq.size();
      if (size != 2) {
        throw new IllegalArgumentException("invalid sequence.size() " + seq.size());
      }

      ASN1ObjectIdentifier componentClass = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
      byte[] value = ((ASN1OctetString) seq.getObjectAt(1)).getOctets();
      return new ComponentClass(componentClass, value);
    } else {
      return getInstance(ASN1Sequence.getInstance(obj));
    }
  }

}
