// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.security.asn1.ccc;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.xipki.security.util.Asn1Util;
import org.xipki.util.codec.Args;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * CCC InstanceCACertificateExtensionSchema.
 *
 * Note it is not specified whether the tags [0] and [1] is IMPLICIT or
 * EXPLICIT. We assume in this class the "EXPLICIT" which is also
 * for the "extensions" in the TBSCertificate.
 *
 * <pre>
 * EndpointCertificateExtensionSchema ::= SEQUENCE {
 *     extension_version    INTEGER (1..255),
 *     vehicle_identifier   OCTET STRING (SIZE (8)),
 *     option_group_1       OCTET STRING (SIZE (1)),
 *     option_group_2       OCTET STRING (SIZE (1)),
 *     protocol_version     OCTET STRING (SIZE (2)),
 *     vehicle_PK           PublicKey,
 *     initial_key_slot     OCTET STRING (SIZE (1..8)),
 *     authorized_PK_list   SEQUENCE (SIZE (1..5)) OF PublicKey OPTIONAL,
 *     confidential_mailbox_size [0] INTEGER (1..65535) OPTIONAL,
 *     private_mailbox_size      [1] INTEGER (1..65535) OPTIONAL,
 *     account_info_hash         OCTET STRING (SIZE (32)) OPTIONAL
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class EndpointCertificateExtensionSchema extends ASN1Object {

  private final ASN1Integer extensionVersion;

  private final ASN1OctetString vehicleIdentifier;

  private final ASN1OctetString optionGroup1;

  private final ASN1OctetString optionGroup2;

  private final ASN1OctetString protocolVersion;

  private final SubjectPublicKeyInfo vehiclePK;

  private final ASN1OctetString initialKeySlot;

  private final List<SubjectPublicKeyInfo> authorizedPKList;

  private final ASN1Integer confidentialMailboxSize;

  private final ASN1Integer privateMailboxSize;

  private final ASN1OctetString accountInfoHash;

  public EndpointCertificateExtensionSchema(
      int extensionVersion, byte[] vehicleIdentifier, byte optionGroup1, byte optionGroup2,
      byte[] protocolVersion, SubjectPublicKeyInfo vehiclePK, byte[] initialKeySlot) {
    this(extensionVersion, vehicleIdentifier, optionGroup1, optionGroup2,
        protocolVersion, vehiclePK, initialKeySlot,
        null, null, null, null);
  }

  public EndpointCertificateExtensionSchema(
      int extensionVersion, byte[] vehicleIdentifier, byte optionGroup1, byte optionGroup2,
      byte[] protocolVersion, SubjectPublicKeyInfo vehiclePK, byte[] initialKeySlot,
      List<SubjectPublicKeyInfo> authorizedPKList,
      Integer confidentialMailboxSize, Integer privateMailboxSize, byte[] accountInfoHash) {
    Args.range(extensionVersion, "extensionVersion", 1, 255);
    this.extensionVersion = new ASN1Integer(BigInteger.valueOf(extensionVersion));
    this.vehicleIdentifier = new DEROctetString(
        Args.fixedLen(vehicleIdentifier, "vehicleIdentifier", 8));
    this.optionGroup1 = new DEROctetString(new byte[]{optionGroup1});
    this.optionGroup2 = new DEROctetString(new byte[]{optionGroup2});
    this.protocolVersion = new DEROctetString(
        Args.fixedLen(protocolVersion, "protocolVersion", 2));
    this.vehiclePK = Args.notNull(vehiclePK, "vehiclePK");

    this.initialKeySlot = new DEROctetString(
        Args.variableLen(initialKeySlot, "initialKeySlot", 1, 8));

    if (authorizedPKList == null || authorizedPKList.isEmpty()) {
      this.authorizedPKList = null;
    } else {
      this.authorizedPKList = authorizedPKList;
    }

    if (confidentialMailboxSize == null) {
      this.confidentialMailboxSize = null;
    } else {
      this.confidentialMailboxSize = new ASN1Integer(BigInteger.valueOf(
          Args.range(confidentialMailboxSize, "confidentialMailboxSize", 1, 65535)));
    }

    if (privateMailboxSize == null) {
      this.privateMailboxSize = null;
    } else {
      this.privateMailboxSize = new ASN1Integer(BigInteger.valueOf(
          Args.range(privateMailboxSize, "privateMailboxSize", 1, 65535)));
    }

    if (accountInfoHash == null) {
      this.accountInfoHash = null;
    } else {
      this.accountInfoHash = new DEROctetString(
          Args.fixedLen(accountInfoHash, "accountInfoHash", 32));
    }
  }

  public ASN1Integer getExtensionVersion() {
    return extensionVersion;
  }

  public ASN1OctetString getVehicleIdentifier() {
    return vehicleIdentifier;
  }

  public ASN1OctetString getOptionGroup1() {
    return optionGroup1;
  }

  public ASN1OctetString getOptionGroup2() {
    return optionGroup2;
  }

  public ASN1OctetString getProtocolVersion() {
    return protocolVersion;
  }

  public SubjectPublicKeyInfo getVehiclePK() {
    return vehiclePK;
  }

  public ASN1OctetString getInitialKeySlot() {
    return initialKeySlot;
  }

  public List<SubjectPublicKeyInfo> getAuthorizedPKList() {
    return authorizedPKList;
  }

  public ASN1Integer getConfidentialMailboxSize() {
    return confidentialMailboxSize;
  }

  public ASN1Integer getPrivateMailboxSize() {
    return privateMailboxSize;
  }

  public ASN1OctetString getAccountInfoHash() {
    return accountInfoHash;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector vec = new ASN1EncodableVector(11);
    vec.add(extensionVersion);
    vec.add(vehicleIdentifier);
    vec.add(optionGroup1);
    vec.add(optionGroup2);
    vec.add(protocolVersion);
    vec.add(vehiclePK);
    vec.add(initialKeySlot);
    if (authorizedPKList != null) {
      vec.add(new DERSequence(authorizedPKList.toArray(new ASN1Encodable[0])));
    }

    if (confidentialMailboxSize != null) {
      vec.add(new DERTaggedObject(true, 0, confidentialMailboxSize));
    }

    if (privateMailboxSize != null) {
      vec.add(new DERTaggedObject(true, 1, privateMailboxSize));
    }

    if (accountInfoHash != null) {
      vec.add(accountInfoHash);
    }
    return new DERSequence(vec);
  }

  /*
 *     extension_version    INTEGER (1..255),
 *     vehicle_identifier   OCTET STRING (SIZE (8)),
 *     option_group_1       OCTET STRING (SIZE (1)),
 *     option_group_2       OCTET STRING (SIZE (1)),
 *     protocol_version     OCTET STRING (SIZE (2)),
 *     vehicle_PK           PublicKey,
 *     initial_key_slot     OCTET STRING (SIZE (1..8)),
 *     authorized_PK_list   SEQUENCE (SIZE (1..5)) OF PublicKey OPTIONAL,
 *     confidential_mailbox_size [0] INTEGER (1..65535) OPTIONAL,
 *     private_mailbox_size      [1] INTEGER (1..65535) OPTIONAL,
 *     account_info_hash         OCTET STRING (SIZE (32)) OPTIONAL
   */

  public static EndpointCertificateExtensionSchema getInstance(Object  obj) {
    if (obj instanceof EndpointCertificateExtensionSchema) {
      return (EndpointCertificateExtensionSchema)obj;
    } else if (obj != null) {
      ASN1Sequence seq = ASN1Sequence.getInstance(obj);
      int seqSize = seq.size();
      if (seqSize < 7) {
        throw new IllegalArgumentException("Bad sequence size: " + seqSize);
      }

      int extensionVersion = ((ASN1Integer) seq.getObjectAt(0)).intValueExact();
      byte[] vehicleIdentifier = ((ASN1OctetString) seq.getObjectAt(1)).getOctets();
      byte[] optionGroup1 = ((ASN1OctetString) seq.getObjectAt(2)).getOctets();
      Args.fixedLen(optionGroup1, "optionGroup1", 1);

      byte[] optionGroup2 = ((ASN1OctetString) seq.getObjectAt(3)).getOctets();
      Args.fixedLen(optionGroup2, "optionGroup2", 1);

      byte[] protocolVersion = ((ASN1OctetString) seq.getObjectAt(4)).getOctets();
      SubjectPublicKeyInfo vehiclePK = SubjectPublicKeyInfo.getInstance(seq.getObjectAt(5));
      byte[] initialKeySlot = ((ASN1OctetString) seq.getObjectAt(6)).getOctets();

      List<SubjectPublicKeyInfo> authorizedPKList = null;
      Integer confidentialMailboxSize = null;
      Integer privateMailboxSize = null;
      byte[] accountInfoHash = null;

      for  (int i = 7; i < seqSize; i++) {
        ASN1Encodable e = seq.getObjectAt(i);
        boolean valid = true;
        if (e instanceof ASN1Sequence) {
          if (authorizedPKList != null || confidentialMailboxSize != null
              || privateMailboxSize != null || accountInfoHash != null) {
            valid = false;
          } else {
            ASN1Sequence seq1 = (ASN1Sequence) e;
            int seq1Size = seq1.size();
            authorizedPKList = new ArrayList<>(seq1Size);
            for (int j = 0; j < seq1Size; j++) {
              authorizedPKList.add(SubjectPublicKeyInfo.getInstance(seq1.getObjectAt(j)));
            }
          }
        } else if (e instanceof ASN1TaggedObject) {
          int tag = ((ASN1TaggedObject) e).getTagNo();
          ASN1Encodable value = Asn1Util.getBaseObject((ASN1TaggedObject) e);
          if (tag == 0) {
            if (confidentialMailboxSize != null || privateMailboxSize != null
                || accountInfoHash != null) {
              valid = false;
            } else {
              confidentialMailboxSize = ((ASN1Integer) value).intValueExact();
            }
          } else if (tag == 1) {
            if (privateMailboxSize != null || accountInfoHash != null) {
              valid = false;
            } else {
              privateMailboxSize = ((ASN1Integer) value).intValueExact();
            }
          } else {
            valid = false;
          }
        } else if (e instanceof ASN1OctetString) {
          accountInfoHash = ((ASN1OctetString) e).getOctets();
        }

        if (!valid) {
          throw new IllegalArgumentException("invalid element at index " + i);
        }
      }

      return new EndpointCertificateExtensionSchema(extensionVersion, vehicleIdentifier,
          optionGroup1[0], optionGroup2[0], protocolVersion, vehiclePK, initialKeySlot,
          authorizedPKList, confidentialMailboxSize, privateMailboxSize, accountInfoHash);
    } else {
      throw new IllegalArgumentException("invalid object null");
    }
  }

}
