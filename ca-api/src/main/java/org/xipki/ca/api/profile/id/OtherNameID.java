// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.profile.id;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.xipki.security.OIDs;
import org.xipki.util.codec.Args;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * OtherName Type definition.
 *
 * @author Lijun Liao (xipki)
 */
public class OtherNameID extends AbstractID {

  private static final Map<String, OtherNameID> typeMap = new HashMap<>();

  public static final OtherNameID DMTF_device_info =
      initOf(OIDs.Spdm.id_DMTF_device_info, "DMTF-device-info");

  public static final OtherNameID tcg_platformIdentifier =
      initOf(OIDs.TCG.tcg_at_platformIdentifier, "TCG-platformIdentifier");

  public static final OtherNameID hardwareModuleName =
      initOf(OIDs.X509.id_on_hardwareModuleName, "HardwareModuleName");

  public static final OtherNameID smtpUTF8Mailbox =
      initOf(OIDs.X509.id_on_SmtpUTF8Mailbox, "SmtpUTF8Mailbox");

  public static final OtherNameID macAddress =
      initOf(OIDs.X509.id_on_MACAddress, "MACAddress");

  private OtherNameID(ASN1ObjectIdentifier x509, List<String> aliases) {
    super(x509, aliases);
  }

  private static OtherNameID initOf(ASN1ObjectIdentifier oid, String alias) {
    Args.notNull(oid, "oid");
    List<String> l = new ArrayList<>();
    l.add(alias);
    l.add(oid.getId());
    return addToMap(new OtherNameID(oid, l), typeMap);
  }

  public static OtherNameID ofOid(ASN1ObjectIdentifier oid) {
    Args.notNull(oid, "oid");
    OtherNameID attr = ofOidOrName(typeMap, oid.getId());
    if (attr != null) {
      return attr;
    }

    return new OtherNameID(oid, Collections.singletonList(oid.getId()));
  }

  public static OtherNameID ofOidOrName(String oidOrName) {
    String c14n = canonicalizeAlias(Args.notNull(oidOrName, "oidOrName"));
    OtherNameID id = ofOidOrName(typeMap, c14n);
    if (id != null) {
      return id;
    }

    try {
      ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(c14n);
      return new OtherNameID(oid, Collections.singletonList(oid.getId()));
    } catch (RuntimeException e) {
      return null;
    }
  }

}
