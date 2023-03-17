// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.profile;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.xipki.util.Args;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Container of extension value control.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class ExtensionValues {

  private final Map<ASN1ObjectIdentifier, ExtensionValue> extensions = new HashMap<>();

  public boolean addExtension(ASN1ObjectIdentifier type, boolean critical, ASN1Encodable value) {
    Args.notNull(type, "type");
    Args.notNull(value, "value");

    if (extensions.containsKey(type)) {
      return false;
    }
    extensions.put(type, new ExtensionValue(critical, value));
    return true;
  } // method addExtension

  public boolean addExtension(ASN1ObjectIdentifier type, ExtensionValue value) {
    Args.notNull(type, "type");
    Args.notNull(value, "value");

    if (extensions.containsKey(type)) {
      return false;
    }
    extensions.put(type, value);
    return true;
  } // method addExtension

  public Set<ASN1ObjectIdentifier> getExtensionTypes() {
    return Collections.unmodifiableSet(extensions.keySet());
  }

  public ExtensionValue getExtensionValue(ASN1ObjectIdentifier type) {
    return extensions.get(Args.notNull(type, "type"));
  }

  public ExtensionValue removeExtensionTuple(ASN1ObjectIdentifier type) {
    return extensions.remove(Args.notNull(type, "type"));
  }

  public boolean containsExtension(ASN1ObjectIdentifier type) {
    return extensions.containsKey(Args.notNull(type, "type"));
  }

  public int size() {
    return extensions.size();
  }

}
