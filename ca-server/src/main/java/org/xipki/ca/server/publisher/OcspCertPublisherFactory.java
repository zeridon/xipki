// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.server.publisher;

import org.xipki.ca.api.publisher.CertPublisher;
import org.xipki.ca.api.publisher.CertPublisherFactory;
import org.xipki.util.exception.ObjectCreationException;

import java.util.Collections;
import java.util.Set;

/**
 * Factory of {@link OcspCertPublisher}.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class OcspCertPublisherFactory implements CertPublisherFactory {

  private static final String TYPE = "ocsp";

  private static final Set<String> types = Set.copyOf(Collections.singletonList(TYPE));

  @Override
  public Set<String> getSupportedTypes() {
    return types;
  }

  @Override
  public boolean canCreatePublisher(String type) {
    return types.contains(type.toLowerCase());
  }

  @Override
  public CertPublisher newPublisher(String type) throws ObjectCreationException {
    if (TYPE.equalsIgnoreCase(type)) {
      return new OcspCertPublisher();
    } else {
      throw new ObjectCreationException("unknown publisher type " + type);
    }
  }

}
