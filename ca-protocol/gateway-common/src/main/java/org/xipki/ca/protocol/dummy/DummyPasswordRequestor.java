package org.xipki.ca.protocol.dummy;

import org.xipki.ca.protocol.Requestor;
import org.xipki.security.X509Cert;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author Lijun Liao
 * @since 6.0.0
 */

public class DummyPasswordRequestor implements Requestor {

  private String user;

  private byte[] keyId;

  private char[] password;

  private static Map<String, char[]> passwordMap = new HashMap<>();

  static {
    System.err.println("DO NOT USE "
        + DummyPasswordRequestor.class.getName()
        + " IN THE PRODUCT ENVIRONMENT");
    passwordMap.put("user1", "password1".toCharArray());
    passwordMap.put("user2", "password2".toCharArray());
  }

  private DummyPasswordRequestor(String user, char[] password) {
    this.user = user;
    this.keyId = user.getBytes(StandardCharsets.UTF_8);
    this.password = password;
  }

  public static DummyPasswordRequestor ofUser(String user) {
    char[] password = passwordMap.get(user);
    if (password == null) {
      return null;
    }
    return new DummyPasswordRequestor(user, password);
  }

  public static DummyPasswordRequestor ofKeyId(byte[] keyId) {
    String user = new String(keyId, StandardCharsets.UTF_8);
    char[] password = passwordMap.get(user);
    if (password == null) {
      return null;
    }
    return new DummyPasswordRequestor(user, password);
  }

  @Override
  public String getName() {
    return user;
  }

  @Override
  public char[] getPassword() {
    return password;
  }

  @Override
  public byte[] getKeyId() {
    return keyId;
  }

  @Override
  public X509Cert getCert() {
    throw new UnsupportedOperationException("getCert() unsupported");
  }

  @Override
  public boolean authenticate(char[] password) {
    return Arrays.equals(this.password, password);
  }

  @Override
  public boolean authenticate(byte[] password) {
    char[] charPassword = password == null ? null
        : new String(password, StandardCharsets.UTF_8).toCharArray();
    return authenticate(charPassword);
  }

  @Override
  public boolean isCertprofilePermitted(String certprofile) {
    return true;
  }

  @Override
  public boolean isPermitted(int permission) {
    return true;
  }
}
