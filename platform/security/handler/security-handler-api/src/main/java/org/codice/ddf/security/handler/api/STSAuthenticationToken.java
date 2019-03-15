package org.codice.ddf.security.handler.api;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class STSAuthenticationToken extends BaseAuthenticationToken {

  private static final Logger LOGGER = LoggerFactory.getLogger(STSAuthenticationToken.class);

  public STSAuthenticationToken(Object principal, String realm, Object credentials) {
    super(principal, realm, credentials);
  }

  /**
   * Returns the credentials as an XML string suitable for injecting into a STS request. This
   * default behavior assumes that the credentials actually are stored in their XML representation.
   * If a subclass stores them differently, it is up to them to override this method.
   *
   * @return String containing the XML representation of this token's credentials
   */
  @Override
  public String getCredentialsAsString() {
    String retVal = "";
    if (getCredentials() != null) {
      retVal = getCredentials().toString();
    } else {
      LOGGER.debug("Credentials are null - unable to create XML representation.");
    }

    return retVal;
  }
}
