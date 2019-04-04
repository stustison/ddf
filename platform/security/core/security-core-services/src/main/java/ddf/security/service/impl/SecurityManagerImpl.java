/**
 * Copyright (c) Codice Foundation
 *
 * <p>This is free software: you can redistribute it and/or modify it under the terms of the GNU
 * Lesser General Public License as published by the Free Software Foundation, either version 3 of
 * the License, or any later version.
 *
 * <p>This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details. A copy of the GNU Lesser General Public
 * License is distributed along with this program and can be found at
 * <http://www.gnu.org/licenses/lgpl.html>.
 */
package ddf.security.service.impl;

import ddf.security.Subject;
import ddf.security.impl.SubjectImpl;
import ddf.security.service.SecurityManager;
import ddf.security.service.SecurityServiceException;
import java.util.Collection;
import java.util.UUID;
import org.apache.cxf.ws.security.tokenstore.SecurityToken;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.session.mgt.SimpleSession;
import org.codice.ddf.security.handler.api.OidcAuthenticationToken;
import org.codice.ddf.security.handler.api.SAMLAuthenticationToken;
import org.pac4j.oidc.credentials.OidcCredentials;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SecurityManagerImpl implements SecurityManager {

  private static final Logger LOGGER = LoggerFactory.getLogger(SecurityManagerImpl.class);

  private DefaultSecurityManager internalManager;

  /** Creates a new security manager with the collection of given realms. */
  public SecurityManagerImpl() {
    // create the new security manager
    internalManager = new DefaultSecurityManager();
  }

  /** @param realms The realms used for the backing authZ and authN operations. */
  public void setRealms(Collection<Realm> realms) {
    // update the default manager with current realm list
    LOGGER.debug("Updating manager with {} realms.", realms.size());
    internalManager.setRealms(realms);
  }

  public Subject getSubject(Object token) throws SecurityServiceException {
    AuthenticationToken authenticationToken = null;
    if (token instanceof AuthenticationToken) {
      authenticationToken = (AuthenticationToken) token;
    } else if (token instanceof SecurityToken) {
      authenticationToken = new SAMLAuthenticationToken(null, (SecurityToken) token, "karaf");
    } else if (token instanceof OidcCredentials) {
      authenticationToken = new OidcAuthenticationToken(null, "karaf", token);
    }

    if (authenticationToken != null) {
      return getSubject(authenticationToken);
    } else {
      throw new SecurityServiceException(
          "Incoming token object NOT supported by security manager implementation. Currently supported types are AuthenticationToken and SecurityToken");
    }
  }

  /**
   * Creates a new subject based on an incoming AuthenticationToken
   *
   * @param token AuthenticationToken that should be used to authenticate the user and use as the
   *     basis for the new subject.
   * @return new subject
   * @throws SecurityServiceException
   */
  private Subject getSubject(AuthenticationToken token) throws SecurityServiceException {
    if (token.getCredentials() == null) {
      throw new SecurityServiceException(
          "CANNOT AUTHENTICATE USER: Authentication token did not contain any credentials. "
              + "This is generally due to an error on the authentication server.");
    }
    AuthenticationInfo info = internalManager.authenticate(token);
    try {
      return new SubjectImpl(
          info.getPrincipals(),
          true,
          new SimpleSession(UUID.randomUUID().toString()),
          internalManager);
    } catch (Exception e) {
      throw new SecurityServiceException("Could not create a new subject", e);
    }
  }
}
