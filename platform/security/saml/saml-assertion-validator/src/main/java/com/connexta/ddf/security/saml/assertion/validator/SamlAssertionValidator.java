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
package com.connexta.ddf.security.saml.assertion.validator;

import ddf.security.http.SessionFactory;
import java.security.cert.X509Certificate;
import org.apache.cxf.ws.security.tokenstore.SecurityToken;
import org.codice.ddf.platform.filter.AuthenticationFailureException;

public interface SamlAssertionValidator {

  void validate(SecurityToken token, X509Certificate[] certs, String requestUri)
      throws AuthenticationFailureException;

  void setSignatureProperties(String signatureProperties);

  String getSignatureProperties(String signatureProperties);

  void setSessionFactory(SessionFactory sessionFactory);
}
