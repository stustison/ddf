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
package org.codice.ddf.security.handler.api;

import org.pac4j.core.context.WebContext;

public class OidcAuthenticationToken extends BaseAuthenticationToken {
  private WebContext webContext;

  public OidcAuthenticationToken(Object credentials, WebContext webContext, String ip) {
    super(null, credentials, ip);

    this.webContext = webContext;
  }

  @Override
  public String getCredentialsAsString() {
    return null;
  }

  public WebContext getWebContext() {
    return webContext;
  }
}
