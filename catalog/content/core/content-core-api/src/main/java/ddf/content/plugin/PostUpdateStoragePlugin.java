/**
 * Copyright (c) Codice Foundation
 * <p>
 * This is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser
 * General Public License as published by the Free Software Foundation, either version 3 of the
 * License, or any later version.
 * <p>
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details. A copy of the GNU Lesser General Public License
 * is distributed along with this program and can be found at
 * <http://www.gnu.org/licenses/lgpl.html>.
 */
package ddf.content.plugin;

import ddf.content.operation.UpdateResponse;

/**
 * Services implementing this interface are called immediately after an item is updated in the
 * content repository.
 */
public interface PostUpdateStoragePlugin {
    /**
     * Processes the {@link UpdateResponse}.
     * <p>
     * If this storage plugin generates attributes that should be added to the resulting
     * {@code Metacard} created by the Content Cataloger Plugin, they should be inserted into a
     * {@code Map<String, Serializable>} (key = attribute name, value = attribute value) inside the
     * {@code Map<String, Serializable>} returned by {@code input.getProperties()} at the key
     * {@link ContentPlugin#STORAGE_PLUGIN_METACARD_ATTRIBUTES}.
     *
     * @param input the {@code UpdateResponse} to process
     * @return the processed {@code UpdateResponse} to pass to the next {@link PostUpdateStoragePlugin}
     * @throws PluginExecutionException if an error occurs during processing
     */
    UpdateResponse process(UpdateResponse input) throws PluginExecutionException;
}
