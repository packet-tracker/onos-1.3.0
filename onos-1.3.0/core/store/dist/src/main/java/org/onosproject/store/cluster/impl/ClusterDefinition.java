/*
 * Copyright 2015 Open Networking Laboratory
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.onosproject.store.cluster.impl;

import java.util.Set;

import com.google.common.collect.ImmutableSet;

/**
 * Cluster definition.
 */
public class ClusterDefinition {

    private Set<NodeInfo> nodes;
    private String ipPrefix;

    /**
     * Creates a new cluster definition.
     * @param nodes cluster nodes information
     * @param ipPrefix ip prefix common to all cluster nodes
     * @return cluster definition
     */
    public static ClusterDefinition from(Set<NodeInfo> nodes, String ipPrefix) {
        ClusterDefinition definition = new ClusterDefinition();
        definition.ipPrefix = ipPrefix;
        definition.nodes = ImmutableSet.copyOf(nodes);
        return definition;
    }

    /**
     * Returns set of cluster nodes info.
     * @return cluster nodes info
     */
    public Set<NodeInfo> getNodes() {
        return ImmutableSet.copyOf(nodes);
    }

    /**
     * Returns ipPrefix in dotted decimal notion.
     * @return ip prefix
     */
    public String getIpPrefix() {
        return ipPrefix;
    }
}