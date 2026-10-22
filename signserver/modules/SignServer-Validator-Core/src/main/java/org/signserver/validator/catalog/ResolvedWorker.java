package org.signserver.validator.catalog;

/*************************************************************************
 *                                                                       *
 *  SignServer: The OpenSource Automated Signing Server                  *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;
import org.signserver.validator.catalog.CatalogModel.MetadataKeySpec;
import org.signserver.validator.catalog.CatalogModel.PatternSpec;
import org.signserver.validator.catalog.CatalogModel.PropertySpec;
import org.signserver.validator.catalog.CatalogModel.RuleSpec;

/**
 * Everything the catalog says about one concrete worker configuration, after
 * resolving inherited groups and the conditional groups that apply.
 *
 * @version $Id$
 */
public final class ResolvedWorker {

    /** A property together with the catalog file declaring it. */
    public record SourcedProperty(String name, PropertySpec spec, String file) {
    }

    /** A property name pattern together with the catalog file declaring it. */
    public record SourcedPattern(Pattern pattern, PatternSpec spec, String file) {
    }

    /** A rule together with the catalog file declaring it. */
    public record SourcedRule(RuleSpec rule, String file) {
    }

    /** A request metadata key together with the catalog file declaring it. */
    public record SourcedMetadataKey(String name, MetadataKeySpec spec, String file) {
    }

    private final String name;
    private final String kind;
    private final boolean known;
    private final String file;
    private final Set<String> capabilities;
    private final Map<String, SourcedProperty> properties;
    private final List<SourcedPattern> patterns;
    private final List<SourcedRule> rules;
    private final List<SourcedRule> combinationRules;
    private final Map<String, SourcedMetadataKey> metadataKeys;
    private final boolean metadataAllowUnknown;

    ResolvedWorker(final String name, final String kind, final boolean known,
            final String file, final Set<String> capabilities,
            final Map<String, SourcedProperty> properties,
            final List<SourcedPattern> patterns, final List<SourcedRule> rules,
            final List<SourcedRule> combinationRules,
            final Map<String, SourcedMetadataKey> metadataKeys,
            final boolean metadataAllowUnknown) {
        this.name = name;
        this.kind = kind;
        this.known = known;
        this.file = file;
        this.capabilities = Collections.unmodifiableSet(capabilities);
        this.properties = Collections.unmodifiableMap(properties);
        this.patterns = Collections.unmodifiableList(patterns);
        this.rules = Collections.unmodifiableList(rules);
        this.combinationRules = Collections.unmodifiableList(combinationRules);
        this.metadataKeys = Collections.unmodifiableMap(metadataKeys);
        this.metadataAllowUnknown = metadataAllowUnknown;
    }

    /** @return catalog worker name (e.g. CMSSigner) or the class name when unknown */
    public String getName() {
        return name;
    }

    /** @return signer, crypto, ... or null when not known */
    public String getKind() {
        return kind;
    }

    /** @return true if a worker file of the catalog matched the configuration */
    public boolean isKnown() {
        return known;
    }

    /** @return catalog file of the worker, or null when unknown */
    public String getFile() {
        return file;
    }

    public Set<String> getCapabilities() {
        return capabilities;
    }

    public Map<String, SourcedProperty> getProperties() {
        return properties;
    }

    public List<SourcedRule> getRules() {
        return rules;
    }

    public List<SourcedRule> getCombinationRules() {
        return combinationRules;
    }

    public Map<String, SourcedMetadataKey> getMetadataKeys() {
        return metadataKeys;
    }

    public boolean isMetadataAllowUnknown() {
        return metadataAllowUnknown;
    }

    /**
     * @param propertyName upper-case property name
     * @return the declaration of the property, by exact name or by pattern
     */
    public Optional<SourcedProperty> property(final String propertyName) {
        final SourcedProperty exact = properties.get(propertyName);
        if (exact != null) {
            return Optional.of(exact);
        }
        for (SourcedPattern p : patterns) {
            if (p.pattern().matcher(propertyName).matches()) {
                final PatternSpec ps = p.spec();
                return Optional.of(new SourcedProperty(propertyName,
                        new PropertySpec(ps.type(), null, null, ps.allowedValues(),
                                null, null, null, null, ps.description(),
                                ps.source(), null, null, ps.sensitive(), null),
                        p.file()));
            }
        }
        return Optional.empty();
    }

    /** @return true if the property value must not be shown in reports */
    public boolean isSensitive(final String propertyName) {
        return property(propertyName).map(p -> Boolean.TRUE.equals(p.spec().sensitive())).orElse(false);
    }
}
