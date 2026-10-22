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

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.List;
import java.util.Map;

/**
 * Data model of the rule catalog files, bound strictly from YAML (unknown
 * keys are rejected). See validator-rules/schema/catalog.schema.json for the
 * authoritative description of each field.
 *
 * @version $Id$
 */
public final class CatalogModel {

    private CatalogModel() {
    }

    /** catalog.yaml */
    public record IndexFile(String catalogVersion, String valueTypes,
            List<String> groups, List<String> workers,
            List<String> cliOptionGroups, List<String> cli,
            String combinations, List<String> tests) {
    }

    /** One value type definition. */
    public record TypeDef(String kind, List<String> values,
            Boolean caseInsensitive, Long min, Long max, String pattern,
            String of, String separator, List<String> types,
            String description) {
    }

    /** value-types.yaml */
    public record ValueTypesFile(Map<String, TypeDef> types) {
    }

    /** A worker property. */
    public record PropertySpec(String type, Boolean required,
            @JsonProperty("default") String defaultValue,
            List<String> allowedValues, Boolean caseSensitive, Long min,
            Long max, String invalidSeverity, String description,
            String source, String doc, String deprecated, Boolean sensitive,
            String codeRef) {
    }

    /** Properties whose names are built at runtime, e.g. USER.alice. */
    public record PatternSpec(String pattern, String type,
            List<String> allowedValues, Boolean sensitive, String description,
            String source) {
    }

    /** A rule: finding when "when" holds and "require" does not. */
    public record RuleSpec(String id, String description, JsonNode when,
            JsonNode require, String severity, String message,
            String suggestion, String property, String option,
            String source) {
    }

    /** Groups to include when a condition on the configuration holds. */
    public record ConditionalInherit(JsonNode when, List<String> groups) {
    }

    /** A key the client may send as request metadata. */
    public record MetadataKeySpec(String type, List<String> allowedValues,
            String requiresTrue, String requiresListed, String description,
            String source) {
    }

    /** Request metadata accepted by a worker. */
    public record RequestMetadataSpec(Boolean allowUnknown,
            Map<String, MetadataKeySpec> keys) {
    }

    /** Where the drift check finds the property/option constants in code. */
    public record ExtractionSpec(List<String> sources,
            List<String> ignoreConstants) {
    }

    /** common/*.yaml */
    public record GroupFile(String group, String description, String doc,
            Map<String, TypeDef> types, Map<String, PropertySpec> properties,
            List<PatternSpec> propertyPatterns,
            List<ConditionalInherit> conditionalInherits,
            List<RuleSpec> rules, List<RuleSpec> combinationRules,
            RequestMetadataSpec requestMetadata) {
    }

    /** workers/*.yaml */
    public record WorkerFile(String worker, String description, String kind,
            String doc, Map<String, String> match, List<String> capabilities,
            List<String> inherits,
            List<ConditionalInherit> conditionalInherits,
            Map<String, TypeDef> types, Map<String, PropertySpec> properties,
            List<PatternSpec> propertyPatterns, List<RuleSpec> rules,
            List<RuleSpec> combinationRules,
            RequestMetadataSpec requestMetadata, ExtractionSpec extraction) {
    }

    /** A signclient option. */
    public record OptionSpec(Boolean arg, String type,
            List<String> allowedValues, Boolean caseSensitive,
            @JsonProperty("default") String defaultValue, Boolean repeatable,
            Boolean sensitive, String description) {
    }

    /** cli/*-options.yaml: options shared by several commands. */
    public record CliOptionGroupFile(String optionGroup, String description,
            Map<String, OptionSpec> options, List<RuleSpec> rules,
            ExtractionSpec extraction) {
    }

    /** cli/*.yaml: one signclient command. */
    public record CliFile(String command, String description,
            List<String> targetKinds, List<String> workerOptions,
            List<String> optionGroups, Map<String, OptionSpec> options,
            List<RuleSpec> rules, ExtractionSpec extraction) {
    }

    /** combinations.yaml */
    public record CombinationsFile(List<RuleSpec> rules) {
    }

    /** One golden test case. */
    public record GoldenTest(String name, String description,
            @JsonProperty("extends") String extendsTest,
            Map<String, String> config, List<Map<String, String>> otherWorkers,
            String cli, Boolean strict, Boolean expectPassed,
            List<String> expectCodes, List<String> forbidCodes) {
    }

    /** tests/*.yaml */
    public record TestFile(List<GoldenTest> tests) {
    }
}
