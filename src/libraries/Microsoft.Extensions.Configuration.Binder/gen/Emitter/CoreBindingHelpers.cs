﻿// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text.RegularExpressions;
using Microsoft.CodeAnalysis;
using SourceGenerators;

namespace Microsoft.Extensions.Configuration.Binder.SourceGeneration
{
    public sealed partial class ConfigurationBindingGenerator
    {
        private sealed partial class Emitter
        {
            private int _valueSuffixIndex;
            private bool _emitBlankLineBeforeNextStatement;
            private static readonly Regex s_arrayBracketsRegex = new(Regex.Escape("[]"));

            private bool ShouldEmitMethods(MethodsToGen_CoreBindingHelper methods) => (_bindingHelperInfo.MethodsToGen & methods) != 0;

            private void EmitCoreBindingHelpers()
            {
                Debug.Assert(_emitBlankLineBeforeNextStatement);
                EmitBindingExtStartRegion("Core binding");
                EmitConfigurationKeyCaches();
                EmitGetCoreMethod();
                EmitGetValueCoreMethod();
                EmitBindCoreMainMethod();
                EmitBindCoreMethods();
                EmitInitializeMethods();
                EmitHelperMethods();
                EmitBindingExtEndRegion();
            }

            private void EmitConfigurationKeyCaches()
            {
                if (_bindingHelperInfo.TypesForGen_BindCore is not { Count: not 0 } types)
                {
                    return;
                }

                EmitBlankLineIfRequired();

                foreach (TypeSpec type in types)
                {
                    if (type is not ObjectSpec objectType)
                    {
                        continue;
                    }

                    Debug.Assert(_typeIndex.HasBindableMembers(objectType));

                    HashSet<string>? keys = null;
                    static string GetCacheElement(MemberSpec member) => $@"""{member.ConfigurationKeyName}""";

                    if (objectType.ConstructorParameters?.Select(m => GetCacheElement(m)) is IEnumerable<string> paramNames)
                    {
                        keys = new(paramNames);
                    }

                    if (objectType.Properties?.Select(m => GetCacheElement(m)) is IEnumerable<string> propNames)
                    {
                        if (keys is null)
                        {
                            keys = new(propNames);
                        }
                        else
                        {
                            keys.UnionWith(propNames);
                        }
                    }

                    // Type has bindable members.
                    Debug.Assert(keys is not null);

                    string configKeysSource = string.Join(", ", keys);
                    string fieldName = TypeIndex.GetConfigKeyCacheFieldName(objectType);
                    _writer.WriteLine($@"private readonly static Lazy<{TypeDisplayString.HashSetOfString}> {fieldName} = new(() => new {TypeDisplayString.HashSetOfString}(StringComparer.OrdinalIgnoreCase) {{ {configKeysSource} }});");
                }
            }

            private void EmitGetCoreMethod()
            {
                if (_bindingHelperInfo.TypesForGen_GetCore is not { Count: not 0 } targetTypes)
                {
                    return;
                }

                EmitBlankLineIfRequired();
                EmitStartBlock($"public static object? {nameof(MethodsToGen_CoreBindingHelper.GetCore)}(this {Identifier.IConfiguration} {Identifier.configuration}, Type {Identifier.type}, Action<{Identifier.BinderOptions}>? {Identifier.configureOptions})");

                EmitCheckForNullArgument_WithBlankLine(Identifier.configuration, _emitThrowIfNullMethod);

                _writer.WriteLine($"{Identifier.BinderOptions}? {Identifier.binderOptions} = {Identifier.GetBinderOptions}({Identifier.configureOptions});");
                _writer.WriteLine();

                EmitIConfigurationHasValueOrChildrenCheck(voidReturn: false);

                bool isFirstType = true;
                foreach (TypeSpec type in targetTypes)
                {
                    TypeSpec effectiveType = _typeIndex.GetEffectiveTypeSpec(type);

                    Debug.Assert(effectiveType is UnsupportedTypeSpec || _typeIndex.CanBindTo(type.TypeRef));

                    string conditionKindExpr = GetConditionKindExpr(ref isFirstType);

                    EmitStartBlock($"{conditionKindExpr} ({Identifier.type} == typeof({type.TypeRef.FullyQualifiedName}))");

                    switch (effectiveType)
                    {
                        case ParsableFromStringSpec stringParsableType:
                            {
                                EmitCastToIConfigurationSection();

                                EmitStartBlock($"if ({Identifier.TryGetConfigurationValue}({Identifier.configuration}, {Identifier.key}: null, out string? {Identifier.value}))");
                                EmitBindingLogic(
                                    stringParsableType,
                                    Identifier.value,
                                    Expression.sectionPath,
                                    writeOnSuccess: parsedValueExpr => _writer.WriteLine($"return {parsedValueExpr};"),
                                    checkForNullSectionValue: stringParsableType.StringParsableTypeKind is not StringParsableTypeKind.AssignFromSectionValue);
                                EmitEndBlock(); // End if-check for input type.
                            }
                            break;
                        case ConfigurationSectionSpec:
                            {
                                EmitCastToIConfigurationSection();
                                _writer.WriteLine($"return {Identifier.section};");
                            }
                            break;
                        case ComplexTypeSpec complexType:
                            {
                                if (_typeIndex.CanInstantiate(complexType))
                                {
                                    EmitBindingLogic(complexType, Identifier.instance, Identifier.configuration, InitializationKind.Declaration, ValueDefaulting.CallSetter);
                                    _writer.WriteLine($"return {Identifier.instance};");
                                }
                                else if (type is ObjectSpec { InitExceptionMessage: string exMsg })
                                {
                                    _writer.WriteLine($@"throw new {Identifier.InvalidOperationException}(""{exMsg}"");");
                                }
#if DEBUG
                                else
                                {
                                    Debug.Fail($"Complex should not be included for GetCore gen: {complexType.TypeRef.FullyQualifiedName}");
                                }
#endif
                            }
                            break;
                    }

                    EmitEndBlock(); // End if-check for input type.
                }

                _writer.WriteLine();
                Emit_NotSupportedException_TypeNotDetectedAsInput();
                EmitEndBlock();
                _emitBlankLineBeforeNextStatement = true;

                void EmitCastToIConfigurationSection() =>
                    _writer.WriteLine($$"""
                        if ({{Identifier.configuration}} is not {{Identifier.IConfigurationSection}} {{Identifier.section}})
                        {
                            throw new {{Identifier.InvalidOperationException}}();
                        }
                        """);
            }

            private void EmitGetValueCoreMethod()
            {
                if (_bindingHelperInfo.TypesForGen_GetValueCore is not { Count: not 0 } targetTypes)
                {
                    return;
                }

                EmitBlankLineIfRequired();
                EmitStartBlock($"public static object? {nameof(MethodsToGen_CoreBindingHelper.GetValueCore)}(this {Identifier.IConfiguration} {Identifier.configuration}, Type {Identifier.type}, string {Identifier.key})");

                EmitCheckForNullArgument_WithBlankLine(Identifier.configuration, _emitThrowIfNullMethod);
                _writer.WriteLine($@"{Identifier.IConfigurationSection} {Identifier.section} = {GetSectionFromConfigurationExpression(Identifier.key, addQuotes: false)};");
                _writer.WriteLine();

                EmitStartBlock($"if ({Identifier.TryGetConfigurationValue}({Identifier.section}, {Identifier.key}: null, out string? {Identifier.value}) && !string.IsNullOrEmpty({Identifier.value}))");

                bool isFirstType = true;
                foreach (TypeSpec type in targetTypes)
                {
                    string conditionKindExpr = GetConditionKindExpr(ref isFirstType);
                    EmitStartBlock($"{conditionKindExpr} ({Identifier.type} == typeof({type.TypeRef.FullyQualifiedName}))");

                    EmitBindingLogic(
                        (ParsableFromStringSpec)_typeIndex.GetEffectiveTypeSpec(type),
                        Identifier.value,
                        Expression.sectionPath,
                        writeOnSuccess: (parsedValueExpr) => _writer.WriteLine($"return {parsedValueExpr};"),
                        checkForNullSectionValue: false);

                    EmitEndBlock();
                }
                EmitEndBlock();

                _writer.WriteLine();
                _writer.WriteLine("return null;");
                EmitEndBlock();
                _emitBlankLineBeforeNextStatement = true;
            }

            private void EmitBindCoreMainMethod()
            {
                if (_bindingHelperInfo.TypesForGen_BindCoreMain is not { Count: not 0 } targetTypes)
                {
                    return;
                }

                EmitBlankLineIfRequired();
                EmitStartBlock($"public static void {nameof(MethodsToGen_CoreBindingHelper.BindCoreMain)}({Identifier.IConfiguration} {Identifier.configuration}, object {Identifier.instance}, Type {Identifier.type}, {TypeDisplayString.NullableActionOfBinderOptions} {Identifier.configureOptions})");
                EmitCheckForNullArgument_WithBlankLine(Identifier.instance, _emitThrowIfNullMethod, voidReturn: true);
                EmitIConfigurationHasValueOrChildrenCheck(voidReturn: true);
                _writer.WriteLine($"{Identifier.BinderOptions}? {Identifier.binderOptions} = {Identifier.GetBinderOptions}({Identifier.configureOptions});");
                _writer.WriteLine();

                bool isFirstType = true;
                foreach (ComplexTypeSpec type in targetTypes)
                {
                    ComplexTypeSpec effectiveType = (ComplexTypeSpec)_typeIndex.GetEffectiveTypeSpec(type);
                    Debug.Assert(_typeIndex.HasBindableMembers(effectiveType));
                    string conditionKindExpr = GetConditionKindExpr(ref isFirstType);

                    EmitStartBlock($"{conditionKindExpr} ({Identifier.type} == typeof({type.TypeRef.FullyQualifiedName}))");
                    _writer.WriteLine($"var {Identifier.temp} = ({effectiveType.TypeRef.FullyQualifiedName}){Identifier.instance};");
                    EmitBindingLogic(type, Identifier.temp, Identifier.configuration, InitializationKind.None, ValueDefaulting.None);
                    _writer.WriteLine($"return;");
                    EmitEndBlock();
                }

                _writer.WriteLine();
                Emit_NotSupportedException_TypeNotDetectedAsInput();
                EmitEndBlock();
            }

            private void EmitBindCoreMethods()
            {
                if (_bindingHelperInfo.TypesForGen_BindCore is not ImmutableEquatableArray<ComplexTypeSpec> types)
                {
                    return;
                }

                foreach (ComplexTypeSpec type in types)
                {
                    Debug.Assert(_typeIndex.HasBindableMembers(type));
                    EmitBlankLineIfRequired();
                    EmitBindCoreMethod(type);
                }
            }

            private void EmitBindCoreMethod(ComplexTypeSpec type)
            {
                string objParameterExpression = $"ref {type.TypeRef.FullyQualifiedName} {Identifier.instance}";
                EmitStartBlock(@$"public static void {nameof(MethodsToGen_CoreBindingHelper.BindCore)}({Identifier.IConfiguration} {Identifier.configuration}, {objParameterExpression}, bool defaultValueIfNotFound, {Identifier.BinderOptions}? {Identifier.binderOptions})");

                ComplexTypeSpec effectiveType = (ComplexTypeSpec)_typeIndex.GetEffectiveTypeSpec(type);

                switch (effectiveType)
                {
                    case ArraySpec arrayType:
                        {
                            EmitBindCoreImplForArray(arrayType);
                        }
                        break;
                    case EnumerableSpec enumerableType:
                        {
                            EmitBindCoreImplForEnumerableWithAdd(enumerableType);
                        }
                        break;
                    case DictionarySpec dictionaryType:
                        {
                            EmitBindCoreImplForDictionary(dictionaryType);
                        }
                        break;
                    case ObjectSpec objectType:
                        {
                            EmitBindCoreImplForObject(objectType);
                        }
                        break;
                    default:
                        {
                            Debug.Fail($"Unsupported spec for bind core gen: {effectiveType.GetType()}");
                        }
                        break;
                }

                EmitEndBlock();
            }

            private void EmitInitializeMethods()
            {
                if (_bindingHelperInfo.TypesForGen_Initialize is not ImmutableEquatableArray<ObjectSpec> types)
                {
                    return;
                }

                foreach (ObjectSpec type in types)
                {
                    EmitBlankLineIfRequired();
                    EmitInitializeMethod(type);
                }
            }

            private void EmitInitializeMethod(ObjectSpec type)
            {
                Debug.Assert(type.InstantiationStrategy is ObjectInstantiationStrategy.ParameterizedConstructor);
                Debug.Assert(_typeIndex.CanInstantiate(type));
                Debug.Assert(
                    type is { Properties: not null, ConstructorParameters: not null },
                    $"Expecting type for init method, {type.DisplayString}, to have both properties and ctor params.");

                IEnumerable<PropertySpec> initOnlyProps = type.Properties
                    .Where(prop => prop.SetOnInit && _typeIndex.ShouldBindTo(prop));
                List<string> ctorArgList = new();

                EmitStartBlock($"public static {type.TypeRef.FullyQualifiedName} {GetInitializeMethodDisplayString(type)}({Identifier.IConfiguration} {Identifier.configuration}, {Identifier.BinderOptions}? {Identifier.binderOptions})");
                _emitBlankLineBeforeNextStatement = false;

                foreach (ParameterSpec parameter in type.ConstructorParameters)
                {
                    string name = parameter.Name;
                    string argExpr = parameter.RefKind switch
                    {
                        RefKind.None => name,
                        RefKind.Ref => $"ref {name}",
                        RefKind.Out => "out _",
                        RefKind.In => $"in {name}",
                        _ => throw new InvalidOperationException()
                    };

                    ctorArgList.Add(argExpr);
                    EmitBindImplForMember(parameter);
                }

                foreach (PropertySpec property in initOnlyProps)
                {
                    if (property.MatchingCtorParam is null)
                    {
                        EmitBindImplForMember(property);
                    }
                }

                string returnExpression = $"return new {type.TypeRef.FullyQualifiedName}({string.Join(", ", ctorArgList)})";
                if (!initOnlyProps.Any())
                {
                    _writer.WriteLine($"{returnExpression};");
                }
                else
                {
                    EmitStartBlock(returnExpression);
                    foreach (PropertySpec property in initOnlyProps)
                    {
                        string propertyName = property.Name;
                        _writer.WriteLine($@"{propertyName} = {propertyName},");
                    }
                    EmitEndBlock(endBraceTrailingSource: ";");
                }

                // End method.
                EmitEndBlock();
                _emitBlankLineBeforeNextStatement = true;

                void EmitBindImplForMember(MemberSpec member)
                {
                    TypeSpec memberType = _typeIndex.GetTypeSpec(member.TypeRef);
                    string parsedMemberDeclarationLhs = $"{memberType.TypeRef.FullyQualifiedName} {member.Name}";
                    string configKeyName = member.ConfigurationKeyName;

                    switch (memberType)
                    {
                        case ParsableFromStringSpec { StringParsableTypeKind: StringParsableTypeKind.AssignFromSectionValue }:
                            {
                                if (member is ParameterSpec parameter && parameter.ErrorOnFailedBinding)
                                {
                                    string condition = $@"if ({Identifier.configuration}[""{configKeyName}""] is not {parsedMemberDeclarationLhs})";
                                    EmitThrowBlock(condition);
                                    _writer.WriteLine();
                                    return;
                                }
                            }
                            break;
                        case ConfigurationSectionSpec:
                            {
                                _writer.WriteLine($"{parsedMemberDeclarationLhs} = {GetSectionFromConfigurationExpression(configKeyName)};");
                                return;
                            }
                    }

                    string bangExpr = memberType.IsValueType ? string.Empty : "!";
                    _writer.WriteLine($"{parsedMemberDeclarationLhs} = {member.DefaultValueExpr}{bangExpr};");
                    _emitBlankLineBeforeNextStatement = false;

                    bool canBindToMember = this.EmitBindImplForMember(
                        member,
                        member.Name,
                        sectionPathExpr: GetSectionPathFromConfigurationExpression(configKeyName),
                        // Since we're binding to local variables, we can always get and set
                        canSet: true,
                        canGet: true,
                        InitializationKind.None);

                    if (canBindToMember)
                    {
                        if (member is ParameterSpec parameter && parameter.ErrorOnFailedBinding)
                        {
                            // Add exception logic for parameter ctors; must be present in configuration object.
                            // In case of Arrays, we emit extra block to handle empty arrays. The throw block will not be `else` case at that time.
                            EmitThrowBlock(condition: _typeIndex.GetEffectiveTypeSpec(member.TypeRef) is ArraySpec ? $"if ({member.Name} is null)" : "else");
                        }

                        _writer.WriteLine();
                    }

                    void EmitThrowBlock(string condition) =>
                        _writer.WriteLine($$"""
                            {{condition}}
                            {
                                throw new {{Identifier.InvalidOperationException}}("{{string.Format(ExceptionMessages.ParameterHasNoMatchingConfig, type.FullName, member.Name)}}");
                            }
                            """);
                }
            }

            private void EmitHelperMethods()
            {
                // This is used all the time Get, Bind, and GetValue methods.
                EmitTryGetConfigurationValueMethod();

                // Emitted if we are to bind objects with complex members, or if we're emitting BindCoreMain or GetCore methods.
                bool emitAsConfigWithChildren = ShouldEmitMethods(MethodsToGen_CoreBindingHelper.AsConfigWithChildren);

                if (ShouldEmitMethods(MethodsToGen_CoreBindingHelper.BindCore))
                {
                    EmitBlankLineIfRequired();
                    EmitValidateConfigurationKeysMethod();
                }

                if (ShouldEmitMethods(MethodsToGen_CoreBindingHelper.BindCoreMain | MethodsToGen_CoreBindingHelper.GetCore))
                {
                    // HasValueOrChildren references this method.
                    Debug.Assert(emitAsConfigWithChildren);
                    EmitBlankLineIfRequired();
                    EmitHasValueOrChildrenMethod();
                }

                if (emitAsConfigWithChildren)
                {
                    EmitBlankLineIfRequired();
                    EmitAsConfigWithChildrenMethod();
                }

                if (ShouldEmitMethods(MethodsToGen_CoreBindingHelper.BindCoreMain | MethodsToGen_CoreBindingHelper.GetCore) ||
                    ShouldEmitMethods(MethodsToGen.ConfigBinder_Bind_instance_BinderOptions))
                {
                    EmitBlankLineIfRequired();
                    EmitGetBinderOptionsHelper();
                }

                if (_emitEnumParseMethod)
                {
                    _writer.WriteLine();
                    EmitEnumParseMethod();
                    _emitBlankLineBeforeNextStatement = true;
                }

                if (_bindingHelperInfo.TypesForGen_ParsePrimitive is { Count: not 0 } stringParsableTypes)
                {
                    foreach (ParsableFromStringSpec type in stringParsableTypes)
                    {
                        if (type.StringParsableTypeKind is not StringParsableTypeKind.Enum)
                        {
                            EmitBlankLineIfRequired();
                            EmitPrimitiveParseMethod(type);
                        }
                    }
                }
            }

            private void EmitTryGetConfigurationValueMethod()
            {
                EmitBlankLineIfRequired();
                _writer.WriteLine($$"""
                    /// <summary>Tries to get the configuration value for the specified key.</summary>
                    public static bool {{Identifier.TryGetConfigurationValue}}({{Identifier.IConfiguration}} {{Identifier.configuration}}, string {{Identifier.key}}, out string? {{Identifier.value}})
                    {
                        if ({{Identifier.configuration}} is {{Identifier.ConfigurationSection}} {{Identifier.section}})
                        {
                            return {{Identifier.section}}.TryGetValue({{Identifier.key}}, out {{Identifier.value}});
                        }

                        {{Identifier.value}} = {{Identifier.key}} != null ? {{Identifier.configuration}}[{{Identifier.key}}] : {{Identifier.configuration}} is {{Identifier.IConfigurationSection}} sec ? sec.Value : null;
                        return {{Identifier.value}} != null;
                    }
                    """);
            }

            private void EmitValidateConfigurationKeysMethod()
            {
                const string keysIdentifier = "keys";
                string exceptionMessage = string.Format(ExceptionMessages.MissingConfig, Identifier.ErrorOnUnknownConfiguration, Identifier.BinderOptions, $"{{{Identifier.type}}}", $@"{{string.Join("", "", {Identifier.temp})}}");

                EmitBlankLineIfRequired();
                _writer.WriteLine($$"""
                    /// <summary>If required by the binder options, validates that there are no unknown keys in the input configuration object.</summary>
                    public static void {{Identifier.ValidateConfigurationKeys}}(Type {{Identifier.type}}, {{TypeDisplayString.LazyHashSetOfString}} {{keysIdentifier}}, {{Identifier.IConfiguration}} {{Identifier.configuration}}, {{Identifier.BinderOptions}}? {{Identifier.binderOptions}})
                    {
                        if ({{Identifier.binderOptions}}?.{{Identifier.ErrorOnUnknownConfiguration}} is true)
                        {
                            {{TypeDisplayString.ListOfString}}? {{Identifier.temp}} = null;

                            foreach ({{Identifier.IConfigurationSection}} {{Identifier.section}} in {{Identifier.configuration}}.{{Identifier.GetChildren}}())
                            {
                                if (!{{keysIdentifier}}.Value.Contains({{Expression.sectionKey}}))
                                {
                                    ({{Identifier.temp}} ??= new {{TypeDisplayString.ListOfString}}()).Add($"'{{{Expression.sectionKey}}}'");
                                }
                            }

                            if ({{Identifier.temp}} is not null)
                            {
                                throw new InvalidOperationException($"{{exceptionMessage}}");
                            }
                        }
                    }
                    """);
            }

            private void EmitHasValueOrChildrenMethod()
            {
                _writer.WriteLine($$"""
                    public static bool {{Identifier.HasValueOrChildren}}({{Identifier.IConfiguration}} {{Identifier.configuration}})
                    {
                        if (({{Identifier.configuration}} as {{Identifier.IConfigurationSection}})?.{{Identifier.Value}} is not null)
                        {
                            return true;
                        }
                        return {{MethodsToGen_CoreBindingHelper.AsConfigWithChildren}}({{Identifier.configuration}}) is not null;
                    }
                    """);
            }

            private void EmitAsConfigWithChildrenMethod()
            {
                _writer.WriteLine($$"""
                    public static {{Identifier.IConfiguration}}? {{MethodsToGen_CoreBindingHelper.AsConfigWithChildren}}({{Identifier.IConfiguration}} {{Identifier.configuration}})
                    {
                        foreach ({{Identifier.IConfigurationSection}} _ in {{Identifier.configuration}}.{{Identifier.GetChildren}}())
                        {
                            return {{Identifier.configuration}};
                        }
                        return null;
                    }
                    """);
            }

            private void EmitGetBinderOptionsHelper()
            {
                _writer.WriteLine($$"""
                    public static {{Identifier.BinderOptions}}? {{Identifier.GetBinderOptions}}({{TypeDisplayString.NullableActionOfBinderOptions}} {{Identifier.configureOptions}})
                    {
                        if ({{Identifier.configureOptions}} is null)
                        {
                            return null;
                        }

                        {{Identifier.BinderOptions}} {{Identifier.binderOptions}} = new();
                        {{Identifier.configureOptions}}({{Identifier.binderOptions}});

                        if ({{Identifier.binderOptions}}.BindNonPublicProperties)
                        {
                            throw new NotSupportedException($"{{string.Format(ExceptionMessages.CannotSpecifyBindNonPublicProperties)}}");
                        }

                        return {{Identifier.binderOptions}};
                    }
                    """);
            }

            private void EmitEnumParseMethod()
            {
                string exceptionArg1 = string.Format(ExceptionMessages.FailedBinding, $"{{{Identifier.value} ?? \"null\"}}", $"{{{Identifier.path}}}", $"{{typeof(T)}}");

                string parseEnumCall = _emitGenericParseEnum ? "Enum.Parse<T>(value, ignoreCase: true)" : "(T)Enum.Parse(typeof(T), value, ignoreCase: true)";
                _writer.WriteLine($$"""
                    public static T ParseEnum<T>(string value, string? path) where T : struct
                    {
                        try
                        {
                            return {{parseEnumCall}};
                        }
                        catch ({{Identifier.Exception}} {{Identifier.exception}})
                        {
                            throw new {{Identifier.InvalidOperationException}}($"{{exceptionArg1}}", {{Identifier.exception}});
                        }
                    }
                    """);
            }

            private void EmitPrimitiveParseMethod(ParsableFromStringSpec type)
            {
                StringParsableTypeKind typeKind = type.StringParsableTypeKind;
                string typeFQN = type.TypeRef.FullyQualifiedName;

                string invariantCultureExpression = $"{Identifier.CultureInfo}.InvariantCulture";
                string parsedValueExpr;

                switch (typeKind)
                {
                    case StringParsableTypeKind.ByteArray:
                        {
                            parsedValueExpr = $"Convert.FromBase64String({Identifier.value})";
                        }
                        break;
                    case StringParsableTypeKind.Integer:
                        {
                            parsedValueExpr = $"{typeFQN}.{Identifier.Parse}({Identifier.value}, {Identifier.NumberStyles}.Integer, {invariantCultureExpression})";
                        }
                        break;
                    case StringParsableTypeKind.Float:
                        {
                            parsedValueExpr = $"{typeFQN}.{Identifier.Parse}({Identifier.value}, {Identifier.NumberStyles}.Float, {invariantCultureExpression})";
                        }
                        break;
                    case StringParsableTypeKind.Parse:
                        {
                            parsedValueExpr = $"{typeFQN}.{Identifier.Parse}({Identifier.value})";
                        }
                        break;
                    case StringParsableTypeKind.ParseInvariant:
                        {
                            parsedValueExpr = $"{typeFQN}.{Identifier.Parse}({Identifier.value}, {invariantCultureExpression})"; ;
                        }
                        break;
                    case StringParsableTypeKind.CultureInfo:
                        {
                            parsedValueExpr = $"{Identifier.CultureInfo}.GetCultureInfo({Identifier.value})";
                        }
                        break;
                    case StringParsableTypeKind.Uri:
                        {
                            parsedValueExpr = $"new Uri({Identifier.value}, UriKind.RelativeOrAbsolute)";
                        }
                        break;
                    default:
                        {
                            Debug.Fail($"Invalid string parsable kind: {typeKind}");
                            return;
                        }
                }

                string exceptionArg1 = string.Format(ExceptionMessages.FailedBinding, $"{{{Identifier.value} ?? \"null\"}}", $"{{{Identifier.path}}}", $"{{typeof({typeFQN})}}");

                EmitStartBlock($"public static {typeFQN} {TypeIndex.GetParseMethodName(type)}(string {Identifier.value}, string? {Identifier.path})");
                EmitEndBlock($$"""
                    try
                    {
                        return {{parsedValueExpr}};
                    }
                    catch ({{Identifier.Exception}} {{Identifier.exception}})
                    {
                        throw new {{Identifier.InvalidOperationException}}($"{{exceptionArg1}}", {{Identifier.exception}});
                    }
                    """);
            }

            private void EmitBindCoreImplForArray(ArraySpec type)
            {
                TypeRef elementTypeRef = type.ElementTypeRef;
                string elementTypeFQN = type.ElementTypeRef.FullyQualifiedName;
                string tempIdentifier = GetIncrementalIdentifier(Identifier.temp);

                // Create temp list.
                _writer.WriteLine($"var {tempIdentifier} = new List<{elementTypeFQN}>();");
                _writer.WriteLine();

                // Bind elements to temp list.
                EmitBindingLogicForEnumerableWithAdd(elementTypeRef, tempIdentifier);
                _writer.WriteLine();

                // Resize array and add binded elements.
                _writer.WriteLine($$"""
                    {{Identifier.Int32}} {{Identifier.originalCount}} = {{Identifier.instance}}.{{Identifier.Length}};
                    {{Identifier.Array}}.{{Identifier.Resize}}(ref {{Identifier.instance}}, {{Identifier.originalCount}} + {{tempIdentifier}}.{{Identifier.Count}});
                    {{tempIdentifier}}.{{Identifier.CopyTo}}({{Identifier.instance}}, {{Identifier.originalCount}});
                    """);
            }

            private void EmitBindCoreImplForEnumerableWithAdd(EnumerableSpec type)
            {
                EmitCollectionCastIfRequired(type, out string instanceIdentifier);
                EmitBindingLogicForEnumerableWithAdd(type.ElementTypeRef, instanceIdentifier);
            }

            private void EmitBindingLogicForEnumerableWithAdd(TypeRef elementTypeRef, string enumerableIdentifier)
            {
                Emit_Foreach_Section_In_ConfigChildren_StartBlock();

                string addExpr = $"{enumerableIdentifier}.{Identifier.Add}";

                switch (_typeIndex.GetEffectiveTypeSpec(elementTypeRef))
                {
                    case ParsableFromStringSpec stringParsableType:
                        {
                            EmitStartBlock($"if ({Identifier.TryGetConfigurationValue}({Identifier.section}, {Identifier.key}: null, out string? {Identifier.value}))");
                            EmitBindingLogic(
                                stringParsableType,
                                Identifier.value,
                                Expression.sectionPath,
                                (parsedValueExpr) => _writer.WriteLine($"{addExpr}({parsedValueExpr});"),
                                checkForNullSectionValue: true);
                            EmitEndBlock(); // End if-check for input type.
                        }
                        break;
                    case ConfigurationSectionSpec:
                        {
                            _writer.WriteLine($"{addExpr}({Identifier.section});");
                        }
                        break;
                    case ComplexTypeSpec complexType when _typeIndex.CanInstantiate(complexType):
                        {
                            // If a section possesses a null or empty string value and lacks any children, we bind to the default value of the type.
                            // In the case of a non-null or non-empty string value without any section children, binding cannot be performed at that moment,
                            // and this section should be skipped.
                            EmitBindCheckForSectionValue();

                            EmitBindingLogic(complexType, Identifier.value, Identifier.section, InitializationKind.Declaration, ValueDefaulting.None);
                            _writer.WriteLine($"{addExpr}({Identifier.value});");
                        }
                        break;
                }

                EmitEndBlock();
            }

            // EmitBindCheckForSectionValue produce the following code:
            // if (!string.IsNullOrEmpty(section.Value) && !section.GetChildren().Any()) { continue; }
            //
            // If a section possesses a null or empty string value and lacks any children, we bind to the default value of the type.
            // In the case of a non-null or non-empty string value without any section children, binding cannot be performed at that moment,
            // and this section should be skipped.
            private void EmitBindCheckForSectionValue()
            {
                EmitStartBlock($"if (!string.IsNullOrEmpty({Expression.sectionValue}) && !{Identifier.section}.{Identifier.GetChildren}().{Identifier.Any}())");
                _writer.WriteLine($@"continue;");
                EmitEndBlock();
            }

            private void EmitBindCoreImplForDictionary(DictionarySpec type)
            {
                EmitCollectionCastIfRequired(type, out string instanceIdentifier);

                Emit_Foreach_Section_In_ConfigChildren_StartBlock();

                ParsableFromStringSpec keyType = (ParsableFromStringSpec)_typeIndex.GetEffectiveTypeSpec(type.KeyTypeRef);
                TypeSpec elementType = _typeIndex.GetEffectiveTypeSpec(type.ElementTypeRef);

                // Parse key
                EmitBindingLogic(
                    keyType,
                    Expression.sectionKey,
                    Expression.sectionPath,
                    Emit_BindAndAddLogic_ForElement,
                    checkForNullSectionValue: false);

                void Emit_BindAndAddLogic_ForElement(string parsedKeyExpr)
                {
                    switch (elementType)
                    {
                        case ParsableFromStringSpec stringParsableElementType:
                            {
                                EmitStartBlock($"if ({Identifier.TryGetConfigurationValue}({Identifier.section}, {Identifier.key}: null, out string? {Identifier.value}))");
                                EmitBindingLogic(
                                    stringParsableElementType,
                                    Identifier.value,
                                    Expression.sectionPath,
                                    writeOnSuccess: parsedValueExpr => _writer.WriteLine($"{instanceIdentifier}[{parsedKeyExpr}] = {parsedValueExpr};"),
                                    checkForNullSectionValue: true);
                                EmitEndBlock(); // End if-check for input type.
                            }
                            break;
                        case ConfigurationSectionSpec:
                            {
                                _writer.WriteLine($"{instanceIdentifier}[{parsedKeyExpr}] = {Identifier.section};");
                            }
                            break;
                        case ComplexTypeSpec complexElementType:
                            {
                                if (keyType.StringParsableTypeKind is not StringParsableTypeKind.AssignFromSectionValue)
                                {
                                    // Save value to local to avoid parsing twice - during look-up and during add.
                                    _writer.WriteLine($"{keyType.TypeRef.FullyQualifiedName} {Identifier.key} = {parsedKeyExpr};");
                                    parsedKeyExpr = Identifier.key;
                                }

                                bool isValueType = complexElementType.IsValueType;
                                string expressionForElementIsNotNull = $"{Identifier.element} is not null";
                                string elementTypeDisplayString = complexElementType.TypeRef.FullyQualifiedName + (complexElementType.IsValueType ? string.Empty : "?");

                                string expressionForElementExists = $"{instanceIdentifier}.{Identifier.TryGetValue}({parsedKeyExpr}, out {elementTypeDisplayString} {Identifier.element})";
                                string conditionToUseExistingElement = expressionForElementExists;

                                // If key already exists, bind to existing element instance if not null (for ref types).
                                if (!isValueType)
                                {
                                    conditionToUseExistingElement += $" && {expressionForElementIsNotNull}";
                                }

                                if (_typeIndex.CanInstantiate(complexElementType))
                                {
                                    EmitStartBlock($"if (!({conditionToUseExistingElement}))");
                                    EmitObjectInit(complexElementType, Identifier.element, InitializationKind.SimpleAssignment, Identifier.section);
                                    EmitEndBlock();

                                    EmitBindingLogic();
                                }
                                else
                                {
                                    EmitStartBlock($"if ({conditionToUseExistingElement})");
                                    EmitBindingLogic();
                                    EmitEndBlock();
                                }

                                void EmitBindingLogic()
                                {
                                    this.EmitBindingLogic(
                                        complexElementType,
                                        Identifier.element,
                                        Identifier.section,
                                        InitializationKind.None,
                                        ValueDefaulting.None);

                                    _writer.WriteLine($"{instanceIdentifier}[{parsedKeyExpr}] = {Identifier.element};");
                                }
                            }
                            break;
                    }
                }

                EmitEndBlock();
            }

            private void EmitBindCoreImplForObject(ObjectSpec type)
            {
                Debug.Assert(_typeIndex.HasBindableMembers(type));

                string keyCacheFieldName = TypeIndex.GetConfigKeyCacheFieldName(type);
                string validateMethodCallExpr = $"{Identifier.ValidateConfigurationKeys}(typeof({type.TypeRef.FullyQualifiedName}), {keyCacheFieldName}, {Identifier.configuration}, {Identifier.binderOptions});";
                _writer.WriteLine(validateMethodCallExpr);

                foreach (PropertySpec property in type.Properties!)
                {
                    if (_typeIndex.ShouldBindTo(property))
                    {
                        string containingTypeRef = property.IsStatic ? type.TypeRef.FullyQualifiedName : Identifier.instance;
                        EmitBindImplForMember(
                            property,
                            memberAccessExpr: $"{containingTypeRef}.{property.Name}",
                            GetSectionPathFromConfigurationExpression(property.ConfigurationKeyName),
                            canSet: property.CanSet,
                            canGet: property.CanGet,
                            InitializationKind.Declaration);
                    }
                }
            }

            private bool EmitBindImplForMember(
                MemberSpec member,
                string memberAccessExpr,
                string sectionPathExpr,
                bool canSet,
                bool canGet,
                InitializationKind initializationKind)
            {
                string sectionParseExpr = GetSectionFromConfigurationExpression(member.ConfigurationKeyName);

                switch (_typeIndex.GetEffectiveTypeSpec(member.TypeRef))
                {
                    case ParsableFromStringSpec stringParsableType:
                        {
                            // Reflection binder does not support binding to set-only properties
                            if (canSet && canGet)
                            {
                                EmitBlankLineIfRequired();
                                string valueIdentifier = GetIncrementalIdentifier(Identifier.value);
                                EmitStartBlock($@"if ({Identifier.TryGetConfigurationValue}({Identifier.configuration}, {Identifier.key}: ""{member.ConfigurationKeyName}"", out string? {valueIdentifier}))");

                                // Decide to emit the null check block for nullable types (e.g. int?).
                                // We don't emit this block for types that can be assigned directly from IConfigurationSection.Value as the valueIdentifier value can assigned
                                // anyway to the memberAccessExpr regardless of the nullability. This can reduce the emitted code size when assigning objects or strings which
                                // are common cases.
                                bool emitNullCheck = member.TypeRef.CanBeNull && stringParsableType.StringParsableTypeKind != StringParsableTypeKind.AssignFromSectionValue;

                                // Nullable type can be set to null
                                if (emitNullCheck)
                                {
                                    EmitStartBlock($"if ({valueIdentifier} is null)");
                                    _writer.WriteLine($"{memberAccessExpr} = null;");
                                    EmitEndBlock(); // End if-check for input type.
                                    EmitStartBlock($"else");
                                }

                                EmitBindingLogic(
                                    stringParsableType,
                                    valueIdentifier,
                                    sectionPathExpr,
                                    writeOnSuccess: parsedValueExpr => _writer.WriteLine($"{memberAccessExpr} = {parsedValueExpr};"),
                                    checkForNullSectionValue: true);

                                if (emitNullCheck)
                                {
                                    EmitEndBlock(); // end of $"if ({valueIdentifier} is null)"
                                }

                                EmitEndBlock(); // End if-check for input type.

                                if (initializationKind == InitializationKind.Declaration)
                                {
                                    EmitStartBlock($"else if (defaultValueIfNotFound)");
                                    if (!stringParsableType.TypeRef.CanBeNull)
                                    {
                                        _writer.WriteLine($"{memberAccessExpr} = {memberAccessExpr};");
                                    }
                                    else
                                    {
                                        _writer.WriteLine($"var currentValue = {memberAccessExpr};");
                                        EmitStartBlock($"if (currentValue is not null)");
                                        _writer.WriteLine($"{memberAccessExpr} = currentValue;");
                                        EmitEndBlock();
                                    }
                                    EmitEndBlock();
                                }
                            }

                            return true;
                        }
                    case ConfigurationSectionSpec:
                        {
                            if (canSet)
                            {
                                EmitBlankLineIfRequired();
                                _writer.WriteLine($"{memberAccessExpr} = {sectionParseExpr};");
                            }

                            return true;
                        }
                    case ComplexTypeSpec complexType:
                        {
                            // Early detection of types we cannot bind to and skip it.
                            if (!_typeIndex.HasBindableMembers(complexType) &&
                                !_typeIndex.GetEffectiveTypeSpec(complexType).IsValueType &&
                                complexType is not CollectionSpec &&
                                ((ObjectSpec)complexType).InstantiationStrategy == ObjectInstantiationStrategy.ParameterizedConstructor)
                            {
                                return false;
                            }

                            EmitBlankLineIfRequired();
                            string configSection = GetIncrementalIdentifier(Identifier.value);
                            _writer.WriteLine($"var {configSection} = {sectionParseExpr};");

                            string sectionValidationCall = $"{MethodsToGen_CoreBindingHelper.AsConfigWithChildren}({configSection})";
                            string sectionIdentifier = GetIncrementalIdentifier(Identifier.section);

                            EmitStartBlock($"if ({sectionValidationCall} is {Identifier.IConfigurationSection} {sectionIdentifier})");
                            EmitBindingLogicForComplexMember(member, memberAccessExpr, sectionIdentifier, canSet);
                            EmitEndBlock();

                            // The current configuration section doesn't have any children, let's check if we are binding to an array and the configuration value is empty string.
                            // In this case, we will assign an empty array to the member. Otherwise, we will skip the binding logic.
                            if (complexType is ArraySpec arraySpec && canSet)
                            {
                                string valueIdentifier = GetIncrementalIdentifier(Identifier.value);
                                EmitStartBlock($@"if ({memberAccessExpr} is null && {Identifier.TryGetConfigurationValue}({configSection}, {Identifier.key}: null, out string? {valueIdentifier}) && {valueIdentifier} == string.Empty)");
                                _writer.WriteLine($"{memberAccessExpr} = global::System.{Identifier.Array}.Empty<{arraySpec.ElementTypeRef.FullyQualifiedName}>();");
                                EmitEndBlock();
                            }

                            return _typeIndex.CanInstantiate(complexType);
                        }
                    default:
                        return false;
                }
            }

            private void EmitBindingLogicForComplexMember(
                MemberSpec member,
                string memberAccessExpr,
                string configArgExpr,
                bool canSet)
            {

                TypeSpec memberType = _typeIndex.GetTypeSpec(member.TypeRef);
                ComplexTypeSpec effectiveMemberType = (ComplexTypeSpec)_typeIndex.GetEffectiveTypeSpec(memberType);

                string tempIdentifier = GetIncrementalIdentifier(Identifier.temp);
                InitializationKind initKind;
                string targetObjAccessExpr;

                if (effectiveMemberType.IsValueType)
                {
                    if (!canSet)
                    {
                        return;
                    }

                    Debug.Assert(canSet);
                    string effectiveMemberTypeFQN = effectiveMemberType.TypeRef.FullyQualifiedName;
                    initKind = InitializationKind.None;

                    if (memberType is NullableSpec)
                    {
                        string nullableTempIdentifier = GetIncrementalIdentifier(Identifier.temp);

                        _writer.WriteLine($"{memberType.TypeRef.FullyQualifiedName} {nullableTempIdentifier} = {memberAccessExpr};");

                        _writer.WriteLine(
                            $"{effectiveMemberTypeFQN} {tempIdentifier} = {nullableTempIdentifier}.{Identifier.HasValue} ? {nullableTempIdentifier}.{Identifier.Value} : new {effectiveMemberTypeFQN}();");
                    }
                    else
                    {
                        _writer.WriteLine($"{effectiveMemberTypeFQN} {tempIdentifier} = {memberAccessExpr};");
                    }

                    targetObjAccessExpr = tempIdentifier;
                }
                else if (member.CanGet)
                {
                    targetObjAccessExpr = memberAccessExpr;
                    initKind = InitializationKind.AssignmentWithNullCheck;
                }
                else
                {
                    targetObjAccessExpr = memberAccessExpr;
                    initKind = InitializationKind.SimpleAssignment;
                }

                Action<string, string?>? writeOnSuccess = !canSet
                    ? null
                    : (bindedValueIdentifier, tempIdentifierStoringExpr) =>
                    {
                        if (memberAccessExpr != bindedValueIdentifier)
                        {
                            _writer.WriteLine($"{memberAccessExpr} = {bindedValueIdentifier};");

                            if (tempIdentifierStoringExpr is not null)
                            {
                                _writer.WriteLine($"{tempIdentifierStoringExpr}");
                            }

                            if (member.CanGet && _typeIndex.CanInstantiate(effectiveMemberType))
                            {
                                EmitEndBlock();
                                EmitStartBlock("else");
                                _writer.WriteLine($"{memberAccessExpr} = {memberAccessExpr};");
                            }
                        }
                        else
                        {
                            _writer.WriteLine($"{tempIdentifierStoringExpr}");
                        }
                    };

                EmitBindingLogic(
                    effectiveMemberType,
                    targetObjAccessExpr,
                    configArgExpr,
                    initKind,
                    ValueDefaulting.None,
                    writeOnSuccess
                    );
            }

            private void EmitBindingLogic(
                ComplexTypeSpec type,
                string memberAccessExpr,
                string configArgExpr,
                InitializationKind initKind,
                ValueDefaulting valueDefaulting,
                Action<string, string?>? writeOnSuccess = null)
            {
                if (!_typeIndex.HasBindableMembers(type))
                {
                    if (initKind is not InitializationKind.None)
                    {
                        if (_typeIndex.CanInstantiate(type))
                        {
                            EmitObjectInit(type, memberAccessExpr, initKind, configArgExpr);
                        }
                        else if (type is ObjectSpec { InitExceptionMessage: string exMsg })
                        {
                            _writer.WriteLine($@"throw new {Identifier.InvalidOperationException}(""{exMsg}"");");
                        }
                    }

                    return;
                }

                string tempIdentifier = GetIncrementalIdentifier(Identifier.temp);
                if (initKind is InitializationKind.AssignmentWithNullCheck)
                {
                    Debug.Assert(!type.IsValueType);
                    _writer.WriteLine($"{type.TypeRef.FullyQualifiedName}? {tempIdentifier} = {memberAccessExpr};");
                    EmitBindingLogic(tempIdentifier, InitializationKind.AssignmentWithNullCheck);
                }
                else if (initKind is InitializationKind.None && type.IsValueType)
                {
                    EmitBindingLogic(tempIdentifier, InitializationKind.Declaration, $"{memberAccessExpr} = {tempIdentifier};");
                }
                else
                {
                    EmitBindingLogic(memberAccessExpr, initKind);
                }

                void EmitBindingLogic(string instanceToBindExpr, InitializationKind initKind, string? tempIdentifierStoringExpr = null)
                {
                    string bindCoreCall = $@"{nameof(MethodsToGen_CoreBindingHelper.BindCore)}({configArgExpr}, ref {instanceToBindExpr}, defaultValueIfNotFound: {FormatDefaultValueIfNotFound()}, {Identifier.binderOptions});";

                    if (_typeIndex.CanInstantiate(type))
                    {
                        if (initKind is not InitializationKind.None)
                        {
                            EmitObjectInit(type, instanceToBindExpr, initKind, configArgExpr);
                        }

                        EmitBindCoreCall();
                    }
                    else
                    {
                        Debug.Assert(!type.IsValueType);
                        EmitStartBlock($"if ({instanceToBindExpr} is not null)");
                        EmitBindCoreCall();
                        EmitEndBlock();
                        if (type is ObjectSpec { InitExceptionMessage: string exMsg })
                        {
                            EmitStartBlock("else");
                            _writer.WriteLine($@"throw new {Identifier.InvalidOperationException}(""{exMsg}"");");
                            EmitEndBlock();
                        }
                    }

                    void EmitBindCoreCall()
                    {
                        _writer.WriteLine(bindCoreCall);
                        writeOnSuccess?.Invoke(instanceToBindExpr, tempIdentifierStoringExpr);
                    }

                    string FormatDefaultValueIfNotFound() => valueDefaulting == ValueDefaulting.CallSetter ? "true" : "false";
                }
            }

            private void EmitBindingLogic(
                ParsableFromStringSpec type,
                string sectionValueExpr,
                string sectionPathExpr,
                Action<string>? writeOnSuccess,
                bool checkForNullSectionValue)
            {
                StringParsableTypeKind typeKind = type.StringParsableTypeKind;
                Debug.Assert(typeKind is not StringParsableTypeKind.None);

                string parsedValueExpr = typeKind switch
                {
                    StringParsableTypeKind.AssignFromSectionValue => sectionValueExpr,
                    StringParsableTypeKind.Enum => $"ParseEnum<{type.TypeRef.FullyQualifiedName}>({sectionValueExpr}, {sectionPathExpr})",
                    _ => $"{TypeIndex.GetParseMethodName(type)}({sectionValueExpr}, {sectionPathExpr})",
                };

                // Usually assigning the configuration value to string or object
                if (!checkForNullSectionValue || typeKind == StringParsableTypeKind.AssignFromSectionValue)
                {
                    writeOnSuccess?.Invoke(parsedValueExpr);
                }
                else
                {
                    // call parsing methods

                    string conditionPrefix = string.Empty;
                    // Special case ByteArray when having empty string configuration value as we need to assign empty byte array at that time.
                    if (typeKind == StringParsableTypeKind.ByteArray)
                    {
                        EmitStartBlock($"if ({sectionValueExpr} == string.Empty)");
                        writeOnSuccess?.Invoke(parsedValueExpr);
                        EmitEndBlock();
                        conditionPrefix = "else ";
                    }

                    EmitStartBlock($"{conditionPrefix}if (!string.IsNullOrEmpty({sectionValueExpr}))");
                    writeOnSuccess?.Invoke(parsedValueExpr);
                    EmitEndBlock();
                }
            }

            private bool EmitObjectInit(ComplexTypeSpec type, string memberAccessExpr, InitializationKind initKind, string configArgExpr)
            {
                CollectionSpec? collectionType = type as CollectionSpec;
                ObjectSpec? objectType = type as ObjectSpec;

                string? castExpr = null;
                string initExpr;

                string typeFQN = type.TypeRef.FullyQualifiedName;
                if (collectionType is not null)
                {
                    if (collectionType is ArraySpec)
                    {
                        initExpr = $"new {s_arrayBracketsRegex.Replace(typeFQN, "[0]", 1)}";
                    }
                    else
                    {
                        CollectionWithCtorInitSpec collectionWithCtorInitType = (CollectionWithCtorInitSpec)collectionType;

                        if (collectionWithCtorInitType.InstantiationConcreteType is not CollectionInstantiationConcreteType.Self)
                        {
                            castExpr = $"({collectionWithCtorInitType.TypeRef.FullyQualifiedName})";
                        }

                        typeFQN = TypeIndex.GetInstantiationTypeDisplayString(collectionWithCtorInitType);
                        initExpr = $"{castExpr}new {typeFQN}()";
                    }
                }
                else
                {
                    Debug.Assert(objectType is not null);
                    ObjectInstantiationStrategy strategy = objectType.InstantiationStrategy;

                    if (strategy is ObjectInstantiationStrategy.ParameterlessConstructor)
                    {
                        // value tuple types will be declared with syntax like:
                        //     (int, int) value = default;
                        // This is to avoid using invalid syntax calling the parameterless constructor
                        initExpr = type.IsValueTuple ? "default" : $"new {typeFQN}()";
                    }
                    else
                    {
                        Debug.Assert(strategy is ObjectInstantiationStrategy.ParameterizedConstructor);
                        string initMethodIdentifier = GetInitializeMethodDisplayString(((ObjectSpec)type));
                        initExpr = $"{initMethodIdentifier}({configArgExpr}, {Identifier.binderOptions})";
                    }
                }

                switch (initKind)
                {
                    case InitializationKind.Declaration:
                        {
                            Debug.Assert(!memberAccessExpr.Contains('.'));
                            // value tuple will be declared with syntax like:
                            //     (int, int) value = default;
                            // We need to specify the typeFQN as we assign the variable to default value.
                            string declarationType = type.IsValueTuple ? typeFQN : $"var";
                            _writer.WriteLine($"{declarationType} {memberAccessExpr} = {initExpr};");
                        }
                        break;
                    case InitializationKind.AssignmentWithNullCheck:
                        {

                            if (collectionType is CollectionWithCtorInitSpec
                                {
                                    InstantiationStrategy: CollectionInstantiationStrategy.CopyConstructor or CollectionInstantiationStrategy.LinqToDictionary
                                } collectionWithCtorInitType)
                            {
                                string assignmentValueIfMemberNull = collectionWithCtorInitType.InstantiationStrategy is CollectionInstantiationStrategy.CopyConstructor
                                    ? $"new {typeFQN}({memberAccessExpr})"
                                    : $"{memberAccessExpr}.ToDictionary(pair => pair.Key, pair => pair.Value)";

                                Debug.Assert(castExpr is not null || collectionWithCtorInitType.InstantiationConcreteType is CollectionInstantiationConcreteType.Self);
                                assignmentValueIfMemberNull = $"{castExpr}{assignmentValueIfMemberNull}";

                                _writer.WriteLine($"{memberAccessExpr} = {memberAccessExpr} is null ? {initExpr} : {assignmentValueIfMemberNull};");
                            }
                            else
                            {
                                _writer.WriteLine($"{memberAccessExpr} ??= {initExpr};");
                            }
                        }
                        break;
                    case InitializationKind.SimpleAssignment:
                        {
                            _writer.WriteLine($"{memberAccessExpr} = {initExpr};");
                        }
                        break;
                    default:
                        {
                            Debug.Fail($"Invalid initialization kind: {initKind}");
                        }
                        break;
                }

                return true;
            }

            private void EmitIConfigurationHasValueOrChildrenCheck(bool voidReturn)
            {
                string returnPostfix = voidReturn ? string.Empty : " null";
                _writer.WriteLine($$"""
                    if (!{{Identifier.HasValueOrChildren}}({{Identifier.configuration}}))
                    {
                        return{{returnPostfix}};
                    }
                    """);
                _writer.WriteLine();
            }

            private void EmitCollectionCastIfRequired(CollectionWithCtorInitSpec type, out string instanceIdentifier)
            {
                if (type.PopulationCastType is CollectionPopulationCastType.NotApplicable)
                {
                    instanceIdentifier = Identifier.instance;
                    return;
                }

                instanceIdentifier = Identifier.temp;
                string castExpression = $"{TypeIndex.GetPopulationCastTypeDisplayString(type)} {instanceIdentifier}";

                if (type.ShouldTryCast)
                {
                    _writer.WriteLine($$"""
                            if ({{Identifier.instance}} is not {{castExpression}})
                            {
                                return;
                            }
                            """);
                }
                else
                {
                    _writer.WriteLine($$"""
                            {{castExpression}} = {{Identifier.instance}};
                            """);
                }

                _writer.WriteLine();

            }

            private void Emit_Foreach_Section_In_ConfigChildren_StartBlock() =>
                EmitStartBlock($"foreach ({Identifier.IConfigurationSection} {Identifier.section} in {Identifier.configuration}.{Identifier.GetChildren}())");

            private void Emit_NotSupportedException_TypeNotDetectedAsInput() =>
                _writer.WriteLine(@$"throw new NotSupportedException($""{string.Format(ExceptionMessages.TypeNotDetectedAsInput, "{type}")}"");");

            private static string GetSectionPathFromConfigurationExpression(string configurationKeyName)
                => $@"{GetSectionFromConfigurationExpression(configurationKeyName)}.{Identifier.Path}";

            private static string GetSectionFromConfigurationExpression(string configurationKeyName, bool addQuotes = true)
            {
                string argExpr = addQuotes ? $@"""{configurationKeyName}""" : configurationKeyName;
                return $@"{Identifier.configuration}.{Identifier.GetSection}({argExpr})";
            }

            private static string GetConditionKindExpr(ref bool isFirstType)
            {
                if (isFirstType)
                {
                    isFirstType = false;
                    return "if";
                }

                return "else if";
            }
        }
    }
}
