// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;
using Microsoft.AspNetCore.Mvc;

namespace Microsoft.AspNetCore.Http;

internal sealed class ProblemDetailsJsonConverter : JsonConverter<ProblemDetails>
{
    private static readonly JsonEncodedText Type = JsonEncodedText.Encode("type");
    private static readonly JsonEncodedText Title = JsonEncodedText.Encode("title");
    private static readonly JsonEncodedText Status = JsonEncodedText.Encode("status");
    private static readonly JsonEncodedText Detail = JsonEncodedText.Encode("detail");
    private static readonly JsonEncodedText Instance = JsonEncodedText.Encode("instance");

    public override ProblemDetails Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var problemDetails = new ProblemDetails();

        if (reader.TokenType != JsonTokenType.StartObject)
        {
            throw new JsonException("Unexpected end when reading JSON.");
        }

        var objectTypeInfo = options.GetTypeInfo(typeof(object));
        while (reader.Read() && reader.TokenType != JsonTokenType.EndObject)
        {
            ReadValue(ref reader, problemDetails, objectTypeInfo);
        }

        if (reader.TokenType != JsonTokenType.EndObject)
        {
            throw new JsonException("Unexpected end when reading JSON.");
        }

        return problemDetails;
    }

    public override void Write(Utf8JsonWriter writer, ProblemDetails value, JsonSerializerOptions options)
    {
        writer.WriteStartObject();
        WriteProblemDetails(writer, value, options);
        writer.WriteEndObject();
    }

    internal static void ReadValue(ref Utf8JsonReader reader, ProblemDetails value, JsonTypeInfo extensionDataTypeInfo)
    {
        if (TryReadStringProperty(ref reader, Type, out var propertyValue))
        {
            value.Type = propertyValue;
        }
        else if (TryReadStringProperty(ref reader, Title, out propertyValue))
        {
            value.Title = propertyValue;
        }
        else if (TryReadStringProperty(ref reader, Detail, out propertyValue))
        {
            value.Detail = propertyValue;
        }
        else if (TryReadStringProperty(ref reader, Instance, out propertyValue))
        {
            value.Instance = propertyValue;
        }
        else if (reader.ValueTextEquals(Status.EncodedUtf8Bytes))
        {
            reader.Read();
            if (reader.TokenType == JsonTokenType.Null)
            {
                // Nothing to do here.
            }
            else
            {
                value.Status = reader.GetInt32();
            }
        }
        else
        {
            var key = reader.GetString()!;
            reader.Read();
            value.Extensions[key] = JsonSerializer.Deserialize(ref reader, extensionDataTypeInfo);
        }
    }

    internal static bool TryReadStringProperty(ref Utf8JsonReader reader, JsonEncodedText propertyName, [NotNullWhen(true)] out string? value)
    {
        if (!reader.ValueTextEquals(propertyName.EncodedUtf8Bytes))
        {
            value = default;
            return false;
        }

        reader.Read();
        value = reader.GetString()!;
        return true;
    }

    internal static void WriteProblemDetails(Utf8JsonWriter writer, ProblemDetails value, JsonSerializerOptions options)
    {
        if (value.Type != null)
        {
            writer.WriteString(Type, value.Type);
        }

        if (value.Title != null)
        {
            writer.WriteString(Title, value.Title);
        }

        if (value.Status != null)
        {
            writer.WriteNumber(Status, value.Status.Value);
        }

        if (value.Detail != null)
        {
            writer.WriteString(Detail, value.Detail);
        }

        if (value.Instance != null)
        {
            writer.WriteString(Instance, value.Instance);
        }

        foreach (var kvp in value.Extensions)
        {
            writer.WritePropertyName(kvp.Key);

            if (kvp.Value is null)
            {
                writer.WriteNullValue();
            }
            else
            {
                JsonSerializer.Serialize(writer, kvp.Value, options.GetTypeInfo(kvp.Value.GetType()));
            }
        }
    }
}
