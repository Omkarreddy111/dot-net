// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Text;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;

namespace Microsoft.AspNetCore.Http.Generators.StaticRouteHandlerModel;

internal static class StaticRouteHandlerModelEmitter
{
    /*
     * TODO: Emit code that represents the signature of the delegate
     * represented by the handler. When the handler does not return a value
     * but consumes parameters the following will be emitted:
     *
     * ```
     * System.Action<string, int>
     * ```
     *
     * Where `string` and `int` represent parameter types. For handlers
     * that do return a value, `System.Func<string, int, string>` will
     * be emitted to indicate a `string`return type.
     */
    public static string EmitHandlerDelegateType(this Endpoint endpoint)
    {
        if (endpoint.Response.IsVoid)
        {
            return $"System.Action";
        }
        if (endpoint.Response.IsAwaitable)
        {
            return $"System.Func<{endpoint.Response.WrappedResponseType}>";
        }
        return $"System.Func<{endpoint.Response.ResponseType}>";
    }

    public static string EmitSourceKey(this Endpoint endpoint)
    {
        return $@"(@""{endpoint.Location.Item1}"", {endpoint.Location.Item2})";
    }

    public static string EmitVerb(this Endpoint endpoint)
    {
        return endpoint.HttpMethod switch
        {
            "MapGet" => "GetVerb",
            "MapPut" => "PutVerb",
            "MapPost" => "PostVerb",
            "MapDelete" => "DeleteVerb",
            "MapPatch" => "PatchVerb",
            _ => throw new ArgumentException($"Received unexpected HTTP method: {endpoint.HttpMethod}")
        };
    }

    /*
     * TODO: Emit invocation to the request handler. The structure
     * involved here consists of a call to bind parameters, check
     * their validity (optionality), invoke the underlying handler with
     * the arguments bound from HTTP context, and write out the response.
     */
    public static string EmitRequestHandler(this Endpoint endpoint)
    {
        var code = new StringBuilder();
        code.AppendLine(endpoint.Response.IsAwaitable
            ? "async Task RequestHandler(HttpContext httpContext)"
            : "Task RequestHandler(HttpContext httpContext)");
        code.AppendLine("{");

        if (endpoint.Response.IsVoid)
        {
            code.AppendLine("handler();");
            code.AppendLine("return Task.CompletedTask;");
        }
        else
        {
            code.AppendLine($"""httpContext.Response.ContentType ??= "{endpoint.Response.ContentType}";""");
            if (endpoint.Response.IsAwaitable)
            {
                code.AppendLine("var result = await handler();");
                code.AppendLine(endpoint.EmitResponseWritingCall());
            }
            else
            {
                code.AppendLine("var result = handler();");
                code.AppendLine("return GeneratedRouteBuilderExtensionsCore.ExecuteObjectResult(result, httpContext);");
            }
        }
        code.AppendLine("}");
        var formattedCode = SyntaxFactory.ParseCompilationUnit(code.ToString()).NormalizeWhitespace();
        return formattedCode.ToString();
    }

    public static string EmitResponseWritingCall(this Endpoint endpoint)
    {
        var code = new StringBuilder();
        code.Append(endpoint.Response.IsAwaitable ? "await " : "return ");

        if (endpoint.Response.IsIResult)
        {
            code.Append("result.ExecuteAsync(httpContext);");
        }
        else if (endpoint.Response.ResponseType.SpecialType == SpecialType.System_String)
        {
            code.Append("httpContext.Response.WriteAsync(result);");
        }
        else if (endpoint.Response.ResponseType.SpecialType == SpecialType.System_Object)
        {
            code.Append("GeneratedRouteBuilderExtensionsCore.ExecuteObjectResult(result, httpContext);");
        }
        else if (!endpoint.Response.IsVoid)
        {
            code.Append("httpContext.Response.WriteAsJsonAsync(result);");
        }
        else if (!endpoint.Response.IsAwaitable && endpoint.Response.IsVoid)
        {
            code.Append("Task.CompletedTask;");
        }

        return code.ToString();
    }

    /*
     * TODO: Emit invocation to the `filteredInvocation` pipeline by constructing
     * the `EndpointFilterInvocationContext` using the bound arguments for the handler.
     * In the source generator context, the generic overloads for `EndpointFilterInvocationContext`
     * can be used to reduce the boxing that happens at runtime when constructing
     * the context object.
     */
    public static string EmitFilteredRequestHandler()
    {
        return """
async Task RequestHandlerFiltered(HttpContext httpContext)
{
    var result = await filteredInvocation(new DefaultEndpointFilterInvocationContext(httpContext));
    await GeneratedRouteBuilderExtensionsCore.ExecuteObjectResult(result, httpContext);
}
""";
    }

    /*
     * TODO: Emit code that will call the `handler` with
     * the appropriate arguments processed via the parameter binding.
     *
     * ```
     * return ValueTask.FromResult<object?>(handler(name, age));
     * ```
     *
     * If the handler returns void, it will be invoked and an `EmptyHttpResult`
     * will be returned to the user.
     *
     * ```
     * handler(name, age);
     * return ValueTask.FromResult<object?>(Results.Empty);
     * ```
     */
    public static string EmitFilteredInvocation(this Endpoint endpoint)
    {
        if (endpoint.Response.IsVoid)
        {
            return """
handler();
return ValueTask.FromResult<object?>(Results.Empty);
""";
        }
        else
        {
            return """
return ValueTask.FromResult<object?>(handler());
""";
        }
    }
}
