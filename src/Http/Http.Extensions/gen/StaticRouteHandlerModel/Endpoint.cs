// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
using System.Collections.Generic;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Operations;

namespace Microsoft.AspNetCore.Http.Generators.StaticRouteHandlerModel;

internal class Endpoint
{
    public string HttpMethod { get; set; }
    public EndpointRoute Route { get; set; }
    public EndpointResponse Response { get; set; }
    public List<DiagnosticDescriptor> Diagnostics { get; init; } = new List<DiagnosticDescriptor>();

    public (string, int) Location { get; init; }
    public IInvocationOperation Operation { get; init; }

    internal WellKnownTypes WellKnownTypes { get; init; }

    public Endpoint(IInvocationOperation operation, WellKnownTypes wellKnownTypes)
    {
        Operation = operation;
        var filePath = operation.Syntax.SyntaxTree.FilePath;
        var span = operation.Syntax.SyntaxTree.GetLineSpan(operation.Syntax.Span);
        var lineNumber = span.EndLinePosition.Line + 1;
        Location = (filePath, lineNumber);
        WellKnownTypes = wellKnownTypes;
        HttpMethod = GetHttpMethod();
        Response = new EndpointResponse(Operation, wellKnownTypes);
        Route = new EndpointRoute(Operation);
    }

    private string GetHttpMethod()
    {
        if (Operation.Syntax is InvocationExpressionSyntax
        {
            Expression: MemberAccessExpressionSyntax
            {
                Name: IdentifierNameSyntax
                {
                    Identifier: { ValueText: var method }
                }
            },
            ArgumentList: { Arguments: { Count: 2 } args }
        })
        {
            HttpMethod = method;
        }
    }
}
