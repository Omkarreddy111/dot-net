// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Collections.Generic;

namespace Microsoft.AspNetCore.Http.Generators.StaticRouteHandlerModel;

internal sealed class EndpointComparer : IEqualityComparer<Endpoint>
{
    public static IEqualityComparer<Endpoint> Instance { get; } = new EndpointComparer();

    public bool Equals(Endpoint? endpoint, Endpoint? other)
    {
        if (endpoint == null && other == null)
        {
            return true;
        }
        if (endpoint == null || other == null)
        {
            return false;
        }

        return endpoint.HttpMethod.Equals(other.HttpMethod, StringComparison.OrdinalIgnoreCase) ||
               endpoint.Location.Item1.Equals(other.Location.Item1, StringComparison.OrdinalIgnoreCase) ||
               endpoint.Location.Item2.Equals(other.Location.Item2) ||
               endpoint.Response.Equals(other.Response);
    }

    public int GetHashCode(Endpoint obj)
    {
        unchecked
        {
            var hashCode = obj.HttpMethod.GetHashCode();
            hashCode = (hashCode * 397) ^ obj.Route.GetHashCode();
            hashCode = (hashCode * 397) ^ obj.Response.GetHashCode();
            hashCode = (hashCode * 397) ^ obj.Diagnostics.GetHashCode();
            hashCode = (hashCode * 397) ^ obj.Location.GetHashCode();
            hashCode = (hashCode * 397) ^ obj.Operation.GetHashCode();
            return hashCode;
        }
    }
}
