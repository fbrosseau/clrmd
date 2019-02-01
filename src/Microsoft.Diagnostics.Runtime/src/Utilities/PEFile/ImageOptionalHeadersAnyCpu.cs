﻿// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Runtime.InteropServices;

namespace Microsoft.Diagnostics.Runtime.Utilities
{
    [StructLayout(LayoutKind.Explicit)]
    internal struct IMAGE_OPTIONAL_HEADER_SlimAnyCpu
    {
        [FieldOffset(60)]
        public uint SizeOfHeaders;
    }
}