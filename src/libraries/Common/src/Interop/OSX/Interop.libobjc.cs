// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class @libobjc
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct NSOperatingSystemVersion
        {
            public nint majorVersion;
            public nint minorVersion;
            public nint patchVersion;
        }

        [LibraryImport(Libraries.libobjc, StringMarshalling = StringMarshalling.Utf8)]
        private static partial IntPtr objc_getClass(string className);
        [LibraryImport(Libraries.libobjc, StringMarshalling = StringMarshalling.Utf8)]
        private static partial IntPtr sel_getUid(string selector);
        [LibraryImport(Libraries.libobjc, EntryPoint = "objc_msgSend")]
        private static partial IntPtr intptr_objc_msgSend(IntPtr basePtr, IntPtr selector);

        internal static Version GetOperatingSystemVersion()
        {
            int major = 0;
            int minor = 0;
            int patch = 0;

            IntPtr processInfo = intptr_objc_msgSend(objc_getClass("NSProcessInfo"), sel_getUid("processInfo"));

            if (processInfo != IntPtr.Zero)
            {
#if TARGET_ARM64
                NSOperatingSystemVersion osVersion = NSOperatingSystemVersion_objc_msgSend(processInfo, sel_getUid("operatingSystemVersion"));
#else
                NSOperatingSystemVersion_objc_msgSend_stret(out NSOperatingSystemVersion osVersion, processInfo, sel_getUid("operatingSystemVersion"));
#endif
                checked
                {
                    major = (int)osVersion.majorVersion;
                    minor = (int)osVersion.minorVersion;
                    patch = (int)osVersion.patchVersion;
                }
            }

#if TARGET_OSX
            if (major == 16)
            {
                // MacOS Tahoe returns a compatibility version unless it is built with a new SDK. Map the compatibility
                // version to the "correct" version. This assumes the minor versions will map unchanged.
                // 16.0 => 26.0
                // 16.1 => 26.1
                // etc
                major = 26;
            }
#endif

            return new Version(major, minor, patch);
        }

        [LibraryImport(Libraries.libobjc, EntryPoint = "objc_msgSend")]
        private static partial NSOperatingSystemVersion NSOperatingSystemVersion_objc_msgSend(IntPtr basePtr, IntPtr selector);

        [LibraryImport(Libraries.libobjc, EntryPoint = "objc_msgSend_stret")]
        private static partial void NSOperatingSystemVersion_objc_msgSend_stret(out NSOperatingSystemVersion osVersion, IntPtr basePtr, IntPtr selector);
    }
}
