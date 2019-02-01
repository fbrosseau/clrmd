// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using Microsoft.Diagnostics.Runtime.DacInterface;
using Microsoft.Diagnostics.Runtime.Interop;
using Microsoft.Diagnostics.Runtime.Utilities;
using FileVersionInfo = System.Diagnostics.FileVersionInfo;
using IMAGE_FILE_HEADER = Microsoft.Diagnostics.Runtime.Interop.IMAGE_FILE_HEADER;
using IMAGE_DOS_HEADER = Microsoft.Diagnostics.Runtime.Interop.IMAGE_DOS_HEADER;

namespace Microsoft.Diagnostics.Runtime.Desktop
{
    internal class DesktopModule : DesktopBaseModule
    {
        private static readonly PdbInfo s_failurePdb = new PdbInfo();
        private readonly bool _isPE;
        private readonly string _name;
        private MetaDataImport _metadata;
        private readonly Dictionary<ClrAppDomain, ulong> _mapping = new Dictionary<ClrAppDomain, ulong>();
        private readonly ulong _address;
        private readonly Lazy<ulong> _size;
        private DebuggableAttribute.DebuggingModes? _debugMode;
        private bool _typesLoaded;
        private ClrAppDomain[] _appDomainList;
        private PdbInfo _pdb;
        private FileVersionInfo _fileVersion;

        public DesktopModule(DesktopRuntimeBase runtime, ulong address, IModuleData data, string name, string assemblyName)
            : base(runtime)
        {
            _address = address;
            Revision = runtime.Revision;
            ImageBase = data.ImageBase;
            AssemblyName = assemblyName;
            _isPE = data.IsPEFile;
            IsDynamic = data.IsReflection || string.IsNullOrEmpty(name);
            _name = name;
            ModuleId = data.ModuleId;
            ModuleIndex = data.ModuleIndex;
            MetadataAddress = data.MetdataStart;
            MetadataLength = data.MetadataLength;
            AssemblyId = data.Assembly;
            _size = new Lazy<ulong>(() => runtime.GetModuleSize(address));
        }

        public override ulong Address => _address;

        public override PdbInfo Pdb
        {
            get
            {
                if (_pdb == null)
                {
                    try
                    {

                        using (ReadVirtualStream stream = new ReadVirtualStream(_runtime.DataReader, (long)ImageBase, (long)(Size > 0 ? Size : 0x1000)))
                        {
                            PEImage pefile = new PEImage(stream, true);
                            if (pefile.IsValid)
                                _pdb = pefile.DefaultPdb ?? s_failurePdb;
                        }
                    }
                    catch
                    {
                    }
                }

                return _pdb != s_failurePdb ? _pdb : null;
            }
        }

        public override FileVersionInfo ModuleFileVersionInfo
        {
            get
            {
                if (_fileVersion != null)
                    return _fileVersion;

                var tempFileName = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".dll");
                try
                {
                    using (var temporaryFile = new FileStream(tempFileName, FileMode.Create, FileAccess.Write))
                    {
                        Save(temporaryFile);
                    }

                    _fileVersion = FileVersionInfo.GetVersionInfo(tempFileName);
                    return _fileVersion;
                }
                finally
                {
                    try
                    {
                        File.Delete(tempFileName);
                    }
                    catch
                    {
                    }
                }
            }
        }
               
        internal ulong GetMTForDomain(ClrAppDomain domain, DesktopHeapType type)
        {
            DesktopGCHeap heap = null;
            IList<MethodTableTokenPair> mtList = _runtime.GetMethodTableList(_mapping[domain]);

            bool hasToken = type.MetadataToken != 0 && type.MetadataToken != uint.MaxValue;

            uint token = ~0xff000000 & type.MetadataToken;

            foreach (MethodTableTokenPair pair in mtList)
            {
                if (hasToken)
                {
                    if (pair.Token == token)
                        return pair.MethodTable;
                }
                else
                {
                    if (heap == null)
                        heap = (DesktopGCHeap)_runtime.Heap;

                    if (heap.GetTypeByMethodTable(pair.MethodTable, 0) == type)
                        return pair.MethodTable;
                }
            }

            return 0;
        }

        public override IEnumerable<ClrType> EnumerateTypes()
        {
            DesktopGCHeap heap = (DesktopGCHeap)_runtime.Heap;
            IList<MethodTableTokenPair> mtList = _runtime.GetMethodTableList(_address);
            if (_typesLoaded)
            {
                foreach (ClrType type in heap.EnumerateTypes())
                    if (type.Module == this)
                        yield return type;
            }
            else
            {
                if (mtList != null)
                {
                    foreach (MethodTableTokenPair pair in mtList)
                    {
                        ulong mt = pair.MethodTable;
                        if (mt != _runtime.ArrayMethodTable)
                        {
                            // prefetch element type, as this also can load types
                            ClrType type = heap.GetTypeByMethodTable(mt, 0, 0);
                            if (type != null)
                                yield return type;
                        }
                    }
                }

                _typesLoaded = true;
            }
        }

        public override string AssemblyName { get; }
        public override string Name => _name;
        public override bool IsDynamic { get; }
        public override bool IsFile => _isPE;
        public override string FileName => _isPE ? _name : null;
        internal ulong ModuleIndex { get; }

        internal void AddMapping(ClrAppDomain domain, ulong domainModule)
        {
            DesktopAppDomain appDomain = (DesktopAppDomain)domain;
            _mapping[domain] = domainModule;
        }

        public override IList<ClrAppDomain> AppDomains
        {
            get
            {
                if (_appDomainList == null)
                {
                    _appDomainList = new ClrAppDomain[_mapping.Keys.Count];
                    _appDomainList = _mapping.Keys.ToArray();
                    Array.Sort(_appDomainList, (d, d2) => d.Id.CompareTo(d2.Id));
                }

                return _appDomainList;
            }
        }

        internal override ulong GetDomainModule(ClrAppDomain domain)
        {
            IList<ClrAppDomain> domains = _runtime.AppDomains;
            if (domain == null)
            {
                foreach (ulong addr in _mapping.Values)
                    return addr;

                return 0;
            }

            if (_mapping.TryGetValue(domain, out ulong value))
                return value;

            return 0;
        }

        internal override MetaDataImport GetMetadataImport()
        {
            if (Revision != _runtime.Revision)
                ClrDiagnosticsException.ThrowRevisionError(Revision, _runtime.Revision);

            if (_metadata != null)
                return _metadata;

            _metadata = _runtime.GetMetadataImport(_address);
            return _metadata;
        }

        public override ulong ImageBase { get; }
        public override ulong Size => _size.Value;
        public override ulong MetadataAddress { get; }
        public override ulong MetadataLength { get; }
        public override object MetadataImport => GetMetadataImport();

        public override DebuggableAttribute.DebuggingModes DebuggingMode
        {
            get
            {
                if (_debugMode == null)
                    InitDebugAttributes();

                Debug.Assert(_debugMode != null);
                return _debugMode.Value;
            }
        }

        private unsafe void InitDebugAttributes()
        {
            MetaDataImport metadata = GetMetadataImport();
            if (metadata == null)
            {
                _debugMode = DebuggableAttribute.DebuggingModes.None;
                return;
            }

            try
            {
                if (metadata.GetCustomAttributeByName(0x20000001, "System.Diagnostics.DebuggableAttribute", out IntPtr data, out uint cbData) && cbData >= 4)
                {
                    byte* b = (byte*)data.ToPointer();
                    ushort opt = b[2];
                    ushort dbg = b[3];

                    _debugMode = (DebuggableAttribute.DebuggingModes)((dbg << 8) | opt);
                }
                else
                {
                    _debugMode = DebuggableAttribute.DebuggingModes.None;
                }
            }
            catch (SEHException)
            {
                _debugMode = DebuggableAttribute.DebuggingModes.None;
            }
        }

        public override ClrType GetTypeByName(string name)
        {
            foreach (ClrType type in EnumerateTypes())
                if (type.Name == name)
                    return type;

            return null;
        }

        public override ulong AssemblyId { get; }
        
        public override void Save(Stream destination)
        {
            _runtime.DataReader.VirtualQuery(ImageBase, out var virtualQueryResult);
            bool isImage = virtualQueryResult.Type == VirtualMemoryType.Image;

            var dosHeader = ReadStruct<IMAGE_DOS_HEADER>(ImageBase);
            var ntHeader = ReadStruct<IMAGE_NT_HEADERS_SlimAnyCpu>(ImageBase + dosHeader.e_lfanew);

            var locations = new List<IMAGE_SECTION_HEADER>();

            var sectionAddr = ImageBase + dosHeader.e_lfanew + ntHeader.FileHeader.SizeOfOptionalHeader + 4 + (ulong)Marshal.SizeOf(typeof(IMAGE_FILE_HEADER));

            int sizeofSectionHeader = Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER));
            for (var i = 0; i < ntHeader.FileHeader.NumberOfSections; ++i)
            {
                var sectionHeader = ReadStruct<IMAGE_SECTION_HEADER>(sectionAddr);
                locations.Add(sectionHeader);
                sectionAddr += (ulong)sizeofSectionHeader;
            }

            locations.Sort((a, b) => a.PointerToRawData.CompareTo(b.PointerToRawData));

            CopyDumpMemoryToStream(destination, ImageBase, ntHeader.OptionalHeader.SizeOfHeaders);
            foreach (var loc in locations)
            {
                ulong readAddr = ImageBase + (isImage ? loc.VirtualAddress : loc.PointerToRawData);
                CopyDumpMemoryToStream(destination, readAddr, loc.SizeOfRawData);
            }
        }

        private unsafe T ReadStruct<T>(ulong address)
        {
            var buffer = new byte[Marshal.SizeOf(typeof(T))];
            FillBuffer(address, buffer, 0, buffer.Length);
            fixed(byte* ptr = buffer)
            {
                return (T)Marshal.PtrToStructure((IntPtr)ptr, typeof(T));
            }
        }

        private void FillBuffer(ulong address, byte[] buffer, int offset, int count)
        {
            const int maxReadSize = 4096;
            byte[] temp = new byte[maxReadSize];

            int remaining = count;
            while (remaining > 0)
            {
                int readSize = Math.Min(remaining, maxReadSize);
                if (!_runtime.DataReader.ReadMemory(address, temp, readSize, out var actualRead) || actualRead <= 0)
                    throw new InvalidOperationException("Failed to read memory");

                Buffer.BlockCopy(temp, 0, buffer, offset, actualRead);

                offset += actualRead;
                remaining -= actualRead;
            }
        }

        private void CopyDumpMemoryToStream(Stream output, ulong address, uint count)
        {
            const int maxReadSize = 4096;
            byte[] temp = new byte[maxReadSize];

            var remaining = checked((int)count);
            while (remaining > 0)
            {
                int readSize = Math.Min(remaining, maxReadSize);
                FillBuffer(address, temp, 0, readSize);
                output.Write(temp, 0, readSize);
                remaining -= readSize;
                address += (uint)readSize;
            }
        }
    }
}