// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// This file contains the globals and statics that are visible to DAC.
// It is used for the following:
// 1. in daccess.h to build the table of DAC globals
// 2. in enummem.cpp to dump out the related memory of static and globals
//    in a mini dump or heap dump
// 3. in DacUpdateDll and tools\DacTablenGen\main.cs
//
// To use this functionality for other tools or purposes, define the
// DEFINE_DACVAR macro & include dacvars.h like so (see enummem.cpp and/or
// daccess.h for examples):
//
// #define DEFINE_DACVAR(type, size, id, var)  type id;     //this defn. discards
//                                                          //the size
// #include "dacvars.h"
//
// @dbgtodo:
// Ideally we may be able to build a tool that generates this automatically.
// At the least, we should automatically verify that the contents of this file
// are consistent with the uses of all the macros like SVAL_DECL and GARY_DECL.
//
//=================================================
// INSTRUCTIONS FOR ADDING VARIABLES TO THIS FILE
//=================================================
// You need to add a global or static declared with DAC macros, such as SPTR_*
// GPTR_*, SVAL_*, GVAL_*, or GARY_*, only if the global or static is actually used
// in a DACized code path. If you have declared a static or global that way just
// because you were pattern-matching or because you anticipate that the variable
// may eventually be used in a DACized code path, you don't need to add it here,
// although in that case, you should not really use the DAC macro when you declare
// the global or static.
//					*				*				*
// The FIRST ARGUMENT should always be specified as ULONG. This is the type of
// the offsets for the corresponding id in the _DacGlobals table.
// @dbgtodo:
// We should get rid of the ULONG argument since it's always the same. We would
// also need to modify DacTablenGen\main.cs.
//					*				*				*
// The SECOND ARGUMENT, "true_type," is used to calculate the true size of the
// static/global variable. It is currently used only in enummem.cpp to write out
// theproper size of memory for dumps.
//					*				*				*
// The THIRD ARGUMENT should be a qualified name. If the variable is a static data
// member, the name should be <class_name>__<member_name>. If the variable is a
// global, the name should be <dac>__<global_name>.
//					*				*				*
// The FOURTH ARGUMENT should be the actual name of the static/global variable. If
// static data the should be [<namespace>::]<class_name>::<member_name>. If global,
// it should look like <global_name>.
//					*				*				*
// If you need to add an entry to this file, your type may not be visible when
// this file is compiled. In that case, you need to do one of two things:
// - If the type is a pointer type, you can simply use UNKNOWN_POINTER_TYPE as the
//	 "true type." It may be useful to specify the non-visible type in a comment.
// - If the type is a composite/user-defined type, you must #include the header
//   file that defines the type in enummem.cpp. Do NOT #include it in daccess.h
// Array types may be dumped via an explicit call to enumMem, so they should
// be declared with DEFINE_DACVAR_NO_DUMP. The size in this case is immaterial, since
// nothing will be dumped.

#ifndef DEFINE_DACVAR
#define DEFINE_DACVAR(true_type, id, var)
#endif

// Use this macro to define a static var that is known to the DAC and uses Volatile<T> for storage in the runtime
#ifndef DEFINE_DACVAR_VOLATILE
#define DEFINE_DACVAR_VOLATILE(true_type, id, var)
#endif

// Use this macro to define a static var that is known to DAC, but not captured in a dump.
#ifndef DEFINE_DACVAR_NO_DUMP
#define DEFINE_DACVAR_NO_DUMP(true_type, id, var)
#endif

#define UNKNOWN_POINTER_TYPE SIZE_T

DEFINE_DACVAR(PTR_RangeSectionMap, ExecutionManager__g_codeRangeMap, ExecutionManager::g_codeRangeMap)
DEFINE_DACVAR(PTR_EECodeManager, ExecutionManager__m_pDefaultCodeMan, ExecutionManager::m_pDefaultCodeMan)
DEFINE_DACVAR_VOLATILE(LONG, ExecutionManager__m_dwReaderCount, ExecutionManager::m_dwReaderCount)
DEFINE_DACVAR_VOLATILE(LONG, ExecutionManager__m_dwWriterLock, ExecutionManager::m_dwWriterLock)

DEFINE_DACVAR(PTR_EEJitManager, ExecutionManager__m_pEEJitManager, ExecutionManager::m_pEEJitManager)
#ifdef FEATURE_READYTORUN
DEFINE_DACVAR(PTR_ReadyToRunJitManager, ExecutionManager__m_pReadyToRunJitManager, ExecutionManager::m_pReadyToRunJitManager)
#endif
#ifdef FEATURE_INTERPRETER
DEFINE_DACVAR(PTR_InterpreterJitManager, ExecutionManager__m_pInterpreterJitManager, ExecutionManager::m_pInterpreterJitManager)
DEFINE_DACVAR(PTR_InterpreterCodeManager, ExecutionManager__m_pInterpreterCodeMan, ExecutionManager::m_pInterpreterCodeMan)
#endif

DEFINE_DACVAR_NO_DUMP(VMHELPDEF *, dac__hlpFuncTable, ::hlpFuncTable)
DEFINE_DACVAR(VMHELPDEF *, dac__hlpDynamicFuncTable, ::hlpDynamicFuncTable)

DEFINE_DACVAR(PTR_StubManager, StubManager__g_pFirstManager, StubManager::g_pFirstManager)
DEFINE_DACVAR(PTR_PrecodeStubManager, PrecodeStubManager__g_pManager, PrecodeStubManager::g_pManager)
DEFINE_DACVAR(PTR_StubLinkStubManager, StubLinkStubManager__g_pManager, StubLinkStubManager::g_pManager)
DEFINE_DACVAR(PTR_JumpStubStubManager, JumpStubStubManager__g_pManager, JumpStubStubManager::g_pManager)
DEFINE_DACVAR(PTR_RangeSectionStubManager, RangeSectionStubManager__g_pManager, RangeSectionStubManager::g_pManager)
DEFINE_DACVAR(PTR_VirtualCallStubManagerManager, VirtualCallStubManagerManager__g_pManager, VirtualCallStubManagerManager::g_pManager)
DEFINE_DACVAR(PTR_CallCountingStubManager, CallCountingStubManager__g_pManager, CallCountingStubManager::g_pManager)

DEFINE_DACVAR(PTR_ThreadStore, ThreadStore__s_pThreadStore, ThreadStore::s_pThreadStore)

DEFINE_DACVAR(PTR_Thread, dac__g_pFinalizerThread, ::g_pFinalizerThread)
DEFINE_DACVAR(PTR_Thread, dac__g_pSuspensionThread, ::g_pSuspensionThread)

DEFINE_DACVAR(DWORD, dac__g_heap_type, g_heap_type)
DEFINE_DACVAR(PTR_GcDacVars, dac__g_gcDacGlobals, g_gcDacGlobals)

DEFINE_DACVAR(PTR_AppDomain, AppDomain__m_pTheAppDomain, AppDomain::m_pTheAppDomain)
DEFINE_DACVAR(PTR_SystemDomain, SystemDomain__m_pSystemDomain, SystemDomain::m_pSystemDomain)

#ifdef FEATURE_INTEROP_DEBUGGING
DEFINE_DACVAR(DWORD, dac__g_debuggerWordTLSIndex, g_debuggerWordTLSIndex)
#endif
DEFINE_DACVAR(DWORD, dac__g_TlsIndex, g_TlsIndex)
DEFINE_DACVAR(DWORD, dac__g_offsetOfCurrentThreadInfo, g_offsetOfCurrentThreadInfo)

#ifdef FEATURE_EH_FUNCLETS
DEFINE_DACVAR(UNKNOWN_POINTER_TYPE, dac__g_pEHClass, ::g_pEHClass)
DEFINE_DACVAR(UNKNOWN_POINTER_TYPE, dac__g_pExceptionServicesInternalCallsClass, ::g_pExceptionServicesInternalCallsClass)
DEFINE_DACVAR(UNKNOWN_POINTER_TYPE, dac__g_pStackFrameIteratorClass, ::g_pStackFrameIteratorClass)
#endif

DEFINE_DACVAR(PTR_SString, SString__s_Empty, SString::s_Empty)

DEFINE_DACVAR(INT32, ArrayBase__s_arrayBoundsZero, ArrayBase::s_arrayBoundsZero)
DEFINE_DACVAR(BOOL, CodeVersionManager__s_HasNonDefaultILVersions, CodeVersionManager::s_HasNonDefaultILVersions)

DEFINE_DACVAR(PTR_JITNotification, dac__g_pNotificationTable, ::g_pNotificationTable)
DEFINE_DACVAR(ULONG32, dac__g_dacNotificationFlags, ::g_dacNotificationFlags)
DEFINE_DACVAR(PTR_GcNotification, dac__g_pGcNotificationTable, ::g_pGcNotificationTable)

DEFINE_DACVAR(PTR_EEConfig, dac__g_pConfig, ::g_pConfig)

DEFINE_DACVAR(CoreLibBinder, dac__g_CoreLib, ::g_CoreLib)

#if defined(PROFILING_SUPPORTED) || defined(PROFILING_SUPPORTED_DATA)
DEFINE_DACVAR(ProfControlBlock, dac__g_profControlBlock, ::g_profControlBlock)
#endif // defined(PROFILING_SUPPORTED) || defined(PROFILING_SUPPORTED_DATA)

DEFINE_DACVAR(PTR_DWORD, dac__g_card_table, ::g_card_table)
DEFINE_DACVAR(PTR_BYTE, dac__g_lowest_address, ::g_lowest_address)
DEFINE_DACVAR(PTR_BYTE, dac__g_highest_address, ::g_highest_address)
DEFINE_DACVAR(ee_alloc_context, dac__g_global_alloc_context, ::g_global_alloc_context)

DEFINE_DACVAR(IGCHeap, dac__g_pGCHeap, ::g_pGCHeap)

DEFINE_DACVAR(UNKNOWN_POINTER_TYPE, dac__g_pThinLockThreadIdDispenser, ::g_pThinLockThreadIdDispenser)
DEFINE_DACVAR(UNKNOWN_POINTER_TYPE, dac__g_pObjectClass, ::g_pObjectClass)
DEFINE_DACVAR(UNKNOWN_POINTER_TYPE, dac__g_pRuntimeTypeClass, ::g_pRuntimeTypeClass)
DEFINE_DACVAR(UNKNOWN_POINTER_TYPE, dac__g_pCanonMethodTableClass, ::g_pCanonMethodTableClass)
DEFINE_DACVAR(UNKNOWN_POINTER_TYPE, dac__g_pStringClass, ::g_pStringClass)
DEFINE_DACVAR(UNKNOWN_POINTER_TYPE, dac__g_pArrayClass, ::g_pArrayClass)
DEFINE_DACVAR(UNKNOWN_POINTER_TYPE, dac__g_pSZArrayHelperClass, ::g_pSZArrayHelperClass)
DEFINE_DACVAR(UNKNOWN_POINTER_TYPE, dac__g_pNullableClass, ::g_pNullableClass)
DEFINE_DACVAR(UNKNOWN_POINTER_TYPE, dac__g_pExceptionClass, ::g_pExceptionClass)
DEFINE_DACVAR(UNKNOWN_POINTER_TYPE, dac__g_pThreadAbortExceptionClass, ::g_pThreadAbortExceptionClass)
DEFINE_DACVAR(UNKNOWN_POINTER_TYPE, dac__g_pOutOfMemoryExceptionClass, ::g_pOutOfMemoryExceptionClass)
DEFINE_DACVAR(UNKNOWN_POINTER_TYPE, dac__g_pStackOverflowExceptionClass, ::g_pStackOverflowExceptionClass)
DEFINE_DACVAR(UNKNOWN_POINTER_TYPE, dac__g_pExecutionEngineExceptionClass, ::g_pExecutionEngineExceptionClass)
DEFINE_DACVAR(UNKNOWN_POINTER_TYPE, dac__g_pDelegateClass, ::g_pDelegateClass)
DEFINE_DACVAR(UNKNOWN_POINTER_TYPE, dac__g_pMulticastDelegateClass, ::g_pMulticastDelegateClass)
DEFINE_DACVAR(UNKNOWN_POINTER_TYPE, dac__g_pFreeObjectMethodTable, ::g_pFreeObjectMethodTable)
DEFINE_DACVAR(UNKNOWN_POINTER_TYPE, dac__g_pValueTypeClass, ::g_pValueTypeClass)
DEFINE_DACVAR(UNKNOWN_POINTER_TYPE, dac__g_pEnumClass, ::g_pEnumClass)
DEFINE_DACVAR(UNKNOWN_POINTER_TYPE, dac__g_pThreadClass, ::g_pThreadClass)
DEFINE_DACVAR(UNKNOWN_POINTER_TYPE, dac__g_pPredefinedArrayTypes, ::g_pPredefinedArrayTypes)
DEFINE_DACVAR(UNKNOWN_POINTER_TYPE, dac__g_TypedReferenceMT, ::g_TypedReferenceMT)

DEFINE_DACVAR(UNKNOWN_POINTER_TYPE, dac__g_pWeakReferenceClass, ::g_pWeakReferenceClass)
DEFINE_DACVAR(UNKNOWN_POINTER_TYPE, dac__g_pWeakReferenceOfTClass, ::g_pWeakReferenceOfTClass)

#ifdef FEATURE_COMINTEROP
DEFINE_DACVAR(UNKNOWN_POINTER_TYPE, dac__g_pBaseCOMObject, ::g_pBaseCOMObject)
#endif

DEFINE_DACVAR(UNKNOWN_POINTER_TYPE, dac__g_pIDynamicInterfaceCastableInterface, ::g_pIDynamicInterfaceCastableInterface)

DEFINE_DACVAR(UNKNOWN_POINTER_TYPE, dac__g_pObjectFinalizerMD, ::g_pObjectFinalizerMD)

DEFINE_DACVAR(bool, dac__g_fProcessDetach, ::g_fProcessDetach)
DEFINE_DACVAR_VOLATILE(DWORD, dac__g_fEEShutDown, ::g_fEEShutDown)

DEFINE_DACVAR(ULONG, dac__g_CORDebuggerControlFlags, ::g_CORDebuggerControlFlags)
DEFINE_DACVAR(UNKNOWN_POINTER_TYPE, dac__g_pDebugger, ::g_pDebugger)
DEFINE_DACVAR(UNKNOWN_POINTER_TYPE, dac__g_pDebugInterface, ::g_pDebugInterface)
DEFINE_DACVAR(UNKNOWN_POINTER_TYPE, dac__g_pEEDbgInterfaceImpl, ::g_pEEDbgInterfaceImpl)
DEFINE_DACVAR(UNKNOWN_POINTER_TYPE, dac__g_pEEInterface, ::g_pEEInterface)
DEFINE_DACVAR(ULONG, dac__CLRJitAttachState, ::CLRJitAttachState)

DEFINE_DACVAR(BOOL, Debugger__s_fCanChangeNgenFlags, Debugger::s_fCanChangeNgenFlags)

DEFINE_DACVAR(PTR_DebuggerPatchTable, DebuggerController__g_patches, DebuggerController::g_patches)
DEFINE_DACVAR(BOOL, DebuggerController__g_patchTableValid, DebuggerController::g_patchTableValid)

DEFINE_DACVAR(SIZE_T, dac__gLowestFCall, ::gLowestFCall)
DEFINE_DACVAR(SIZE_T, dac__gHighestFCall, ::gHighestFCall)
DEFINE_DACVAR(SIZE_T, dac__gFCallMethods, ::gFCallMethods)

DEFINE_DACVAR(PTR_SyncTableEntry, dac__g_pSyncTable, ::g_pSyncTable)
#ifdef FEATURE_COMINTEROP
DEFINE_DACVAR(UNKNOWN_POINTER_TYPE, dac__g_pRCWCleanupList, ::g_pRCWCleanupList)
#endif // FEATURE_COMINTEROP

#ifndef TARGET_UNIX
DEFINE_DACVAR(SIZE_T, dac__g_runtimeLoadedBaseAddress, ::g_runtimeLoadedBaseAddress)
DEFINE_DACVAR(SIZE_T, dac__g_runtimeVirtualSize, ::g_runtimeVirtualSize)
#endif // !TARGET_UNIX

DEFINE_DACVAR(SyncBlockCache *, SyncBlockCache__s_pSyncBlockCache, SyncBlockCache::s_pSyncBlockCache)

DEFINE_DACVAR(UNKNOWN_POINTER_TYPE, dac__g_pStressLog, ::g_pStressLog)

DEFINE_DACVAR(SIZE_T, dac__s_gsCookie, ::s_gsCookie)

DEFINE_DACVAR_NO_DUMP(SIZE_T, dac__g_FCDynamicallyAssignedImplementations, ::g_FCDynamicallyAssignedImplementations)

#ifndef TARGET_UNIX
DEFINE_DACVAR(HANDLE, dac__g_hContinueStartupEvent, ::g_hContinueStartupEvent)
#endif // !TARGET_UNIX
DEFINE_DACVAR(DWORD, CorHost2__m_dwStartupFlags, CorHost2::m_dwStartupFlags)

DEFINE_DACVAR(HRESULT, dac__g_hrFatalError, ::g_hrFatalError)

#ifdef FEATURE_MINIMETADATA_IN_TRIAGEDUMPS
DEFINE_DACVAR(DWORD, dac__g_MiniMetaDataBuffMaxSize, ::g_MiniMetaDataBuffMaxSize)
DEFINE_DACVAR(TADDR, dac__g_MiniMetaDataBuffAddress, ::g_MiniMetaDataBuffAddress)
#endif // FEATURE_MINIMETADATA_IN_TRIAGEDUMPS

DEFINE_DACVAR(SIZE_T, dac__g_clrNotificationArguments, ::g_clrNotificationArguments)

#ifdef FEATURE_METADATA_UPDATER
DEFINE_DACVAR(bool, dac__g_metadataUpdatesApplied, ::g_metadataUpdatesApplied)
#endif

DEFINE_DACVAR(PTR_WSTR, dac__g_EntryAssemblyPath, ::g_EntryAssemblyPath)

DEFINE_DACVAR(CDacPlatformMetadata, dac__g_cdacPlatformMetadata, ::g_cdacPlatformMetadata)

#undef DEFINE_DACVAR
#undef DEFINE_DACVAR_NO_DUMP
