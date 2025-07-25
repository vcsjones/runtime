// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#ifndef __GCTOENV_EE_STANDALONE_INL__
#define __GCTOENV_EE_STANDALONE_INL__

#include "gcinterface.h"
#include "env/gcenv.ee.h"

// The singular interface instance. All calls in GCToEEInterface
// will be forwarded to this interface instance.
extern IGCToCLR* g_theGCToCLR;

// GC version that the current runtime supports
extern VersionInfo g_runtimeSupportedVersion;

// Does the runtime use the old method table flags
extern bool g_oldMethodTableFlags;

struct StressLogMsg;

// When we are building the GC in a standalone environment, we
// will be dispatching virtually against g_theGCToCLR to call
// into the EE. This class provides an identical API to the existing
// GCToEEInterface, but only forwards the call onto the global
// g_theGCToCLR instance.
inline void GCToEEInterface::SuspendEE(SUSPEND_REASON reason)
{
    assert(g_theGCToCLR != nullptr);
    g_theGCToCLR->SuspendEE(reason);
}

inline void GCToEEInterface::RestartEE(bool bFinishedGC)
{
    assert(g_theGCToCLR != nullptr);
    g_theGCToCLR->RestartEE(bFinishedGC);
}

inline void GCToEEInterface::GcScanRoots(promote_func* fn, int condemned, int max_gen, ScanContext* sc)
{
    assert(g_theGCToCLR != nullptr);
    g_theGCToCLR->GcScanRoots(fn, condemned, max_gen, sc);
}

inline void GCToEEInterface::GcStartWork(int condemned, int max_gen)
{
    assert(g_theGCToCLR != nullptr);
    g_theGCToCLR->GcStartWork(condemned, max_gen);
}

inline void GCToEEInterface::BeforeGcScanRoots(int condemned, bool is_bgc, bool is_concurrent)
{
    assert(g_theGCToCLR != nullptr);
    g_theGCToCLR->BeforeGcScanRoots(condemned, is_bgc, is_concurrent);
}

inline void GCToEEInterface::AfterGcScanRoots(int condemned, int max_gen, ScanContext* sc)
{
    assert(g_theGCToCLR != nullptr);
    g_theGCToCLR->AfterGcScanRoots(condemned, max_gen, sc);
}

inline void GCToEEInterface::GcDone(int condemned)
{
    assert(g_theGCToCLR != nullptr);
    g_theGCToCLR->GcDone(condemned);
}

inline bool GCToEEInterface::RefCountedHandleCallbacks(Object * pObject)
{
    assert(g_theGCToCLR != nullptr);
    return g_theGCToCLR->RefCountedHandleCallbacks(pObject);
}

inline void GCToEEInterface::TriggerClientBridgeProcessing(MarkCrossReferencesArgs* args)
{
    assert(g_theGCToCLR != nullptr);
    if (g_runtimeSupportedVersion.MajorVersion >= 4)
    {
        g_theGCToCLR->TriggerClientBridgeProcessing(args);
    }
}

inline void GCToEEInterface::SyncBlockCacheWeakPtrScan(HANDLESCANPROC scanProc, uintptr_t lp1, uintptr_t lp2)
{
    assert(g_theGCToCLR != nullptr);
    g_theGCToCLR->SyncBlockCacheWeakPtrScan(scanProc, lp1, lp2);
}

inline void GCToEEInterface::SyncBlockCacheDemote(int max_gen)
{
    assert(g_theGCToCLR != nullptr);
    g_theGCToCLR->SyncBlockCacheDemote(max_gen);
}

inline void GCToEEInterface::SyncBlockCachePromotionsGranted(int max_gen)
{
    assert(g_theGCToCLR != nullptr);
    g_theGCToCLR->SyncBlockCachePromotionsGranted(max_gen);
}

inline uint32_t GCToEEInterface::GetActiveSyncBlockCount()
{
    assert(g_theGCToCLR != nullptr);
    return g_theGCToCLR->GetActiveSyncBlockCount();
}

inline bool GCToEEInterface::IsPreemptiveGCDisabled()
{
    assert(g_theGCToCLR != nullptr);
    return g_theGCToCLR->IsPreemptiveGCDisabled();
}

inline bool GCToEEInterface::EnablePreemptiveGC()
{
    assert(g_theGCToCLR != nullptr);
    return  g_theGCToCLR->EnablePreemptiveGC();
}

inline void GCToEEInterface::DisablePreemptiveGC()
{
    assert(g_theGCToCLR != nullptr);
    g_theGCToCLR->DisablePreemptiveGC();
}

inline Thread* GCToEEInterface::GetThread()
{
    assert(g_theGCToCLR != nullptr);
    return g_theGCToCLR->GetThread();
}

inline gc_alloc_context * GCToEEInterface::GetAllocContext()
{
    assert(g_theGCToCLR != nullptr);
    return g_theGCToCLR->GetAllocContext();
}

inline void GCToEEInterface::GcEnumAllocContexts(enum_alloc_context_func* fn, void* param)
{
    assert(g_theGCToCLR != nullptr);
    g_theGCToCLR->GcEnumAllocContexts(fn, param);
}

inline uint8_t *GCToEEInterface::GetLoaderAllocatorObjectForGC(Object* pObject)
{
    assert(g_theGCToCLR != nullptr);
    return g_theGCToCLR->GetLoaderAllocatorObjectForGC(pObject);
}

inline void GCToEEInterface::DiagGCStart(int gen, bool isInduced)
{
    assert(g_theGCToCLR != nullptr);
    g_theGCToCLR->DiagGCStart(gen, isInduced);
}

inline void GCToEEInterface::DiagUpdateGenerationBounds()
{
    assert(g_theGCToCLR != nullptr);
    g_theGCToCLR->DiagUpdateGenerationBounds();
}

inline void GCToEEInterface::DiagGCEnd(size_t index, int gen, int reason, bool fConcurrent)
{
    assert(g_theGCToCLR != nullptr);
    g_theGCToCLR->DiagGCEnd(index, gen, reason, fConcurrent);
}

inline void GCToEEInterface::DiagWalkFReachableObjects(void* gcContext)
{
    assert(g_theGCToCLR != nullptr);
    g_theGCToCLR->DiagWalkFReachableObjects(gcContext);
}

inline void GCToEEInterface::DiagWalkSurvivors(void* gcContext, bool fCompacting)
{
    assert(g_theGCToCLR != nullptr);
    g_theGCToCLR->DiagWalkSurvivors(gcContext, fCompacting);
}

inline void GCToEEInterface::DiagWalkUOHSurvivors(void* gcContext, int gen)
{
    assert(g_theGCToCLR != nullptr);
    g_theGCToCLR->DiagWalkUOHSurvivors(gcContext, gen);
}

inline void GCToEEInterface::DiagWalkBGCSurvivors(void* gcContext)
{
    assert(g_theGCToCLR != nullptr);
    return g_theGCToCLR->DiagWalkBGCSurvivors(gcContext);
}

inline void GCToEEInterface::StompWriteBarrier(WriteBarrierParameters* args)
{
    assert(g_theGCToCLR != nullptr);
    g_theGCToCLR->StompWriteBarrier(args);
}

inline void GCToEEInterface::EnableFinalization(bool gcHasWorkForFinalizerThread)
{
    assert(g_theGCToCLR != nullptr);
    g_theGCToCLR->EnableFinalization(gcHasWorkForFinalizerThread);
}

inline void GCToEEInterface::HandleFatalError(unsigned int exitCode)
{
    assert(g_theGCToCLR != nullptr);
    g_theGCToCLR->HandleFatalError(exitCode);
}

inline bool GCToEEInterface::EagerFinalized(Object* obj)
{
    assert(g_theGCToCLR != nullptr);
    return g_theGCToCLR->EagerFinalized(obj);
}

inline MethodTable* GCToEEInterface::GetFreeObjectMethodTable()
{
    assert(g_theGCToCLR != nullptr);
    return g_theGCToCLR->GetFreeObjectMethodTable();
}

inline bool GCToEEInterface::GetBooleanConfigValue(const char* privateKey, const char* publicKey, bool* value)
{
    assert(g_theGCToCLR != nullptr);
    return g_theGCToCLR->GetBooleanConfigValue(privateKey, publicKey, value);
}

inline bool GCToEEInterface::GetIntConfigValue(const char* privateKey, const char* publicKey, int64_t* value)
{
    assert(g_theGCToCLR != nullptr);
    return g_theGCToCLR->GetIntConfigValue(privateKey, publicKey, value);
}

inline bool GCToEEInterface::GetStringConfigValue(const char* privateKey, const char* publicKey, const char** value)
{
    assert(g_theGCToCLR != nullptr);
    return g_theGCToCLR->GetStringConfigValue(privateKey, publicKey, value);
}

inline void GCToEEInterface::FreeStringConfigValue(const char* value)
{
    assert(g_theGCToCLR != nullptr);
    g_theGCToCLR->FreeStringConfigValue(value);
}

inline bool GCToEEInterface::IsGCThread()
{
    assert(g_theGCToCLR != nullptr);
    return g_theGCToCLR->IsGCThread();
}

inline bool GCToEEInterface::WasCurrentThreadCreatedByGC()
{
    assert(g_theGCToCLR != nullptr);
    return g_theGCToCLR->WasCurrentThreadCreatedByGC();
}

inline bool GCToEEInterface::CreateThread(void (*threadStart)(void*), void* arg, bool is_suspendable, const char* name)
{
    assert(g_theGCToCLR != nullptr);
    return g_theGCToCLR->CreateThread(threadStart, arg, is_suspendable, name);
}

inline void GCToEEInterface::WalkAsyncPinnedForPromotion(Object* object, ScanContext* sc, promote_func* callback)
{
    assert(g_theGCToCLR != nullptr);
    return g_theGCToCLR->WalkAsyncPinnedForPromotion(object, sc, callback);
}

inline void GCToEEInterface::WalkAsyncPinned(Object* object, void* context, void(*callback)(Object*, Object*, void*))
{
    assert(g_theGCToCLR != nullptr);
    return g_theGCToCLR->WalkAsyncPinned(object, context, callback);
}

inline IGCToCLREventSink* GCToEEInterface::EventSink()
{
    assert(g_theGCToCLR != nullptr);
    return g_theGCToCLR->EventSink();
}

inline uint32_t GCToEEInterface::GetTotalNumSizedRefHandles()
{
    assert(g_theGCToCLR != nullptr);
    return g_theGCToCLR->GetTotalNumSizedRefHandles();
}

inline bool GCToEEInterface::AnalyzeSurvivorsRequested(int condemnedGeneration)
{
    assert(g_theGCToCLR != nullptr);
    return g_theGCToCLR->AnalyzeSurvivorsRequested(condemnedGeneration);
}

inline void GCToEEInterface::AnalyzeSurvivorsFinished(size_t gcIndex, int condemnedGeneration, uint64_t promoted_bytes, void (*reportGenerationBounds)())
{
    assert(g_theGCToCLR != nullptr);
    g_theGCToCLR->AnalyzeSurvivorsFinished(gcIndex, condemnedGeneration, promoted_bytes, reportGenerationBounds);
}

inline void GCToEEInterface::VerifySyncTableEntry()
{
    assert(g_theGCToCLR != nullptr);
    g_theGCToCLR->VerifySyncTableEntry();
}

inline void GCToEEInterface::UpdateGCEventStatus(int publicLevel, int publicKeywords, int privateLevel, int privateKeywords)
{
    assert(g_theGCToCLR != nullptr);
#if defined(__linux__)
    g_theGCToCLR->UpdateGCEventStatus(publicLevel, publicKeywords, privateLevel, privateKeywords);
#endif // __linux__
}

inline void GCToEEInterface::LogStressMsg(unsigned level, unsigned facility, const StressLogMsg & msg)
{
    g_theGCToCLR->LogStressMsg(level, facility, msg);
}

inline uint32_t GCToEEInterface::GetCurrentProcessCpuCount()
{
    return g_theGCToCLR->GetCurrentProcessCpuCount();
}

inline void GCToEEInterface::DiagAddNewRegion(int generation, uint8_t* rangeStart, uint8_t* rangeEnd, uint8_t* rangeEndReserved)
{
    g_theGCToCLR->DiagAddNewRegion(generation, rangeStart, rangeEnd, rangeEndReserved);
}

inline void GCToEEInterface::LogErrorToHost(const char *message)
{
    if (g_runtimeSupportedVersion.MajorVersion >= 1)
    {
        g_theGCToCLR->LogErrorToHost(message);
    }
}

inline uint64_t GCToEEInterface::GetThreadOSThreadId(Thread* thread)
{
    if (g_runtimeSupportedVersion.MajorVersion >= 3)
    {
        return g_theGCToCLR->GetThreadOSThreadId(thread);
    }
    else
    {
        return 0;
    }
}

#endif // __GCTOENV_EE_STANDALONE_INL__
