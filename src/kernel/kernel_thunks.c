/*
 * kernel_thunks.c - Xbox Kernel Thunk Table & Initialization
 *
 * Provides target-neutral Xbox kernel export resolution and logging.
 *
 * The title-specific thunk table is decoded and patched by kernel_bridge.c.
 * This file maintains an ordinal-indexed compatibility table of available
 * replacement functions and data exports; it contains no per-title slot order.
 *
 * This file provides:
 *   - xbox_kernel_thunk_table[] - compatibility entries indexed by ordinal
 *   - xbox_resolve_ordinal() - maps ordinal → function/data pointer
 *   - xbox_kernel_init() - fills the thunk table and initializes subsystems
 *   - xbox_kernel_shutdown() - cleanup
 *   - xbox_log() - logging implementation
 */

#include "kernel.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>

/* ============================================================================
 * Thunk Table Storage
 * ============================================================================ */

ULONG_PTR xbox_kernel_thunk_table[XBOX_KERNEL_EXPORT_TABLE_SIZE] = {0};

/* ============================================================================
 * Logging Implementation
 * ============================================================================ */

static FILE* g_log_file = NULL;
static int   g_log_level = XBOX_LOG_INFO;
static CRITICAL_SECTION g_log_cs;
static BOOL  g_log_cs_init = FALSE;

static const char* xbox_log_level_str(int level)
{
    switch (level) {
        case XBOX_LOG_ERROR: return "ERROR";
        case XBOX_LOG_WARN:  return "WARN ";
        case XBOX_LOG_INFO:  return "INFO ";
        case XBOX_LOG_DEBUG: return "DEBUG";
        case XBOX_LOG_TRACE: return "TRACE";
        default:             return "?????";
    }
}

void xbox_log(int level, const char* subsystem, const char* fmt, ...)
{
    va_list args;
    char timestamp[32];
    SYSTEMTIME st;

    if (level > g_log_level)
        return;

    GetLocalTime(&st);
    snprintf(timestamp, sizeof(timestamp), "%02d:%02d:%02d.%03d",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    if (g_log_cs_init)
        EnterCriticalSection(&g_log_cs);

    FILE* out = g_log_file ? g_log_file : stderr;
    fprintf(out, "[%s] %s [%-6s] ", timestamp, xbox_log_level_str(level), subsystem);

    va_start(args, fmt);
    vfprintf(out, fmt, args);
    va_end(args);

    fprintf(out, "\n");
    fflush(out);

    if (g_log_cs_init)
        LeaveCriticalSection(&g_log_cs);
}

/* ============================================================================
 * Ordinal Resolution
 *
 * Maps each Xbox kernel ordinal to our implementation address.
 * Returns 0 for unimplemented ordinals (logged as warnings).
 *
 * Ordinals are from the Xbox kernel export table. Each one maps to
 * either a function pointer or a data pointer.
 * ============================================================================ */

ULONG_PTR xbox_resolve_ordinal(ULONG ordinal)
{
    switch (ordinal) {
    case   1: return (ULONG_PTR)xbox_AvGetSavedDataAddress;  /* AvGetSavedDataAddress */
    case   2: return (ULONG_PTR)xbox_AvSendTVEncoderOption;  /* AvSendTVEncoderOption */
    case   3: return (ULONG_PTR)xbox_AvSetDisplayMode;  /* AvSetDisplayMode */
    case   4: return (ULONG_PTR)xbox_AvSetSavedDataAddress;  /* AvSetSavedDataAddress */
    case   9: return (ULONG_PTR)xbox_HalReadSMCTrayState;  /* HalReadSMCTrayState */
    case  14: return (ULONG_PTR)xbox_ExAllocatePool;  /* ExAllocatePool */
    case  15: return (ULONG_PTR)xbox_ExAllocatePoolWithTag;  /* ExAllocatePoolWithTag */
    case  16: return (ULONG_PTR)&xbox_ExEventObjectType;  /* ExEventObjectType */
    case  17: return (ULONG_PTR)xbox_ExFreePool;  /* ExFreePool */
    case  23: return (ULONG_PTR)xbox_ExQueryPoolBlockSize;  /* ExQueryPoolBlockSize */
    case  24: return (ULONG_PTR)xbox_ExQueryNonVolatileSetting;  /* ExQueryNonVolatileSetting */
    case  29: return (ULONG_PTR)xbox_ExSaveNonVolatileSetting;  /* ExSaveNonVolatileSetting */
    case  38: return (ULONG_PTR)xbox_HalClearSoftwareInterrupt;  /* HalClearSoftwareInterrupt */
    case  39: return (ULONG_PTR)xbox_HalDisableSystemInterrupt;  /* HalDisableSystemInterrupt */
    case  44: return (ULONG_PTR)xbox_HalGetInterruptVector;  /* HalGetInterruptVector */
    case  45: return (ULONG_PTR)xbox_HalReadSMBusValue;  /* HalReadSMBusValue */
    case  46: return (ULONG_PTR)xbox_HalReadWritePCISpace;  /* HalReadWritePCISpace */
    case  48: return (ULONG_PTR)xbox_HalRequestSoftwareInterrupt;  /* HalRequestSoftwareInterrupt */
    case  49: return (ULONG_PTR)xbox_HalReturnToFirmware;  /* HalReturnToFirmware */
    case  50: return (ULONG_PTR)xbox_HalWriteSMBusValue;  /* HalWriteSMBusValue */
    case  61: return (ULONG_PTR)xbox_IoBuildDeviceIoControlRequest;  /* IoBuildDeviceIoControlRequest */
    case  64: return (ULONG_PTR)&xbox_IoCompletionObjectType;  /* IoCompletionObjectType */
    case  65: return (ULONG_PTR)xbox_IoCreateDevice;  /* IoCreateDevice */
    case  66: return (ULONG_PTR)xbox_IoCreateFile;  /* IoCreateFile */
    case  68: return (ULONG_PTR)xbox_IoDeleteDevice;  /* IoDeleteDevice */
    case  70: return (ULONG_PTR)&xbox_IoDeviceObjectType;  /* IoDeviceObjectType */
    case  73: return (ULONG_PTR)xbox_IoInitializeIrp;  /* IoInitializeIrp */
    case  79: return (ULONG_PTR)xbox_IoSetIoCompletion;  /* IoSetIoCompletion */
    case  81: return (ULONG_PTR)xbox_IoStartNextPacket;  /* IoStartNextPacket */
    case  82: return (ULONG_PTR)xbox_IoStartNextPacketByKey;  /* IoStartNextPacketByKey */
    case  83: return (ULONG_PTR)xbox_IoStartPacket;  /* IoStartPacket */
    case  84: return (ULONG_PTR)xbox_IoSynchronousDeviceIoControlRequest;  /* IoSynchronousDeviceIoControlRequest */
    case  85: return (ULONG_PTR)xbox_IoSynchronousFsdRequest;  /* IoSynchronousFsdRequest */
    case  93: return (ULONG_PTR)xbox_KeAlertThread;  /* KeAlertThread */
    case  95: return (ULONG_PTR)xbox_KeBugCheck;  /* KeBugCheck */
    case  96: return (ULONG_PTR)xbox_KeBugCheckEx;  /* KeBugCheckEx */
    case  97: return (ULONG_PTR)xbox_KeCancelTimer;  /* KeCancelTimer */
    case  98: return (ULONG_PTR)xbox_KeConnectInterrupt;  /* KeConnectInterrupt */
    case  99: return (ULONG_PTR)xbox_KeDelayExecutionThread;  /* KeDelayExecutionThread */
    case 107: return (ULONG_PTR)xbox_KeInitializeDpc;  /* KeInitializeDpc */
    case 109: return (ULONG_PTR)xbox_KeInitializeInterrupt;  /* KeInitializeInterrupt */
    case 113: return (ULONG_PTR)xbox_KeInitializeTimerEx;  /* KeInitializeTimerEx */
    case 119: return (ULONG_PTR)xbox_KeInsertQueueDpc;  /* KeInsertQueueDpc */
    case 124: return (ULONG_PTR)xbox_KeQueryBasePriorityThread;  /* KeQueryBasePriorityThread */
    case 126: return (ULONG_PTR)xbox_KeQueryPerformanceCounter;  /* KeQueryPerformanceCounter */
    case 127: return (ULONG_PTR)xbox_KeQueryPerformanceFrequency;  /* KeQueryPerformanceFrequency */
    case 128: return (ULONG_PTR)xbox_KeQuerySystemTime;  /* KeQuerySystemTime */
    case 129: return (ULONG_PTR)xbox_KeRaiseIrqlToDpcLevel;  /* KeRaiseIrqlToDpcLevel */
    case 137: return (ULONG_PTR)xbox_KeRemoveQueueDpc;  /* KeRemoveQueueDpc */
    case 139: return (ULONG_PTR)xbox_KeRestoreFloatingPointState;  /* KeRestoreFloatingPointState */
    case 142: return (ULONG_PTR)xbox_KeSaveFloatingPointState;  /* KeSaveFloatingPointState */
    case 143: return (ULONG_PTR)xbox_KeSetBasePriorityThread;  /* KeSetBasePriorityThread */
    case 145: return (ULONG_PTR)xbox_KeSetEvent;  /* KeSetEvent */
    case 149: return (ULONG_PTR)xbox_KeSetTimer;  /* KeSetTimer */
    case 150: return (ULONG_PTR)xbox_KeSetTimerEx;  /* KeSetTimerEx */
    case 151: return (ULONG_PTR)xbox_KeStallExecutionProcessor;  /* KeStallExecutionProcessor */
    case 153: return (ULONG_PTR)xbox_KeSynchronizeExecution;  /* KeSynchronizeExecution */
    case 156: return (ULONG_PTR)&xbox_KeTickCount;  /* KeTickCount */
    case 158: return (ULONG_PTR)xbox_KeWaitForMultipleObjects;  /* KeWaitForMultipleObjects */
    case 159: return (ULONG_PTR)xbox_KeWaitForSingleObject;  /* KeWaitForSingleObject */
    case 160: return (ULONG_PTR)xbox_KfRaiseIrql;  /* KfRaiseIrql */
    case 161: return (ULONG_PTR)xbox_KfLowerIrql;  /* KfLowerIrql */
    case 164: return (ULONG_PTR)&xbox_LaunchDataPage;  /* LaunchDataPage */
    case 165: return (ULONG_PTR)xbox_MmAllocateContiguousMemory;  /* MmAllocateContiguousMemory */
    case 166: return (ULONG_PTR)xbox_MmAllocateContiguousMemoryEx;  /* MmAllocateContiguousMemoryEx */
    case 167: return (ULONG_PTR)xbox_MmAllocateSystemMemory;  /* MmAllocateSystemMemory */
    case 168: return (ULONG_PTR)xbox_MmClaimGpuInstanceMemory;  /* MmClaimGpuInstanceMemory */
    case 169: return (ULONG_PTR)xbox_MmCreateKernelStack;  /* MmCreateKernelStack */
    case 170: return (ULONG_PTR)xbox_MmDeleteKernelStack;  /* MmDeleteKernelStack */
    case 171: return (ULONG_PTR)xbox_MmFreeContiguousMemory;  /* MmFreeContiguousMemory */
    case 172: return (ULONG_PTR)xbox_MmFreeSystemMemory;  /* MmFreeSystemMemory */
    case 173: return (ULONG_PTR)xbox_MmGetPhysicalAddress;  /* MmGetPhysicalAddress */
    case 175: return (ULONG_PTR)xbox_MmLockUnlockBufferPages;  /* MmLockUnlockBufferPages */
    case 176: return (ULONG_PTR)xbox_MmLockUnlockPhysicalPage;  /* MmLockUnlockPhysicalPage */
    case 177: return (ULONG_PTR)xbox_MmMapIoSpace;  /* MmMapIoSpace */
    case 178: return (ULONG_PTR)xbox_MmPersistContiguousMemory;  /* MmPersistContiguousMemory */
    case 179: return (ULONG_PTR)xbox_MmQueryAddressProtect;  /* MmQueryAddressProtect */
    case 180: return (ULONG_PTR)xbox_MmQueryAllocationSize;  /* MmQueryAllocationSize */
    case 181: return (ULONG_PTR)xbox_MmQueryStatistics;  /* MmQueryStatistics */
    case 182: return (ULONG_PTR)xbox_MmSetAddressProtect;  /* MmSetAddressProtect */
    case 183: return (ULONG_PTR)xbox_MmUnmapIoSpace;  /* MmUnmapIoSpace */
    case 184: return (ULONG_PTR)xbox_NtAllocateVirtualMemory;  /* NtAllocateVirtualMemory */
    case 187: return (ULONG_PTR)xbox_NtClose;  /* NtClose */
    case 189: return (ULONG_PTR)xbox_NtCreateEvent;  /* NtCreateEvent */
    case 190: return (ULONG_PTR)xbox_NtCreateFile;  /* NtCreateFile */
    case 193: return (ULONG_PTR)xbox_NtCreateSemaphore;  /* NtCreateSemaphore */
    case 195: return (ULONG_PTR)xbox_NtDeleteFile;  /* NtDeleteFile */
    case 196: return (ULONG_PTR)xbox_NtDeviceIoControlFile;  /* NtDeviceIoControlFile */
    case 197: return (ULONG_PTR)xbox_NtDuplicateObject;  /* NtDuplicateObject */
    case 198: return (ULONG_PTR)xbox_NtFlushBuffersFile;  /* NtFlushBuffersFile */
    case 199: return (ULONG_PTR)xbox_NtFreeVirtualMemory;  /* NtFreeVirtualMemory */
    case 200: return (ULONG_PTR)xbox_NtFsControlFile;  /* NtFsControlFile */
    case 202: return (ULONG_PTR)xbox_NtOpenFile;  /* NtOpenFile */
    case 203: return (ULONG_PTR)xbox_NtOpenSymbolicLinkObject;  /* NtOpenSymbolicLinkObject */
    case 207: return (ULONG_PTR)xbox_NtQueryDirectoryFile;  /* NtQueryDirectoryFile */
    case 210: return (ULONG_PTR)xbox_NtQueryFullAttributesFile;  /* NtQueryFullAttributesFile */
    case 211: return (ULONG_PTR)xbox_NtQueryInformationFile;  /* NtQueryInformationFile */
    case 215: return (ULONG_PTR)xbox_NtQuerySymbolicLinkObject;  /* NtQuerySymbolicLinkObject */
    case 217: return (ULONG_PTR)xbox_NtQueryVirtualMemory;  /* NtQueryVirtualMemory */
    case 218: return (ULONG_PTR)xbox_NtQueryVolumeInformationFile;  /* NtQueryVolumeInformationFile */
    case 219: return (ULONG_PTR)xbox_NtReadFile;  /* NtReadFile */
    case 222: return (ULONG_PTR)xbox_NtReleaseSemaphore;  /* NtReleaseSemaphore */
    case 225: return (ULONG_PTR)xbox_NtSetEvent;  /* NtSetEvent */
    case 226: return (ULONG_PTR)xbox_NtSetInformationFile;  /* NtSetInformationFile */
    case 228: return (ULONG_PTR)xbox_NtSetSystemTime;  /* NtSetSystemTime */
    case 233: return (ULONG_PTR)xbox_NtWaitForSingleObject;  /* NtWaitForSingleObject */
    case 235: return (ULONG_PTR)xbox_NtWaitForMultipleObjectsEx;  /* NtWaitForMultipleObjectsEx */
    case 236: return (ULONG_PTR)xbox_NtWriteFile;  /* NtWriteFile */
    case 238: return (ULONG_PTR)xbox_NtYieldExecution;  /* NtYieldExecution */
    case 246: return (ULONG_PTR)xbox_ObReferenceObjectByHandle;  /* ObReferenceObjectByHandle */
    case 247: return (ULONG_PTR)xbox_ObReferenceObjectByName;  /* ObReferenceObjectByName */
    case 250: return (ULONG_PTR)xbox_ObfDereferenceObject;  /* ObfDereferenceObject */
    case 251: return (ULONG_PTR)xbox_ObfReferenceObject;  /* ObfReferenceObject */
    case 252: return (ULONG_PTR)xbox_PhyGetLinkState;  /* PhyGetLinkState */
    case 253: return (ULONG_PTR)xbox_PhyInitialize;  /* PhyInitialize */
    case 255: return (ULONG_PTR)xbox_PsCreateSystemThreadEx;  /* PsCreateSystemThreadEx */
    case 258: return (ULONG_PTR)xbox_PsTerminateSystemThread;  /* PsTerminateSystemThread */
    case 259: return (ULONG_PTR)&xbox_PsThreadObjectType;  /* PsThreadObjectType */
    case 260: return (ULONG_PTR)xbox_RtlAnsiStringToUnicodeString;  /* RtlAnsiStringToUnicodeString */
    case 269: return (ULONG_PTR)xbox_RtlCompareMemoryUlong;  /* RtlCompareMemoryUlong */
    case 277: return (ULONG_PTR)xbox_RtlEnterCriticalSection;  /* RtlEnterCriticalSection */
    case 279: return (ULONG_PTR)xbox_RtlEqualString;  /* RtlEqualString */
    case 289: return (ULONG_PTR)xbox_RtlInitAnsiString;  /* RtlInitAnsiString */
    case 290: return (ULONG_PTR)xbox_RtlInitUnicodeString;  /* RtlInitUnicodeString */
    case 291: return (ULONG_PTR)xbox_RtlInitializeCriticalSection;  /* RtlInitializeCriticalSection */
    case 294: return (ULONG_PTR)xbox_RtlLeaveCriticalSection;  /* RtlLeaveCriticalSection */
    case 301: return (ULONG_PTR)xbox_RtlNtStatusToDosError;  /* RtlNtStatusToDosError */
    case 302: return (ULONG_PTR)xbox_RtlRaiseException;  /* RtlRaiseException */
    case 304: return (ULONG_PTR)xbox_RtlTimeFieldsToTime;  /* RtlTimeFieldsToTime */
    case 305: return (ULONG_PTR)xbox_RtlTimeToTimeFields;  /* RtlTimeToTimeFields */
    case 308: return (ULONG_PTR)xbox_RtlUnicodeStringToAnsiString;  /* RtlUnicodeStringToAnsiString */
    case 312: return (ULONG_PTR)xbox_RtlUnwind;  /* RtlUnwind */
    case 322: return (ULONG_PTR)&xbox_HardwareInfo;  /* XboxHardwareInfo */
    case 323: return (ULONG_PTR)xbox_HDKey;  /* XboxHDKey */
    case 324: return (ULONG_PTR)&xbox_KrnlVersion;  /* XboxKrnlVersion */
    case 325: return (ULONG_PTR)xbox_SignatureKey;  /* XboxSignatureKey */
    case 326: return (ULONG_PTR)&xbox_XeImageFileName;  /* XeImageFileName */
    case 327: return (ULONG_PTR)xbox_XeLoadSection;  /* XeLoadSection */
    case 328: return (ULONG_PTR)xbox_XeUnloadSection;  /* XeUnloadSection */
    case 333: return (ULONG_PTR)xbox_WRITE_PORT_BUFFER_USHORT;  /* WRITE_PORT_BUFFER_USHORT */
    case 334: return (ULONG_PTR)xbox_WRITE_PORT_BUFFER_ULONG;  /* WRITE_PORT_BUFFER_ULONG */
    case 335: return (ULONG_PTR)xbox_XcSHAInit;  /* XcSHAInit */
    case 336: return (ULONG_PTR)xbox_XcSHAUpdate;  /* XcSHAUpdate */
    case 337: return (ULONG_PTR)xbox_XcSHAFinal;  /* XcSHAFinal */
    case 338: return (ULONG_PTR)xbox_XcRC4Key;  /* XcRC4Key */
    case 339: return (ULONG_PTR)xbox_XcRC4Crypt;  /* XcRC4Crypt */
    case 340: return (ULONG_PTR)xbox_XcHMAC;  /* XcHMAC */
    case 341: return (ULONG_PTR)xbox_XcPKEncPublic;  /* XcPKEncPublic */
    case 342: return (ULONG_PTR)xbox_XcPKDecPrivate;  /* XcPKDecPrivate */
    case 343: return (ULONG_PTR)xbox_XcPKGetKeyLen;  /* XcPKGetKeyLen */
    case 344: return (ULONG_PTR)xbox_XcVerifyPKCS1Signature;  /* XcVerifyPKCS1Signature */
    case 345: return (ULONG_PTR)xbox_XcModExp;  /* XcModExp */
    case 346: return (ULONG_PTR)xbox_XcDESKeyParity;  /* XcDESKeyParity */
    case 347: return (ULONG_PTR)xbox_XcKeyTable;  /* XcKeyTable */
    case 348: return (ULONG_PTR)xbox_XcBlockCrypt;  /* XcBlockCrypt */
    case 349: return (ULONG_PTR)xbox_XcBlockCryptCBC;  /* XcBlockCryptCBC */
    case 350: return (ULONG_PTR)xbox_XcCryptService;  /* XcCryptService */
    case 351: return (ULONG_PTR)xbox_XcUpdateCrypto;  /* XcUpdateCrypto */
    case 352: return (ULONG_PTR)xbox_RtlRip;  /* RtlRip */
    case 353: return (ULONG_PTR)xbox_LANKey;  /* XboxLANKey */
    case 354: return (ULONG_PTR)xbox_AlternateSignatureKeys;  /* XboxAlternateSignatureKeys */
    case 355: return (ULONG_PTR)xbox_XePublicKeyData;  /* XePublicKeyData */
    case 358: return (ULONG_PTR)xbox_HalIsResetOrShutdownPending;  /* HalIsResetOrShutdownPending */
    case 359: return (ULONG_PTR)xbox_IoMarkIrpMustComplete;  /* IoMarkIrpMustComplete */
    case 360: return (ULONG_PTR)xbox_HalInitiateShutdown;  /* HalInitiateShutdown */
    case 361: return (ULONG_PTR)xbox_RtlSnprintf;  /* RtlSnprintf */
    case 362: return (ULONG_PTR)xbox_RtlSprintf;  /* RtlSprintf */
    case 363: return (ULONG_PTR)xbox_RtlVsnprintf;  /* RtlVsnprintf */
    case 364: return (ULONG_PTR)xbox_RtlVsprintf;  /* RtlVsprintf */
    default:
        xbox_log(XBOX_LOG_ERROR, XBOX_LOG_THUNK,
            "Unresolved kernel ordinal %u", ordinal);
        return 0;
    }
}

/* ============================================================================
 * Unresolved Thunk Handler
 *
 * Called if game code tries to use a thunk slot that wasn't resolved.
 * Logs the error and triggers a debug break.
 * ============================================================================ */

static void __stdcall xbox_unresolved_thunk(void)
{
    xbox_log(XBOX_LOG_ERROR, XBOX_LOG_THUNK,
        "Call to unresolved kernel thunk! Return address is on the stack.");
#ifdef _DEBUG
    DebugBreak();
#endif
}

/* ============================================================================
 * xbox_kernel_init - Initialize the kernel replacement layer
 *
 * Must be called before any game code runs. Sets up:
 *   1. Logging system
 *   2. Path translation
 *   3. Ordinal-indexed compatibility export table
 * ============================================================================ */

void xbox_kernel_init(void)
{
    ULONG resolved = 0;
    ULONG unresolved = 0;

    /* Initialize logging */
    InitializeCriticalSection(&g_log_cs);
    g_log_cs_init = TRUE;

    /* Try to open log file, fall back to stderr */
    g_log_file = fopen("xbox_kernel.log", "w");

    /* Set log level from environment variable if present */
    const char* log_env = getenv("XBOX_LOG_LEVEL");
    if (log_env) {
        g_log_level = atoi(log_env);
        if (g_log_level < XBOX_LOG_ERROR) g_log_level = XBOX_LOG_ERROR;
        if (g_log_level > XBOX_LOG_TRACE) g_log_level = XBOX_LOG_TRACE;
    }

    xbox_log(XBOX_LOG_INFO, XBOX_LOG_THUNK,
        "=== Xbox Kernel Replacement Layer initializing ===");
    xbox_log(XBOX_LOG_INFO, XBOX_LOG_THUNK,
        "Kernel version: %u.%u.%u.%u (emulated)",
        xbox_KrnlVersion.Major, xbox_KrnlVersion.Minor,
        xbox_KrnlVersion.Build, xbox_KrnlVersion.Qfe);

    /* Fill the compatibility table by export ordinal, not title thunk slot. */
    for (ULONG ordinal = 1; ordinal <= XBOX_KERNEL_MAX_ORDINAL; ordinal++) {
        ULONG_PTR ptr = xbox_resolve_ordinal(ordinal);
        if (ptr) {
            xbox_kernel_thunk_table[ordinal] = ptr;
            resolved++;
        } else {
            xbox_kernel_thunk_table[ordinal] = (ULONG_PTR)xbox_unresolved_thunk;
            unresolved++;
        }
    }

    xbox_log(XBOX_LOG_INFO, XBOX_LOG_THUNK,
        "Kernel exports: %u/%u implemented, %u unresolved",
        resolved, XBOX_KERNEL_MAX_ORDINAL, unresolved);

    xbox_log(XBOX_LOG_INFO, XBOX_LOG_THUNK,
        "=== Xbox Kernel Replacement Layer ready ===");
}

/* ============================================================================
 * xbox_kernel_shutdown - Clean up the kernel replacement layer
 * ============================================================================ */

void xbox_kernel_shutdown(void)
{
    xbox_log(XBOX_LOG_INFO, XBOX_LOG_THUNK,
        "=== Xbox Kernel Replacement Layer shutting down ===");

    /* Close log file */
    if (g_log_file) {
        fclose(g_log_file);
        g_log_file = NULL;
    }

    if (g_log_cs_init) {
        DeleteCriticalSection(&g_log_cs);
        g_log_cs_init = FALSE;
    }

    /* Zero thunk table */
    memset(xbox_kernel_thunk_table, 0, sizeof(xbox_kernel_thunk_table));
}
