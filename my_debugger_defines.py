from asyncio.windows_events import INFINITE
from ctypes import *
from doctest import OutputChecker
from logging import Handler
from pickle import FALSE
from py_compile import PycInvalidationMode
from ssl import HAS_NEVER_CHECK_COMMON_NAME
from subprocess import *

# Let's map the Microsoft types to ctypes for clarity
BOOL        = c_bool
BYTE        = c_byte
WORD        = c_ushort
DWORD       = c_ulong
DWORD64     = c_ulonglong
LPBYTE      = POINTER(c_ubyte)
LPSTR       = POINTER(c_char)
LPCSTR      = POINTER(c_char)
HANDLE      = c_void_p
PVOID       = c_void_p
LPVOID      = c_void_p
UINT_PTR    = c_ulong
SIZE_T      = c_ulong
LONGLONG    = c_long
ULONGLONG   = c_ulong


# Constants
DEBUG_PROCESS       = 0x00000001
CREATE_NEW_CONSOLE  = 0x00000010
PROCESS_ALL_ACCESS  = 0x001F0FFF
INFINITE            = 0xFFFFFFFF
DBG_CONTINUE        = 0x00010002
DBG_EXCEPTION_NOT_HANDLED   = 0x80010001

# Debug event constants
EXCEPTION_DEBUG_EVENT       = 0x1
CREATE_THREAD_DEBUG_EVENT   = 0x2
CREATE_PROCESS_DEBUG_EVENT  = 0x3
EXIT_THREAD_DEBUG_EVENT     = 0x4
EXIT_PROCESS_DEBUG_EVENT    = 0x5
LOAD_DLL_DEBUG_EVENT        = 0x6
UNLOAD_DLL_DEBUG_EVENT      = 0x7
OUTPUT_DEBUG_STRING_EVENT   = 0x8
RIP_EVENT                   = 0x9

# debug exception codes
EXCEPTION_ACCESS_VIOLATION  = 0xC0000005
EXCEPTION_BREAKPOINT        = 0x80000003
EXCEPTION_GUARD_PAGE        = 0x80000001
EXCEPTION_SINGLE_STEP       = 0x80000004

# debug exception constants
EXCEPTION_MAXIMUM_PARAMETERS    = 15

# Thread constants for CreateToolhelp32Snapshot()
TH32CS_SNAPHEAPLIST = 0x00000001
TH32CS_SNAPPROCESS  = 0x00000002
TH32CS_SNAPTHREAD   = 0x00000004
TH32CS_SNAPMODULE   = 0x00000008
TH32CS_INHERIT      = 0x80000000
TH32CS_SNAPALL      = (TH32CS_SNAPHEAPLIST | TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD | TH32CS_SNAPMODULE)

# Thread constatns for OpenThread()
THREAD_GET_CONTEXT  = 0x0008
THREAD_SET_CONTEXT  = 0x0010
THREAD_ALL_ACCESS   = 0x001F03FF

# Context flags for GetThreadContext()
CONTEXT_FULL            = 0x00010007
CONTEXT_DEBUG_REGISTERS = 0x00010010

# Data structures for CreateProcessA() function
class STARTUPINFO(Structure):
    _fields_ = [
        ("cb",              DWORD),
        ("lpReserved",      LPSTR),
        ("lpDesktop",       LPSTR),
        ("lpTitle",         LPSTR),
        ("dwX",             DWORD),
        ("dwY",             DWORD),
        ("dwXSize",         DWORD),
        ("dwYSize",         DWORD),
        ("dwXCountChars",   DWORD),
        ("dwYCountChars",   DWORD),
        ("dwFillAttribute", DWORD),
        ("dwFlags",         DWORD),
        ("wShowWindow",     WORD),
        ("cbReserved2",     WORD),
        ("lpReserved2",     LPBYTE),
        ("hStdInput",       HANDLE),
        ("hStdOutput",      HANDLE),
        ("hStdError",       HANDLE)
    ]

class PROCESS_INFORMATION(Structure):
    _fields_ = [
        ("hProcess",    HANDLE),
        ("hThread",     HANDLE),
        ("dwProcessId", DWORD),
        ("dwThreadId",  DWORD)
    ]


# Data structures for Exception event
class EXCEPTION_RECORD(Structure):
    pass

EXCEPTION_RECORD._fields_ = [
    ("ExceptionCode",           DWORD),
    ("ExceptionFlags",          DWORD),
    ("ExceptionRecord",         POINTER(EXCEPTION_RECORD)),
    ("ExceptionAddress",        PVOID),
    ("NumberParameters",        DWORD),
    ("ExceptionInformation",    UINT_PTR * 15)    
]

class EXCEPTION_DEBUG_INFO(Structure):
    _fields_ = [
        ("ExceptionRecord", EXCEPTION_RECORD),
        ("dwFirstChance",   DWORD),
    ]

# As this premitive debugger deals with Exception events,
# thus we specify only exeception debug info
class DEBUG_EVENT_UNION(Union):
    _fields_ = [
        ("Exception",           EXCEPTION_DEBUG_INFO),
    ]

class DEBUG_EVENT(Structure):
    _fields_ = [
        ("dwDebugEventCode",    DWORD),
        ("dwProcessId",         DWORD),
        ("dwThreadId",          DWORD),
        ("u",                   DEBUG_EVENT_UNION),
    ]


# Data Structures for x86-64 thread context
class M128A(Structure):
    _fields_ = [
        ("Low",     DWORD64),
        ("High",    DWORD64),
    ]

class XMM_SAVE_AREA32(Structure):
    _fields_ = [
        ("ControlWord",         WORD),
        ("StatusWord",          WORD),
        ("Tagword",             BYTE),
        ("Reserved1",           BYTE),
        ("ErrorOpcode",         WORD),
        ("ErrorOffset",         DWORD),
        ("ErrorSelector",       WORD),
        ("Reserved2",           WORD),
        ("DataOffset",          DWORD),
        ("DataSelector",        WORD),
        ("Reserved3",           WORD),
        ("MxCsr",               DWORD),
        ("MxCsr_Mask",          DWORD),
        ("FloatRegisters",      M128A * 8),
        ("XmmRegisters",        M128A * 16),
        ("Reserved4",           BYTE * 96)
    ]

class NEON128(Structure):
    _fields_ = [
        ("Low",     ULONGLONG),
        ("High",    LONGLONG),
    ]

class DUMMYSTRUCTNAME(Structure):
    _fields_= [
        ("Header",  M128A * 2),
        ("Legacy",  M128A * 8),
        ("Xmm0",    M128A),
        ("Xmm1",    M128A),
        ("Xmm2",    M128A),
        ("Xmm3",    M128A),
        ("Xmm4",    M128A),
        ("Xmm5",    M128A),
        ("Xmm6",    M128A),
        ("Xmm7",    M128A),
        ("Xmm8",    M128A),
        ("Xmm9",    M128A),
        ("Xmm10",   M128A),
        ("Xmm11",   M128A),
        ("Xmm12",   M128A),
        ("Xmm13",   M128A),
        ("Xmm14",   M128A),
        ("Xmm15",   M128A)
    ]

class DUMMYUNIONNAME(Union):
    _fields_ = [
        ("FltSave",         XMM_SAVE_AREA32),
        ("Q",               NEON128 * 16),
        ("D",               ULONGLONG * 32),
        ("DummyStruct",     DUMMYSTRUCTNAME),
        ("S",               DWORD * 32)
    ]

# x86-64 thread context
class CONTEXT(Structure):
    _fields_ = [
        ("P1Home",                  DWORD64),
        ("P2Home",                  DWORD64),
        ("P3Home",                  DWORD64),
        ("P4Home",                  DWORD64),
        ("P5Home",                  DWORD64),
        ("P6Home",                  DWORD64),
        ("ContextFlags",            DWORD),
        ("MxCsr",                   DWORD),
        ("SegCs",                   WORD),
        ("SegDs",                   WORD),
        ("SegEs",                   WORD),
        ("SegFs",                   WORD),
        ("SegGs",                   WORD),
        ("SegSs",                   WORD),
        ("EFlags",                  DWORD),
        ("Dr0",                     DWORD64),
        ("Dr1",                     DWORD64),
        ("Dr2",                     DWORD64),
        ("Dr3",                     DWORD64),
        ("Dr6",                     DWORD64),
        ("Dr7",                     DWORD64),
        ("Rax",                     DWORD64),
        ("Rcx",                     DWORD64),
        ("Rdx",                     DWORD64),
        ("Rbx",                     DWORD64),
        ("Rsp",                     DWORD64),
        ("Rbp",                     DWORD64),
        ("Rsi",                     DWORD64),
        ("Rdi",                     DWORD64),
        ("R8",                      DWORD64),
        ("R9",                      DWORD64),
        ("R10",                     DWORD64),
        ("R11",                     DWORD64),
        ("R12",                     DWORD64),
        ("R13",                     DWORD64),
        ("R14",                     DWORD64),
        ("R15",                     DWORD64),
        ("Rip",                     DWORD64),
        ("DummyUnion",              DUMMYUNIONNAME),
        ("VectorRegister",          M128A * 26),
        ("VectorControl",           DWORD64),
        ("DebugControl",            DWORD64),
        ("LastBranchToRip",         DWORD64),
        ("LastBranchFromRip",       DWORD64),
        ("LastExceptionToRip",      DWORD64),
        ("LastExceptionFromRip",    DWORD64)
    ]

# Data Structures for x86 thread context
class FLOATING_SAVE_AREA(Structure):
   _fields_ = [   
        ("ControlWord",     DWORD),
        ("StatusWord",      DWORD),
        ("TagWord",         DWORD),
        ("ErrorOffset",     DWORD),
        ("ErrorSelector",   DWORD),
        ("DataOffset",      DWORD),
        ("DataSelector",    DWORD),
        ("RegisterArea",    BYTE * 80),
        ("Cr0NpxState",     DWORD),
]

# WOW64: Windows 32bit on Windows 64bit
# x86 thread context
class WOW64_CONTEXT(Structure):
    _fields_ = [    
        ("ContextFlags",        DWORD),
        ("Dr0",                 DWORD),
        ("Dr1",                 DWORD),
        ("Dr2",                 DWORD),
        ("Dr3",                 DWORD),
        ("Dr6",                 DWORD),
        ("Dr7",                 DWORD),
        ("FloatSave",           FLOATING_SAVE_AREA),
        ("SegGs",               DWORD),
        ("SegFs",               DWORD),
        ("SegEs",               DWORD),
        ("SegDs",               DWORD),
        ("Edi",                 DWORD),
        ("Esi",                 DWORD),
        ("Ebx",                 DWORD),
        ("Edx",                 DWORD),
        ("Ecx",                 DWORD),
        ("Eax",                 DWORD),
        ("Ebp",                 DWORD),
        ("Eip",                 DWORD),
        ("SegCs",               DWORD),
        ("EFlags",              DWORD),
        ("Esp",                 DWORD),
        ("SegSs",               DWORD),
        ("ExtendedRegisters",   BYTE * 512),
]


# Data structures for thread in process snapshot
class THREADENTRY32(Structure):
    _fields_ = [
        ("dwSize",              DWORD),
        ("cntUsage",            DWORD),
        ("th32ThreadID",        DWORD),
        ("th32OwnerProcessID",  DWORD),
        ("tpBasePri",           DWORD),
        ("tpDeltaPri",          DWORD),
        ("dwFlags",             DWORD)
    ]