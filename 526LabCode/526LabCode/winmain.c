#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <WinInet.h>
#include <wincrypt.h>
#pragma comment(lib, "WinInet.lib")
VOID DownloadFile(HINTERNET hConnection, LPCWSTR url, LPCWSTR outFile);
VOID ComputeHash(LPCWSTR file);
int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
	HINTERNET hInternet = InternetOpen(TEXT("GovindDownloader/1.0"), INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
	if (hInternet == NULL)
	{
		LPVOID lpMsgBuf;
		FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, GetLastError(), 0, (LPWSTR)&lpMsgBuf, 0, NULL);
		MessageBox(NULL, (LPCWSTR)lpMsgBuf, TEXT("Error"), MB_OK | MB_ICONSTOP);
		InternetCloseHandle(hInternet);
		return 0;
	}
	
	InternetCloseHandle(hInternet);
	return 0;
}

VOID ComputeHash(LPCWSTR file)
{
	HCRYPTPROV hCryptProv;
	HCRYPTHASH hHash;
	HANDLE hFile, hOut;
	TCHAR out[MAX_PATH], sHash[33];
	CHAR *hex = "0123456789abcdef";
	BYTE *fData, hash[16];
	DWORD dwRead = 0xFFFFFFFF, dwWritten = 0, fLen = 0, dwHash=16;
	int i;
	ZeroMemory(out, MAX_PATH * sizeof(TCHAR));
	wsprintf(out, TEXT("%s.hash"), file);
	hOut = CreateFile(out, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);

	CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
	CryptCreateHash(hCryptProv, CALG_MD5, 0, 0, &hHash);
	hFile=CreateFile(file, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
	fLen = GetFileSize(hFile, NULL);
	fData = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, fLen + 1);
	fData[fLen] = 0;
	ReadFile(hFile, fData, fLen, &dwWritten, NULL);
	CryptHashData(hHash, fData, fLen, 0);
	CryptGetHashParam(hHash, HP_HASHVAL, hash, &dwHash, 0);

	for (i = 0; i < 16; i++)
	{
		TCHAR tmp[3];
		wsprintf(tmp, TEXT("%c%c"), hex[hash[i] >> 4], hex[hash[i] & 0xF]);
		wcscat(sHash, tmp);
	}
	sHash[32] = 0x0000;

	WriteFile(hOut, sHash, wcslen(sHash)*sizeof(TCHAR), &dwWritten, NULL);
	CloseHandle(hOut);
	HeapFree(GetProcessHeap(), 0, fData);
	CloseHandle(hFile);
}

VOID DownloadFile(HINTERNET hConnection, LPCWSTR url, LPCWSTR outFile)
{
	HINTERNET hURL = InternetOpenUrl(hConnection, url, NULL, 0, 0, 0);
	BYTE buffer[4096];
	DWORD dwRead = 0xFFFFFFFF, dwWritten = 0;
	HANDLE hFile = CreateFile(outFile, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	while (dwRead!=0)
	{
		InternetReadFile(hURL, buffer, 4096, &dwRead);
		WriteFile(hFile, buffer, dwRead, &dwWritten, NULL);
	}
	CloseHandle(hFile);
	InternetCloseHandle(hURL);
}