// dllmain.cpp : Defines the entry point for the DLL application.
#include <pe/module.h>
#include <xorstr/include/xorstr.hpp>
#include <pluginsdk.h>
#include <searchers.h>
#include "pugixml/src/pugixml.hpp"
#include <map>
#include <ShlObj.h>
#include <KnownFolders.h>
#include <filesystem>
#include <wil/include/wil/stl.h>
#include <wil/include/wil/win32_helpers.h>
#include <Detours/include/detours.h>
#include <locale>
#include <codecvt>
#include <string>
#include <format>
#include "hash_table8.h"

// Dual map because Emhash8 only supports one key, could store everything in one table but that requires templating, using a variant and it basically translate to the same thing.
static emhash8::HashMap<std::wstring, std::wstring> alias_table;
static emhash8::HashMap<unsigned __int64, std::wstring> id_table;

uintptr_t GetAddress(uintptr_t AddressOfCall, int index, int length)
{
	if (!AddressOfCall)
		return 0;

	long delta = *(long*)(AddressOfCall + index);
	return (AddressOfCall + delta + length);
}

/*
void ConsoleWrite(const wchar_t* msg, ...) {
	wchar_t szBuffer[1024];
	va_list args;
	va_start(args, msg);
	vswprintf(szBuffer, 1024, msg, args);
	WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), szBuffer, wcslen(szBuffer), NULL, NULL);
	va_end(args);
}
*/

char(__fastcall* formatTextArgumentList_Id)(std::wstring* output, const unsigned __int64 textDataId, char* args);
char(__fastcall* formatTextArgumentList_Text)(std::wstring* output, const wchar_t* formatAlias, char* args);

#define QueryTextRecord(aliasMap, textId) (*(__int64(__fastcall**)(__int64, const unsigned __int64))(*(_QWORD*)aliasMap + 0xB8))(aliasMap, textId)

__int64(__fastcall* formatTextInternal)(std::wstring* output, const wchar_t* xmlText, char* args);
__int64(__fastcall* DataManager_AliasMap)();
// Thought about doing a mid-hook to reduce querying but realized it introduces more problems then it's worth
// textDataId is the key attribute or more precisely the table entry ID. 
char __fastcall hkformatTextArgumentList_Id(std::wstring* output, const unsigned __int64 textDataId, char* args)
{
	if (!textDataId) return 0;
	
	if (auto* r = id_table.try_get(textDataId); r) {
		return formatTextInternal(output, r->c_str(), args);
	}

	return formatTextArgumentList_Id(output, textDataId, args);
}

char __fastcall hkformatTextArgumentList_Alias(std::wstring* output, const wchar_t* formatAlias, char* args)
{
	if (auto* r = alias_table.try_get(formatAlias); r) {
		return formatTextInternal(output, r->c_str(), args);
	}

	return formatTextArgumentList_Text(output, formatAlias, args);
}

void __cdecl oep_notify([[maybe_unused]] const Version client_version)
{
	if (const auto module = pe::get_module()) {
		uintptr_t handle = module->handle();
		const auto sections = module->segments();
		const auto& s1 = std::find_if(sections.begin(), sections.end(), [](const IMAGE_SECTION_HEADER& x) {
			return x.Characteristics & IMAGE_SCN_CNT_CODE;
			});
		const auto data = s1->as_bytes();

		DetourTransactionBegin();
		DetourUpdateThread(NtCurrentThread());

		std::filesystem::path languageDoc(std::move(wil::GetModuleFileNameW<std::wstring>(nullptr)));
		languageDoc.remove_filename(); 
		const auto str = wil::TryGetEnvironmentVariableW(xorstr_(L"BNS_PROFILE_PLUGINS_DIR"));
		if (str) {
			THROW_IF_WIN32_BOOL_FALSE(SetEnvironmentVariableW(xorstr_(L"BNS_PROFILE_PLUGINS_DIR"), nullptr));
			std::filesystem::path tmp{ wil::str_raw_ptr(str) };
			if (tmp.is_relative())
				languageDoc /= tmp;
			else
				languageDoc = std::move(tmp);

			languageDoc /= xorstr_(L"/language_table.xml");
		} else
			languageDoc /= xorstr_(L"plugins/language_table.xml");

		pugi::xml_document xmldoc;
		pugi::xml_parse_result loadResult = xmldoc.load_file(languageDoc.c_str(), pugi::parse_default);

		if (!loadResult) {
			MessageBox(NULL, xorstr_(L"Failed to load language_table.xml\rGame will function normally."), xorstr_(L"[Translator]"), MB_OK);
			return;
		}

		// You can find this by looking for aInvalid_13 (#INVALID) it's the second ref
		auto sFormatTextArgumentList = std::search(data.begin(), data.end(), pattern_searcher(xorstr_("4C 89 44 24 ?? 48 89 54 24 ?? 48 89 4C 24 ?? 48 83 EC ?? 48 83 7C 24 ?? ?? 75 ?? 32 C0 E9 ?? ?? ?? ?? E8")));
		if (sFormatTextArgumentList != data.end()) {
			formatTextArgumentList_Id = module->rva_to<std::remove_pointer_t<decltype(formatTextArgumentList_Id)>>((uintptr_t)&sFormatTextArgumentList[0] - handle);
			formatTextInternal = module->rva_to<std::remove_pointer_t<decltype(formatTextInternal)>>(GetAddress((uintptr_t)&sFormatTextArgumentList[0] + 0xBD, 1, 5) - handle); // Should be a call
			DataManager_AliasMap = module->rva_to<std::remove_pointer_t<decltype(DataManager_AliasMap)>>(GetAddress((uintptr_t)&sFormatTextArgumentList[0] + 0x22, 1, 5) - handle); // Should be a Call although not using this anymore

			if (*reinterpret_cast<BYTE*>((uintptr_t)&sFormatTextArgumentList[0] - 0xD0) != 0x4C) {
				MessageBox(NULL, xorstr_(L"Failed to hook"), xorstr_(L"Failed to hook functions do to byte mismatch, func size diff?\rLocalization will not work, recommended to delete plugin till update available"), MB_OK);
				return;
			}

			formatTextArgumentList_Text = module->rva_to<std::remove_pointer_t<decltype(formatTextArgumentList_Text)>>((uintptr_t)&sFormatTextArgumentList[0] - 0xD0 - handle);
			DetourAttach(&(PVOID&)formatTextArgumentList_Id, &hkformatTextArgumentList_Id);
			DetourAttach(&(PVOID&)formatTextArgumentList_Text, &hkformatTextArgumentList_Alias);
		}

		pugi::xpath_query query(xorstr_(L"table/record"));
		auto results = xmldoc.select_nodes(query);
		if (results.begin() == results.end()) {
			MessageBox(NULL, xorstr_(L"Failed to get records"), xorstr_(L"Table build failure"), MB_OK);
			xmldoc.reset();
			return;
		}
		else {
			//AllocConsole();
			//ConsoleWrite(L"Building language table\n");
			alias_table.reserve(results.size());
			id_table.reserve(results.size());
			//auto start = std::chrono::steady_clock::now();
			for (auto& result : results) {
				auto alias = result.node().attribute(L"alias").as_string();
				auto value = result.node().attribute(L"text").as_string();
				alias_table.emplace_unique(alias, value);
				auto key = result.node().attribute(L"key").as_ullong();
				id_table.emplace_unique(key, value);
			}

			xmldoc.reset(); // Free this up
		}

		DetourTransactionCommit();
	}
}

bool __cdecl init([[maybe_unused]] const Version client_version)
{
	NtCurrentPeb()->BeingDebugged = FALSE;
	return true;
}

BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD fdwReason, LPVOID lpvReserved)
{
	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		DisableThreadLibraryCalls(hInstance);
	}

	return TRUE;
}

extern "C" __declspec(dllexport) PluginInfo GPluginInfo = {
  .hide_from_peb = true,
  .erase_pe_header = true,
  .init = init,
  .oep_notify = oep_notify,
  .priority = 1,
  .target_apps = L"BNSR.exe"
};
