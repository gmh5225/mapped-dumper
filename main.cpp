#include <Windows.h>
#include <iostream>
#include <vector>
#include <fstream>

#define NEXT(cur, size) cur < size - 1

std::vector<MEMORY_BASIC_INFORMATION> get_pages(HANDLE handle, uint64_t query) {
	std::vector<MEMORY_BASIC_INFORMATION> pages;
	
	NTSTATUS status = 0;
	uint64_t address = 0;
	MEMORY_BASIC_INFORMATION page = {};
	SIZE_T out = 0;

	// invoke the query function
	while ((status = ((NTSTATUS(*)(...))query)(handle, address, 0, &page, sizeof(page), &out)) == 0) {
		// save the page info
		pages.push_back(page);

		// advance the scan
		address += page.RegionSize;

		// reset the page for sanity
		memset(&page, 0, sizeof(page));
	}

	return pages;
}

bool is_executable(uint32_t protect) {
	return protect == PAGE_EXECUTE
		|| protect == PAGE_EXECUTE_READ
		|| protect == PAGE_EXECUTE_READWRITE
		|| protect == PAGE_EXECUTE_WRITECOPY;
}

bool is_storage(uint32_t protect) {
	return  protect == PAGE_READONLY
		|| protect == PAGE_READWRITE
		|| protect == PAGE_WRITECOPY;
}

int main() {
#undef max
	std::cout << "Welcome to @dllcrt0's manual mapped module dumper!" << std::endl;
	std::cout << "To get started, enter the process id of the target process (hint: you can find this in Task Manager!)" << std::endl;
	std::cout << ">> !!Disclaimer!!: this is very bad and would need a few modifications to detect modules with headers removed :)" << std::endl;
	std::cout << "Process ID: ";

start:
	// get the process id from user input
	uint32_t process_id = 0; // max is 0xFFFFFFFC
	std::cin >> process_id;

	if (process_id > 0) {
		// attempt to get a handle to the process
		HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
		if (handle > 0) {
			// resolve a page query function from ntdll
			uint64_t query = (uint64_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryVirtualMemory");
			if (query) {
				// query each page
				std::vector<MEMORY_BASIC_INFORMATION> pages = get_pages(handle, query);
				if (pages.size()) {
					std::vector<std::pair<uint64_t, uint64_t>> found_modules = {};

					// iterate through each page c-style (reason for it will be obvious later)
					for (std::size_t i = 0; i < pages.size(); i++) {
						MEMORY_BASIC_INFORMATION page = pages[i];

						// simple checks to see if the page is executable
						bool executable = is_executable(page.Protect);

						// simple checks to see if the page is likely just for data
						bool storage = is_storage(page.Protect);

						// if the page is private it's more than likely manual mapped
						if (page.Type == MEM_PRIVATE) {
							// now is the part that depends on what was done during injection...
							// if the injector didn't free the page created for the PE header, this can be found.
							// how? PE headers only use up one page, so we can check the page size and scan for pages
							// directly after it.

							// 0x1000 is the size of one page, typically (4096kb).
							// PE headers are usually not executable, if you're suspecting that for whatever reason it is,
							// you can remove the storage check below.
							if (storage && page.RegionSize == 0x1000) {
								if (NEXT(i, pages.size())) {
									MEMORY_BASIC_INFORMATION next_page = pages[i + 1];
									
									// if the next page is executable
									if (next_page.Protect == PAGE_EXECUTE || next_page.Protect == PAGE_EXECUTE_READ || next_page.Protect == PAGE_EXECUTE_READWRITE || next_page.Protect == PAGE_EXECUTE_WRITECOPY) {
										// variable used in module size calculation, incremented at 1 page (the header)
										uint64_t end_range = 0x1000;
										std::size_t page_increment = 1;

										while (true) {
											if (NEXT(i + page_increment, pages.size())) {
												MEMORY_BASIC_INFORMATION current_page = pages[i + page_increment];
												if (current_page.Type == MEM_PRIVATE) {
													if (!is_executable(current_page.Protect) && !is_storage(current_page.Protect)) {
														i += page_increment;
														break;
													}

													end_range += current_page.RegionSize;
													page_increment++;
												} else {
													// presumably end of module, increment after these pages
													i += page_increment;
													break;
												}
											} else break;
										}

										found_modules.push_back({ (uint64_t)page.BaseAddress, end_range });
									}
								}
							}
						}
					}

					if (found_modules.size()) {
						std::cout << "[!] potentially found " << found_modules.size() << " unmapped modules!" << std::endl;
						for (std::pair<uint64_t, uint64_t> mod : found_modules) {
							std::cout << "> module @ 0x" << std::hex << mod.first << " -> 0x" << std::hex << (mod.first + mod.second) << std::endl;

							// create a buffer for the module
							void* memory = new void*[mod.second];
							
							// attempt to read the module
							SIZE_T read_bytes = 0;
							if (!ReadProcessMemory(handle, (void*)mod.first, memory, mod.second, &read_bytes)) {
								std::cout << "\t> failed dumping module, tried to read 0x" << std::hex << mod.second << " but only read 0x" << std::hex << read_bytes << std::endl;
								delete[] memory;
								continue;
							}

							// write the module with the header
							char module_name[MAX_PATH];
							sprintf_s(module_name, "0x%llx - 0x%llx, with header.bin", mod.first, mod.first + mod.second);

							std::ofstream output(module_name, std::ios::binary);
							if (output.good()) {
								output.write((const char*)memory, read_bytes);
								output.close();

								std::cout << "> > wrote module with header" << std::endl;
							}

							// write the module without the header, just for keepsake
							sprintf_s(module_name, "0x%llx - 0x%llx, without header.bin", mod.first, mod.first + mod.second);
							output = std::ofstream(module_name, std::ios::binary);
							if (output.good()) {
								output.write((const char*)((uint64_t)memory + 0x1000), read_bytes);
								output.close();

								std::cout << "> > wrote module without header" << std::endl;
							}

							delete[] memory;
						}
					} else {
						std::cout << "> couldn't find any unmapped modules in memory, sorry :( try again" << std::endl;
						goto start;
					}
				} else {
					std::cout << "> couldn't find any memory pages in target process (wtf?). try again" << std::endl;
					goto start;
				}
			} else {
				std::cout << "> couldn't resolve NtQueryVirtualMemory (wtf?). try again" << std::endl;
				goto start;
			}
		} else {
			std::cout << "> couldn't open a handle to that process. try again" << std::endl;
			goto start;
		}
	} else {
		std::cout << "> try again" << std::endl;
		goto start;
	}

	system("pause");
	return 0;
}
