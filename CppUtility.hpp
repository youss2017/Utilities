#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include <string>
#include <vector>
#include <string_view>
#include <fstream>
#include <iostream>
#include <cstdint>
#include <string>
#include <cassert>
#include <cstring>
#include <chrono>

// #define CPP_UTILITY_IMPLEMENTATION in one of your cpp files (only one)
// #define LOGGER_DISABLE_LOGGING to disable logging

#ifdef _WIN32
#define __FILENAME__ (strrchr(__FILE__, '\\') ? strrchr(__FILE__, '\\') + 1 : __FILE__)
#else
#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#endif

#ifndef LOGGER_DISABLE_LOGGING
#define LOG(logLevel, x, ...) ut::Logger::GetGlobalLogger().print(ut::LogLevel::logLevel, __FILENAME__, __LINE__,  x, __VA_ARGS__)
#else
#define LOG(logLevel, x, ...)
#define LOGLN(logLevel, x, ...)
#endif

#ifdef CPP_UTILITY_IMPLEMENTATION
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <signal.h>
#endif
#include <signal.h>
#include <regex>
#include <filesystem>
#include <cwctype>
#include <mutex>
#endif

#ifdef CPP_UTILITY_IMPLEMENTATION
namespace NMB
{

	enum Result
	{
		CANCEL,
		OK
	};

	enum Icon
	{
		ICON_INFO,
		ICON_WARNING,
		ICON_ERROR
	};


	static Result show(const char* p_title, const char* p_message, Icon icon)
	{
#if defined(_WIN32)

		int icon_flag = 0;

		switch (icon)
		{
		case NMB::Icon::ICON_INFO:
			icon_flag = MB_ICONINFORMATION;
			break;
		case NMB::Icon::ICON_WARNING:
			icon_flag = MB_ICONWARNING;
			break;
		case NMB::Icon::ICON_ERROR:
			icon_flag = MB_ICONERROR;
			break;
		}

		int result = MessageBoxA(nullptr, p_message, p_title, MB_OKCANCEL | MB_SYSTEMMODAL | icon_flag);

		if (result == IDOK)
			return NMB::Result::OK;
		else
			return NMB::Result::CANCEL;

#elif defined(__APPLE__)

		CFOptionFlags cf_alert_icon;

		switch (icon)
		{
		case NMB::Icon::INFO:
			cf_alert_icon = kCFUserNotificationNoteAlertLevel;
			break;
		case NMB::Icon::WARNING:
			cf_alert_icon = kCFUserNotificationCautionAlertLevel;
			break;
		case NMB::Icon::ERROR:
			cf_alert_icon = kCFUserNotificationStopAlertLevel;
			break;
		}

		CFStringRef cf_title = CFStringCreateWithCString(kCFAllocatorDefault, p_title, kCFStringEncodingUTF8);
		CFStringRef cf_message = CFStringCreateWithCString(kCFAllocatorDefault, p_message, kCFStringEncodingUTF8);

		CFOptionFlags result;

		CFUserNotificationDisplayAlert(0, cf_alert_icon, nullptr, nullptr, nullptr, cf_title, cf_message, CFSTR("OK"), CFSTR("Cancel"), nullptr, &result);

		CFRelease(cf_title);
		CFRelease(cf_message);

		if (result == kCFUserNotificationDefaultResponse)
			return NMB::Result::OK;
		else
			return NMB::Result::CANCEL;

#elif defined(__linux__)

		GtkMessageType gtk_message_type;

		switch (icon)
		{
		case NMB::Icon::ICON_INFO:
			gtk_message_type = GTK_MESSAGE_INFO;
			break;
		case NMB::Icon::ICON_WARNING:
			gtk_message_type = GTK_MESSAGE_WARNING;
			break;
		case NMB::Icon::ICON_ERROR:
			gtk_message_type = GTK_MESSAGE_ERROR;
			break;
		}

		GtkWidget* p_dialog = gtk_message_dialog_new(nullptr, GTK_DIALOG_DESTROY_WITH_PARENT, gtk_message_type, GTK_BUTTONS_OK_CANCEL, "%s\n\n%s", p_title, p_message);
		gint result = gtk_dialog_run(GTK_DIALOG(p_dialog));
		gtk_widget_destroy(p_dialog);

		if (result == GTK_RESPONSE_OK)
			return NMB::Result::OK;
		else
			return NMB::Result::CANCEL;

#else

#error "Platform not supported!"

#endif
	}

}
#endif

namespace ut
{
	template <typename T>
	inline static T clamp(T& value, T min, T max)
	{
		if (value < min)
			return min;
		if (value > max)
			return max;
		return value;
	}

	void DebugBreak();

	void ShowInfoBox(std::string_view title, std::string_view text);
	void ShowWarningBox(std::string_view title, std::string_view text);
	void ShowErrorBox(std::string_view title, std::string_view text);

	// std::string contains find (indexOf) rfind(lastIndexOf) substring
	// for more info lookup std::string::find() and std::string::rfind()

	std::string replace(std::string_view source, std::string_view find, std::string_view replace);
	std::string replaceAll(std::string_view source, std::string_view find, std::string_view replace);
	std::wstring replace(std::wstring_view source, std::wstring_view find, std::wstring_view replace);
	std::wstring replaceAll(std::wstring_view source, std::wstring_view find, std::wstring_view replace);

	inline size_t lastIndexOf(std::string_view source, std::string_view find) { return source.rfind(find.data()); }
	inline size_t indexOf(std::string_view source, std::string_view find) { return source.find(find.data()); }

	inline size_t lastIndexOf(std::wstring_view source, std::wstring_view find) { return source.rfind(find.data()); }
	inline size_t indexOf(std::wstring_view source, std::wstring_view find) { return source.find(find.data()); }

	std::vector<std::string> split(const std::string& source, std::string_view regex);
	std::vector<std::wstring> split(const std::wstring& source, std::wstring_view regex);

	std::string lower(std::string_view source);
	std::string upper(std::string_view source);

	std::wstring lower(std::wstring_view source);
	std::wstring upper(std::wstring_view source);

	std::wstring ToWideString(std::string_view source);
	std::string ToAsciiString(std::wstring_view source);

	std::string ltrim(std::string_view source);
	std::string rtrim(std::string_view source);
	std::string trim(std::string_view source);

	std::wstring ltrim(std::wstring_view source);
	std::wstring rtrim(std::wstring_view source);
	std::wstring trim(std::wstring_view source);

	bool EqualIgnoreCase(std::string_view a, std::string_view b);
	bool StartsWith(std::string_view source, std::string_view find);
	bool EndsWith(std::string_view source, std::string_view find);
	bool contains(std::string_view source, std::string_view find);

	bool EqualIgnoreCase(std::wstring_view a, std::wstring_view b);
	bool StartsWith(std::wstring_view source, std::wstring_view find);
	bool EndsWith(std::wstring_view source, std::wstring_view find);
	bool contains(std::wstring_view source, std::wstring_view find);

	size_t ToInt64(std::string_view source);
	bool TryToInt64(std::string_view source, size_t& RefInt64);

	size_t ToInt64(std::wstring_view source);
	bool TryToInt64(std::wstring_view source, size_t& RefInt64);

	double ToDouble(std::string_view source);
	bool TryToDouble(std::string_view source, double& RefDouble);

	double ToDouble(std::wstring_view source);
	bool TryToDouble(std::wstring_view source, double& RefDouble);

	bool WriteBinaryFile(std::string_view path, const void* data, size_t size);
	bool WriteTextFile(std::string_view path, const char* text, size_t size);

	/// <summary>
	/// Reads file binary into vector. First element in vector determines success status.
	/// </summary>
	/// <returns>First element in vector determines success status. 1 == success, 0 == fail</returns>
	std::vector<uint8_t> ReadBinaryFile(std::string_view path);

	/// <summary>
	/// Reads file binary into vector. First element in vector determines success status.
	/// </summary>
	/// <returns>First element in vector determines success status. 1 == success, 0 == fail</returns>
	std::vector<char> ReadTextFile(std::string_view path);

	bool Exists(std::string_view path);
	std::string ReadLine(FILE* file);
	bool CreateEmptyFile(std::string_view path);

	struct any {
		enum type { Int8, Int16, Int32, Int64, UInt8, UInt16, UInt32, UInt64, Float, Double, String, Ptr };
		any(int8_t   e) { m_data.INT8 = e; m_type = Int8; }
		any(int16_t   e) { m_data.INT16 = e; m_type = Int16; }
		any(int32_t   e) { m_data.INT32 = e; m_type = Int32; }
		any(int64_t   e) { m_data.INT64 = e; m_type = Int64; }
		any(uint8_t   e) { m_data.UINT8 = e; m_type = UInt8; }
		any(uint16_t   e) { m_data.UINT16 = e; m_type = UInt16; }
		any(uint32_t   e) { m_data.UINT32 = e; m_type = UInt32; }
		any(uint64_t   e) { m_data.UINT64 = e; m_type = UInt64; }
#ifdef _MSC_VER
		// For DWORD
		any(wchar_t e) { m_data.INT16 = (int16_t)e; m_type = Int16; }
		any(unsigned long e) { m_data.UINT16 = (uint16_t)e; m_type = UInt16; }
#endif
		any(float e) { m_data.FLOAT = e; m_type = Float; }
		any(double e) { m_data.DOUBLE = e; m_type = Double; }
		any(const char* e) { m_data.STRING = e; m_type = String; }
		any(const std::string& e) { m_data.STRING = e.c_str(); m_type = String; }
		any(void* e) { m_data.PTR = e; m_type = Ptr; }
		inline type get_type() const { return m_type; }
		inline int8_t get_int8() const { return m_data.INT8; }
		inline int16_t get_int16() const { return m_data.INT16; }
		inline int32_t get_int32() const { return m_data.INT32; }
		inline int64_t get_int64() const { return m_data.INT64; }
		inline uint8_t get_uint8() const { return m_data.UINT8; }
		inline uint16_t get_uint16() const { return m_data.UINT16; }
		inline uint32_t get_uint32() const { return m_data.UINT32; }
		inline uint64_t get_uint64() const { return m_data.UINT64; }
		inline float get_float() const { return m_data.FLOAT; }
		inline double get_double() const { return m_data.DOUBLE; }
		inline const char* get_string() const { return m_data.STRING; }
		inline void* get_ptr() const { return m_data.PTR; }
	private:
		type m_type;
		union {
			int8_t   INT8;
			int16_t   INT16;
			int32_t   INT32;
			int64_t   INT64;
			uint8_t    UINT8;
			uint16_t   UINT16;
			uint32_t   UINT32;
			uint64_t   UINT64;
			float FLOAT;
			double DOUBLE;
			const char* STRING;
			void* PTR;
		} m_data;
	};

	template<typename ... Arg>
	std::string Format(const std::string& input, Arg... arguments)
	{
		using namespace std;
		std::vector<any> vec{ arguments... };
		std::string result;
		result.reserve((size_t)(input.size() * 1.5));
		
		bool openbracket = false;
		bool closebracket = false;
		int argumentId = 0;
		for (int i = 0; i < input.size(); i++) {
			if (input[i] == '{') {
				openbracket = !openbracket;
				if (!openbracket) result += "{";
				continue;
			}
			if (input[i] == '}' && !openbracket) {
				closebracket = !closebracket;
				if (!closebracket) result += "}";
				continue;
			}
			if (openbracket) {
				if (argumentId >= vec.size()) {
					result += "{OUT_OF_RANGE:" + std::to_string(argumentId) + "}";
					openbracket = false;
					argumentId = 0;
					continue;
				}
				switch (input[i]) {
				case '0': argumentId = argumentId * 10 + 0; break;
				case '1': argumentId = argumentId * 10 + 1; break;
				case '2': argumentId = argumentId * 10 + 2; break;
				case '3': argumentId = argumentId * 10 + 3; break;
				case '4': argumentId = argumentId * 10 + 4; break;
				case '5': argumentId = argumentId * 10 + 5; break;
				case '6': argumentId = argumentId * 10 + 6; break;
				case '7': argumentId = argumentId * 10 + 7; break;
				case '8': argumentId = argumentId * 10 + 8; break;
				case '9': argumentId = argumentId * 10 + 9; break;
				case '}': {
					auto& e = vec[argumentId];
					switch (e.get_type()) {
					case any::Int8: result += std::to_string(e.get_int8()); break;
					case any::Int16: result += std::to_string(e.get_int16()); break;
					case any::Int32: result += std::to_string(e.get_int32()); break;
					case any::Int64: result += std::to_string(e.get_int64()); break;
					case any::UInt8: result += std::to_string(e.get_uint8()); break;
					case any::UInt16: result += std::to_string(e.get_uint16()); break;
					case any::UInt32: result += std::to_string(e.get_uint32()); break;
					case any::UInt64: result += std::to_string(e.get_uint64()); break;
					case any::Float: result += std::to_string(e.get_float()); break;
					case any::Double: result += std::to_string(e.get_double()); break;
					case any::String: result += e.get_string(); break;
					case any::Ptr: result += std::to_string((uint64_t)e.get_ptr()); break;
					}
					openbracket = false;
					argumentId = 0;
					break;
				}
				default: openbracket = false;
				}
			}
			else {
				result += input[i];
			}
		}
		return result;
	}

	enum LoggerFlags : int32_t {
		LOGGER_TYPE_CONSOLE = 0b01,
		LOGGER_TYPE_FILE = 0b10
	};

	enum class LogLevel {
		INFO,
		INFOBOLD,
		WARNING,
		ERR
	};

	struct LoggerOptions {
		int32_t LoggerType = LOGGER_TYPE_CONSOLE;
		bool IncludeDate = false;
		bool IncludeFileAndLine = true;
		std::string LoggerOutputFileName;
		bool ShowMessageBoxOnError = false;
		bool DebugBreakOnError = false;
	};

	class Logger {
	public:
		Logger(LoggerOptions options);
		Logger(Logger&) = delete;
		Logger(Logger&&) noexcept;
		~Logger();

		void AddFileLogging(const char* FileName);

		static Logger& GetGlobalLogger();

		template<typename ... Arg>
		void print(LogLevel logLevel, const char* FileName, int LineNumber, const std::string& input, Arg... arguments) {
			using namespace std;
			std::vector<any> vec{ arguments... };
			char currentTime[80]{};
			{
				time_t rawTime = time(NULL);
				if (_options.IncludeDate) {
					strftime(currentTime, 80, "%Y/%m/%d %H:%M:%S %p", localtime(&rawTime));
				}
				else {
					strftime(currentTime, 80, "%H:%M:%S %p", localtime(&rawTime));
				}
			}
			std::string result = currentTime;
			double timeSinceStart = double(std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::high_resolution_clock::now() - _start_timestamp).count()) * 1e-9;
			result.reserve((size_t)(input.size() * 1.5));
			uint64_t threadId = _get_current_thread_id();
			{
				FileName = FileName ? FileName : ".";
				char metadata[256];
				char fileAndNumber[125]{};
				
				if (_options.IncludeFileAndLine) {
					sprintf(fileAndNumber, " %s:%03d", FileName, LineNumber);
				}
				
				switch (logLevel) {
				case LogLevel::INFO:
				case LogLevel::INFOBOLD:
					sprintf(metadata, " (%.2fs) |%s (%llu) %-7s ", timeSinceStart, fileAndNumber, threadId, "INFO");
					break;
					sprintf(metadata, " (%.2fs) |%s (%llu) %-7s ", timeSinceStart, fileAndNumber, threadId, "INFO");
					break;
				case LogLevel::WARNING:
					sprintf(metadata, " (%.2fs) |%s (%llu) %-7s ", timeSinceStart, fileAndNumber, threadId, "WARNING");
					break;
				case LogLevel::ERR:
					sprintf(metadata, " (%.2fs) |%s (%llu) %-7s ", timeSinceStart, fileAndNumber, threadId, "ERROR");
					break;
				default:
					sprintf(metadata, " (%.2fs) |%s (%llu) %-7s ", timeSinceStart, fileAndNumber, threadId, "UNKNOWN");
					break;
				}
				std::string fmtInput = Format(input, arguments...);
				std::string alt = Format("{0} ({1:%.2fs}) | {2} {3} {4:%-7s} {5}", currentTime, timeSinceStart, fileAndNumber, threadId, "INFO",
					fmtInput);
				result += metadata;
			}
			bool openbracket = false;
			bool closebracket = false;
			int argumentId = 0;
			for (int i = 0; i < input.size(); i++) {
				if (input[i] == '{') {
					openbracket = !openbracket;
					if (!openbracket) result += "{";
					continue;
				}
				if (input[i] == '}' && !openbracket) {
					closebracket = !closebracket;
					if (!closebracket) result += "}";
					continue;
				}
				if (openbracket) {
					if (argumentId >= vec.size()) {
						result += "{OUT_OF_RANGE:" + std::to_string(argumentId) + "}";
						openbracket = false;
						argumentId = 0;
						continue;
					}
					switch (input[i]) {
					case '0': argumentId = argumentId * 10 + 0; break;
					case '1': argumentId = argumentId * 10 + 1; break;
					case '2': argumentId = argumentId * 10 + 2; break;
					case '3': argumentId = argumentId * 10 + 3; break;
					case '4': argumentId = argumentId * 10 + 4; break;
					case '5': argumentId = argumentId * 10 + 5; break;
					case '6': argumentId = argumentId * 10 + 6; break;
					case '7': argumentId = argumentId * 10 + 7; break;
					case '8': argumentId = argumentId * 10 + 8; break;
					case '9': argumentId = argumentId * 10 + 9; break;
					case '}': {
						auto& e = vec[argumentId];
						switch (e.get_type()) {
						case any::Int8: result += std::to_string(e.get_int8()); break;
						case any::Int16: result += std::to_string(e.get_int16()); break;
						case any::Int32: result += std::to_string(e.get_int32()); break;
						case any::Int64: result += std::to_string(e.get_int64()); break;
						case any::UInt8: result += std::to_string(e.get_uint8()); break;
						case any::UInt16: result += std::to_string(e.get_uint16()); break;
						case any::UInt32: result += std::to_string(e.get_uint32()); break;
						case any::UInt64: result += std::to_string(e.get_uint64()); break;
						case any::Float: result += std::to_string(e.get_float()); break;
						case any::Double: result += std::to_string(e.get_double()); break;
						case any::String: result += e.get_string(); break;
						case any::Ptr: result += std::to_string((uint64_t)e.get_ptr()); break;
						}
						openbracket = false;
						argumentId = 0;
						break;
					}
					default: openbracket = false;
					}
				}
				else {
					result += input[i];
				}
			}
			result += "\n";
			_internal_log(logLevel, result);
		}

		Logger& operator<<(const char* input) {
			print(LogLevel::INFO, nullptr, 0, input);
			return *this;
		}

		Logger& operator<<(const std::string& input) {
			print(LogLevel::INFO, nullptr, 0, input);
			return *this;
		}

	public:
		static LoggerOptions GlobalLoggerOptions;

	private:
		void _internal_log(LogLevel logLevel, const std::string& input);
		uint64_t _get_current_thread_id();

	private:
		LoggerOptions _options;
		std::fstream _file_stream;
		static std::chrono::steady_clock::time_point _start_timestamp;
	};

#ifdef CPP_UTILITY_IMPLEMENTATION
	static std::mutex _console_lock;

	std::string replace(std::string_view source, std::string_view find, std::string_view replace)
	{
		std::string result = source.data();
		size_t start_pos = source.find(find);
		if (start_pos == std::string::npos)
			return result;
		result.replace(start_pos, replace.length(), replace);
		return result;
	}

	std::string replaceAll(std::string_view source, std::string_view find, std::string_view replace)
	{
		std::string result = source.data();
		if (find.empty())
			return result;
		size_t start_pos = 0;
		while ((start_pos = result.find(find, start_pos)) != std::string::npos)
		{
			result.replace(start_pos, find.length(), replace);
			start_pos += replace.length();
		}
		return result;
	}

	std::wstring replace(std::wstring_view source, std::wstring_view find, std::wstring_view replace)
	{
		std::wstring result = source.data();
		size_t start_pos = source.find(find);
		if (start_pos == std::string::npos)
			return result;
		result.replace(start_pos, find.length(), replace);
		return result;
	}

	std::wstring replaceAll(std::wstring_view source, std::wstring_view find, std::wstring_view replace)
	{
		std::wstring result = source.data();
		if (find.empty())
			return result;
		size_t start_pos = 0;
		while ((start_pos = result.find(find, start_pos)) != std::string::npos)
		{
			result.replace(start_pos, result.length(), replace);
			start_pos += replace.length();
		}
		return result;
	}

	std::vector<std::string> split(const std::string& source, std::string_view regex)
	{
		std::vector<std::string> split_content;
		std::regex pattern(regex.data());
		std::copy(std::sregex_token_iterator(source.begin(), source.end(), pattern, -1),
			std::sregex_token_iterator(), back_inserter(split_content));
		return split_content;
	}

	std::vector<std::wstring> split(const std::wstring& source, std::wstring_view regex)
	{
		std::vector<std::wstring> split_content;
		std::wregex pattern(regex.data());
		std::copy(std::wsregex_token_iterator(source.begin(), source.end(), pattern, -1),
			std::wsregex_token_iterator(), back_inserter(split_content));
		return split_content;
	}

	std::string lower(std::string_view source)
	{
		std::string lw = source.data();
		for (int i = 0; i < lw.size(); i++)
			lw[i] = std::tolower(lw[i]);
		return lw;
	}

	std::string upper(std::string_view source)
	{
		std::string up = source.data();
		for (int i = 0; i < up.length(); i++)
			up[i] = std::toupper(up[i]);
		return up;
	}

	std::wstring lower(std::wstring_view source)
	{
		std::wstring lw = source.data();
		for (int i = 0; i < lw.size(); i++)
			lw[i] = std::towlower(lw[i]);
		return lw;
	}

	std::wstring upper(std::wstring_view source)
	{
		std::wstring up = source.data();
		for (int i = 0; i < up.length(); i++)
			up[i] = std::towupper(up[i]);
		return up;
	}

	std::wstring ToWideString(std::string_view source)
	{
		std::wstring result;
		result.resize(source.size());
		::mbstowcs(result.data(), source.data(), source.size());
		return result;
	}

	std::string ToAsciiString(std::wstring_view source)
	{
		std::string result;
		result.resize(source.size());
		::wcstombs(result.data(), source.data(), source.size());
		return result;
	}

	std::string ltrim(std::string_view source)
	{
		std::string s = source.data();
		s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch)
			{ return !std::isspace(ch); }));
		return s;
	}

	std::string rtrim(std::string_view source)
	{
		std::string s = source.data();
		s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch)
			{ return !std::isspace(ch); })
			.base(),
			s.end());
		return s;
	}

	std::string trim(std::string_view source)
	{
		return rtrim(ltrim(source));
	}

	std::wstring ltrim(std::wstring_view source)
	{
		std::wstring s = source.data();
		s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](wchar_t ch)
			{ return !std::isspace(ch); }));
		return s;
	}

	std::wstring rtrim(std::wstring_view source)
	{
		std::wstring s = source.data();
		s.erase(std::find_if(s.rbegin(), s.rend(), [](wchar_t ch)
			{ return !std::isspace(ch); })
			.base(),
			s.end());
		return s;
	}

	std::wstring trim(std::wstring_view source)
	{
		return rtrim(ltrim(source));
	}

	bool EqualIgnoreCase(std::string_view a, std::string_view b)
	{
		return lower(a) == lower(b);
	}

	bool StartsWith(std::string_view source, std::string_view find)
	{
		return source.rfind(find, 0) != std::string_view::npos;
	}

	bool EndsWith(std::string_view source, std::string_view find)
	{
		return source.rfind(find) != std::string_view::npos;
	}

	bool contains(std::string_view source, std::string_view find)
	{
		return source.find(find) != std::string_view::npos;
	}

	bool EqualIgnoreCase(std::wstring_view a, std::wstring_view b)
	{
		return lower(a) == lower(b);
	}

	bool StartsWith(std::wstring_view source, std::wstring_view find)
	{
		return source.rfind(find, 0);
	}

	bool EndsWith(std::wstring_view source, std::wstring_view find)
	{
		return source.rfind(find);
	}

	bool contains(std::wstring_view source, std::wstring_view find)
	{
		return source.find(find) != std::string_view::npos;
	}

	size_t ToInt64(std::string_view source)
	{
		return std::stoull(source.data());
	}

	bool TryToInt64(std::string_view source, size_t& RefInt64)
	{
		try
		{
			RefInt64 = std::stoull(source.data());
			return true;
		}
		catch (...)
		{
			return false;
		}
	}

	size_t ToInt64(std::wstring_view source)
	{
		return std::stoull(source.data());
	}

	bool TryToInt64(std::wstring_view source, size_t& RefInt64)
	{
		try
		{
			RefInt64 = std::stoull(source.data());
			return true;
		}
		catch (...)
		{
			return false;
		}
	}

	double ToDouble(std::string_view source)
	{
		return std::stod(source.data());
	}

	bool TryToDouble(std::string_view source, double& RefDouble)
	{
		try
		{
			RefDouble = std::stod(source.data());
			return true;
		}
		catch (...)
		{
			return false;
		}
	}

	double ToDouble(std::wstring_view source)
	{
		return std::stod(source.data());
	}

	bool TryToDouble(std::wstring_view source, double& RefDouble)
	{
		try
		{
			RefDouble = std::stod(source.data());
			return true;
		}
		catch (...)
		{
			return false;
		}
	}

	std::vector<char> ReadTextFile(std::string_view path)
	{
		std::vector<char> text;
		text.push_back(0);
		try
		{
			std::filesystem::path location(path);
			if (std::filesystem::is_regular_file(location))
			{
				FILE* input = fopen(path.data(), "r");
				if (!input)
				{
					text.push_back('\0');
					return text;
				}
				fseek(input, 0, SEEK_END);
				size_t size = ftell(input);
				if (size == 0)
				{
					text[0] = 1;
					text.push_back('\0');
					fclose(input);
					return text;
				}
				fseek(input, 0, SEEK_SET);
				text.resize(size + 1);
				size = fread(&text[1], 1, size, input);
				fclose(input);
				text.resize(size + 1);
				text.shrink_to_fit();
				text[0] = 1;
			}
		}
		catch (std::exception)
		{
			text.push_back('\0');
			return text;
		}
		text.push_back('\0');
		return text;
	}

	bool Exists(std::string_view path)
	{
		return std::filesystem::exists(path);
	}

	std::string ReadLine(FILE* file)
	{
		int character = '\n';
		std::string line = "";
		do
		{
			character = fgetc(file);
			if (character == '\n')
				break;
			line += character;
		} while (!feof(file));
		return line;
	}

	bool CreateEmptyFile(std::string_view path)
	{
		FILE* file = fopen(path.data(), "w");
		if (!file)
			return false;
		fflush(file);
		fclose(file);
		return true;
	}

	std::vector<uint8_t> ReadBinaryFile(std::string_view path)
	{
		std::vector<uint8_t> binary;
		binary.push_back(0);
		try
		{
			std::filesystem::path location(path);
			if (std::filesystem::is_regular_file(location))
			{
				FILE* input = fopen(path.data(), "rb");
				if (!input)
				{
					return binary;
				}
				fseek(input, 0, SEEK_END);
				size_t size = ftell(input);
				if (size == 0)
				{
					binary[0] = 1;
					fclose(input);
					return binary;
				}
				fseek(input, 0, SEEK_SET);
				binary.resize(size + 1);
				size = fread(&binary[1], 1, size, input);
				fclose(input);
				binary.resize(size + 1);
				binary.shrink_to_fit();
				binary[0] = 1;
			}
		}
		catch (std::exception)
		{
			return binary;
		}
		return binary;
	}

	bool WriteBinaryFile(std::string_view path, const void* data, size_t size)
	{
		FILE* output = fopen(path.data(), "wb");
		if (!output)
			return false;
		fwrite(data, 1, size, output);
		fclose(output);
		return true;
	}

	bool WriteTextFile(std::string_view path, const char* text, size_t size)
	{
		FILE* output = fopen(path.data(), "w");
		if (!output)
			return false;
		fwrite(text, 1, size, output);
		fclose(output);
		return true;
	}

	void DebugBreak()
	{
#if defined(_WIN32)
		::DebugBreak();
#else
		raise(SIGTRAP);
#endif
}

	void ShowInfoBox(std::string_view title, std::string_view text)
	{
		NMB::show(title.data(), text.data(), NMB::ICON_INFO);
	}

	void ShowWarningBox(std::string_view title, std::string_view text)
	{
		NMB::show(title.data(), text.data(), NMB::ICON_WARNING);
	}

	void ShowErrorBox(std::string_view title, std::string_view text)
	{
		NMB::show(title.data(), text.data(), NMB::ICON_ERROR);
	}

	Logger::Logger(LoggerOptions options) :
		_options(options)
	{
		if (_options.LoggerType & LOGGER_TYPE_FILE) {
			if (_options.LoggerOutputFileName.length() == 0)
				_options.LoggerOutputFileName = (std::to_string(time(NULL)) + ".log.txt");
			_file_stream.open(_options.LoggerOutputFileName, std::ios::out);
		}
	}

	Logger::Logger(Logger&& move) noexcept
	{
		_options = move._options;
		_file_stream = std::move(move._file_stream);
	}

	Logger::~Logger()
	{
		_file_stream.close();
	}

	Logger& Logger::GetGlobalLogger()
	{
		static Logger logger(Logger::GlobalLoggerOptions);
		return logger;
	}

	void Logger::_internal_log(LogLevel logLevel, const std::string& output)
	{
		std::lock_guard<std::mutex> lock(_console_lock);
		if (_options.LoggerType & LOGGER_TYPE_CONSOLE) {
#ifdef _WIN32
			static HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
			switch (logLevel) {
			case LogLevel::INFOBOLD:
				SetConsoleTextAttribute(hStdOut, 15);
				break;
			case LogLevel::WARNING:
				SetConsoleTextAttribute(hStdOut, 6);
				break;
			case LogLevel::ERR:
				SetConsoleTextAttribute(hStdOut, 4);
				break;
			}
#else
			switch (logLevel) {
			case LogLevel::INFOBOLD:
				std::cout << "\033[1;47;35m";
				break;
			case LogLevel::WARNING:
				std::cout << "\x1B[33m";
				break;
			case LogLevel::ERR:
				std::cout << "\x1B[31m";
				break;
			}
#endif
#ifdef _WIN32
			std::cout << output;
			SetConsoleTextAttribute(hStdOut, 7);
#else
			std::cout << output << "\033[0m";
#endif
		}
		if (_options.LoggerType & LOGGER_TYPE_FILE) {
			_file_stream << output;
			_file_stream.flush();
		}
	}

	void Logger::AddFileLogging(const char* FileName)
	{
		_file_stream = std::fstream(FileName, std::ios::out);
		_options.LoggerType |= LOGGER_TYPE_FILE;
	}

	uint64_t Logger::_get_current_thread_id()
	{
#ifdef _WIN32
		return GetCurrentThreadId();
#else
#error "Not Implemented"
#endif
	}

	std::chrono::steady_clock::time_point Logger::_start_timestamp = std::chrono::high_resolution_clock::now();
	LoggerOptions Logger::GlobalLoggerOptions;

#endif

}