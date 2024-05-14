#pragma once
#include <string>
#include <vector>
#include <string_view>
#include <fstream>
#include <sstream>
#include <iostream>
#include <cstdint>
#include <string>
#include <cassert>
#include <cstring>
#include <chrono>
#include <stdexcept>

#ifndef CPP_UTILITY_NAMESPACE
#define CPP_UTILITY_NAMESPACE cpp
#endif

// #define CPP_UTILITY_IMPLEMENTATION in one of your cpp files (only one)
// #define LOGGER_DISABLE_LOGGING to disable logging macro

// #define CPP_UTILITY_IMPLEMENTATION

#ifdef _WIN32
#define __FILENAME__ (strrchr(__FILE__, '\\') ? strrchr(__FILE__, '\\') + 1 : __FILE__)
#else
#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#endif

#ifndef LOGGER_DISABLE_LOGGING
#define LOG(logLevel, x, ...) CPP_UTILITY_NAMESPACE ::Logger::GetGlobalLogger().print(CPP_UTILITY_NAMESPACE ::LogLevel::logLevel, __FILENAME__, __LINE__,  x, __VA_ARGS__)
#else
#define LOG(logLevel, x, ...)
#endif

#define LOGEXCEPT(x, ...) { auto err = CPP_UTILITY_NAMESPACE ::Format(x, __VA_ARGS__); LOG(ERR, err); throw std::runtime_error(err); }

#ifdef CPP_UTILITY_IMPLEMENTATION
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <signal.h>
#include <syscall.h>
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


namespace CPP_UTILITY_NAMESPACE
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

	namespace Base64 {
		std::string Encode(const std::string& data);
		std::string Encode(const uint8_t* data, size_t len);
		std::vector<uint8_t> Decode(const std::string& input);
		std::string DecodeString(const std::string& input);
	};


	class SHA1 {

	public:
        static std::string hash(const std::vector<uint8_t>& message);
        static std::vector<uint32_t> hash_words(const std::vector<uint8_t>& message);

		static inline constexpr uint32_t S(uint32_t X, uint8_t n) {
			return (X << n) | (X >> 32 - n);
		}

		static constexpr uint32_t f(int t, uint32_t B, uint32_t C, uint32_t D) {
			//      f(t;B,C,D) =          (B AND C) OR ((NOT B) AND D) ( 0 <= t <= 19)
			if (0 <= t && t <= 19) return (B & C) | ((~B) & D);
			//       f(t;B,C,D) =          B XOR C XOR D                        (20 <= t <= 39)
			if (20 <= t && t <= 39) return B ^ C ^ D;
			//       f(t;B,C,D) =          (B AND C) OR (B AND D) OR (C AND D)  (40 <= t <= 59)
			if (40 <= t && t <= 59) return (B & C) | (B & D) | (C & D);
			//       f(t;B,C,D) = B XOR C XOR D                        (60 <= t <= 79).
			return                B ^ C ^ D;
		}

		static constexpr uint32_t K(int t) {
			if (0 <= t && t <= 19) return 0x5A827999;
			if (20 <= t && t <= 39) return 0x6ED9EBA1;
			if (40 <= t && t <= 59) return 0x8F1BBCDC;
			return 0xCA62C1D6;
		}


	private:
		static std::vector<uint8_t> _pad_message(size_t messageSize);

	private:
		size_t m_messageLength = 0;
		uint32_t H0 = 0x67452301;
		uint32_t H1 = 0xEFCDAB89;
		uint32_t H2 = 0x98BADCFE;
		uint32_t H3 = 0x10325476;
		uint32_t H4 = 0xC3D2E1F0;
	};



	void DebugBreak();

	void ShowInfoBox(const std::string& title, const std::string& text);
	void ShowWarningBox(const std::string& title, const std::string& text);
	void ShowErrorBox(const std::string& title, const std::string& text);

	// std::string contains find (IndexOf) rfind(LastIndexOf) substring
	// for more info lookup std::string::find() and std::string::rfind()

	std::string Replace(const std::string& source, const std::string& find, const std::string& Replace);
	std::string ReplaceAll(const std::string& source, const std::string& find, const std::string& Replace);
	std::wstring Replace(std::wstring_view source, std::wstring_view find, std::wstring_view Replace);
	std::wstring ReplaceAll(std::wstring_view source, std::wstring_view find, std::wstring_view Replace);

	inline size_t LastIndexOf(const std::string& source, const std::string& find) { return source.rfind(find.data()); }
	inline size_t IndexOf(const std::string& source, const std::string& find) { return source.find(find.data()); }

	inline size_t LastIndexOf(std::wstring_view source, std::wstring_view find) { return source.rfind(find.data()); }
	inline size_t IndexOf(std::wstring_view source, std::wstring_view find) { return source.find(find.data()); }

	std::vector<std::string> Split(const std::string& source, const std::string& regex);
	std::vector<std::wstring> Split(const std::wstring& source, std::wstring_view regex);

	std::string LowerCase(const std::string& source);
	std::string UpperCase(const std::string& source);

	std::wstring LowerCase(std::wstring_view source);
	std::wstring UpperCase(std::wstring_view source);

	std::wstring ToWideString(const std::string& source);
	std::string ToAsciiString(std::wstring_view source);

	std::string LTrim(const std::string& source);
	std::string RTrim(const std::string& source);
	std::string Trim(const std::string& source);

	std::wstring LTrim(std::wstring_view source);
	std::wstring RTrim(std::wstring_view source);
	std::wstring Trim(std::wstring_view source);

	bool EqualIgnoreCase(const std::string& a, const std::string& b);
	bool StartsWith(const std::string& source, const std::string& find);
	bool EndsWith(const std::string& source, const std::string& find);
	bool Contains(const std::string& source, const std::string& find);

	bool EqualIgnoreCase(std::wstring_view a, std::wstring_view b);
	bool StartsWith(std::wstring_view source, std::wstring_view find);
	bool EndsWith(std::wstring_view source, std::wstring_view find);
	bool Contains(std::wstring_view source, std::wstring_view find);

	size_t ToInt64(const std::string& source);
	bool TryToInt64(const std::string& source, size_t& RefInt64);

	size_t ToInt64(std::wstring_view source);
	bool TryToInt64(std::wstring_view source, size_t& RefInt64);

	double ToDouble(const std::string& source);
	bool TryToDouble(const std::string& source, double& RefDouble);

	double ToDouble(std::wstring_view source);
	bool TryToDouble(std::wstring_view source, double& RefDouble);

	bool WriteAllBytes(const std::string& path, const void* data, size_t size);
	bool WriteAllText(const std::string& path, const std::string& text);

	/// <summary>
	/// Reads file binary into vector. First element in vector determines success status.
	/// </summary>
	/// <returns>First element in vector determines success status. 1 == success, 0 == fail</returns>
	std::optional<std::vector<uint8_t>> ReadAllBytes(const std::string& path);

	/// <summary>
	/// Reads file binary into string.
	/// </summary>
	/// <returns></returns>
	std::optional<std::string> ReadAllText(const std::string& path);

	bool Exists(const std::string& path);
	std::string ReadLine(FILE* file);
	bool CreateEmptyFile(const std::string& path);

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
		bool formatSpecifier = false;
		bool clearLine = false;
		bool negativeArgumentId = false;
		bool hasArgumentId = false;
		bool noNewLine = false;

		int argumentId = 0;
		int argumentIdCounter = 0;
		std::string argumentFormatSpecifier{};
		std::string controlWord{};
		int formatSpecifierIndex = 0;
		for (int i = 0; i < input.size(); i++) {
			if (input[i] == '{') {
				openbracket = !openbracket;
				if (!openbracket) result.append("{");
				continue;
			}
			if (input[i] == '}' && !openbracket) {
				closebracket = !closebracket;
				if (!closebracket) result.append("}");
				continue;
			}
			if (input[i] == ':' && openbracket) {
				formatSpecifier = true;
				argumentFormatSpecifier.clear();
				argumentFormatSpecifier.reserve(10);
				continue;
			}
			if (formatSpecifier && openbracket && input[i] != '}') {
				argumentFormatSpecifier.push_back(input[i]);
				continue;
			}
			if (openbracket) {
				if (argumentId >= vec.size()) {
					result.append("{OUT_OF_RANGE:" + std::to_string(argumentId) + "}");
					openbracket = false;
					argumentId = 0;
					continue;
				}
				switch (input[i]) {
				case '-': negativeArgumentId = true; break;
				case '0': argumentId = argumentId * 10 + 0; hasArgumentId = true; break;
				case '1': argumentId = argumentId * 10 + 1; hasArgumentId = true; break;
				case '2': argumentId = argumentId * 10 + 2; hasArgumentId = true; break;
				case '3': argumentId = argumentId * 10 + 3; hasArgumentId = true; break;
				case '4': argumentId = argumentId * 10 + 4; hasArgumentId = true; break;
				case '5': argumentId = argumentId * 10 + 5; hasArgumentId = true; break;
				case '6': argumentId = argumentId * 10 + 6; hasArgumentId = true; break;
				case '7': argumentId = argumentId * 10 + 7; hasArgumentId = true; break;
				case '8': argumentId = argumentId * 10 + 8; hasArgumentId = true; break;
				case '9': argumentId = argumentId * 10 + 9; hasArgumentId = true; break;
				case '}': {
					// negativeArgumentId are control codes
					if (!negativeArgumentId) {
						auto& e = vec[hasArgumentId ? argumentId : argumentIdCounter];
						std::string argument_output;
#define set_argument_output(type) \
						{\
							if (formatSpecifier) {\
								if(argumentFormatSpecifier[0] != '%') { argumentFormatSpecifier = "%" + argumentFormatSpecifier; }\
								size_t nbytes = snprintf(nullptr, 0, argumentFormatSpecifier.c_str(), type);\
								argument_output.resize(nbytes);\
								snprintf((char*)argument_output.c_str(), nbytes, argumentFormatSpecifier.c_str(), type);\
								argument_output.pop_back();\
							}\
							else\
								argument_output = std::to_string(type);\
							break;\
						}

						switch (e.get_type()) {
						case any::Int8: set_argument_output(e.get_int8());
						case any::Int16: set_argument_output(e.get_int16());
						case any::Int32: set_argument_output(e.get_int32());
						case any::Int64: set_argument_output(e.get_int64());

						case any::UInt8: set_argument_output(e.get_uint8());
						case any::UInt16: set_argument_output(e.get_uint16());
						case any::UInt32: set_argument_output(e.get_uint32());
						case any::UInt64: set_argument_output(e.get_uint64());

						case any::Float: set_argument_output(e.get_float());
						case any::Double: set_argument_output(e.get_double());
#undef set_argument_output
						case any::String: {
							if (formatSpecifier) {
								size_t nbytes = snprintf(nullptr, 0, argumentFormatSpecifier.c_str(), e.get_string());
								argument_output.resize(nbytes);
								snprintf((char*)argument_output.c_str(), nbytes, argumentFormatSpecifier.c_str(), e.get_string());
								argument_output.pop_back();
							}
							else
								argument_output = e.get_string();
							break;
						}
						case any::Ptr: {
							if (!formatSpecifier) {
								argumentFormatSpecifier += "%p";
							}
							size_t nbytes = snprintf(nullptr, 0, argumentFormatSpecifier.c_str(), e.get_ptr());
							argument_output.resize(nbytes);
							snprintf((char*)argument_output.c_str(), nbytes, argumentFormatSpecifier.c_str(), e.get_ptr());
							argument_output.pop_back();
							break;
						}
						}
						result.append(argument_output);
					}
					openbracket = false;
					argumentId *= negativeArgumentId ? -1 : 1;
					if (argumentId < 0) {
						noNewLine |= argumentId == -1;
						clearLine |= argumentId == -2;
					}
					else if (hasArgumentId)
						argumentIdCounter = argumentId + 1;
					else
						argumentIdCounter++;
					// reset state
					argumentId = 0;
					hasArgumentId = false;
					formatSpecifier = false;
					negativeArgumentId = false;
					break;
				}
				default:
					result += "{INVALID}";
					argumentId = 0;
					hasArgumentId = false;
					formatSpecifier = false;
					negativeArgumentId = false;
				}
			}
			else {
				result += input[i];
			}
		}
		if (clearLine) {
			result = "\33[2K\r" + result;
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
		bool VerboseMode = false;
	};

	class Logger {
	public:
		Logger(LoggerOptions options);
		Logger(Logger&) = delete;
		Logger(Logger&&) noexcept;
		~Logger();

		void AddFileLogging(const char* FileName);

		static Logger& GetGlobalLogger();
		static std::string Escape(const std::string& input);

		template<typename ... Arg>
		void print(LogLevel logLevel, const char* FileName, int LineNumber, const std::string& input, Arg... arguments) {
			using namespace std;
			std::vector<any> vec{ arguments... };
			char currentTime[80]{};
			{
				time_t rawTime = time(NULL);
				if (Options.IncludeDate) {
					strftime(currentTime, 80, "%Y/%m/%d %H:%M:%S %p", localtime(&rawTime));
				}
				else {
					strftime(currentTime, 80, "%H:%M:%S %p", localtime(&rawTime));
				}
			}
			double timeSinceStart = double(std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now() - _start_timestamp).count()) * 1e-9;
			uint64_t threadId = _get_current_thread_id();
			std::string result;
			FileName = FileName ? FileName : ".";
			char fileAndNumber[125]{};

			if (Options.IncludeFileAndLine) {
				sprintf(fileAndNumber, " %s:%03d", FileName, LineNumber);
			}

			const char* INFOLabel = "INFO";
			const char* WARNINGLabel = "WARNING";
			const char* ERRORLabel = "ERROR";
			const char* UNKNOWNLabel = "UNKNOWN";
			const char* pLogLevel = "";

			switch (logLevel) {
			case LogLevel::INFO:
			case LogLevel::INFOBOLD:
				pLogLevel = INFOLabel;
				break;
			case LogLevel::WARNING:
				pLogLevel = WARNINGLabel;
				break;
			case LogLevel::ERR:
				pLogLevel = ERRORLabel;
				break;
			default:
				pLogLevel = UNKNOWNLabel;
				break;
			}
			string formatted_input_string = Format(input, arguments...);
			bool newLine = strncmp("\33[2K\r", formatted_input_string.data(), 5);
			if (Options.VerboseMode) {
				result = Format("{0} ({1:%.2fs}) | {2} {3} {4:%-8s} {5}", currentTime, timeSinceStart, fileAndNumber, threadId, pLogLevel,
					formatted_input_string);
			}
			else {
				result = Format("[{0:%.2fs} |{1}] {2}", timeSinceStart, fileAndNumber,
					formatted_input_string);
			}
			if (newLine) {
				// doesn't have clear line
				result += "\n";
			}
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
		LoggerOptions Options;

	private:
		void _internal_log(LogLevel logLevel, const std::string& input);
		uint64_t _get_current_thread_id();

	private:
		std::fstream _file_stream;
		static std::chrono::steady_clock::time_point _start_timestamp;
	};

#ifdef CPP_UTILITY_IMPLEMENTATION
	using namespace std;
	static std::mutex _console_lock;

	namespace Base64 {
		string Encode(const string& data) {
			return Encode((const unsigned char*)data.c_str(), data.length());
		}

		string Encode(const uint8_t* data, size_t len) {
			const std::string base64_chars =
				"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
				"abcdefghijklmnopqrstuvwxyz"
				"0123456789+/";

			std::string encoded;
			encoded.reserve(((len + 2) / 3) * 4);

			for (size_t i = 0; i < len; i += 3) {
				uint8_t b0 = data[i];
				uint8_t b1 = (i + 1 < len) ? data[i + 1] : 0;
				uint8_t b2 = (i + 2 < len) ? data[i + 2] : 0;

				uint8_t enc1 = b0 >> 2;
				uint8_t enc2 = ((b0 & 0x03) << 4) | (b1 >> 4);
				uint8_t enc3 = ((b1 & 0x0F) << 2) | (b2 >> 6);
				uint8_t enc4 = b2 & 0x3F;

				encoded.push_back(base64_chars[enc1]);
				encoded.push_back(base64_chars[enc2]);
				encoded.push_back((i + 1 < len) ? base64_chars[enc3] : '=');
				encoded.push_back((i + 2 < len) ? base64_chars[enc4] : '=');
			}

			return encoded;
		}

		vector<uint8_t> Decode(const std::string& input) {
			const std::string base64_chars =
				"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
				"abcdefghijklmnopqrstuvwxyz"
				"0123456789+/";

			std::vector<unsigned char> binary;
			binary.reserve((input.size() / 4) * 3);

			for (size_t i = 0; i < input.size(); i += 4) {
				unsigned char enc1 = input[i];
				unsigned char enc2 = input[i + 1];
				unsigned char enc3 = input[i + 2];
				unsigned char enc4 = input[i + 3];

				unsigned char b0 = (base64_chars.find(enc1) << 2) | (base64_chars.find(enc2) >> 4);
				unsigned char b1 = ((base64_chars.find(enc2) & 0x0F) << 4) | (base64_chars.find(enc3) >> 2);
				unsigned char b2 = ((base64_chars.find(enc3) & 0x03) << 6) | base64_chars.find(enc4);

				binary.push_back(b0);
				if (enc3 != '=')
					binary.push_back(b1);
				if (enc4 != '=')
					binary.push_back(b2);
			}

			return binary;
		}

		string DecodeString(const std::string& input) {
			auto binary = Decode(input);
			return string(binary.begin(), binary.end());
		}

	}

	vector<uint32_t> SHA1::hash_words(const vector<uint8_t>& message)
	{
		uint32_t H0 = 0x67452301;
		uint32_t H1 = 0xEFCDAB89;
		uint32_t H2 = 0x98BADCFE;
		uint32_t H3 = 0x10325476;
		uint32_t H4 = 0xC3D2E1F0;

		auto padding = _pad_message(message.size());
		// display_stream(padding);
		size_t totalSize = message.size() + padding.size();
		for (size_t blockCount = 0; blockCount < totalSize / (512 / 8); blockCount++) {
			uint32_t W[80] = {};
			size_t start = blockCount * (512 / 8);
			//const uint8_t* M = &padding[start];

			auto readByte = [&](size_t t) {
				t += start;
				if (t < message.size()) return message[t];
				return padding[t - message.size()];
				};

			for (int t = 0; t < 16; t++)
			{
				/*W[t]  = M[t * 4] << 24;
				W[t] |= M[t * 4 + 1] << 16;
				W[t] |= M[t * 4 + 2] << 8;
				W[t] |= M[t * 4 + 3];*/
				W[t] = readByte(t * 4) << 24;
				W[t] |= readByte(t * 4 + 1) << 16;
				W[t] |= readByte(t * 4 + 2) << 8;
				W[t] |= readByte(t * 4 + 3);
			}

			for (int t = 16; t < 80; t++) {
				// W(t) = S^1(W(t-3) XOR W(t-8) XOR W(t-14) XOR W(t-16))
				W[t] = S(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);
			}
			uint32_t A = H0;
			uint32_t B = H1;
			uint32_t C = H2;
			uint32_t D = H3;
			uint32_t E = H4;
			for (int t = 0; t < 80; t++) {
				uint32_t TEMP = S(A, 5) + f(t, B, C, D) + E + W[t] + K(t);
				E = D;  D = C;  C = S(B, 30);  B = A; A = TEMP;
			}
			H0 = H0 + A;
			H1 = H1 + B;
			H2 = H2 + C;
			H3 = H3 + D;
			H4 = H4 + E;
		}
        return { H0, H1, H2, H3, H4 };

	}

    std::string SHA1::hash(const std::vector<uint8_t>& message) {
        auto words = hash_words(message);
        char szBuf[10 * 8];
        sprintf(szBuf, "%08x%08x%08x%08x%08x", words[0], words[1], words[2], words[3], words[4]);
        return szBuf;
    }

	vector<uint8_t> SHA1::_pad_message(size_t messageSize) {
		vector<uint8_t> padding;
		padding.push_back(0x80); // append 1

		size_t totalSize = messageSize + 1;

		// 1) Get Last 512-bit block
		auto _512BlockCount = totalSize / (512 / 8);
		auto byteOffset = (_512BlockCount * (512 / 8));
		auto remainingBytes = (512 / 8) - (totalSize - byteOffset);
		// Do we have the last 64 bits (8 bytes) free?
		if (remainingBytes < 8) {
			// get new block
			// finish current block
			for (int i = 0; i < remainingBytes; i++) padding.push_back(0);
			// pad 0s for the new block
			for (int i = 0; i < 64 - 7; i++) padding.push_back(0);
		}
		else {
			// append with zeros until last 8 bytes
			do {
				padding.push_back(0);
				remainingBytes--;
			} while (remainingBytes > 7);
		}

		uint64_t length = (uint64_t)(messageSize * 8);
		// AMD/INTEL cpus are little endian so
		padding.push_back((length >> 48) & 0xFF);
		padding.push_back((length >> 40) & 0xFF);
		padding.push_back((length >> 32) & 0xFF);
		padding.push_back((length >> 24) & 0xFF);
		padding.push_back((length >> 16) & 0xFF);
		padding.push_back((length >> 8) & 0xFF);
		padding.push_back((length >> 0) & 0xFF);
		return padding;
	}

	std::string Replace(const std::string& source, const std::string& find, const std::string& Replace)
	{
		std::string result = source.data();
		size_t start_pos = source.find(find);
		if (start_pos == std::string::npos)
			return result;
		result.replace(start_pos, Replace.length(), Replace);
		return result;
	}

	std::string ReplaceAll(const std::string& source, const std::string& find, const std::string& Replace)
	{
		std::string result = source.data();
		if (find.empty())
			return result;
		size_t start_pos = 0;
		while ((start_pos = result.find(find, start_pos)) != std::string::npos)
		{
			result.replace(start_pos, find.length(), Replace);
			start_pos += Replace.length();
		}
		return result;
	}

	std::wstring Replace(std::wstring_view source, std::wstring_view find, std::wstring_view Replace)
	{
		std::wstring result = source.data();
		size_t start_pos = source.find(find);
		if (start_pos == std::string::npos)
			return result;
		result.replace(start_pos, find.length(), Replace);
		return result;
	}

	std::wstring ReplaceAll(std::wstring_view source, std::wstring_view find, std::wstring_view Replace)
	{
		std::wstring result = source.data();
		if (find.empty())
			return result;
		size_t start_pos = 0;
		while ((start_pos = result.find(find, start_pos)) != std::string::npos)
		{
			result.replace(start_pos, result.length(), Replace);
			start_pos += Replace.length();
		}
		return result;
	}

	std::vector<std::string> Split(const std::string& source, const std::string& regex)
	{
		std::vector<std::string> Split_content;
		std::regex pattern(regex.data());
		std::copy(std::sregex_token_iterator(source.begin(), source.end(), pattern, -1),
			std::sregex_token_iterator(), back_inserter(Split_content));
		return Split_content;
	}

	std::vector<std::wstring> Split(const std::wstring& source, std::wstring_view regex)
	{
		std::vector<std::wstring> Split_content;
		std::wregex pattern(regex.data());
		std::copy(std::wsregex_token_iterator(source.begin(), source.end(), pattern, -1),
			std::wsregex_token_iterator(), back_inserter(Split_content));
		return Split_content;
	}

	std::string LowerCase(const std::string& source)
	{
		std::string lw = source.data();
		for (int i = 0; i < lw.size(); i++)
			lw[i] = std::tolower(lw[i]);
		return lw;
	}

	std::string UpperCase(const std::string& source)
	{
		std::string up = source.data();
		for (int i = 0; i < up.length(); i++)
			up[i] = std::toupper(up[i]);
		return up;
	}

	std::wstring LowerCase(std::wstring_view source)
	{
		std::wstring lw = source.data();
		for (int i = 0; i < lw.size(); i++)
			lw[i] = std::towlower(lw[i]);
		return lw;
	}

	std::wstring UpperCase(std::wstring_view source)
	{
		std::wstring up = source.data();
		for (int i = 0; i < up.length(); i++)
			up[i] = std::towupper(up[i]);
		return up;
	}

	std::wstring ToWideString(const std::string& source)
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

	std::string LTrim(const std::string& source)
	{
		std::string s = source.data();
		s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch)
			{ return !std::isspace(ch); }));
		return s;
	}

	std::string RTrim(const std::string& source)
	{
		std::string s = source.data();
		s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch)
			{ return !std::isspace(ch); })
			.base(),
			s.end());
		return s;
	}

	std::string Trim(const std::string& source)
	{
		return RTrim(LTrim(source));
	}

	std::wstring LTrim(std::wstring_view source)
	{
		std::wstring s = source.data();
		s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](wchar_t ch)
			{ return !std::isspace(ch); }));
		return s;
	}

	std::wstring RTrim(std::wstring_view source)
	{
		std::wstring s = source.data();
		s.erase(std::find_if(s.rbegin(), s.rend(), [](wchar_t ch)
			{ return !std::isspace(ch); })
			.base(),
			s.end());
		return s;
	}

	std::wstring Trim(std::wstring_view source)
	{
		return RTrim(LTrim(source));
	}

	bool EqualIgnoreCase(const std::string& a, const std::string& b)
	{
		return LowerCase(a) == LowerCase(b);
	}

	bool StartsWith(const std::string& source, const std::string& find)
	{
		return source.rfind(find, 0) != std::string::npos;
	}

	bool EndsWith(const std::string& source, const std::string& find)
	{
		return source.rfind(find) != std::string::npos;
	}

	bool Contains(const std::string& source, const std::string& find)
	{
		return source.find(find) != std::string::npos;
	}

	bool EqualIgnoreCase(std::wstring_view a, std::wstring_view b)
	{
		return LowerCase(a) == LowerCase(b);
	}

	bool StartsWith(std::wstring_view source, std::wstring_view find)
	{
		return source.rfind(find, 0);
	}

	bool EndsWith(std::wstring_view source, std::wstring_view find)
	{
		return source.rfind(find);
	}

	bool Contains(std::wstring_view source, std::wstring_view find)
	{
		return source.find(find) != std::string::npos;
	}

	size_t ToInt64(const std::string& source)
	{
		return std::stoull(source.data());
	}

	bool TryToInt64(const std::string& source, size_t& RefInt64)
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

	double ToDouble(const std::string& source)
	{
		return std::stod(source.data());
	}

	bool TryToDouble(const std::string& source, double& RefDouble)
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

	std::optional<std::string> ReadAllText(const std::string& path)
	{
		// Open the file for reading
		std::ifstream file(path);

		// Check if the file was opened successfully
		if (!file.is_open()) {
			return std::nullopt;
		}

		// Read the contents of the file into a stringstream
		std::stringstream ss;
		ss << file.rdbuf();

		// Close the file
		file.close();

		// Return the contents of the stringstream as an std::string
		return ss.str();
	}

	bool Exists(const std::string& path)
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

	bool CreateEmptyFile(const std::string& path)
	{
		FILE* file = fopen(path.data(), "w");
		if (!file)
			return false;
		fflush(file);
		fclose(file);
		return true;
	}

	std::optional<std::vector<uint8_t>> ReadAllBytes(const std::string& path)
	{
		// Open the file for reading in binary mode
		std::ifstream file(path, std::ios::binary);

		// Check if the file was opened successfully
		if (!file.is_open()) {
			return std::nullopt;
		}

		// Determine the size of the file
		file.seekg(0, std::ios::end);
		std::streampos fileSize = file.tellg();
		file.seekg(0, std::ios::beg);

		// Read the contents of the file into a vector
		std::vector<uint8_t> buffer(fileSize);
		file.read(reinterpret_cast<char*>(buffer.data()), fileSize);

		// Close the file
		file.close();

		// Return the vector containing the contents of the file
		return buffer;
	}

	bool WriteAllBytes(const std::string& path, const void* data, size_t size)
	{
		FILE* output = fopen(path.data(), "wb");
		if (!output)
			return false;
		fwrite(data, 1, size, output);
		fclose(output);
		return true;
	}

	bool WriteAllText(const std::string& path, const std::string& text)
	{
		FILE* output = fopen(path.data(), "w");
		if (!output)
			return false;
		fwrite(text.data(), 1, text.size(), output);
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

	void ShowInfoBox(const std::string& title, const std::string& text)
	{
		NMB::show(title.data(), text.data(), NMB::ICON_INFO);
	}

	void ShowWarningBox(const std::string& title, const std::string& text)
	{
		NMB::show(title.data(), text.data(), NMB::ICON_WARNING);
	}

	void ShowErrorBox(const std::string& title, const std::string& text)
	{
		NMB::show(title.data(), text.data(), NMB::ICON_ERROR);
	}

	Logger::Logger(LoggerOptions options) :
		Options(options)
	{
		if (Options.LoggerType & LOGGER_TYPE_FILE) {
			if (Options.LoggerOutputFileName.length() == 0)
				Options.LoggerOutputFileName = (std::to_string(time(NULL)) + ".log.txt");
			_file_stream.open(Options.LoggerOutputFileName, std::ios::out);
		}
	}

	Logger::Logger(Logger&& move) noexcept
	{
		Options = move.Options;
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

	std::string Logger::Escape(const std::string& input)
	{
		std::string out;
		out.reserve(input.size());
		for (size_t i = 0; i < input.size(); i++) {
			if (input[i] == '{')
				out += "{{";
			else if (input[i] == '}')
				out += "}}";
			else
				out += input[i];
		}
		return out;
	}

	void Logger::_internal_log(LogLevel logLevel, const std::string& output)
	{
		std::lock_guard<std::mutex> lock(_console_lock);
		if (Options.LoggerType & LOGGER_TYPE_CONSOLE) {
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
		if (Options.LoggerType & LOGGER_TYPE_FILE) {
			_file_stream << output;
			_file_stream.flush();
		}
		if (logLevel == LogLevel::ERR) {
			if (Options.ShowMessageBoxOnError) {
				CPP_UTILITY_NAMESPACE::ShowErrorBox("Encountered an Error", output);
			}
			if (Options.DebugBreakOnError) {
				CPP_UTILITY_NAMESPACE::DebugBreak();
			}
		}
	}

	void Logger::AddFileLogging(const char* FileName)
	{
		_file_stream = std::fstream(FileName, std::ios::out);
		Options.LoggerType |= LOGGER_TYPE_FILE;
	}

	uint64_t Logger::_get_current_thread_id()
	{
#ifdef _WIN32
		return GetCurrentThreadId();
#else
        return syscall(__NR_gettid);
#endif
	}

	std::chrono::steady_clock::time_point Logger::_start_timestamp = std::chrono::steady_clock::now();
	LoggerOptions Logger::GlobalLoggerOptions;

#endif

}