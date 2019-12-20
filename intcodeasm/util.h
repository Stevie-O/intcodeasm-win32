#pragma once
#include <cstdint>
#include <cerrno>
#include <cinttypes>
#include <stdexcept>

namespace util {
	static std::intmax_t string_to_intmax(const char *s, int radix) {
		// NOTE that strtoimax clamps the value to the maximum range, and there
		// is nothing we can do about that. The errno == ERANGE case is useless
		// because the call may have been successful and the error value may have been
		// left by a previous call.
		char *end_ptr;
		auto old_errno = errno;
		errno = 0;
		std::intmax_t result = std::strtoimax(s, &end_ptr, radix);
		if (*end_ptr || errno == ERANGE)
			throw std::invalid_argument{ "Failed to parse as intmax_t: " + std::string(s) };
		errno = old_errno;
		return result;
	}

}