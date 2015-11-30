#pragma once
#include "Stdafx.h"
#include <iostream>

#ifdef Windows
	#include <io.h>

	#define isatty(f) _isatty(f)
	#define fileno(s) _fileno(s)
#elif Unix
	#include <unistd.h>
#endif

/*!
 * Methods to change the color of the output.
 */
namespace Format
{
	using namespace std;

	/*!
	 * Available colors.
	 */
	enum ColorCode
	{
#ifdef Windows

		Red     = FOREGROUND_RED,
		Green   = FOREGROUND_GREEN,
		Blue    = FOREGROUND_BLUE,
		Yellow  = FOREGROUND_RED  | FOREGROUND_GREEN,
		Magenta = FOREGROUND_RED  | FOREGROUND_BLUE,
		Cyan    = FOREGROUND_BLUE | FOREGROUND_GREEN,
		White   = FOREGROUND_RED  | FOREGROUND_GREEN | FOREGROUND_BLUE,
		Default = INT_MAX

#elif Unix

		Red     = 31,
		Green   = 32,
		Blue    = 34,
		Yellow  = 33,
		Magenta = 35,
		Cyan    = 36,
		White   = 37,
		Default = 39

#endif
	};

	/*!
	 * Available font styles.
	 */
	enum StyleCode
	{
#if Windows

		Bold	  = FOREGROUND_INTENSITY,
		Underline = COMMON_LVB_UNDERSCORE,
		Blink     = 0, // N/A
		Reverse   = COMMON_LVB_REVERSE_VIDEO,
		Hidden    = 0, // N/A
		Normal    = INT_MAX

#elif Unix

		Bold       = 1,
		Underline  = 4,
		Blink      = 5,
		Reverse    = 7,
		Hidden     = 8,
		Normal     = 0

#endif
	};

	/*!
	 * An ephemeral class to hold console color data.
	 */
	class Data
	{
	public:

		/*!
		 * Whether the current terminal is interactive.
		 */
		static bool istty;

#ifdef Windows
		static HANDLE stdHwd;
		static CONSOLE_SCREEN_BUFFER_INFO bufInf;
		static WORD defColor;
		static WORD curColor;
		static WORD curStyle;
#endif

	};

	/*!
	 * Initializes the coloring support.
	 */
	void Init();

	/*!
	 * Implements printing for the `Color::ColorCode` type.
	 */
	ostream& operator<< (ostream& os, ColorCode code);

	/*!
	 * Implements printing for the `Color::StyleCode` type.
	 */
	ostream& operator<< (ostream& os, StyleCode code);

}
