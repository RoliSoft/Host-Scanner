#pragma once
#include "stdafx.h"
#include <iostream>

#ifdef Windows
	#include <io.h>

	#define isatty(f) _isatty(f)
	#define fileno(s) _fileno(s)
#elif Linux
	#include <unistd.h>
#endif

/*!
 * Methods to change the color of the output.
 */
namespace Color
{
	using namespace std;

	/*!
	 * Available colors and font types.
	 */
	enum Code
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
#elif Linux
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
		static HANDLE chndl;
		static CONSOLE_SCREEN_BUFFER_INFO csbi;
		static WORD sa;
#endif

	};

	/*!
	 * Initializes the coloring support.
	 */
	void Init();

	/*!
	 * Implements printing for the `Colors::Code` type.
	 */
	ostream& operator<< (ostream& os, Code code);

}
