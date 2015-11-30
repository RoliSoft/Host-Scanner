#include "Format.h"

using namespace std;

bool Format::Data::istty = false;

#ifdef Windows
HANDLE Format::Data::stdHwd;
CONSOLE_SCREEN_BUFFER_INFO Format::Data::bufInf;
WORD Format::Data::defColor;
WORD Format::Data::curColor;
WORD Format::Data::curStyle;
#endif

void Format::Init()
{
	Data::istty = isatty(fileno(stdout)) != 0;

	if (!Data::istty)
	{
		return;
	}

#ifdef Windows

	Data::stdHwd = GetStdHandle(STD_OUTPUT_HANDLE);
	GetConsoleScreenBufferInfo(Data::stdHwd, &Data::bufInf);
	Data::defColor = Data::bufInf.wAttributes;

#endif
}

ostream& Format::operator<<(ostream& os, ColorCode code)
{
	if (!Data::istty)
	{
		return os;
	}

#ifdef Windows

	if (code == ColorCode::Default)
	{
		Data::curColor = Data::defColor;
	}
	else
	{
		Data::curColor = WORD(code);
	}

	SetConsoleTextAttribute(Data::stdHwd, Data::curColor | Data::curStyle);

#elif Unix

	os << "\033[" << static_cast<int>(code) << "m";

#endif

	return os;
}

ostream& Format::operator<<(ostream& os, StyleCode code)
{
	if (!Data::istty)
	{
		return os;
	}

#ifdef Windows

	if (code == StyleCode::Normal)
	{
		Data::curStyle = 0;
	}
	else
	{
		Data::curStyle |= WORD(code);
	}

	SetConsoleTextAttribute(Data::stdHwd, Data::curColor | Data::curStyle);

#elif Unix

	os << "\033[" << static_cast<int>(code) << "m";

#endif

	return os;
}
