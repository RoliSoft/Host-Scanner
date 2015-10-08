#include "color.h"

using namespace std;

bool Color::Data::istty = false;

#ifdef Windows
HANDLE Color::Data::chndl;
CONSOLE_SCREEN_BUFFER_INFO Color::Data::csbi;
WORD Color::Data::sa;
#endif

void Color::Init()
{
	Data::istty = isatty(fileno(stdout)) != 0;

	if (!Data::istty)
	{
		return;
	}

#ifdef Windows
	Data::chndl = GetStdHandle(STD_OUTPUT_HANDLE);
	GetConsoleScreenBufferInfo(Data::chndl, &Data::csbi);
	Data::sa = Data::csbi.wAttributes;
#endif
}

ostream& Color::operator<<(ostream& os, Code code)
{
	if (!Data::istty)
	{
		return os;
	}

#ifdef Windows
	SetConsoleTextAttribute(Data::chndl, code == Default ? Data::sa : WORD(code));
	return os;
#elif Linux
	return os << "\033[" << static_cast<int>(code) << "m";
#endif
}
