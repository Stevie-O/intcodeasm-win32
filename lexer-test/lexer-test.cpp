// lexer-test.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include <iostream>
#include <iomanip>
#include "lex.yy.h"

using namespace std;

void yy::parser::error(const location_type& l, const std::string& m)
{
	cout << "at " << l << ": " << m << endl;
}

int lex_only(yy::Lexer& lex)
{
	while (1) {
		auto lex_info = lex.lex();
		auto result = lex_info.type;
		if (result == 0) return 0;
		switch (result) {
		case INTEGER: cout << "integer" " " << lex.text() << endl; break;
		case WORD: cout << "word" " " << lex.text() << endl; break;
		case ERR: cout << "invalid" " " << lex.text() << endl; return 1;  break;
		case EOL: cout << "eol" << endl; break;
		case MNEMONIC: cout << "mnemonic" " " << lex.text() << endl; break;
		case KEYWORD_DI: cout << "keyword 'DI'" " " << lex.text() << endl; break;
		case KEYWORD_BP: cout << "keyword 'BP'" " " << lex.text() << endl; break;

		default:
			if (result <= ' ') {
				std::ios_base::fmtflags f(cout.flags());
				cout << "0x" << std::hex << std::setfill('0') << std::setw(2) << result;
				cout.flags(f);
				cout << endl;
			}
			else {
				cout << char(result) << endl;
			}
			break;
		}
		//cout << result << endl;
	}
}

int main(int argc, char **argv)
{
	reflex::Input input(stdin, reflex::Input::file_encoding::utf8);
	yy::Lexer lex(input);

	// return lex_only(lex);
	yy::parser parser(lex);
	if (argc >= 2 && !strcmp(argv[1], "-d"))
		parser.set_debug_level(1);
	return parser.parse();
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
