// lexer-test.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include <iostream>
#include <iomanip>
#include "lex.yy.h"

using namespace std;

int main()
{
	reflex::Input input(stdin, reflex::Input::file_encoding::utf8);
	Lexer lex(input);

	int result;
	while ((result = lex.lex())) {
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

	return 0;
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
