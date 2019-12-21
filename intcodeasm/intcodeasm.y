%language "c++"

/* %define api.pure full */
%define parse.trace
%define api.namespace {yy}
%define api.parser.class {parser}
%define api.value.type variant
%define api.token.constructor
%define parse.error verbose
%locations

%code requires{
  namespace yy {
    class Lexer;  // Generated by reflex with namespace=yy lexer=Lexer lex=yylex
  }
}

%parse-param { yy::Lexer& lexer }  // Construct parser object with lexer
%code{
  #include "lex.yy.h"  // header file generated with reflex --header-file
  #undef yylex
  #define yylex lexer.lex  // Within bison's parse() we should invoke lexer.lex(), not the global yylex()

  using std::endl;
}

%token <std::string> MNEMONIC "mnemonic"
%token <std::string> IDENTIFIER "identifier"
%token KEYWORD_BP "BP"
%token KEYWORD_DI "DI"
%token <intmax_t> INTEGER "integer"
%token EOL "end-of-line"

%%

program
	: statement { lexer.out() << "statement(1)" << endl; }
	| program statement { lexer.out() << "statement(2)" << endl; }

label_definition: IDENTIFIER ':' { lexer.out() << "(label) '" << $1 << "'" << endl; }
optional_label:
	| label_definition			{ lexer.out() << "(optional-label)" << endl; }

argument_expression: IDENTIFIER	{ lexer.out() << "(argument-expression.IDENTIFIER) '" << $1 << "'" << endl; }
		| INTEGER				{ lexer.out() << "(agrument-expression.INTEGER) " << $1 << endl; }
bp_modifier: '+' argument_expression	{ lexer.out() << "(bp-modifier +)" << endl; }
		| '-' argument_expression		{ lexer.out() << "(bp-modifier -)" << endl; }
relative_argument: '[' KEYWORD_BP bp_modifier ']' { lexer.out() << "(relative-argument)" << endl; }
absolute_argument: '[' argument_expression ']'	  { lexer.out() << "(absolute-argument)" << endl; }
immediate_argument: argument_expression			  { lexer.out() << "(immediate-argument)" << endl; }
argument: absolute_argument
	| relative_argument
	| immediate_argument

labeled_argument: argument						  { lexer.out() << "(label-less argument)" << endl; }
	| label_definition argument					  { lexer.out() << "(labeled argument)" << endl; }

argument_list
		: labeled_argument
		| argument_list ',' labeled_argument

instruction
		: MNEMONIC								 { lexer.out() << "(instruction) '" << $1 << "'" << endl; }
		| MNEMONIC argument_list				 {  lexer.out() << "(instruction) '" << $1 << "'" << endl; }
optional_instruction: 							 { lexer.out() << "(no instruction)" << endl; }
	| instruction

instruction_statement: optional_label optional_instruction EOL	{ lexer.out() << "(instruction-statement)" << endl; }
di_statement: optional_label KEYWORD_DI argument_list EOL		{ lexer.out() << "(di-statement)" << endl; }

statement:  instruction_statement
	| di_statement

%%
