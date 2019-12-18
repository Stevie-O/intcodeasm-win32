%{
  #include "lex.yy.h"
  #define YYPARSE_PARAM scanner
  #define YYLEX_PARAM   scanner
%}

%define api.pure
%locations

%token MNEMONIC
%token IDENTIFIER
%token BP
%token DI
%token INTEGER
%token EOL

%%

program: statement
	| statement statement

label_definition: IDENTIFIER ':'
optional_label: 
	| label_definition

argument_expression: IDENTIFIER
		| INTEGER
bp_modifier: '+' argument_expression
		| '-' argument_expression
relative_argument: '[' BP bp_modifier ']'
absolute_argument: '[' argument_expression ']'
immediate_argument: argument_expression
argument: absolute_argument
	| relative_argument
	| immediate_argument

labeled_argument: argument
	| label_definition argument

argument_list: labeled_argument 
		| labeled_argument ',' argument_list

instruction: MNEMONIC argument_list
optional_instruction: 
	| instruction

instruction_statement: optional_label optional_instruction EOL
di_statement: optional_label DI argument_list EOL

statement:  instruction_statement
	| di_statement

%%
