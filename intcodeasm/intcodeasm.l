%top{
#include "../lexer-test/symbols.h"
%}

%o fast freespace case-insensitive header-file

space				[ \t]+
identifier			[a-zA-Z_][a-zA-Z0-9_$]*
decimal_integer		[0-9]+
hex_integer			0x[0-9A-Fa-f]+
integer				{hex_integer}|{decimal_integer}
eol					\r?\n

%x COMMENT

%%

{eol}				{ return '\n'; }
{space}				{ /* ignore */ }
;					{ start(COMMENT); }
{identifier}		{ return WORD; }
[][,+:()-]			{ return text()[0]; }
{integer}			{ return INTEGER; }

<COMMENT>{
{eol}				{ start(INITIAL); return EOL; }
[^\n]+				{ /* ignore */ }
}

<*>.				{ return ERR; }

%%
