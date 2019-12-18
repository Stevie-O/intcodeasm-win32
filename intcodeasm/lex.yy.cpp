// lex.yy.cpp generated by reflex 1.5.4 from intcodeasm.l

////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  OPTIONS USED                                                              //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#define REFLEX_OPTION_case_insensitive    true
#define REFLEX_OPTION_fast                true
#define REFLEX_OPTION_freespace           true
#define REFLEX_OPTION_header_file         "lex.yy.h"
#define REFLEX_OPTION_lex                 lex
#define REFLEX_OPTION_lexer               Lexer
#define REFLEX_OPTION_outfile             "lex.yy.cpp"

////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  SECTION 1: %top{ user code %}                                             //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#line 1 "intcodeasm.l"

#include "../lexer-test/symbols.h"


////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  REGEX MATCHER                                                             //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include <reflex/matcher.h>

////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  ABSTRACT LEXER CLASS                                                      //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include <reflex/abslexer.h>

////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  LEXER CLASS                                                               //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

class Lexer : public reflex::AbstractLexer<reflex::Matcher> {
 public:
  typedef reflex::AbstractLexer<reflex::Matcher> AbstractBaseLexer;
  Lexer(
      const reflex::Input& input = reflex::Input(),
      std::ostream&        os    = std::cout)
    :
      AbstractBaseLexer(input, os)
  {
  }
  static const int INITIAL = 0;
  static const int COMMENT = 1;
  virtual int lex();
  int lex(
      const reflex::Input& input,
      std::ostream        *os = NULL)
  {
    in(input);
    if (os)
      out(*os);
    return lex();
  }
};

////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  SECTION 2: rules                                                          //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

extern void reflex_code_INITIAL(reflex::Matcher&);
extern void reflex_code_COMMENT(reflex::Matcher&);

int Lexer::lex()
{
  static const reflex::Pattern PATTERN_INITIAL(reflex_code_INITIAL);
  static const reflex::Pattern PATTERN_COMMENT(reflex_code_COMMENT);
  if (!has_matcher())
  {
    matcher(new Matcher(PATTERN_INITIAL, stdinit(), this));
  }
  while (true)
  {
    switch (start())
    {
      case INITIAL:
        matcher().pattern(PATTERN_INITIAL);
        switch (matcher().scan())
        {
          case 0:
            if (matcher().at_end())
            {
              return int();
            }
            else
            {
              out().put(matcher().input());
            }
            break;
          case 1: // rule at line 18: (?:\r?\n)
#line 18 "intcodeasm.l"
{ return EOL; }
            break;
          case 2: // rule at line 19: (?:[\x09\x20]+)
#line 19 "intcodeasm.l"
{ /* ignore */ }
            break;
          case 3: // rule at line 20: ;
#line 20 "intcodeasm.l"
{ start(COMMENT); }

            break;
          case 4: // rule at line 22: [Bb][Pp]
#line 22 "intcodeasm.l"
{ return KEYWORD_BP; }

            break;
          case 5: // rule at line 24: [Aa][Dd][Dd]
          case 6: // rule at line 25: [Mm][Uu][Ll]
          case 7: // rule at line 26: [Ii][Nn][Pp]
          case 8: // rule at line 27: [Oo][Uu][Tt]
          case 9: // rule at line 28: [Jj][Nn][Zz]
          case 10: // rule at line 29: [Jj][Zz]
          case 11: // rule at line 30: [Cc][Mm][Pp][Ll][Tt]
          case 12: // rule at line 31: [Cc][Mm][Pp][Ee][Qq]
          case 13: // rule at line 32: [Aa][Bb][Pp]
          case 14: // rule at line 33: [Hh][Aa][Ll][Tt]
#line 33 "intcodeasm.l"
{ return MNEMONIC; }

            break;
          case 15: // rule at line 35: [Dd][Ii]
#line 35 "intcodeasm.l"
{ return KEYWORD_DI; }


            break;
          case 16: // rule at line 38: (?:[A-Z_a-z][\x240-9A-Z_a-z]*)
#line 38 "intcodeasm.l"
{ return WORD; }
            break;
          case 17: // rule at line 39: [()+-\x2d:\x5b\x5d]
#line 39 "intcodeasm.l"
{ return text()[0]; }
            break;
          case 18: // rule at line 40: (?:(?:0[xX][0-9A-Fa-f]+)|(?:[0-9]+))
#line 40 "intcodeasm.l"
{ return INTEGER; }

            break;
          case 19: // rule at line 47: .
#line 47 "intcodeasm.l"
{ return ERR; }

            break;
        }
        break;
      case COMMENT:
        matcher().pattern(PATTERN_COMMENT);
        switch (matcher().scan())
        {
          case 0:
            if (matcher().at_end())
            {
              return int();
            }
            else
            {
              out().put(matcher().input());
            }
            break;
          case 1: // rule at line 43: (?:\r?\n)
#line 43 "intcodeasm.l"
{ start(INITIAL); return EOL; }
            break;
          case 2: // rule at line 44: [^\x0a]+
#line 44 "intcodeasm.l"
{ /* ignore */ }
            break;
          case 3: // rule at line 47: .
#line 47 "intcodeasm.l"
{ return ERR; }

            break;
        }
        break;
      default:
        start(0);
    }
  }
}

////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  TABLES                                                                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include <reflex/matcher.h>

#if defined(OS_WIN)
#pragma warning(disable:4101 4102)
#elif defined(__GNUC__)
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-label"
#elif defined(__clang__)
#pragma clang diagnostic ignored "-Wunused-variable"
#pragma clang diagnostic ignored "-Wunused-label"
#endif

void reflex_code_INITIAL(reflex::Matcher& m)
{
  int c0 = 0, c1 = 0;
  m.FSM_INIT(c1);

S0:
  m.FSM_FIND();
  c1 = m.FSM_CHAR();
  if (c1 == 'o') goto S76;
  if (c1 == 'm') goto S58;
  if (c1 == 'j') goto S85;
  if (c1 == 'i') goto S67;
  if (c1 == 'h') goto S105;
  if ('e' <= c1 && c1 <= 'z') goto S123;
  if (c1 == 'd') goto S114;
  if (c1 == 'c') goto S96;
  if (c1 == 'b') goto S38;
  if (c1 == 'a') goto S47;
  if (c1 == '_') goto S123;
  if (c1 == ']') goto S130;
  if (c1 == '[') goto S130;
  if (c1 == 'O') goto S76;
  if (c1 == 'M') goto S58;
  if (c1 == 'J') goto S85;
  if (c1 == 'I') goto S67;
  if (c1 == 'H') goto S105;
  if ('E' <= c1 && c1 <= 'Z') goto S123;
  if (c1 == 'D') goto S114;
  if (c1 == 'C') goto S96;
  if (c1 == 'B') goto S38;
  if (c1 == 'A') goto S47;
  if (c1 == ';') goto S36;
  if (c1 == ':') goto S130;
  if ('1' <= c1 && c1 <= '9') goto S146;
  if (c1 == '0') goto S132;
  if ('+' <= c1 && c1 <= '-') goto S130;
  if ('(' <= c1 && c1 <= ')') goto S130;
  if (c1 == ' ') goto S142;
  if (c1 == '\r') goto S139;
  if (c1 == '\n') goto S34;
  if (c1 == '\t') goto S142;
  if (0 <= c1) goto S137;
  return m.FSM_HALT(c1);

S34:
  m.FSM_TAKE(1);
  return m.FSM_HALT();

S36:
  m.FSM_TAKE(3);
  return m.FSM_HALT();

S38:
  m.FSM_TAKE(16);
  c1 = m.FSM_CHAR();
  if (c1 == 'p') goto S149;
  if ('a' <= c1 && c1 <= 'z') goto S123;
  if (c1 == '_') goto S123;
  if (c1 == 'P') goto S149;
  if ('A' <= c1 && c1 <= 'Z') goto S123;
  if ('0' <= c1 && c1 <= '9') goto S123;
  if (c1 == '$') goto S123;
  return m.FSM_HALT(c1);

S47:
  m.FSM_TAKE(16);
  c1 = m.FSM_CHAR();
  if (c1 == 'd') goto S156;
  if (c1 == 'b') goto S165;
  if ('a' <= c1 && c1 <= 'z') goto S123;
  if (c1 == '_') goto S123;
  if (c1 == 'D') goto S156;
  if (c1 == 'B') goto S165;
  if ('A' <= c1 && c1 <= 'Z') goto S123;
  if ('0' <= c1 && c1 <= '9') goto S123;
  if (c1 == '$') goto S123;
  return m.FSM_HALT(c1);

S58:
  m.FSM_TAKE(16);
  c1 = m.FSM_CHAR();
  if (c1 == 'u') goto S174;
  if ('a' <= c1 && c1 <= 'z') goto S123;
  if (c1 == '_') goto S123;
  if (c1 == 'U') goto S174;
  if ('A' <= c1 && c1 <= 'Z') goto S123;
  if ('0' <= c1 && c1 <= '9') goto S123;
  if (c1 == '$') goto S123;
  return m.FSM_HALT(c1);

S67:
  m.FSM_TAKE(16);
  c1 = m.FSM_CHAR();
  if (c1 == 'n') goto S183;
  if ('a' <= c1 && c1 <= 'z') goto S123;
  if (c1 == '_') goto S123;
  if (c1 == 'N') goto S183;
  if ('A' <= c1 && c1 <= 'Z') goto S123;
  if ('0' <= c1 && c1 <= '9') goto S123;
  if (c1 == '$') goto S123;
  return m.FSM_HALT(c1);

S76:
  m.FSM_TAKE(16);
  c1 = m.FSM_CHAR();
  if (c1 == 'u') goto S192;
  if ('a' <= c1 && c1 <= 'z') goto S123;
  if (c1 == '_') goto S123;
  if (c1 == 'U') goto S192;
  if ('A' <= c1 && c1 <= 'Z') goto S123;
  if ('0' <= c1 && c1 <= '9') goto S123;
  if (c1 == '$') goto S123;
  return m.FSM_HALT(c1);

S85:
  m.FSM_TAKE(16);
  c1 = m.FSM_CHAR();
  if (c1 == 'z') goto S210;
  if (c1 == 'n') goto S201;
  if ('a' <= c1 && c1 <= 'y') goto S123;
  if (c1 == '_') goto S123;
  if (c1 == 'Z') goto S210;
  if (c1 == 'N') goto S201;
  if ('A' <= c1 && c1 <= 'Y') goto S123;
  if ('0' <= c1 && c1 <= '9') goto S123;
  if (c1 == '$') goto S123;
  return m.FSM_HALT(c1);

S96:
  m.FSM_TAKE(16);
  c1 = m.FSM_CHAR();
  if (c1 == 'm') goto S217;
  if ('a' <= c1 && c1 <= 'z') goto S123;
  if (c1 == '_') goto S123;
  if (c1 == 'M') goto S217;
  if ('A' <= c1 && c1 <= 'Z') goto S123;
  if ('0' <= c1 && c1 <= '9') goto S123;
  if (c1 == '$') goto S123;
  return m.FSM_HALT(c1);

S105:
  m.FSM_TAKE(16);
  c1 = m.FSM_CHAR();
  if ('b' <= c1 && c1 <= 'z') goto S123;
  if (c1 == 'a') goto S226;
  if (c1 == '_') goto S123;
  if ('B' <= c1 && c1 <= 'Z') goto S123;
  if (c1 == 'A') goto S226;
  if ('0' <= c1 && c1 <= '9') goto S123;
  if (c1 == '$') goto S123;
  return m.FSM_HALT(c1);

S114:
  m.FSM_TAKE(16);
  c1 = m.FSM_CHAR();
  if (c1 == 'i') goto S235;
  if ('a' <= c1 && c1 <= 'z') goto S123;
  if (c1 == '_') goto S123;
  if (c1 == 'I') goto S235;
  if ('A' <= c1 && c1 <= 'Z') goto S123;
  if ('0' <= c1 && c1 <= '9') goto S123;
  if (c1 == '$') goto S123;
  return m.FSM_HALT(c1);

S123:
  m.FSM_TAKE(16);
  c1 = m.FSM_CHAR();
  if ('a' <= c1 && c1 <= 'z') goto S123;
  if (c1 == '_') goto S123;
  if ('A' <= c1 && c1 <= 'Z') goto S123;
  if ('0' <= c1 && c1 <= '9') goto S123;
  if (c1 == '$') goto S123;
  return m.FSM_HALT(c1);

S130:
  m.FSM_TAKE(17);
  return m.FSM_HALT();

S132:
  m.FSM_TAKE(18);
  c1 = m.FSM_CHAR();
  if (c1 == 'x') goto S242;
  if (c1 == 'X') goto S242;
  if ('0' <= c1 && c1 <= '9') goto S146;
  return m.FSM_HALT(c1);

S137:
  m.FSM_TAKE(19);
  return m.FSM_HALT();

S139:
  m.FSM_TAKE(19);
  c1 = m.FSM_CHAR();
  if (c1 == '\n') goto S34;
  return m.FSM_HALT(c1);

S142:
  m.FSM_TAKE(2);
  c1 = m.FSM_CHAR();
  if (c1 == ' ') goto S142;
  if (c1 == '\t') goto S142;
  return m.FSM_HALT(c1);

S146:
  m.FSM_TAKE(18);
  c1 = m.FSM_CHAR();
  if ('0' <= c1 && c1 <= '9') goto S146;
  return m.FSM_HALT(c1);

S149:
  m.FSM_TAKE(4);
  c1 = m.FSM_CHAR();
  if ('a' <= c1 && c1 <= 'z') goto S123;
  if (c1 == '_') goto S123;
  if ('A' <= c1 && c1 <= 'Z') goto S123;
  if ('0' <= c1 && c1 <= '9') goto S123;
  if (c1 == '$') goto S123;
  return m.FSM_HALT(c1);

S156:
  m.FSM_TAKE(16);
  c1 = m.FSM_CHAR();
  if (c1 == 'd') goto S246;
  if ('a' <= c1 && c1 <= 'z') goto S123;
  if (c1 == '_') goto S123;
  if (c1 == 'D') goto S246;
  if ('A' <= c1 && c1 <= 'Z') goto S123;
  if ('0' <= c1 && c1 <= '9') goto S123;
  if (c1 == '$') goto S123;
  return m.FSM_HALT(c1);

S165:
  m.FSM_TAKE(16);
  c1 = m.FSM_CHAR();
  if (c1 == 'p') goto S253;
  if ('a' <= c1 && c1 <= 'z') goto S123;
  if (c1 == '_') goto S123;
  if (c1 == 'P') goto S253;
  if ('A' <= c1 && c1 <= 'Z') goto S123;
  if ('0' <= c1 && c1 <= '9') goto S123;
  if (c1 == '$') goto S123;
  return m.FSM_HALT(c1);

S174:
  m.FSM_TAKE(16);
  c1 = m.FSM_CHAR();
  if (c1 == 'l') goto S260;
  if ('a' <= c1 && c1 <= 'z') goto S123;
  if (c1 == '_') goto S123;
  if (c1 == 'L') goto S260;
  if ('A' <= c1 && c1 <= 'Z') goto S123;
  if ('0' <= c1 && c1 <= '9') goto S123;
  if (c1 == '$') goto S123;
  return m.FSM_HALT(c1);

S183:
  m.FSM_TAKE(16);
  c1 = m.FSM_CHAR();
  if (c1 == 'p') goto S267;
  if ('a' <= c1 && c1 <= 'z') goto S123;
  if (c1 == '_') goto S123;
  if (c1 == 'P') goto S267;
  if ('A' <= c1 && c1 <= 'Z') goto S123;
  if ('0' <= c1 && c1 <= '9') goto S123;
  if (c1 == '$') goto S123;
  return m.FSM_HALT(c1);

S192:
  m.FSM_TAKE(16);
  c1 = m.FSM_CHAR();
  if (c1 == 't') goto S274;
  if ('a' <= c1 && c1 <= 'z') goto S123;
  if (c1 == '_') goto S123;
  if (c1 == 'T') goto S274;
  if ('A' <= c1 && c1 <= 'Z') goto S123;
  if ('0' <= c1 && c1 <= '9') goto S123;
  if (c1 == '$') goto S123;
  return m.FSM_HALT(c1);

S201:
  m.FSM_TAKE(16);
  c1 = m.FSM_CHAR();
  if (c1 == 'z') goto S281;
  if ('a' <= c1 && c1 <= 'y') goto S123;
  if (c1 == '_') goto S123;
  if (c1 == 'Z') goto S281;
  if ('A' <= c1 && c1 <= 'Y') goto S123;
  if ('0' <= c1 && c1 <= '9') goto S123;
  if (c1 == '$') goto S123;
  return m.FSM_HALT(c1);

S210:
  m.FSM_TAKE(10);
  c1 = m.FSM_CHAR();
  if ('a' <= c1 && c1 <= 'z') goto S123;
  if (c1 == '_') goto S123;
  if ('A' <= c1 && c1 <= 'Z') goto S123;
  if ('0' <= c1 && c1 <= '9') goto S123;
  if (c1 == '$') goto S123;
  return m.FSM_HALT(c1);

S217:
  m.FSM_TAKE(16);
  c1 = m.FSM_CHAR();
  if (c1 == 'p') goto S288;
  if ('a' <= c1 && c1 <= 'z') goto S123;
  if (c1 == '_') goto S123;
  if (c1 == 'P') goto S288;
  if ('A' <= c1 && c1 <= 'Z') goto S123;
  if ('0' <= c1 && c1 <= '9') goto S123;
  if (c1 == '$') goto S123;
  return m.FSM_HALT(c1);

S226:
  m.FSM_TAKE(16);
  c1 = m.FSM_CHAR();
  if (c1 == 'l') goto S299;
  if ('a' <= c1 && c1 <= 'z') goto S123;
  if (c1 == '_') goto S123;
  if (c1 == 'L') goto S299;
  if ('A' <= c1 && c1 <= 'Z') goto S123;
  if ('0' <= c1 && c1 <= '9') goto S123;
  if (c1 == '$') goto S123;
  return m.FSM_HALT(c1);

S235:
  m.FSM_TAKE(15);
  c1 = m.FSM_CHAR();
  if ('a' <= c1 && c1 <= 'z') goto S123;
  if (c1 == '_') goto S123;
  if ('A' <= c1 && c1 <= 'Z') goto S123;
  if ('0' <= c1 && c1 <= '9') goto S123;
  if (c1 == '$') goto S123;
  return m.FSM_HALT(c1);

S242:
  c1 = m.FSM_CHAR();
  if ('a' <= c1 && c1 <= 'f') goto S308;
  if ('A' <= c1 && c1 <= 'F') goto S308;
  if ('0' <= c1 && c1 <= '9') goto S308;
  return m.FSM_HALT(c1);

S246:
  m.FSM_TAKE(5);
  c1 = m.FSM_CHAR();
  if ('a' <= c1 && c1 <= 'z') goto S123;
  if (c1 == '_') goto S123;
  if ('A' <= c1 && c1 <= 'Z') goto S123;
  if ('0' <= c1 && c1 <= '9') goto S123;
  if (c1 == '$') goto S123;
  return m.FSM_HALT(c1);

S253:
  m.FSM_TAKE(13);
  c1 = m.FSM_CHAR();
  if ('a' <= c1 && c1 <= 'z') goto S123;
  if (c1 == '_') goto S123;
  if ('A' <= c1 && c1 <= 'Z') goto S123;
  if ('0' <= c1 && c1 <= '9') goto S123;
  if (c1 == '$') goto S123;
  return m.FSM_HALT(c1);

S260:
  m.FSM_TAKE(6);
  c1 = m.FSM_CHAR();
  if ('a' <= c1 && c1 <= 'z') goto S123;
  if (c1 == '_') goto S123;
  if ('A' <= c1 && c1 <= 'Z') goto S123;
  if ('0' <= c1 && c1 <= '9') goto S123;
  if (c1 == '$') goto S123;
  return m.FSM_HALT(c1);

S267:
  m.FSM_TAKE(7);
  c1 = m.FSM_CHAR();
  if ('a' <= c1 && c1 <= 'z') goto S123;
  if (c1 == '_') goto S123;
  if ('A' <= c1 && c1 <= 'Z') goto S123;
  if ('0' <= c1 && c1 <= '9') goto S123;
  if (c1 == '$') goto S123;
  return m.FSM_HALT(c1);

S274:
  m.FSM_TAKE(8);
  c1 = m.FSM_CHAR();
  if ('a' <= c1 && c1 <= 'z') goto S123;
  if (c1 == '_') goto S123;
  if ('A' <= c1 && c1 <= 'Z') goto S123;
  if ('0' <= c1 && c1 <= '9') goto S123;
  if (c1 == '$') goto S123;
  return m.FSM_HALT(c1);

S281:
  m.FSM_TAKE(9);
  c1 = m.FSM_CHAR();
  if ('a' <= c1 && c1 <= 'z') goto S123;
  if (c1 == '_') goto S123;
  if ('A' <= c1 && c1 <= 'Z') goto S123;
  if ('0' <= c1 && c1 <= '9') goto S123;
  if (c1 == '$') goto S123;
  return m.FSM_HALT(c1);

S288:
  m.FSM_TAKE(16);
  c1 = m.FSM_CHAR();
  if (c1 == 'l') goto S313;
  if (c1 == 'e') goto S322;
  if ('a' <= c1 && c1 <= 'z') goto S123;
  if (c1 == '_') goto S123;
  if (c1 == 'L') goto S313;
  if (c1 == 'E') goto S322;
  if ('A' <= c1 && c1 <= 'Z') goto S123;
  if ('0' <= c1 && c1 <= '9') goto S123;
  if (c1 == '$') goto S123;
  return m.FSM_HALT(c1);

S299:
  m.FSM_TAKE(16);
  c1 = m.FSM_CHAR();
  if (c1 == 't') goto S331;
  if ('a' <= c1 && c1 <= 'z') goto S123;
  if (c1 == '_') goto S123;
  if (c1 == 'T') goto S331;
  if ('A' <= c1 && c1 <= 'Z') goto S123;
  if ('0' <= c1 && c1 <= '9') goto S123;
  if (c1 == '$') goto S123;
  return m.FSM_HALT(c1);

S308:
  m.FSM_TAKE(18);
  c1 = m.FSM_CHAR();
  if ('a' <= c1 && c1 <= 'f') goto S308;
  if ('A' <= c1 && c1 <= 'F') goto S308;
  if ('0' <= c1 && c1 <= '9') goto S308;
  return m.FSM_HALT(c1);

S313:
  m.FSM_TAKE(16);
  c1 = m.FSM_CHAR();
  if (c1 == 't') goto S338;
  if ('a' <= c1 && c1 <= 'z') goto S123;
  if (c1 == '_') goto S123;
  if (c1 == 'T') goto S338;
  if ('A' <= c1 && c1 <= 'Z') goto S123;
  if ('0' <= c1 && c1 <= '9') goto S123;
  if (c1 == '$') goto S123;
  return m.FSM_HALT(c1);

S322:
  m.FSM_TAKE(16);
  c1 = m.FSM_CHAR();
  if (c1 == 'q') goto S345;
  if ('a' <= c1 && c1 <= 'z') goto S123;
  if (c1 == '_') goto S123;
  if (c1 == 'Q') goto S345;
  if ('A' <= c1 && c1 <= 'Z') goto S123;
  if ('0' <= c1 && c1 <= '9') goto S123;
  if (c1 == '$') goto S123;
  return m.FSM_HALT(c1);

S331:
  m.FSM_TAKE(14);
  c1 = m.FSM_CHAR();
  if ('a' <= c1 && c1 <= 'z') goto S123;
  if (c1 == '_') goto S123;
  if ('A' <= c1 && c1 <= 'Z') goto S123;
  if ('0' <= c1 && c1 <= '9') goto S123;
  if (c1 == '$') goto S123;
  return m.FSM_HALT(c1);

S338:
  m.FSM_TAKE(11);
  c1 = m.FSM_CHAR();
  if ('a' <= c1 && c1 <= 'z') goto S123;
  if (c1 == '_') goto S123;
  if ('A' <= c1 && c1 <= 'Z') goto S123;
  if ('0' <= c1 && c1 <= '9') goto S123;
  if (c1 == '$') goto S123;
  return m.FSM_HALT(c1);

S345:
  m.FSM_TAKE(12);
  c1 = m.FSM_CHAR();
  if ('a' <= c1 && c1 <= 'z') goto S123;
  if (c1 == '_') goto S123;
  if ('A' <= c1 && c1 <= 'Z') goto S123;
  if ('0' <= c1 && c1 <= '9') goto S123;
  if (c1 == '$') goto S123;
  return m.FSM_HALT(c1);
}

#include <reflex/matcher.h>

#if defined(OS_WIN)
#pragma warning(disable:4101 4102)
#elif defined(__GNUC__)
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-label"
#elif defined(__clang__)
#pragma clang diagnostic ignored "-Wunused-variable"
#pragma clang diagnostic ignored "-Wunused-label"
#endif

void reflex_code_COMMENT(reflex::Matcher& m)
{
  int c0 = 0, c1 = 0;
  m.FSM_INIT(c1);

S0:
  m.FSM_FIND();
  c1 = m.FSM_CHAR();
  if (c1 == '\r') goto S9;
  if (c1 == '\n') goto S3;
  if (0 <= c1) goto S5;
  return m.FSM_HALT(c1);

S3:
  m.FSM_TAKE(1);
  return m.FSM_HALT();

S5:
  m.FSM_TAKE(2);
  c1 = m.FSM_CHAR();
  if ('\v' <= c1) goto S5;
  if ('\n' <= c1) return m.FSM_HALT(c1);
  if (0 <= c1 && c1 <= '\t') goto S5;
  return m.FSM_HALT(c1);

S9:
  m.FSM_TAKE(2);
  c1 = m.FSM_CHAR();
  if (c1 == '\n') goto S3;
  if (0 <= c1) goto S5;
  return m.FSM_HALT(c1);
}

