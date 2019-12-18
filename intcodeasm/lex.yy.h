// lex.yy.h generated by reflex 1.5.4 from intcodeasm.l

#ifndef REFLEX_HEADER_H
#define REFLEX_HEADER_H
#define IN_HEADER 1

////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  OPTIONS USED                                                              //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#define REFLEX_OPTION_bison_bridge        true
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
  virtual int lex(YYSTYPE& yylval);
};

////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  BISON BRIDGE                                                              //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

typedef Lexer yyscanner_t;
typedef void *yyscan_t;

#ifndef YY_EXTERN_C
#define YY_EXTERN_C
#endif

YY_EXTERN_C int yylex(YYSTYPE*, yyscan_t);
YY_EXTERN_C void yylex_init(yyscan_t*);
YY_EXTERN_C void yylex_destroy(yyscan_t);

#endif
