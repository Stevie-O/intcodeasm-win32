@echo off
pushd intcodeasm
..\..\win_flex_bison\win_bison -d intcodeasm.y %*
popd

