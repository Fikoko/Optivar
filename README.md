
# Ɵ-Programming-Language
Ɵ (Optivar) is an extremely strict and extremely declarative programming language designed for prioritizing simplicity and performance through defining variables and using a comprehensive library of pre-defined, highly optimized functions. 

## Description
This programming language is created in order to leave the manual function creation (operators such as additions, substractions, loops, conditionals, and other control structures) to researchers so that they can deal with the manual creation of the optimized functions via a minimalist turing complete instruction list (command/commands that have the same feature/features as the abstractions of "MOV", "ADD", "SUB", "CMP", "JMP") depending on "hardware infrastructure". So the other practitioners of this programming language (non-researchers) do not need anything else than defining inputs/outputs as variables.

## Getting Started

![Community](https://img.shields.io/badge/community-join-blue.svg) ![Contribute](https://img.shields.io/badge/contribute-join-yellow.svg)

Copyright © 2025 Fikret Güney Ersezer. All rights reserved.

See the end of this file for further copyright and license information.

This repository only includes simple parser and simple debugger.

### Dependencies

* Regardless of future releases of libraries, the logic behind parsing and debugging will not change. Any dependency issue is related with the library conditions.

### Installing

* How to download the parser and debugger:
  
```
git clone https://github.com/Fikoko/optivar.git
cd optivar
./configure
make
make test
sudo make install
```
  

### Philosophy and Execution of code

* Philosophy of Code

| Feature                                 | Description                                                                    |
| --------------------------------------- | ------------------------------------------------------------------------------ |
| **Strictly declarative**                | No control flow, no conditionals, no loops — just a sequence of function calls |
| **Function-only**                       | Every operation (even `+`, `return`, I/O etc...) is a function                 |
| **Controlled rebindable variables**     | Variables can be reassigned if previous values are no longer needed            |
| **Compiler-driven optimization**        | Variable reuse, memory reuse, SSA transformation, etc.                         |
| **Disposable values**                   | Through functions like `run()`, `discard()`                                    |
| **Library-based execution**             | Core behaviors (math, I/O, types etc...) come from external libraries          |
| **No types in syntax**                  | Types are inferred or handled within function contracts                        |
| **Natural language-inspired structure** | Heavy emphasis on readability, flow, and structured comments                   |

Whole programming language has the following rules: 

1)  let y1 = f( x1 , x2 , x3 , ... );
2)  -- comment 

* Exectution of Code

```
-- add_numbers.optivar: Read two undeclared numbers, add them, print the result, and return the sum

--libraries
let my_lib = include("lib.h", "C://user/libs/");

--variables
let a = read_undec_num();              -- Read the first undeclared number
let b = read_undec_num();              -- Read the second undeclared number
let b = add_undec_num(a, b);           -- Add numbers, reuse b for sum

--output
let a = print(string("Sum is: "));      -- Print label, reuse a
let a = print(b);                       -- Print sum
let a = print(string("\n"));            -- Print newline
let a = return(b);                      -- Return sum as exit code
```

## Help

Any advise for common problems or issues.
```
command to run if program contains helper info
```

## Authors
Fikret Güney Ersezer

## Version History

* 0.1
    * Initial Release

## License

This project is licensed under the [GPLv3] License - see the LICENSE.md file for details

## Acknowledgments

Inspiration, code snippets, etc.
* [awesome-readme](https://github.com/matiassingers/awesome-readme)
* [PurpleBooth](https://gist.github.com/PurpleBooth/109311bb0361f32d87a2)
* [dbader](https://github.com/dbader/readme-template)
* [zenorocha](https://gist.github.com/zenorocha/4526327)
* [fvcproductions](https://gist.github.com/fvcproductions/1bfc2d4aecb01a834b46)
