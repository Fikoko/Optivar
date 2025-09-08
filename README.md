
# Ɵ-Programming-Language (Optivar)

Ɵ (Optivar) is a **Declarative Intermediate Language (DIL)** designed for **high-performance, modular, and hardware-aware computation**. It emphasizes **simplicity for practitioners** and **maximum flexibility for researchers** through a plugin-based binary ecosystem.

---

## Overview

Ɵ is a **tiny, stable core language** where every function is implemented as a separate, precompiled binary. Users download only the binaries they need, optimized for their **hardware infrastructure**.  

This design allows:

- Extremely **lightweight and fast execution**  
- **Scalable orchestration** via plugin like superoptimized .bin files  

Researchers can implement **low-level operations** (like arithmetic, control structures, loops, etc.) using a **minimalist Turing-complete instruction set**, while practitioners only need to define **inputs/outputs** as **arguments/variables** and orchestrate computations.

---

## Language Philosophy

- **Minimal core, maximum flexibility:** Only essential syntax is built-in; all heavy operations are optional binaries.  
- **Hardware-aware optimization:** Binaries are compiled for specific architectures for maximum performance.  
- **Clear separation of roles:** Researchers build optimized functions; practitioners orchestrate workflows.  
- **Extensible and modular:** Users can fetch new binaries from a marketplace depending on their computation needs.

---

## Syntax

Ɵ has only **two constructs**:

1. **Function call**
```
output = f(input1, input2, input3, ...)
```

2. **Function call** 
```
 -- comment 
```

For simplicity, it is translated to natural language as:

"make functional translation f of inputs (variables/arguments/statements) x1, x2 , x3 ... as equivalent of the output (variable/argument/statements) y1"

## Getting Started

[![Community](https://img.shields.io/badge/Community-Join-blue.svg)](https://github.com/Fikoko/Optivar/discussions) 

Copyright © 2025 Fikret Güney Ersezer. All rights reserved.

See the end of this file for further copyright and license information.

### Dependencies

* Regardless of future releases of libraries, the logic behind parsing and debugging will not change. Any dependency issue is related with the library conditions.

### How to build and run the Optivar IR executor

```bash
# Clone the repository
git clone https://github.com/Fikoko/optivar.git
cd optivar

# Compile the single source file
gcc -O3 -march=native -lz -o optivar optivar.c

# Run a script
./optivar path/to/your/script.optivar
```

### Historical Context and Novelty
The concept of a declarative, minimalist language for both high-level users and low-level optimizers has roots in earlier paradigms but hasn’t been combined in this way:

**Early Minimalism**
1960s–1970s: APL, Forth explored minimal syntax and function-based execution. But they still included built-in operations (arithmetic, stack ops).

**Declarative Paradigms**
1970s–1980s: SQL, Prolog established declarative styles where users described what, not how. But they were domain-specific (databases, logic) and lacked hardware focus.

**Optimization Frameworks**
1990s–2000s: LLVM IR, Haskell advanced compiler optimization and declarative purity. But LLVM defines a fixed instruction set; Haskell is a high-level language, not hardware-aware IR.

**Modern Era**
2000s-today: Dataflow, ML Graphs, LabVIEW, TensorFlow, ONNX emphasize dataflow graphs and modular ops. But they are domain-specific, and still ship with built-in operators.


| Feature                                 | Description                                                                    |
| --------------------------------------- | ------------------------------------------------------------------------------ |
| **Strictly declarative**                | No manual creation of anything — just function calls                           |
| **Function-only**                       | Every operation (arithmetic, variables, control flows, I/O etc...) is function |
| **Library-based execution**             | Everything come from external libraries                                        |
| **Natural language-inspired structure** | Heavy emphasis on readability, flow, and structured comments                   |



* Example of Code (HPC mode)

This mode is called as "HPC" referenced as (High Performance Computing) since every statement is 
inside single function as argument. This enables interpreter to call a single bin function (do.bin is an example at below) and give the necessary information about nested arguments inside to that bin. After that, there will be no interpreter overhead since every call will be handled as bin-to-bin calls which is native speed. (Important thing here is that
we assume bin-to-bin calls exists since they are not merged into single bin. We lazy/preload them here assuming they are multiple independent bins)

```
-- add_numbers.optivar: Read two undeclared numbers, add them and return the sum 
-- (assuming do.bin, include.bin and lib.bin exists. Also for this case "lib.bin" has other functions mentioned below in single merged bin)

main = do(

 my_lib = include("lib.bin", "C://user/libs/")  ,   
 a = read_undec_num()  ,                          
 b = read_undec_num()  ,                          
 b = add_undec_num(a, b)  ,                       
 a = return(b)                                   

)
```
* Example of Code (Dynamic mode)

This mode is called as "Dynamic" since every statement is splitted line by line approach.
This enables interpreter to call a each bin at run-time. While it adds some overhead at runtime since interpreter does the
execution, it enables user to dynamically change the script code at run-time. (Important thing here is that
we assume bin-to-bin calls exists since they are not merged into single bin. We lazy/preload them here assuming they are multiple independent bins)
```
-- add_numbers.optivar: Read two undeclared numbers, add them and return the sum 
-- (assuming include.bin and lib.bin exists. Also for this case lib.bin has other functions below in single merged bin)


 my_lib = include("lib.bin", "C://user/libs/")    
 a = read_undec_num()                            
 b = read_undec_num()                          
 b = add_undec_num(a, b)                       
 a = return(b)                                  

```
### Questions 

1) Why not just use Asm/C/C++ for static HPC tasks ?
   
**At nanosecond (or smaller) scales, execution speed dominates.** Assuming that all bins that will be used as functions are merged
into one single bin file, the only overhead of Optivar (for HPC case where all statements are arguments of a single function)
is first interpreter-to-bin call. Meaning it is a **startup speed overhead (one-time event).** Overall execution speed can be equal/faster
since all bins are planned to be written for hardware infrastructure's assembly programming language and then transformed into bin.
This allows language like Optivar (which is actually an interpreter) that can race with compilers in HPC tasks.

## Authors
Fikret Güney Ersezer

## License

This project is licensed under the [GPLv3] License - see the LICENSE.md file for details
