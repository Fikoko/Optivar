
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

"make functional translation f of inputs (variables/arguments) x1, x2 , x3 ... as equivalent of the output (variable/argument) y1"

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

1960s–1970s: APL and Forth explored minimalism and function-based programming, but not with Optivar’s declarative purity or hardware focus.

1970s–1980s: SQL and Prolog established declarative programming, but they were domain-specific and lacked hardware optimization.

1990s–2000s: LLVM IR and Haskell advanced optimization and declarative programming, but not with Optivar’s dual audience or extreme simplicity.

Modern Era: Dataflow languages like LabVIEW and domain-specific tools show continued interest in declarative models, but none match Optivar’s general-purpose, hardware-oriented design.


Optivar’s closest predecessors are likely LLVM IR (for its intermediate, optimizable nature) and SQL (for its declarative simplicity), but its combination of a declarative frontend, researcher-driven low-level functions, and extreme syntactic minimalism is a fresh approach.


| Feature                                 | Description                                                                    |
| --------------------------------------- | ------------------------------------------------------------------------------ |
| **Strictly declarative**                | No manual creation of anything — just function calls                           |
| **Function-only**                       | Every operation (arithmetic, variables, control flows, I/O etc...) is function |
| **Library-based execution**             | Everything come from external libraries                                        |
| **Natural language-inspired structure** | Heavy emphasis on readability, flow, and structured comments                   |



* Example of Code (HPC mode)

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

```
-- add_numbers.optivar: Read two undeclared numbers, add them and return the sum 
-- (assuming include.bin and lib.bin exists. Also for this case lib.bin has other functions below in single merged bin)


 my_lib = include("lib.bin", "C://user/libs/")    
 a = read_undec_num()                            
 b = read_undec_num()                          
 b = add_undec_num(a, b)                       
 a = return(b)                                  

```

## Authors
Fikret Güney Ersezer

## License

This project is licensed under the [GPLv3] License - see the LICENSE.md file for details
