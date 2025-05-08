---
title: Rust编程语言
date: 2025-05-08 08:20:32
categories: 安全学习笔记
tags: [Rust]
---

# Rust编程语言

本地文档： `rustup doc`

更新：`rustup update`

## 编译运行

### Rust安装

https://rustwiki.org/zh-CN/book/ch01-01-installation.html

### 创建项目

``` shell
$ mkdir ~/projects
$ cd ~/projects
$ mkdir hello_world
$ cd hello_world

```

#### Helloworld

``` rust
fn main() {
    println!("Hello, world!");
}
```

`println!` 调用 Rust 宏。如果改为调用函数，则应该将其输入为 `println`（不含 `!`）。我们将在第 19 章中更详细地讨论 Rust 宏。现在只需要知道，当看到一个 `!`，则意味着调用的是宏而不是普通的函数。

#### 编译

``` shell
rustc main.rs
```

### Hello Cargo

``` shell
$ cargo new hello_cargo
$ cd hello_cargo
```

 Cargo 生成了两个文件和一个目录：一个 `Cargo.toml` 文件，一个 *src* 目录，以及位于 *src* 目录中的 *main.rs* 文件。

它也在 *hello_cargo* 目录初始化了一个 Git 仓库，并带有一个 *.gitignore* 文件。如果在现有的 Git 仓库中运行 `cargo new`，则不会生成 Git 文件；

 [*TOML*](https://toml.io/) (*Tom's Obvious, Minimal Language*) 格式，这是 Cargo 配置文件的格式。

`[dependencies]` 是一个表块的开头，你可以在其中列出你的项目所依赖的任何包。在 Rust 中，代码包被称为 *crate*。

#### 构建并运行 Cargo 项目

``` shell
$ cargo build
```

##### 运行

``` shell
$ ./target/debug/hello_cargo # 或者在 Windows 下为 .\target\debug\hello_cargo.exe
Hello, world!
```

或者

``` shell
cargo run
```

##### 检查语法

``` shell
cargo check
```

## 编写猜数字

先用cargo创建项目，然后编写代码

``` rust
use std::io;

fn main() {
    println!("Guess the number!");

    println!("Please input your guess.");

    let mut guess = String::new();

    io::stdin()
        .read_line(&mut guess)
        .expect("Failed to read line");

    println!("You guessed: {}", guess);
}
```

为了获取用户输入并打印结果作为输出，我们需要引入 `io` 输入/输出库到当前作用域。`io` 库来自于标准库，标准库也被称为 `std`：

``` rust
use std::io;
```

### 使用变量存储值

``` rust
let mut guess = String::new();

let apples = 5; // 不可变
let mut bananas = 5; // 可变
```

在 Rust 中，变量默认是不可变的。我们将会在第 3 章的 [“变量与可变性”](https://rustwiki.org/zh-CN/book/ch03-01-variables-and-mutability.html#变量和可变性)章节详细讨论这个概念。想要让变量可变，可以在变量名前添加 `mut`（mutability，可变性）：

### 接收用户输入

`stdin` 函数返回一个 [`std::io::Stdin`](https://rustwiki.org/zh-CN/std/io/struct.Stdin.html) 的实例，这是一个类型，代表终端标准输入的句柄。

接下来，`.read_line(&mut guess)` 这一行调用了 [`read_line`](https://rustwiki.org/zh-CN/std/io/struct.Stdin.html#method.read_line) 方法，来从标准输入句柄中获取用户输入。我们还将 `&mut guess` 作为参数传递给 `read_line()`

`&` 表示这个参数是一个**引用**（*reference*），这为你提供了一种方法，让代码的多个部分可以访问同一处数据，而无需在内存中多次拷贝。

现在，我们只需知道就像变量一样，引用默认是不可变的。因此，需要写成 `&mut guess` 来使其可变，而不是 `&guess`。

之前提到了 `read_line` 将用户输入存储到我们传递给它的字符串中，但它也返回一个值——在这个例子中是 [`io::Result`](https://rustwiki.org/zh-CN/std/io/type.Result.html)。

`Result` 类型是 [*枚举*（*enumerations*）](https://rustwiki.org/zh-CN/book/ch06-00-enums.html)，通常也写作 *enum*。枚举类型持有固定集合的值，这些值被称为枚举的**成员**（*variant*）。

`Result` 的成员是 `Ok` 和 `Err`，`Ok` 成员表示操作成功，且 `Ok` 内部包含成功生成的值。`Err` 成员则意味着操作失败，并且包含失败的前因后果。

`io::Result` 的实例拥有 [`expect` 方法](https://rustwiki.org/zh-CN/std/result/enum.Result.html#method.expect)。

* 如果 `io::Result` 实例的值是 `Err`，`expect` 会导致程序崩溃，并显示传递给 `expect` 的参数。
* 如果 `io::Result` 实例的值是 `Ok`，`expect` 会获取 `Ok` 中的值并原样返回，以便你可以使用它。在本例中，这个值是用户输入的字节数。

如果不调用 `expect`，程序也能编译，但会出现警告提示

### println 

``` rust
fn main() {
    let x = 5;
    let y = 10;

    println!("x = {} and y = {}", x, y);
}
```

里面的 `{}` 是预留在特定位置的占位符：把 `{}` 想象成小蟹钳，可以夹住合适的值。使用 `{}` 也可以打印多个值：第一对 `{}` 使用格式化字符串之后的第一个值，第二对则使用第二个值，依此类推。

### 生成秘密数字

接下来，需要生成一个秘密数字，好让用户来猜。秘密数字应该每次都不同，这样重复玩才不会乏味；

#### crate

*crate* 是一个 Rust 代码包。我们正在构建的项目是一个 **二进制 crate**，它生成一个可执行文件。 `rand` crate 是一个 **库 crate**，库 crate 可以包含任意能被其他程序使用的代码，但是不能独自执行。

在 toml文件的dependency下加入

``` toml
rand = "0.8.3"
```

当你**确实**需要升级 crate 时，Cargo 提供了这样一个命令 `update`，它会忽略 *Cargo.lock* 文件，并计算出所有符合 *Cargo.toml* 声明的最新版本。

#### 生成一个随机数

``` rust
use std::io;
use rand::Rng;

fn main() {
    println!("Guess the number!");
    let secret_number = rand::thread_rng().gen_range(1..101);
    println!("The secret number is: {}", secret_number);
    println!("Please input your guess.");
    let mut guess = String::new();
    io::stdin()
        .read_line(&mut guess)
        .expect("Failed to read line");
    println!("You guessed: {}", guess);
}
```

首先，我们新增了一行 `use rand::Rng`。`Rng` 是一个 trait，它定义了随机数生成器应实现的方法，想使用这些方法的话，此 trait 必须在作用域中。

我们调用 `rand::thread_rng` 函数来为我们提供将要使用的特定随机数生成器：它位于当前执行线程的本地环境中，并从操作系统获取 seed。然后我们调用随机数生成器的 `gen_range` 方法。该方法由我们刚才使用 `use rand::Rng` 语句引入的 `Rng` trait 定义。

> Cargo 有一个很棒的功能是：运行 `cargo doc --open` 命令来构建所有本地依赖提供的文档，并在浏览器中打开。

### 比较

``` rust
use std::cmp::Ordering;
match guess.cmp(&secret_number) {
    Ordering::Less => println!("Too small!"),
    Ordering::Greater => println!("Too big!"),
    Ordering::Equal => println!("You win!"),
}
```

引入了一个叫做 `std::cmp::Ordering` 的类型到作用域中。`Ordering` 也是一个枚举，不过它的成员是 `Less`、`Greater` 和 `Equal`。这是比较两个值时可能出现的三种结果。

这里是把 `guess` 与 `secret_number` 做比较。 然后它会返回一个刚才通过 `use` 引入作用域的 `Ordering` 枚举的成员。使用一个 [`match`](https://rustwiki.org/zh-CN/book/ch06-02-match.html) 表达式，根据对 `guess` 和 `secret_number` 调用 `cmp` 返回的 `Ordering` 成员来决定接下来做什么。

一个 `match` 表达式由**分支（arm）** 构成。一个分支包含一个用于匹配的**模式**（*pattern*），给到 `match` 的值与分支模式相匹配时，应该执行对应分支的代码。Rust 获取提供给 `match` 的值并逐个检查每个分支的模式。

这里编译错误，错误的核心表明这里有**不匹配的类型**（*mismatched type*）。Rust 有一个静态强类型系统，同时也有类型推断。当我们写出 `let guess = String::new()` 时，Rust 推断出 `guess` 应该是 `String` 类型，并不需要我们写出类型。另一方面，`secret_number` 是数字类型。

``` rust
let guess: u32 = guess.trim().parse().expect("Please type a number!");
```

创建了一个叫做 `guess` 的变量。不过等等，不是已经有了一个叫做 `guess` 的变量了吗？确实如此，不过 Rust 允许用一个新值来**遮蔽** （*shadow*） `guess` 之前的值。这允许我们复用 `guess` 变量的名字，而不是被迫创建两个不同变量，诸如 `guess_str` 和 `guess` 之类。

[字符串的 `parse` 方法](https://rustwiki.org/zh-CN/std/primitive.str.html#method.parse) 将字符串解析成数字。因为这个方法可以解析多种数字类型，因此需要告诉 Rust 具体的数字类型，这里通过 `let guess: u32` 指定。

### 加入循环

``` rust
loop {
    let mut guess = String::new();
    io::stdin()
        .read_line(&mut guess)
        .expect("Fail to read");

    let guess: u32 = match guess.trim().parse() {
        Ok(num) => num,
        Err(_) => continue,
    };
    println!("You guessed: {}", guess);


    match guess.cmp(&secret_number) {
        Ordering::Less => println!("Too small!"),
        Ordering::Greater => println!("Too big!"),
        Ordering::Equal => {
            println!("You win!");
            break;
        }        
    }
}
```

## 通用编程概念

### 变量和可变性

如[“使用变量存储值”](https://rustwiki.org/zh-CN/book/ch02-00-guessing-game-tutorial.html#使用变量存储值)章节所述，默认情况下变量是**不可变的**（*immutable*）。这是 Rust 众多精妙之处的其中一个，这些特性让你充分利用 Rust 提供的安全性和简单并发性的方式来编写代码。

#### 常量

与不可变变量类似，**常量**（*constant*）是绑定到一个常量名且不允许更改的值，但是常量和变量之间存在一些差异。

首先，常量不允许使用 `mut`。常量不仅仅默认不可变，而且自始至终不可变。

``` rust
const THREE_HOURS_IN_SECONDS: u32 = 60 * 60 * 3;
```

### 遮蔽

正如你在第 2 章[“猜数字游戏”](https://rustwiki.org/zh-CN/book/ch02-00-guessing-game-tutorial.html#比较猜测的数字和秘密数字)章节中所看到的，你可以声明和前面变量具有相同名称的新变量。Rustacean 说这个是第一个变量被第二个变量**遮蔽**（*shadow*）

```rust
let spaces = "   ";
let spaces = spaces.len();
```

第一个 `spaces` 变量是一个字符串类型，第二个 `spaces` 变量是一个数字类型。所以变量遮蔽可以让我们不必给出不同的名称

而，如果我们对此尝试使用 `mut`，如下所示，我们将得到一个编译期错误：

```rust
let mut spaces = "   ";
spaces = spaces.len();
```

### 数据类型

**标量**（*scalar*）类型表示单个值。Rust 有 4 个基本的标量类型：整型、浮点型、布尔型和字符。

#### Rust 中的整型

| 长度   | 有符号类型 | 无符号类型 |
| ------ | ---------- | ---------- |
| 8 位   | `i8`       | `u8`       |
| 16 位  | `i16`      | `u16`      |
| 32 位  | `i32`      | `u32`      |
| 64 位  | `i64`      | `u64`      |
| 128 位 | `i128`     | `u128`     |
| arch   | `isize`    | `usize`    |

#### 整型字面量

| 数字字面量         | 示例          |
| ------------------ | ------------- |
| 十进制             | `98_222`      |
| 十六进制           | `0xff`        |
| 八进制             | `0o77`        |
| 二进制             | `0b1111_0000` |
| 字节 (仅限于 `u8`) | `b'A'`        |

#### 浮点类型

**浮点数**（*floating-point number*）是带有小数点的数字，在 Rust 中浮点类型（简称浮点型）数字也有两种基本类型。Rust 的浮点型是 `f32` 和 `f64`，它们的大小分别为 32 位和 64 位。默认浮点类型是 `f64`，因为在现代的 CPU 中它的速度与 `f32` 的几乎相同，但精度更高。

#### 数字运算

Rust 的所有数字类型都支持基本数学运算：加法、减法、乘法、除法和取模运算。整数除法会向下取整。下面代码演示了各使用一条 `let` 语句来说明相应数字运算的用法：

```rust
fn main() {
    // addition
    let sum = 5 + 10;

    // subtraction
    let difference = 95.5 - 4.3;

    // multiplication
    let product = 4 * 30;

    // division
    let quotient = 56.7 / 32.2;
    let floored = 2 / 3; // Results in 0

    // remainder
    let remainder = 43 % 5;
}
```

这些语句中的每个表达式都使用了数学运算符

#### 布尔类型

和大多数编程语言一样，Rust 中的布尔类型也有两个可能的值：`true` 和 `false`。布尔值的大小为 1 个字节。Rust 中的布尔类型使用 `bool` 声明。

#### 字符类型

Rust 的 `char`（字符）类型是该语言最基本的字母类型

### 复合类型

**复合类型**（*compound type*）可以将多个值组合成一个类型。Rust 有两种基本的复合类型：元组（tuple）和数组（array）。

#### 元组类型

``` rust
fn main() {
    let tup: (i32, f64, u8) = (500, 6.4, 1);
}

fn main() {
    let tup = (500, 6.4, 1);

    let (x, y, z) = tup;

    println!("The value of y is: {}", y);
}
```

除了通过模式匹配进行解构外，我们还可以使用一个句点（`.`）连上要访问的值的索引来直接访问元组元素。例如：

文件名：src/main.rs

```rust
fn main() {
    let x: (i32, f64, u8) = (500, 6.4, 1);

    let five_hundred = x.0;

    let six_point_four = x.1;

    let one = x.2;
}
```

#### 数组类型

将多个值组合在一起的另一种方式就是使用**数组**（*array*）。与元组不同，数组的每个元素必须具有相同的类型。与某些其他语言中的数组不同，Rust 中的数组具有固定长度。

我们在方括号内以逗号分隔的列表形式将值写到数组中：

```rust
fn main() {
    let a = [1, 2, 3, 4, 5];
}
```

使用方括号编写数组的类型，其中包含每个元素的类型、分号，然后是数组中的元素数，如下所示：

```rust
let a: [i32; 5] = [1, 2, 3, 4, 5];
```

### 函数

函数在 Rust 代码中很普遍。你已经见过语言中最重要的函数之一：`main` 函数，它是很多程序的入口点。你也见过 `fn` 关键字，它用来声明新函数。

```rust
fn main() {
    println!("Hello, world!");

    another_function();
}

fn another_function(x: i32) {
    println!("The value of x is: {}", x);
}
```

#### 语句和表达式

函数体由一系列语句组成，也可选择以表达式结尾。

**语句**（*statement*）是执行一些操作但不返回值的指令。表达式（*expression*）计算并产生一个值。让我们看一些例子：

实际上，我们已经使用过语句和表达式。使用 `let` 关键字创建变量并绑定一个值是一个语句。在示例 3-1 中，`let y = 6;` 是一个语句。

表达式会计算出一个值，并且你接下来要用 Rust 编写的大部分代码都由表达式组成。考虑一个数学运算，比如 `5 + 6`，这是一个表达式并计算出值 `11`。表达式可以是语句的一部分：在示例 3-1 中，语句 `let y = 6;` 中的 `6` 是一个表达式，它计算出的值是 `6`。函数调用是一个表达式。宏调用是一个表达式。我们用来创建新作用域的大括号（代码块） `{}` 也是一个表达式，例如：

文件名: src/main.rs

```rust
fn main() {
    let y = {
        let x = 3;
        x + 1
    };

    println!("The value of y is: {}", y);
}
```

意，`x + 1` 行的末尾**没有分号**

#### 带有返回值的函数

函数可以向调用它的代码返回值。我们并不对返回值命名，但要在箭头（`->`）后声明它的类型。在 Rust 中，函数的返回值等同于函数体最后一个表达式的值。使用 `return` 关键字和指定值，可以从函数中提前返回；但大部分函数隐式返回最后一个表达式。这是一个有返回值函数的例子：

```rust
fn five() -> i32 {
    5
}

fn main() {
    let x = five();

    println!("The value of x is: {}", x);
}
```

### 注释

所有的开发者都在努力使他们的代码容易理解，但有时需要额外的解释。在这种情况下，开发者在他们的源码中留下**注释**，编译器将会忽略掉这些内容，但阅读源码的人可能会发现有用。

这是一条简单的注释：

```rust
// Hello, world.
```

### 控制流

#### if

```rust
fn main() {
    let number = 6;

    if number % 4 == 0 {
        println!("number is divisible by 4");
    } else if number % 3 == 0 {
        println!("number is divisible by 3");
    } else if number % 2 == 0 {
        println!("number is divisible by 2");
    } else {
        println!("number is not divisible by 4, 3, or 2");
    }
}
```

#### 在 let 语句中使用 if

因为 `if` 是一个表达式，我们可以在 `let` 语句的右侧使用它来将结果赋值给一个变量，例如在示例 3-2 中：

```rust
fn main() {
    let condition = true;
    let number = if condition { 5 } else { 6 };

    println!("The value of number is: {}", number);
}
```

#### 从循环返回

`loop` 的一个用例是重试可能会失败的操作，比如检查线程是否完成了任务。然而你可能会需要将操作的结果从循环中传递给其它的代码。为此，你可以在用于停止循环的 `break` 表达式添加你想要返回的值；该值将从循环中返回，以便您可以使用它，如下所示：

```rust
fn main() {
    let mut counter = 0;

    let result = loop {
        counter += 1;

        if counter == 10 {
            break counter * 2;
        }
    };

    println!("The result is {}", result);
}
```

#### while

```rust
fn main() {
    let mut number = 3;

    while number != 0 {
        println!("{}!", number);

        number -= 1;
    }

    println!("LIFTOFF!!!");
}
```

#### for

``` rust
fn main() {
    let a = [10, 20, 30, 40, 50];

    for element in a {
        println!("the value is: {}", element);
    }
}

fn main() {
    for number in (1..4).rev() {
        println!("{}!", number);
    }
    println!("LIFTOFF!!!");
}
```

### Exercise 温度转换FC

``` rust
// temperature converter
let mut temperature = String::new();
io::stdin().read_line(&mut temperature).expect("Fail!");
let temperature = temperature.trim();
let (value, unit) = temperature[..temperature.len()-1].parse::<f64>()
    .map(|v| (v, &temperature[temperature.len()-1..]))
    .expect("Invalid Input");

match unit {
    "C" | "c" => println!("{}C = {}F", value, value*1.8 + 32.0),
    "F" | "f" => println!("{}F = {}C", value, (value - 32.0)/1.8),
    _ => println!("Unknown"),
}
```



## 所有权

### 所有权规则

首先，让我们看一下所有权的规则。当我们通过举例说明时，请谨记这些规则：

- Rust 中的每一个值都有一个被称为其 **所有者**（*owner*）的变量。
- 值在任一时刻有且只有一个所有者。
- 当所有者（变量）离开作用域，这个值将被丢弃。

变量 `s` 绑定到了一个字符串字面量，这个字符串值是硬编码进程序代码中的。该变量从声明的那一刻开始直到当前 **作用域** 结束时都是有效的。示例 4-1 的注释标明了变量 `s` 的有效范围。

```rust
    {                      // s 在这里无效, 它尚未声明
        let s = "hello";   // 从此处起，s 开始有效

        // 使用 s
    }                      // 此作用域已结束，s 不再有效
```

示例 4-1：一个变量和其有效的作用域

换句话说，这里有两个重要的时间点：

- 当 `s` **进入作用域** 时，它就是有效的。
- 这一直持续到它 **离开作用域** 为止。

#### String

为此，Rust 有第二个字符串类型，`String`。这个类型管理被分配到堆上的数据，所以能够存储在编译时未知大小的文本。可以使用 `from` 函数基于字符串字面量来创建 `String`，如下：

```rust
let s = String::from("hello");
```

双冒号（`::`）运算符允许我们将特定的 `from` 函数置于 `String` 类型的命名空间（namespace）下，而不需要使用类似 `string_from` 这样的名字。我们将在第 5 章的[“方法语法”（“Method Syntax”）](https://rustwiki.org/zh-CN/book/ch05-03-method-syntax.html#方法语法)以及第 7 章的[“路径用于引用模块树中的项”](https://rustwiki.org/zh-CN/book/ch07-03-paths-for-referring-to-an-item-in-the-module-tree.html)中讨论模块的命名空间时，再详细说明此语法。

**可以** 修改此类字符串 ：

```rust
    let mut s = String::from("hello");

    s.push_str(", world!"); // push_str() 在字符串后追加字面值

    println!("{}", s); // 将打印 `hello, world!`
```

#### 变量与数据交互的方式（一）：移动

现在看看这个 `String` 拷贝版本：

```rust
    let s1 = String::from("hello");
    let s2 = s1;
```

这看起来与上面的代码非常类似，所以我们可能会假设他们的运行方式也是类似的：也就是说，第二行可能会生成一个 `s1` 的拷贝并绑定到 `s2` 上。不过，事实上并不完全是这样。

为了确保内存安全，这种场景下 Rust 的处理有另一个细节值得注意。在 `let s2 = s1` 之后，Rust 认为 `s1` 不再有效，因此 Rust 不需要在 `s1` 离开作用域后清理任何东西。看看在 `s2` 被创建之后尝试使用 `s1` 会发生什么；这段代码不能运行：

```rust
    let s1 = String::from("hello");
    let s2 = s1;

    println!("{}, world!", s1);
```

你会得到一个类似如下的错误，因为 Rust 禁止你使用无效的引用。

如果你在其他语言中听说过术语 **浅拷贝**（*shallow copy*）和 **深拷贝**（*deep copy*），那么拷贝指针、长度和容量而不拷贝数据可能听起来像浅拷贝。不过因为 Rust 同时使第一个变量无效了，这个操作被称为 **移动**（*move*），而不是浅拷贝。

#### 变量与数据交互的方式（二）：克隆

如果我们 **确实** 需要深度复制 `String` 中堆上的数据，而不仅仅是栈上的数据，可以使用一个叫做 `clone` 的通用函数。第 5 章会讨论方法语法，不过因为方法在很多语言中是一个常见功能，所以之前你可能已经见过了。

这是一个实际使用 `clone` 方法的例子：

```rust
    let s1 = String::from("hello");
    let s2 = s1.clone();

    println!("s1 = {}, s2 = {}", s1, s2);
```

这段代码能正常运行，并且明确产生图 4-3 中行为，这里堆上的数据 **确实** 被复制了。

#### 只在栈上的数据：拷贝

Rust 有一个叫做 `Copy` trait 的特殊标注，可以用在类似整型这样的存储在栈上的类型上（第 10 章详细讲解 trait）。如果一个类型实现了 `Copy` trait，那么一个旧的变量在将其赋值给其他变量后仍然可用。

如下是一些 `Copy` 的类型：

- 所有整数类型，比如 `u32`。
- 布尔类型，`bool`，它的值是 `true` 和 `false`。
- 所有浮点数类型，比如 `f64`。
- 字符类型，`char`。
- 元组，当且仅当其包含的类型也都实现 `Copy` 的时候。比如，`(i32, i32)` 实现了 `Copy`，但 `(i32, String)` 就没有。

#### 所有权与函数

将值传递给函数在语义上与给变量赋值相似。向函数传递值可能会移动或者复制，就像赋值语句一样。示例 4-3 使用注释展示变量何时进入和离开作用域：

```rust
fn main() {
  let s = String::from("hello");  // s 进入作用域

  takes_ownership(s);             // s 的值移动到函数里 ...
                                  // ... 所以到这里不再有效

  let x = 5;                      // x 进入作用域

  makes_copy(x);                  // x 应该移动函数里，
                                  // 但 i32 是 Copy 的，所以在后面可继续使用 x

} // 这里, x 先移出了作用域，然后是 s。但因为 s 的值已被移走，
  // 所以不会有特殊操作

fn takes_ownership(some_string: String) { // some_string 进入作用域
  println!("{}", some_string);
} // 这里，some_string 移出作用域并调用 `drop` 方法。占用的内存被释放

fn makes_copy(some_integer: i32) { // some_integer 进入作用域
  println!("{}", some_integer);
} // 这里，some_integer 移出作用域。不会有特殊操作
```

#### 返回值与作用域

返回值也可以转移所有权。示例 4-4 与示例 4-3 一样带有类似的注释。

文件名: src/main.rs

```rust
fn main() {
  let s1 = gives_ownership();         // gives_ownership 将返回值
                                      // 移给 s1

  let s2 = String::from("hello");     // s2 进入作用域

  let s3 = takes_and_gives_back(s2);  // s2 被移动到
                                      // takes_and_gives_back 中,
                                      // 它也将返回值移给 s3
} // 这里, s3 移出作用域并被丢弃。s2 也移出作用域，但已被移走，
  // 所以什么也不会发生。s1 移出作用域并被丢弃

fn gives_ownership() -> String {           // gives_ownership 将返回值移动给
                                           // 调用它的函数

  let some_string = String::from("yours"); // some_string 进入作用域

  some_string                              // 返回 some_string 并移出给调用的函数
}

// takes_and_gives_back 将传入字符串并返回该值
fn takes_and_gives_back(a_string: String) -> String { // a_string 进入作用域

  a_string  // 返回 a_string 并移出给调用的函数
}
```



# 计划

## 🗓️ 第1周：打好基础（Rust 核心语法 + 所有权系统）

### 🎯 目标

- 熟悉语法、变量、函数、控制流
- 理解 Rust 的「所有权」「借用」「生命周期」

### 🧭 每日任务

| 星期 | 内容                                                         |
| ---- | ------------------------------------------------------------ |
| 周一 | 阅读《Rust Book》第1～3章：安装、变量、数据类型、函数、控制流 |
| 周二 | 阅读第4章：**所有权（Ownership）** 并动手写例子              |
| 周三 | 阅读第5章：结构体；第6章：枚举与 `match`                     |
| 周四 | 阅读第7章：模块系统，练习封装模块与调用                      |
| 周五 | 阅读第8章：集合（`Vec`、`HashMap`）                          |
| 周六 | 阅读第9章：错误处理（`Result`、`panic!`、`unwrap`）          |
| 周日 | 复习 + 完成一个简单 CLI 程序（如：记账本/日记本/词频统计）   |



------

## 🗓️ 第2周：深入掌握（所有权 + 模式匹配 + 错误处理 + Crates）

### 🎯 目标

- 熟练掌握所有权模型
- 学会使用常用库和工具

### 🧭 每日任务

| 星期 | 内容                                                   |
| ---- | ------------------------------------------------------ |
| 周一 | 阅读第10章：泛型；第11章：测试                         |
| 周二 | 阅读第13～14章：迭代器与闭包，模式匹配复习             |
| 周三 | 学习 `serde` 和 `serde_json`，写一个 JSON 配置读取程序 |
| 周四 | 学习 `anyhow` 和 `thiserror`，重构错误处理逻辑         |
| 周五 | 学习 `reqwest` + `tokio`，写一个简单异步 HTTP 请求工具 |
| 周六 | 用 `clap` 做一个 CLI 工具，如：天气查询器              |
| 周日 | 总结回顾：写一篇小笔记 + 整合本周代码为工具包          |



------

## 🗓️ 第3周：项目驱动（小型项目开发 + 异步编程）

### 🎯 目标

- 能够独立写出实用工具
- 掌握异步和并发

### 🧭 每日任务

| 星期 | 内容                                                       |
| ---- | ---------------------------------------------------------- |
| 周一 | 阅读第15章：智能指针（`Box`、`Rc`、`RefCell`）             |
| 周二 | 学习 `tokio`，理解 `async` / `await` 基础                  |
| 周三 | 使用 `tokio` 实现一个异步爬虫（抓取网页标题）              |
| 周四 | 使用 `rayon` 做一个并行文本处理工具                        |
| 周五 | 了解 Actix-web 或 Axum，选一个框架跑 Hello World API       |
| 周六 | 实现 RESTful API（如 Todo List），支持增删查改 + JSON 返回 |
| 周日 | 写一篇开发记录笔记，整理项目代码（发到 GitHub）            |



------

## 🗓️ 第4周：进阶实战 + 持续优化

### 🎯 目标

- 能力提升：模块化、文档化、测试
- 深入理解 Rust 架构思维

### 🧭 每日任务

| 星期 | 内容                                                   |
| ---- | ------------------------------------------------------ |
| 周一 | 阅读 Rust Book 第17章 Trait 对象，理解多态与抽象       |
| 周二 | 把之前 CLI 或 API 项目整理成 crate，加入文档 + 测试    |
| 周三 | 学习 Clippy、Rustfmt，掌握代码风格检查与格式化         |
| 周四 | 阅读一个开源 Rust 项目（如 ripgrep），分析模块设计     |
| 周五 | 尝试用 `unsafe` 写一个小例子（如裸指针操作，了解即可） |
| 周六 | 写一篇总结博客，思考 Rust 和其他语言的最大区别与优势   |
| 周日 | 自选项目自由创作，尝试发布 crate 或继续迭代现有作品    |
