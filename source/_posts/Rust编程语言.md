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

for (i, &item) in bytes.iter().enumerate() {
    if item == b' ' {
        return i;
    }
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

#### 遍历

``` rust
for c in s.chars() {
   match c ...
}
for (i,c) in s.chars().enumerate() {
    ...
}
```

字符转换

``` rust
let ascii = c as u8; 
let ch = ascii as char;
```

#### 和int转换, rev, eq

``` rust
impl Solution {
    pub fn is_palindrome(x: i32) -> bool {
        x.to_string().chars().rev().eq(x.to_string().chars())
    }
}
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

### 引用与借用

有这样一个问题：我们必须将 `String` 返回给调用函数，以便在调用 `calculate_length` 后仍能使用 `String`，因为 `String` 被移动到了 `calculate_length` 内。相反我们可以提供一个 `String` 值的引用（reference）。**引用**（*reference*）像一个指针，因为它是一个地址，我们可以由此访问储存于该地址的属于其他变量的数据。 与指针不同，引用确保指向某个特定类型的有效值。

```rust
fn main() {
    let s1 = String::from("hello");

    let len = calculate_length(&s1);

    println!("The length of '{s1}' is {len}.");
}

fn calculate_length(s: &String) -> usize { // s 是 String 的引用
    s.len()
} // 这里，s 离开了作用域。但因为它并不拥有引用值的所有权，
  // 所以什么也不会发生
```

这些 & 符号就是 **引用**，它们允许你使用值但不获取其所有权。图 4-6 展示了一张示意图。

![Three tables: the table for s contains only a pointer to the table for s1. The table for s1 contains the stack data for s1 and points to the string data on the heap.](https://kaisery.github.io/trpl-zh-cn/img/trpl04-06.svg)

我们将创建一个引用的行为称为 **借用**（*borrowing*）。正如现实生活中，如果一个人拥有某样东西，你可以从他那里借来。当你使用完后，必须还回去。因为我们并不拥有它的所有权。

那如果我们尝试修改借用的变量呢？尝试示例 4-6 中的代码。剧透：这行不通！

#### 可变引用

我们通过一个小调整就能修复示例 4-6 代码中的错误，允许我们修改一个借用的值，这就是 **可变引用**（*mutable reference*）：

```rust
fn main() {
    let mut s = String::from("hello");

    change(&mut s);
}

fn change(some_string: &mut String) {
    some_string.push_str(", world");
}
```

首先，我们必须将 `s` 改为 `mut`。然后在调用 `change` 函数的地方创建一个可变引用 `&mut s`，并更新函数签名以接受一个可变引用 `some_string: &mut String`。

可变引用有一个很大的限制：如果你有一个对该变量的可变引用，你就不能再创建对该变量的引用。这些尝试创建两个 `s` 的可变引用的代码会失败：

```rust
    let mut s = String::from("hello");

    let r1 = &mut s;
    let r2 = &mut s;

    println!("{}, {}", r1, r2);
```

这个限制的好处是 Rust 可以在编译时就避免数据竞争。**数据竞争**（*data race*）类似于竞态条件，它可由这三个行为造成：

- 两个或更多指针同时访问同一数据。
- 至少有一个指针被用来写入数据。
- 没有同步数据访问的机制。

Rust 在同时使用可变与不可变引用时也采用的类似的规则。这些代码会导致一个错误：

```rust
    let mut s = String::from("hello");

    let r1 = &s; // 没问题
    let r2 = &s; // 没问题
    let r3 = &mut s; // 大问题

    println!("{}, {}, and {}", r1, r2, r3);
```

哇哦！我们 **也** 不能在拥有不可变引用的同时拥有可变引用。

注意一个引用的作用域从声明的地方开始一直持续到最后一次使用为止。例如，因为最后一次使用不可变引用（`println!`)，发生在声明可变引用之前，所以如下代码是可以编译的：

```rust
    let mut s = String::from("hello");

    let r1 = &s; // 没问题
    let r2 = &s; // 没问题
    println!("{r1} and {r2}");
    // 此位置之后 r1 和 r2 不再使用

    let r3 = &mut s; // 没问题
    println!("{r3}");
```

### 悬垂引用（Dangling References

在具有指针的语言中，很容易通过释放内存时保留指向它的指针而错误地生成一个 **悬垂指针**（*dangling pointer*），所谓悬垂指针是其指向的内存可能已经被分配给其它持有者。相比之下，在 Rust 中编译器确保引用永远也不会变成悬垂状态：当你拥有一些数据的引用，编译器确保数据不会在其引用之前离开作用域。

``` rust
fn dangle() -> &String { // dangle 返回一个字符串的引用

    let s = String::from("hello"); // s 是一个新字符串

    &s // 返回字符串 s 的引用
} // 这里 s 离开作用域并被丢弃。其内存被释放。
  // 危险！
```

让我们概括一下之前对引用的讨论：

- 在任意给定时间，**要么** 只能有一个可变引用，**要么** 只能有多个不可变引用。
- 引用必须总是有效的。

## Slice 类型

*slice* 允许你引用集合中一段连续的元素序列，而不用引用整个集合。slice 是一种引用，所以它没有所有权。

#### string slice

``` rust
    let s = String::from("hello world");

    let hello = &s[0..5];
    let world = &s[6..11];
```

#### 字符串字面值就是 slice

还记得我们讲到过字符串字面值被储存在二进制文件中吗？现在知道 slice 了，我们就可以正确地理解字符串字面值了：

```rust
let s = "Hello, world!";
```

这里 `s` 的类型是 `&str`：它是一个指向二进制程序特定位置的 slice。这也就是为什么字符串字面值是不可变的；`&str` 是一个不可变引用。

#### 其他类型的 slice

字符串 slice，正如你想象的那样，是针对字符串的。不过也有更通用的 slice 类型。考虑一下这个数组：

```rust
let a = [1, 2, 3, 4, 5];
```

就跟我们想要获取字符串的一部分那样，我们也会想要引用数组的一部分。我们可以这样做：

```rust
let a = [1, 2, 3, 4, 5];

let slice = &a[1..3];

assert_eq!(slice, &[2, 3]);
```

## 定义并实例化结构体

需要使用 `struct` 关键字并为整个结构体提供一个名字。结构体的名字需要描述它所组合的数据的意义。接着，在大括号中，定义每一部分数据的名字和类型，我们称为 **字段**（*field*）。

```rust
struct User {
    active: bool,
    username: String,
    email: String,
    sign_in_count: u64,
}
```

我们可以通过为每个字段指定具体值的方式来创建该结构体的**实例**。

```rust
fn main() {
    let user1 = User {
        email: String::from("someone@example.com"),
        username: String::from("someusername123"),
        active: true,
        sign_in_count: 1,
    };
    user1.email = String::from("anotheremail@example.com");
}

fn build_user(email: String, username: String) -> User {
    User {
        email,
        username,
        active: true,
        sign_in_count: 1,
    }
}
```

参数名与字段名都完全相同，我们可以使用**字段初始化简写语法**（*field init shorthand*）

### 元组结构体

``` rust
struct Color(i32, i32, i32);
struct Point(i32, i32, i32);

fn main() {
    let black = Color(0, 0, 0);
    let origin = Point(0, 0, 0);
}
```

我们也可以定义一个没有任何字段的结构体！它们被称为**类单元结构体**（*unit-like structs*）

``` rust
struct AlwaysEqual;

fn main() {
    let subject = AlwaysEqual;
}
```

使用结构体例子

``` rust
struct Rectangle {
    width: u32,
    height: u32,
}

fn main() {
    let rect1 = Rectangle {
        width: 30,
        height: 50,
    };

    println!(
        "The area of the rectangle is {} square pixels.",
        area(&rect1)
    );
}

fn area(rectangle: &Rectangle) -> u32 {
    rectangle.width * rectangle.height
}
```

### 直接打印结构体

在开头加上一行

``` rust
#[derive(Debug)]
struct Rectangle {
    width: u32,
    height: u32,
}

fn main() {
    let rect1 = Rectangle {
        width: 30,
        height: 50,
    };

    println!("rect1 is {:?}", rect1);
}

```

### 方法语法

``` rust
#[derive(Debug)]
struct Rectangle {
    width: u32,
    height: u32,
}

impl Rectangle {
    fn area(&self) -> u32 {
        self.width * self.height
    }
}

fn main() {
    let rect1 = Rectangle {
        width: 30,
        height: 50,
    };

    println!(
        "The area of the rectangle is {} square pixels.",
        rect1.area()
    );
}

```

## 枚举和模式匹配

### 枚举

使用枚举甚至还有更多优势。进一步考虑一下我们的 IP 地址类型，目前没有一个存储实际 IP 地址 **数据** 的方法；只知道它是什么 **类型** 的。考虑到已经在第 5 章学习过结构体了，你可能会像示例 6-1 那样处理这个问题：

```rust
enum IpAddrKind {
    V4,
    V6,
}

struct IpAddr {
    kind: IpAddrKind,
    address: String,
}

let home = IpAddr {
    kind: IpAddrKind::V4,
    address: String::from("127.0.0.1"),
};

let loopback = IpAddr {
    kind: IpAddrKind::V6,
    address: String::from("::1"),
};
```

为此，Rust 并没有空值，不过它确实拥有一个可以编码存在或不存在概念的枚举。这个枚举是 `Option<T>`，而且它[定义于标准库中](https://rustwiki.org/zh-CN/std/option/enum.Option.html)，如下:

```rust
enum Option<T> {
    Some(T),
    None,
}
```

这里是一些包含数字类型和字符串类型 `Option` 值的例子：

```rust
let some_number = Some(5);
let some_string = Some("a string");

let absent_number: Option<i32> = None;
```

### match

``` rust
    let dice_roll = 9;
    match dice_roll {
        3 => add_fancy_hat(),
        7 => remove_fancy_hat(),
        _ => reroll(),
    }

    fn add_fancy_hat() {}
    fn remove_fancy_hat() {}
    fn reroll() {}
```

还有 

``` rust
enum Coin {
    Penny,
    Nickel,
    Dime,
    Quarter,
}

fn value_in_cents(coin: Coin) -> u8 {
    match coin {
        Coin::Penny => 1,
        Coin::Nickel => 5,
        Coin::Dime => 10,
        Coin::Quarter => 25,
    }
}
```

### if let

`if let` 语法让我们以一种不那么冗长的方式结合 `if` 和 `let`，来处理只匹配一个模式的值而忽略其他模式的情况。考虑示例 6-6 中的程序，它匹配一个 `Option<u8>` 值并只希望当值为 3 时执行代码：

```rust
let some_u8_value = Some(0u8);
match some_u8_value {
    Some(3) => println!("three"),
    _ => (),
}
```

简化：

```rust
if let Some(3) = some_u8_value {
    println!("three");
}
```

### Option

* `is_some()` 判断是不是有值
* `as_ref()` **将 `Option<T>`（或 `Result<T, E>`）转换成 `Option<&T>`（或 `Result<&T, &E>`）**，即不获取所有权，而是获取其中值的**引用**。

#### swap

``` rust
impl Solution {
    pub fn merge_two_lists(mut list1: Option<Box<ListNode>>, mut list2: Option<Box<ListNode>>) -> Option<Box<ListNode>> {
        let mut r = &mut list1;
        while list2.is_some() {
            if r.is_none() || list2.as_ref()?.val < r.as_ref()?.val {
                std::mem::swap(r, &mut list2);
            }
            r = &mut r.as_mut()?.next;
        }
        list1
    }
}
```



## 使用包、Crate和模块管理不断增长的项目

### 包和 crate

crate 是一个二进制项或者库。*crate root* 是一个源文件，Rust 编译器以它为起始点，并构成你的 crate 的根模块

一个包中至多 **只能** 包含一个库 crate（library crate）；包中可以包含任意多个二进制 crate（binary crate）；包中至少包含一个 crate，无论是库的还是二进制的。

``` shell
cargo new my-project
```

当我们输入了这条命令，Cargo 会给我们的包创建一个 *Cargo.toml* 文件。查看 *Cargo.toml* 的内容，会发现并没有提到 *src/main.rs*，因为 Cargo 遵循的一个约定：*src/main.rs* 就是一个与包同名的二进制 crate 的 crate 根。

Cargo 知道如果包目录中包含 *src/lib.rs*，则包带有与其同名的库 crate，且 *src/lib.rs* 是 crate 根。crate 根文件将由 Cargo 传递给 `rustc` 来实际构建库或者二进制项目。

通过将文件放在 *src/bin* 目录下，一个包可以拥有多个二进制 crate：每个 *src/bin* 下的文件都会被编译成一个独立的二进制 crate。

### 定义模块来控制作用域与私有性

通过执行 `cargo new --lib restaurant`，来创建一个新的名为 `restaurant` 的库。然后将示例 7-1 中所罗列出来的代码放入 *src/lib.rs* 中，来定义一些模块和函数。

文件名: src/lib.rs

```rust
mod front_of_house {
    mod hosting {
        fn add_to_waitlist() {}

        fn seat_at_table() {}
    }

    mod serving {
        fn take_order() {}

        fn serve_order() {}

        fn take_payment() {}
    }
}
```

示例 7-2 展示了示例 7-1 所对应的模块树。

```text
crate
 └── front_of_house
     ├── hosting
     │   ├── add_to_waitlist
     │   └── seat_at_table
     └── serving
         ├── take_order
         ├── serve_order
         └── take_payment
```

模块树或许让你想起了电脑上文件系统的目录树。这是一个非常恰当的比喻！就像文件系统中的目录那样，你应使用模块来组织你的代码。而且就像一个目录中的文件那样，我们需要一个找到我们的模块的方式。



### 路径

有两种形式：

- **绝对路径**（*absolute path*）从 crate 根部开始，以 crate 名或者字面量 `crate` 开头。
- **相对路径**（*relative path*）从当前模块开始，以 `self`、`super` 或当前模块的标识符开头。

文件名: src/lib.rs

```rust
mod front_of_house {
    pub mod hosting {
        pub fn add_to_waitlist() {}
    }
}

pub fn eat_at_restaurant() {
    // 绝对路径
    crate::front_of_house::hosting::add_to_waitlist();

    // 相对路径
    front_of_house::hosting::add_to_waitlist();
}
```

Rust 中默认所有项（函数、方法、结构体、枚举、模块和常量）都是私有的。父模块中的项不能使用子模块中的私有项，但是子模块中的项可以使用他们父模块中的项。这是因为子模块封装并隐藏了他们的实现详情，但是子模块可以看到他们定义的上下文。继续拿餐馆作比喻，把私有性规则想象成餐馆的后台办公室：餐馆内的事务对餐厅顾客来说是不可知的，但办公室经理可以洞悉其经营的餐厅并在其中做任何事情。

想让父模块中的 `eat_at_restaurant` 函数可以访问子模块中的 `add_to_waitlist` 函数，因此我们使用 `pub` 关键字来标记 `hosting` 模块

#### 使用 `super` 起始的相对路径

我们还可以使用 `super` 开头来构建从父模块开始的相对路径。这么做类似于文件系统中以 `..` 开头的语法。我们为什么要这样做呢？

考虑一下示例 7-8 中的代码，它模拟了厨师更正了一个错误订单，并亲自将其提供给客户的情况。`fix_incorrect_order` 函数通过指定的 `super` 起始的 `serve_order` 路径，来调用 `serve_order` 函数：

文件名: src/lib.rs

```rust
fn serve_order() {}

mod back_of_house {
    fn fix_incorrect_order() {
        cook_order();
        super::serve_order();
    }

    fn cook_order() {}
}
```

#### 创建公有的结构体和枚举

我们还可以使用 `pub` 来设计公有的结构体和枚举，不过有一些额外的细节需要注意。如果我们在一个结构体定义的前面使用了 `pub` ，这个结构体会变成公有的，但是这个结构体的字段仍然是私有的。我们可以根据情况决定每个字段是否公有。在示例 7-9 中，我们定义了一个公有结构体 `back_of_house::Breakfast`，其中有一个公有字段 `toast` 和私有字段 `seasonal_fruit`。这个例子模拟的情况是，在一家餐馆中，顾客可以选择随餐附赠的面包类型，但是厨师会根据季节和库存情况来决定随餐搭配的水果。餐馆可用的水果变化是很快的，所以顾客不能选择水果，甚至无法看到他们将会得到什么水果。

文件名: src/lib.rs

```rust
mod back_of_house {
    pub struct Breakfast {
        pub toast: String,
        seasonal_fruit: String,
    }

    impl Breakfast {
        pub fn summer(toast: &str) -> Breakfast {
            Breakfast {
                toast: String::from(toast),
                seasonal_fruit: String::from("peaches"),
            }
        }
    }
}

pub fn eat_at_restaurant() {
    // 在夏天点一份黑麦面包作为早餐
    let mut meal = back_of_house::Breakfast::summer("Rye");
    // 更改我们想要的面包
    meal.toast = String::from("Wheat");
    println!("I'd like {} toast please", meal.toast);

    // 如果取消下一行的注释，将会导致编译失败；我们不被允许
    // 看到或更改随餐搭配的季节水果
    // meal.seasonal_fruit = String::from("blueberries");
}
```



### 使用 use关键字将名称引入作用域

文件名: src/lib.rs

```rust
mod front_of_house {
    pub mod hosting {
        pub fn add_to_waitlist() {}
    }
}

use crate::front_of_house::hosting;

pub fn eat_at_restaurant() {
    hosting::add_to_waitlist();
}
```

#### 使用 as关键字提供新的名称

使用 `use` 将两个同名类型引入同一作用域这个问题还有另一个解决办法：在这个类型的路径后面，我们使用 `as` 指定一个新的本地名称或者别名。示例 7-16 展示了另一个编写示例 7-15 中代码的方法，通过 `as` 重命名其中一个 `Result` 类型。

文件名: src/lib.rs

```rust
use std::fmt::Result;
use std::io::Result as IoResult;

fn function1() -> Result {
    // --snip--
}

fn function2() -> IoResult<()> {
    // --snip--
}
```

#### 使用 pub use重导出名称

当使用 `use` 关键字将名称导入作用域时，在新作用域中可用的名称是私有的。如果为了让调用你编写的代码的代码能够像在自己的作用域内引用这些类型，可以结合 `pub` 和 `use`。这个技术被称为 “*重导出*（*re-exporting*）”，因为这样做将项引入作用域并同时使其可供其他代码引入自己的作用域。

示例 7-17 展示了将示例 7-11 中使用 `use` 的根模块变为 `pub use` 的版本的代码。

文件名: src/lib.rs

```rust
mod front_of_house {
    pub mod hosting {
        pub fn add_to_waitlist() {}
    }
}

pub use crate::front_of_house::hosting;

pub fn eat_at_restaurant() {
    hosting::add_to_waitlist();
}
```



## 常见集合

### Vector

#### 新建 vector

为了创建一个新的空 vector，可以调用 `Vec::new` 函数，如示例 8-1 所示：

```rust
let v: Vec<i32> = Vec::new();
```

 Rust 提供了 `vec!` 宏。这个宏会根据我们提供的值来创建一个新的 `Vec`。示例 8-2 新建一个拥有值 `1`、`2` 和 `3` 的 `Vec<i32>`：

```rust
let v = vec![1, 2, 3];
let v = vec![i as i32,j as i32];
```

#### 更新vector

对于新建一个 vector 并向其增加元素，可以使用 `push` 方法，如示例 8-3 所示：

```rust
let mut v = Vec::new();

v.push(5);
v.push(6);
v.push(7);
v.push(8);
```

#### 读取 vector 的元素

示例 8-5 展示了访问 vector 中一个值的两种方式，索引语法或者 `get` 方法：

```rust
let v = vec![1, 2, 3, 4, 5];

let third: &i32 = &v[2];
println!("The third element is {}", third);

match v.get(2) {
    Some(third) => println!("The third element is {}", third),
    None => println!("There is no third element."),
}
```

#### 遍历 vector 中的元素

如果想要依次访问 vector 中的每一个元素，我们可以遍历其所有的元素而无需通过索引一次一个的访问。示例 8-8 展示了如何使用 `for` 循环来获取 `i32` 值的 vector 中的每一个元素的不可变引用并将其打印：

```rust
let v = vec![100, 32, 57];
for i in &v {
    println!("{}", i);
}
```

示例 8-8：通过 `for` 循环遍历 vector 的元素并打印

我们也可以遍历可变 vector 的每一个元素的可变引用以便能改变他们。示例 8-9 中的 `for` 循环会给每一个元素加 `50`：

```rust
let mut v = vec![100, 32, 57];
for i in &mut v {
    *i += 50;
}
```

### HashMap

``` rust
use std::collections::HashMap;

let mut map: HashMap<i32, usize> = HashMap::new();
if let Some(&index) = map.get(&complement) {
    return vec![index as i32, i as i32];
}
map.insert(nums[i],i);
```

### Map

The `map` method offers a way to apply a function (or a closure) on each element from a list.

``` rust
let numbers = vec![3, 6, 9, 12];
let result: Vec<i32> = numbers
    .iter()
    .map(|n| n * 10)
    .collect();
// result is now [30, 60, 90, 120]
```

### Box

新建Box节点

```rust
// impl ListNode {
//   #[inline]
//   fn new(val: i32) -> Self {
//     ListNode {
//       next: None,
//       val
//     }
//   }
// }

let mut head = Box::new(ListNode::new(0));
```

## 错误处理

Rust 将错误组合成两个主要类别：**可恢复错误**（*recoverable*）和 **不可恢复错误**（*unrecoverable*）。

### `panic!` 与不可恢复的错误

让我们在一个简单的程序中调用 `panic!`：

文件名: src/main.rs

```rust
fn main() {
    panic!("crash and burn");
}
```

### `Result` 与可恢复的错误

 `Result` 枚举，它定义有如下两个成员，`Ok` 和 `Err`：

```rust
enum Result<T, E> {
    Ok(T),
    Err(E),
}
```

`T` 和 `E` 是泛型类型参数；第 10 章会详细介绍泛型。现在你需要知道的就是 `T` 代表成功时返回的 `Ok` 成员中的数据的类型，而 `E` 代表失败时返回的 `Err` 成员中的错误的类型。

#### 失败时 panic 的简写：`unwrap` 和 `expect`

`match` 能够胜任它的工作，不过它可能有点冗长并且不总是能很好地表明其意图。`Result<T, E>` 类型定义了很多辅助方法来处理各种情况。其中之一叫做 `unwrap`，它的实现就类似于示例 9-4 中的 `match` 语句。如果 `Result` 值是成员 `Ok`，`unwrap` 会返回 `Ok` 中的值。如果 `Result` 是成员 `Err`，`unwrap` 会为我们调用 `panic!`。这里是一个实践 `unwrap` 的例子：

文件名: src/main.rs

```rust
use std::fs::File;

fn main() {
    let f = File::open("hello.txt").unwrap();
}
```

文件名: src/main.rs

```rust
use std::fs::File;

fn main() {
    let f = File::open("hello.txt").expect("Failed to open hello.txt");
}
```

`expect` 与 `unwrap` 的使用方式一样：返回文件句柄或调用 `panic!` 宏。`expect` 在调用 `panic!` 时使用的错误信息将是我们传递给 `expect` 的参数，而不像 `unwrap` 那样使用默认的 `panic!` 信息。

### 传播错误

当编写一个需要先调用一些可能会失败的操作的函数时，除了在这个函数中处理错误外，还可以选择让调用者知道这个错误并决定该如何处理。这被称为 **传播**（*propagating*）错误

文件名: src/main.rs

```rust
use std::io;
use std::io::Read;
use std::fs::File;

fn read_username_from_file() -> Result<String, io::Error> {
    let f = File::open("hello.txt");

    let mut f = match f {
        Ok(file) => file,
        Err(e) => return Err(e),
    };

    let mut s = String::new();

    match f.read_to_string(&mut s) {
        Ok(_) => Ok(s),
        Err(e) => Err(e),
    }
}
```

示例 9-7 展示了一个 `read_username_from_file` 的实现，它实现了与示例 9-6 中的代码相同的功能，不过这个实现使用了 `?` 运算符：

文件名: src/main.rs

```rust
use std::io;
use std::io::Read;
use std::fs::File;

fn read_username_from_file() -> Result<String, io::Error> {
    let mut f = File::open("hello.txt")?;
    let mut s = String::new();
    f.read_to_string(&mut s)?;
    Ok(s)
}
```

`Result` 值之后的 `?` 被定义为与示例 9-6 中定义的处理 `Result` 值的 `match` 表达式有着完全相同的工作方式。如果 `Result` 的值是 `Ok`，这个表达式将会返回 `Ok` 中的值而程序将继续执行。如果值是 `Err`，`Err` 将作为整个函数的返回值，就好像使用了 `return` 关键字一样，这样错误值就被传播给了调用者。





# Rust 代码片段

## 输入

``` rust
/*
This template is made by Naman Garg <naman.rustp@gmail.com>
GitHub : https://github.com/namanlp
GitLab : https://gitlab.com/namanlp
Website : https://rustp.org

You can visit https://rustp.org/basic-programs/basic-template/
for understanding the template

Feel free to copy the template, but not the solutions :D
Thank You
 */

#![allow(unused)]

use std::io::stdin;

fn take_int() -> usize {
    let mut input = String::new();
    stdin().read_line(&mut input).unwrap();
    input.trim().parse().unwrap()
}

fn take_vector() -> Vec<usize> {
    let mut input = String::new();
    stdin().read_line(&mut input).unwrap();
    input
        .trim()
        .split_whitespace()
        .map(|x| x.parse().unwrap())
        .collect();
}

fn take_string() -> String {
    let mut input = String::new();
    stdin().read_line(&mut input).unwrap();
    input
}
fn to_chars(x: String) -> Vec<char> {
    x.chars().collect()
}

fn solve() {
    // ======================= Code Here =========================
}

pub fn main() {
    let t = take_int();
    for _ in 0..t {
        solve();
    }
}
```

## Misc

### min,max

``` rust
use std::cmp::max;

ans = max(ans, r-l);
ans.max(r-l);
```

### type convet

``` rust
ans.try_into().unwrap()
ans as i32
'x' as usize
```

### constants

``` rust
u32::MAX
i32::MAX
```

## Array and Vector

### array

``` rust
let mut cnt = [false;256];
```

### vector

``` rust
let mut vec = Vec::new();
let vec = vec![0; 5]; // [0, 0, 0, 0, 0]
vec.sort(); // from small to big
let mut xs : Vec<i32> = points.iter().map(|p| p[0]).collect(); // get x vals
```

#### enumerate

```  rust
for (i,x) in points.iter().enumerate() {
    
}
for p in &points {
    let (x,y) = (p[0],p[1]);
}
```

## Hashset

``` rust
use std::collections::HashSet;
let mut books = HashSet::new();
books.insert("A Dance With Dragons".to_string());
if !s.contains(&(x1,y1)) {
    continue;
}
books.remove("The Odyssey");
```





# 计划

https://rustwiki.org/zh-CN/book/ch03-02-data-types.html

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
