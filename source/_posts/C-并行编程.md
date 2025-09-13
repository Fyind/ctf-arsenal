---
title: C++并行编程
date: 2025-06-26 09:32:44
tags: C++
categories: 编程语言
---

# C++ 并行编程

## Refernece

https://nj.gitbooks.io/c/content/content/chapter5/chapter5-chinese.html

https://mq-b.github.io/ModernCpp-ConcurrentProgramming-Tutorial/md/05%E5%86%85%E5%AD%98%E6%A8%A1%E5%9E%8B%E4%B8%8E%E5%8E%9F%E5%AD%90%E6%93%8D%E4%BD%9C.html

## 使用线程

### Hello world

用thread来运行hello world

``` cpp
#include <iostream>
#include <thread>

void hello() {
    std::cout << "Hello" << std::endl;
}

int main() {
    std::thread t{ hello };
    t.join();
}
```

`t.join();` 等待线程对象 `t` 关联的线程执行完毕，否则将一直阻塞。这里的调用是必须的，否则 `std::thread` 的析构函数将调用 [`std::terminate()`](https://zh.cppreference.com/w/cpp/error/terminate) 无法正确析构。

### 多线程求和

当前环境支持并发线程数

``` cpp
 unsigned int n = std::thread::hardware_concurrency(); 
```

可以查询硬件支持的并发数量.

``` cpp
#include <iostream>
#include <thread>
#include <vector>
#include <numeric>

template<typename ForwardIt>
auto sum(ForwardIt first, ForwardIt last) {
    using value_type = std::iter_value_t<ForwardIt>;
    std::size_t n = std::thread::hardware_concurrency();
    std::ptrdiff_t total = std::distance(first, last);
    std::vector<value_type> sums(n);
    std::vector<std::thread> threads;

    std::size_t chunk = total / n;
    std::size_t remainder = total % n;

    auto start = first;
    for (int i = 0;i < n; ++i) {
        auto end = std::next(start, chunk + (i<remainder?1:0));
        threads.emplace_back([start, end, &sums, i](){
            sums[i] = std::accumulate(start, end, value_type{});
        });
        start = end;
    }
    for (auto& thread : threads) {
        thread.join();
    }
    return std::accumulate(sums.begin(), sums.end(), value_type{});
}


int main() {
    std::vector<int> x = {1,2,3,4,5,6,7,8,9,10};
    std::cout << sum(x.begin(), x.end()) << std::endl;
}
```

* next 是求 start 往后挪多少个的迭代器
* accumulate是 numeric 库里面的. 会移动迭代器
* [`std::iter_value_t`](https://zh.cppreference.com/w/cpp/iterator/iter_t) 是 C++20 引入的，[返回类型推导](https://zh.cppreference.com/w/cpp/language/function#.E8.BF.94.E5.9B.9E.E7.B1.BB.E5.9E.8B.E6.8E.A8.E5.AF.BC)

### 线程管理

我们上一节的示例是传递了一个函数给 `std::thread` 对象，函数会在新线程中执行。`std::thread` 支持的形式还有很多，只要是[可调用(Callable)](https://zh.cppreference.com/w/cpp/named_req/Callable)对象即可，比如重载了 `operator()` 的类对象（也可以直接叫函数对象）。

```cpp
class Task{
public:
    void operator()()const {
        std::cout << "operator()()const\n";
    }
};
```

#### detach

``` cpp
#include <iostream>
#include <thread>

struct func {
    int& m_i;
    func(int& i) :m_i{ i } {}
    void operator()(int n)const {
        for (int i = 0; i <= n; ++i) {
            m_i += i;           // 可能悬空引用
        }
    }
};

int main(){
    int n = 0;
    std::thread my_thread{ func{n},100 };
    my_thread.detach();        // 分离，不等待线程结束
}                              // 分离的线程可能还在运行
```

### RAII

***构造函数申请资源，析构函数释放资源，让对象的生命周期和资源绑定***。

当异常抛出时，C++ 会自动调用对象的析构函数。

``` cpp
class thread_guard{
    std::thread& m_t;
public:
    explicit thread_guard(std::thread& t) :m_t{ t } {}
    ~thread_guard(){
        std::puts("析构");     // 打印日志 不用在乎
        if (m_t.joinable()) { // 线程对象当前关联了活跃线程
            m_t.join();
        }
    }
    thread_guard(const thread_guard&) = delete;
    thread_guard& operator=(const thread_guard&) = delete;
};
void f(){
    int n = 0;
    std::thread t{ func{n},10 };
    thread_guard g(t);
    f2(); // 可能抛出异常
}
```

**调用析构函数**。**即使函数 f2() 抛出了一个异常，这个销毁依然会发生**（前提是你捕获了这个异常） 如果异常被抛出但未被捕获那么就会调用 [std::terminate](https://zh.cppreference.com/w/cpp/error/terminate)

我们要判断 `std::thread` 线程对象现在是否有关联的活跃线程，如果有，我们才会执行 **`join()`**，阻塞当前线程直到线程对象关联的线程执行完毕。

### 传递参数

向可调用对象传递参数很简单，我们前面也都写了，只需要将这些参数作为 `std::thread` 的构造参数即可。需要注意的是，这些参数会复制到新线程的内存空间中，即使函数中的参数是引用，依然**实际是复制**。

``` cpp
void f(int, const int& a) { // a 并非引用了局部对象 n
    std::cout << &a << '\n'; 
}

int main() {
    int n = 1;
    std::cout << &n << '\n';
    std::thread t{ f, 3, n };
    t.join();
}
```

想要解决这个问题很简单，我们可以使用标准库的设施 [`std::ref`](https://zh.cppreference.com/w/cpp/utility/functional/ref) 、 `std::cref` 函数模板。

``` cpp
void f(int, int& a) {
    std::cout << &a << '\n'; 
}

int main() {
    int n = 1;
    std::cout << &n << '\n';
    std::thread t { f, 3, std::ref(n) };
    t.join();
}
```

### `std::this_thread`

这个命名空间包含了管理当前线程的函数。

1. [`yield`](https://zh.cppreference.com/w/cpp/thread/yield) 建议实现重新调度各执行线程。
2. [`get_id`](https://zh.cppreference.com/w/cpp/thread/get_id) 返回当前线程 id。
3. [`sleep_for`](https://zh.cppreference.com/w/cpp/thread/sleep_for) 使当前线程停止执行指定时间。
4. [`sleep_until`](https://zh.cppreference.com/w/cpp/thread/sleep_until) 使当前线程执行**停止到**指定的时间点

``` cpp
int main() {
    std::this_thread::sleep_for(std::chrono::seconds(3));
}
```

`yield` 减少 CPU 的占用。

``` cpp
while (!isDone()){
    std::this_thread::yield();
}
```

### C++20 `std::jthread`

`std::jthread` 相比于 C++11 引入的 `std::thread`，只是多了两个功能：

1. **RAII 管理**：在析构时自动调用 `join()`。
2. **线程停止功能**：线程的取消/停止。

这就是 C++ 的设计哲学，***零开销原则***：*你不需要为你没有用到的（特性）付出额外的开销*。

`std::jthread` 所谓的线程停止只是一种**基于用户代码的控制机制**，而不是一种与操作系统系统有关系的线程终止。使用 `std::stop_source` 和 [`std::stop_token`](https://zh.cppreference.com/w/cpp/thread/stop_token) 提供了一种优雅地请求线程停止的方式，**但实际上停止的决定和实现都由用户代码来完成**。

``` cpp
using namespace std::literals::chrono_literals;

void f(std::stop_token stop_token, int value){
    while (!stop_token.stop_requested()){ // 检查是否已经收到停止请求
        std::cout << value++ << ' ' << std::flush;
        std::this_thread::sleep_for(200ms);
    }
    std::cout << std::endl;
}

int main(){
    std::jthread thread{ f, 1 }; // 打印 1..15 大约 3 秒
    std::this_thread::sleep_for(3s);
    // jthread 的析构函数调用 request_stop() 和 join()。
}
```

## 共享数据

在多线程的情况下，每个线程都抢着完成自己的任务。在大多数情况下，即使会改变执行顺序，也是良性竞争，这是无所谓的。比如两个线程都要往标准输出输出一段字符，谁先谁后并不会有什么太大影响。

只有在涉及多线程读写相同共享数据的时候，才会导致“*恶性的条件竞争*”。

### 使用互斥量

互斥量（Mutex），又常被称为互斥锁、互斥体（或者直接被称作“锁”），是一种用来保护**临界区**[[1\]](https://mq-b.github.io/ModernCpp-ConcurrentProgramming-Tutorial/md/03共享数据.html#footnote1)的特殊对象，其相当于实现了一个公共的“**标志位**”。它可以处于锁定（locked）状态，也可以处于解锁（unlocked）状态：

``` cpp
#include <mutex> // 必要标头
std::mutex m;

void f() {
    m.lock();
    std::cout << std::this_thread::get_id() << '\n';
    m.unlock();
}

int main() {
    std::vector<std::thread>threads;
    for (std::size_t i = 0; i < 10; ++i)
        threads.emplace_back(f);

    for (auto& thread : threads)
        thread.join();
}
```

#### `std::lock_guard`	

不过一般不推荐这样显式的 `lock()` 与 `unlock()`，应该用这个

``` cpp
void f() {
    std::lock_guard<std::mutex> lc{ m };
    std::cout << std::this_thread::get_id() << '\n';
}
```

这是一个“管理类”模板，用来管理互斥量的上锁与解锁，

这段代码极其简单，首先管理类，自然不可移动不可复制，我们定义复制构造与复制赋值为[弃置函数](https://zh.cppreference.com/w/cpp/language/function#.E5.BC.83.E7.BD.AE.E5.87.BD.E6.95.B0)，同时[阻止](https://zh.cppreference.com/w/cpp/language/rule_of_three#.E4.BA.94.E4.B9.8B.E6.B3.95.E5.88.99)了移动等函数的隐式定义。

构造函数中初始化这个引用，同时上锁，析构函数中解锁，这是一个非常典型的 `RAII` 式的管理。

同时它还提供一个有额外[`std::adopt_lock_t`](https://zh.cppreference.com/w/cpp/thread/lock_tag_t)参数的构造函数 ，如果使用这个构造函数，则构造函数不会上锁。

``` cpp
void f(){
    //code..
    {
        std::lock_guard<std::mutex> lc{ m };
        // 涉及共享资源的修改的代码...
    }
    //code..
}
```

#### `try_lock`

`try_lock` 是互斥量中的一种尝试上锁的方式。与常规的 `lock` 不同，`try_lock` 会尝试上锁，但如果锁已经被其他线程占用，则**不会阻塞当前线程，而是立即返回**。

它的返回类型是 `bool` ，如果上锁成功就返回 `true`，失败就返回 `false`。

### 保护共享数据注意

互斥量主要也就是为了保护共享数据，上一节的*使用互斥量*也已经为各位展示了一些。

然而使用互斥量来保护共享数据也并不是在函数中加上一个 `std::lock_guard` 就万事大吉了。有的时候只需要一个指针或者引用，就能让这种保护**形同虚设**。

- *简而言之：**切勿将受保护数据的指针或引用传递到互斥量作用域之外**，不然保护将**形同虚设**。*

### 死锁：问题与解决

*两个线程需要对它们所有的互斥量做一些操作，其中每个线程都有一个互斥量，且等待另一个线程的互斥量解锁。因为它们都在等待对方释放互斥量，没有线程工作。* 这种情况就是死锁。

- **多个互斥量才可能遇到死锁问题**。

避免死锁的一般建议是让两个互斥量以相同的顺序上锁，总在互斥量 B 之前锁住互斥量 A，就通常不会死锁。反面示例

#### `std::lock`

C++ 标准库有很多办法解决这个问题，**可以使用 [`std::lock`](https://zh.cppreference.com/w/cpp/thread/lock)** ，它能一次性锁住多个互斥量，并且没有死锁风险。修改 swap 代码后如下：

``` cpp
void swap(X& lhs, X& rhs) {
    if (&lhs == &rhs) return;
    std::lock(lhs.m, rhs.m);    // 给两个互斥量上锁
    std::lock_guard<std::mutex> lock1{ lhs.m,std::adopt_lock }; 
    std::lock_guard<std::mutex> lock2{ rhs.m,std::adopt_lock }; 
    swap(lhs.object, rhs.object);
}
```

#### `std::scoped_lock`

C++17 新增了 [`std::scoped_lock`](https://zh.cppreference.com/w/cpp/thread/scoped_lock) ，提供此函数的 [RAII](https://zh.cppreference.com/w/cpp/language/raii) 包装，通常它比裸调用 `std::lock` 更好。

``` cpp
void swap(X& lhs, X& rhs) {
    if (&lhs == &rhs) return;
    std::scoped_lock guard{ lhs.m,rhs.m };
    swap(lhs.object, rhs.object);
}
```

### `std::unique_lock` 灵活的锁

[`std::unique_lock`](https://zh.cppreference.com/w/cpp/thread/unique_lock) 是 C++11 引入的一种通用互斥包装器，它相比于 `std::lock_guard` 更加的灵活。当然，它也更加的复杂，尤其它还可以与我们下一章要讲的[条件变量](https://zh.cppreference.com/w/cpp/thread#.E6.9D.A1.E4.BB.B6.E5.8F.98.E9.87.8F)一起使用。使用它可以将之前使用 `std::lock_guard` 的 `swap` 改写一下：

``` cpp
void swap(X& lhs, X& rhs) {
    if (&lhs == &rhs) return;
    std::unique_lock<std::mutex> lock1{ lhs.m, std::defer_lock };
    std::unique_lock<std::mutex> lock2{ rhs.m, std::defer_lock };
    std::lock(lock1, lock2);
    swap(lhs.object, rhs.object);
}
```

 **`_Owns` 为 `false` 表示没有互斥量所有权**。并且 `std::unique_lock` 是有 [`lock()`](https://zh.cppreference.com/w/cpp/thread/unique_lock/lock) 、[`try_lock()`](https://zh.cppreference.com/w/cpp/thread/unique_lock/try_lock) 、[`unlock()`](https://zh.cppreference.com/w/cpp/thread/unique_lock/unlock) 成员函数的，所以可以直接传递给 `std::lock`、 进行调用。

####  `std::defer_lock` 

我们要了解 `std::defer_lock` 是“不获得互斥体的所有权”。没有所有权自然构造函数就不会上锁

构造函数不上锁，要求构造之后上锁

####  `std::adopt_lock` 

只是不上锁，但是**有所有权**

构造函数不上锁，要求在构造之前互斥量上锁

#### 使用和优点

* RAII 语义，自动解锁， 也可以手动解锁
* 你可以声明时不立刻加锁

``` cpp
void f() {
    //code..
    
    std::unique_lock<std::mutex> lock{ m };

    // 涉及共享资源的修改的代码...

    lock.unlock(); // 解锁并释放所有权，析构函数不会再 unlock()

    //code..
}
```

通常建议优先 `std::lock_guard`，当它无法满足你的需求或者显得代码非常繁琐，那么可以考虑使用 `std::unique_lock`。

如果性能非常敏感（极低开销场景），`std::lock_guard` 更轻量。

如果只需要简单加锁解锁，`std::lock_guard` 语义更清晰。

### 在不同作用域传递互斥量

首先我们要明白，互斥量满足[*互斥体 (Mutex)*](https://zh.cppreference.com/w/cpp/named_req/Mutex)的要求，**不可复制不可移动**。所谓的在不同作用域传递互斥量，其实只是传递了它们的指针或者引用罢了。

`std::unique_lock` 可以获取互斥量的所有权，而互斥量的所有权可以通过移动操作转移给其他的 `std::unique_lock` 对象。

``` cpp
std::unique_lock<std::mutex> get_lock(){
    extern std::mutex some_mutex;
    std::unique_lock<std::mutex> lk{ some_mutex };
    return lk;
}
void process_data(){
    std::unique_lock<std::mutex> lk{ get_lock() };
    // 执行一些任务...
}
```

我相信你可能对 `extern std::mutex some_mutex` 有疑问，其实不用感到奇怪，这是一个互斥量的声明，可能别的翻译单元（或 dll 等）有它的定义，成功链接上。

### 保护共享数据的初始化过程

保护共享数据并非必须使用互斥量，互斥量只是其中一种常见的方式而已，对于一些特殊的场景，也有专门的保护方式，比如**对于共享数据的初始化过程的保护**。我们通常就不会用互斥量，**这会造成很多的额外开销**。

#### `std::call_once()`

比起锁住互斥量并显式检查指针，每个线程只需要使用 `std::call_once` 就可以。**使用 `std::call_once` 比显式使用互斥量消耗的资源更少，特别是当初始化完成之后**。

``` cpp
std::shared_ptr<some> ptr;
std::once_flag resource_flag;

void init_resource(){
    ptr.reset(new some);
}

void foo(){
    std::call_once(resource_flag, init_resource); // 线程安全的一次初始化
    ptr->do_something();
}
```

以上代码 `std::once_flag` 对象是全局命名空间作用域声明，如果你有需要，它也可以是类的成员。用于搭配 `std::call_once` 使用，保证线程安全的**一次**初始化。

#### **静态局部变量初始化在 C++11 是线程安全**

``` cpp
class my_class;
inline my_class& get_my_class_instance(){
    static my_class instance;  // 线程安全的初始化过程 初始化严格发生一次
    return instance;
}
```

### 保护不常更新的数据结构

你有一个数据结构存储了用户的设置信息，每次用户打开程序的时候，都要进行读取，且运行时很多地方都依赖这个数据结构需要读取，所以为了效率，我们使用了多线程读写。这个数据结构很少进行改变，而我们知道，多线程读取，是没有数据竞争的，是安全的，但是有些时候又不可避免的有修改和读取都要工作的时候，所以依然必须得使用互斥量进行保护。

已经想到了：“[***读写锁***](https://zh.wikipedia.org/wiki/读写锁)”

C++ 标准库自然为我们提供了： [`std::shared_timed_mutex`](https://zh.cppreference.com/w/cpp/thread/shared_timed_mutex)（C++14）、 [`std::shared_mutex`](https://zh.cppreference.com/w/cpp/thread/shared_mutex)（C++17）。它们的区别简单来说，前者支持更多的操作方式，后者有更高的性能优势。

#### `std::shared_mutex`

``` cpp
class Settings {
private:
    std::map<std::string, std::string> data_;
    mutable std::shared_mutex mutex_; // “M&M 规则”：mutable 与 mutex 一起出现

public:
    void set(const std::string& key, const std::string& value) {
        std::lock_guard<std::shared_mutex> lock{ mutex_ };
        data_[key] = value;
    }

    std::string get(const std::string& key) const {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        auto it = data_.find(key);
        return (it != data_.end()) ? it->second : ""; // 如果没有找到键返回空字符串
    }
};
```

**而那些无需修改数据结构的读线程，可以使用 [`std::shared_lock`](https://zh.cppreference.com/w/cpp/thread/shared_lock) 获取访问权**，多个线程可以一起读取

#### `std::shared_timed_mutex`

`std::shared_timed_mutex` 具有 `std::shared_mutex` 的所有功能，并且额外支持超时功能。所以以上代码可以随意更换这两个互斥量。

### `std::recursive_mutex`

线程对已经上锁的 `std::mutex` 再次上锁是错误的，这是[*未定义行为*](https://zh.cppreference.com/w/cpp/language/ub)。然而在某些情况下，一个线程会尝试在释放一个互斥量前多次获取，所以提供了`std::recursive_mutex`。

`std::recursive_mutex` 是 C++ 标准库提供的一种互斥量类型，它允许同一线程多次锁定同一个互斥量，而不会造成死锁。**只有在解锁与锁定次数相匹配时，互斥量才会真正释放**。

``` cpp
#include <iostream>
#include <thread>
#include <mutex>

std::recursive_mutex mtx;

void recursive_function(int count) {
    // 递归函数，每次递归都会锁定互斥量
    mtx.lock();
    std::cout << "Locked by thread: " << std::this_thread::get_id() << ", count: " << count << std::endl;
    if (count > 0) {
        recursive_function(count - 1); // 递归调用
    }
    mtx.unlock(); // 解锁互斥量
}

int main() {
    std::thread t1(recursive_function, 3);
    std::thread t2(recursive_function, 2);

    t1.join();
    t2.join();
}
```

同样的，我们也可以使用 `std::lock_guard`、`std::unique_lock` 帮我们管理 `std::recursive_mutex`，

``` cpp
void recursive_function(int count) {
    std::lock_guard<std::recursive_mutex> lc{ mtx };
    std::cout << "Locked by thread: " << std::this_thread::get_id() << ", count: " << count << std::endl;
    if (count > 0) {
        recursive_function(count - 1);
    }
}
```

### **线程存储期**

线程存储期的对象在线程开始时分配，并在线程结束时释放。每个线程拥有自己独立的对象实例，互不干扰。



# CMake

项目结构

``` text
your_project/
├── CMakeLists.txt
├── main.cpp
└── include/
    └── myheader.h
```

构建

``` shell
# 创建构建目录
mkdir build
cd build

# 使用 CMake 生成 Makefile 或项目文件
cmake ..

# 编译项目
cmake --build .

```

