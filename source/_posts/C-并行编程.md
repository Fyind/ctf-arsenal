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





### TODO

* RAII
