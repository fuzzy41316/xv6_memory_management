# CS537 Fall 2024 - Project 5

## 🔍 Problem Statement  
In this project, I implemented advanced memory management features in an operating system kernel. The main tasks were to develop the following functions:

- **`wmap`**: A system call that maps a region of memory to a process's virtual address space. This function supports different flags like `MAP_SHARED`, `MAP_ANONYMOUS`, and `MAP_FIXED`, allowing for shared, anonymous, or fixed address mappings.
- **`wunmap`**: A system call that unmaps a previously mapped region of memory, ensuring proper cleanup and freeing of resources.
- **Page Fault Handling**: Properly managing page faults when accessing memory regions that are mapped lazily. If the page fault occurs within a mapped address range, memory should be allocated, otherwise, the process is killed.
- **`getwmapinfo`**: A system call that returns information about all the memory mappings, such as the total number of mappings, the starting address of each mapping, the size of each mapping, and the number of physically loaded pages in each mapping.
  
The project also involved handling **segmentation faults** gracefully when an access violation occurs due to invalid memory addresses or illegal operations on mapped regions.

---

## 🎯 What I Learned  
This project provided invaluable hands-on experience with **virtual memory management** and **system call implementation**. Key takeaways include:

✅ **Memory Mapping** – Using `wmap` to map memory regions with various flags, supporting shared, anonymous, and fixed memory allocations.  
✅ **Lazy Allocation** – Handling page faults efficiently to allocate memory only when needed, rather than eagerly allocating memory upfront.  
✅ **Unmapping Memory** – Implementing `wunmap` to unmap memory and release resources safely.  
✅ **Segmentation Fault Handling** – Gracefully handling segmentation faults and ensuring proper cleanup when accessing invalid memory.  
✅ **System Call Development** – Creating and testing system calls like `getwmapinfo` to provide detailed information on memory mappings.  
✅ **Kernel Programming** – Gaining a deeper understanding of memory management in the kernel, including page tables and virtual-to-physical address translation.  

---

## 🏆 Results  
I successfully implemented all the required memory management functionality, passing **all test cases**. This included handling different flags for memory mapping, correctly managing page faults, and ensuring proper cleanup when memory is unmapped. Additionally, the system call `getwmapinfo` returned the expected results, providing detailed information about memory mappings and loaded pages.

This project helped deepen my understanding of **virtual memory management**, **lazy allocation techniques**, and the importance of **memory safety** at the system level. It also enhanced my skills in **kernel programming** and **system call development**.

---
