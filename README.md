# Simulation of Page Replacement Algorithms

Our project, Page Replacement Algorithms is a concept under virtual memory in Operating Systems. Virtual memory involves the separation of logical memory as perceived by users from physical memory. This separation allows an extremely large virtual memory to be provided for programmers when only a smaller physical memory is available. Virtual memory makes the task of programming much easier because the programmer no longer needs to worry about the amount of physical memory available.

We have simulated 3 popular page replacement algorithms, LRU, FIFO, and LFU.

## FIFO Page Replacement Algorithm

 As the name suggests, this algorithm works on the principle of “First in First out “.
• It is implemented by keeping track of all the pages in a queue. •
It replaces the oldest page that has been present in the main memory for the longest time.
•
 This algorithm is similar to the operations of the queue. All the pages are stored
 in the queue in the order they are allocated frames in the main memory. The
 one which is allocated first stays in the front of the queue. The one which is
 allocated the memory first is replaced first that is
The one which is at the front of the queue is removed at the time of replacement.
• While using the First In First Out algorithm, the number of page faults increases by increasing the number of frames. This phenomenon is called Belady's Anomaly


## LRU Page Replacement Algorithm

• As the name suggests, this algorithm works on the principle of “Least Recently Used“.
• It replaces the page that has not been referred by the CPU for the longest time.
• The least recently used page replacement algorithm keeps the track of usage of pages over a period of time. This algorithm works on the basis of
the principle of locality of a reference which states that a program has a tendency to access the same set of memory locations repetitively over a short period of time. So pages that have been used heavily in the past are most likely to be used heavily in the future also.
• In this algorithm, when a page fault occurs, then the page that has not been used for the longest duration of time is replaced by the newly requested page.


## LRU Page Replacement Algorithm

LFU Page Replacement Algorithm-
 
The Least frequently used (LFU) page replacement algorithm requires a counter, and
every page has one counter of its own which is initially set to 0.
At each clock interval, all pages that have been referenced within that interval will have
their counter incremented by 1.
In effect, the counters keep track of how frequently a page has been used. Thus, the
page with the lowest counter can be swapped out when necessary.
• • •
•
Advantages of LFU Page Replacement Algorithm
Following are the advantages of the LFU page replacement algorithm:
• Simple algorithm; may give adequate performance on some systems
• It has the essential properties of any page replacement algorithm
• It looks for a (relatively) idle page
• It’s reasonably efficient
Disadvantages of LFU Page Replacement Algorithm
Following are the disadvantages of the LFU page replacement algorithm:
• Bias towards discarding unmodified pages
• It handles modified pages, but is biased against using them
Pseudocode of LFU Algorithm in OS
• If there are multiple references to a page within the same clock cycle, the count stays at 1.
• Upon a clock interrupt, the R bits are added to an array based on their corresponding indices and then the R bits are set back to 0.
• The array is used to keep track of which pages are roughly used the least and then the algorithm evicts the page with the lowest corresponding count.


The GUI is based on React Js, which facilitates input of a reference string , and simulating the algorithms with interesting animations. 

Our project provides an illustration of the various page replacement algorithms and provides a comparison of the number of page faults and the hit ratio for a given reference string.

Page fault occurs when a process tries to access a page that is not in memory. If the reference to a page is a valid address in the memory, a free frame is found, and the page referenced is brought into the memory or else we trap the process to the operating system. A page hit occurs when the process accesses a page already brought into the memory.

Page replacement algorithms complete the separation of the physical and the logical memory. With this mechanism, an enormous virtual memory can be provided for programmers on a smaller physical memory.
Since the aim of any page replacement algorithm should be to lower the rate at which page faults occur, we illustrate the various algorithms in our project and compare their hit ratios and the number of page faults. Through this illustration, we are able to determine the algorithm with the best hit ratio for a given reference string. This hit ratio affects the effective access time. Effective access time is the average time taken to access a particular page.
effective access time = (1 − p) × ma + p × page fault time.
Where p is the rate of page faults and ma is the memory access time and (1-p) being the page hit ratio.
