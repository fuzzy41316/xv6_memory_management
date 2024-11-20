#include "types.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "x86.h"
#include "proc.h"
#include "fs.h"
#include "spinlock.h"
#include "sleeplock.h"
#include "file.h"

struct {
  struct spinlock lock;
  struct proc proc[NPROC];
} ptable;

static struct proc *initproc;

int nextpid = 1;
extern void forkret(void);
extern void trapret(void);

static void wakeup1(void *chan);

void
pinit(void)
{
  initlock(&ptable.lock, "ptable");
}

// Must be called with interrupts disabled
int
cpuid() {
  return mycpu()-cpus;
}

// Must be called with interrupts disabled to avoid the caller being
// rescheduled between reading lapicid and running through the loop.
struct cpu*
mycpu(void)
{
  int apicid, i;
  
  if(readeflags()&FL_IF)
    panic("mycpu called with interrupts enabled\n");
  
  apicid = lapicid();
  // APIC IDs are not guaranteed to be contiguous. Maybe we should have
  // a reverse map, or reserve a register to store &cpus[i].
  for (i = 0; i < ncpu; ++i) {
    if (cpus[i].apicid == apicid)
      return &cpus[i];
  }
  panic("unknown apicid\n");
}

// Disable interrupts so that we are not rescheduled
// while reading proc from the cpu structure
struct proc*
myproc(void) {
  struct cpu *c;
  struct proc *p;
  pushcli();
  c = mycpu();
  p = c->proc;
  popcli();
  return p;
}

//PAGEBREAK: 32
// Look in the process table for an UNUSED proc.
// If found, change state to EMBRYO and initialize
// state required to run in the kernel.
// Otherwise return 0.
static struct proc*
allocproc(void)
{
  struct proc *p;
  char *sp;

  acquire(&ptable.lock);

  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++)
    if(p->state == UNUSED)
      goto found;

  release(&ptable.lock);
  return 0;

found:
  p->state = EMBRYO;
  p->pid = nextpid++;
  p->wmapinfo.total_mmaps = 0;

  release(&ptable.lock);

  // Allocate kernel stack.
  if((p->kstack = kalloc()) == 0){
    p->state = UNUSED;
    return 0;
  }
  sp = p->kstack + KSTACKSIZE;

  // Leave room for trap frame.
  sp -= sizeof *p->tf;
  p->tf = (struct trapframe*)sp;

  // Set up new context to start executing at forkret,
  // which returns to trapret.
  sp -= 4;
  *(uint*)sp = (uint)trapret;

  sp -= sizeof *p->context;
  p->context = (struct context*)sp;
  memset(p->context, 0, sizeof *p->context);
  p->context->eip = (uint)forkret;

  return p;
}

//PAGEBREAK: 32
// Set up first user process.
void
userinit(void)
{
  struct proc *p;
  extern char _binary_initcode_start[], _binary_initcode_size[];

  p = allocproc();
  
  initproc = p;
  if((p->pgdir = setupkvm()) == 0)
    panic("userinit: out of memory?");
  inituvm(p->pgdir, _binary_initcode_start, (int)_binary_initcode_size);
  p->sz = PGSIZE;
  memset(p->tf, 0, sizeof(*p->tf));
  p->tf->cs = (SEG_UCODE << 3) | DPL_USER;
  p->tf->ds = (SEG_UDATA << 3) | DPL_USER;
  p->tf->es = p->tf->ds;
  p->tf->ss = p->tf->ds;
  p->tf->eflags = FL_IF;
  p->tf->esp = PGSIZE;
  p->tf->eip = 0;  // beginning of initcode.S

  safestrcpy(p->name, "initcode", sizeof(p->name));
  p->cwd = namei("/");

  // this assignment to p->state lets other cores
  // run this process. the acquire forces the above
  // writes to be visible, and the lock is also needed
  // because the assignment might not be atomic.
  acquire(&ptable.lock);

  p->state = RUNNABLE;

  release(&ptable.lock);
}

// Grow current process's memory by n bytes.
// Return 0 on success, -1 on failure.
int
growproc(int n)
{
  uint sz;
  struct proc *curproc = myproc();

  sz = curproc->sz;
  if(n > 0){
    if((sz = allocuvm(curproc->pgdir, sz, sz + n)) == 0)
      return -1;
  } else if(n < 0){
    if((sz = deallocuvm(curproc->pgdir, sz, sz + n)) == 0)
      return -1;
  }
  curproc->sz = sz;
  switchuvm(curproc);
  return 0;
}

// Create a new process copying p as the parent.
// Sets up stack to return as if from system call.
// Caller must set state of returned proc to RUNNABLE.
int
fork(void)
{
  int i, pid;
  struct proc *np;
  struct proc *curproc = myproc();

  // Allocate process.
  if((np = allocproc()) == 0){
    return -1;
  }

  // If not a child of a wmapped process, then COW
  if (curproc->wmapinfo.total_mmaps == 0)
  {
    if((np->pgdir = cow_copyuvm(curproc->pgdir, curproc->sz)) == 0)
    {
      kfree(np->kstack);
      np->kstack = 0;
      np->state = UNUSED;
      return -1;
    }
  }
  // Otherwise, mmaped process
  else
  {
    if((np->pgdir = copyuvm(curproc->pgdir, curproc->sz)) == 0)
    {
      kfree(np->kstack);
      np->kstack = 0;
      np->state = UNUSED;
      return -1;
    }

    // Copy wmap mappings from parent to child
    np->wmapinfo.total_mmaps = curproc->wmapinfo.total_mmaps;
    for(i = 0; i < curproc->wmapinfo.total_mmaps; i++)
    {
      np->wmapinfo.addr[i] = curproc->wmapinfo.addr[i];
      np->wmapinfo.length[i] = curproc->wmapinfo.length[i];
      np->wmapinfo.n_loaded_pages[i] = curproc->wmapinfo.n_loaded_pages[i];
      np->wmapinfo.files[i] = curproc->wmapinfo.files[i];

      // Duplicate file if it's a file-backed mapping
      if(np->wmapinfo.files[i]) filedup(np->wmapinfo.files[i]);

      // Map the same virtual addresses in child
      uint start = np->wmapinfo.addr[i];
      uint len = np->wmapinfo.length[i];
      for(uint va = start; va < start + len; va += PGSIZE)
      {
        pte_t *pte_parent = walkpgdir(curproc->pgdir, (void *)va, 0);
        if(!pte_parent || !(*pte_parent & PTE_P))
          continue; // Skip if page not present

        uint pa = PTE_ADDR(*pte_parent);
        uint flags = PTE_FLAGS(*pte_parent);

        // Map the page in the child's page table
        if(mappages(np->pgdir, (void *)va, PGSIZE, pa, flags) < 0) panic("fork: mappages failed");

        // Increase reference count for the physical page (parent)
        inc_ref_count(pa);
      }
    }
  }

  // Flush TLB after modifying PTEs
  lcr3(V2P(np->pgdir));
  lcr3(V2P(curproc->pgdir));
  

  np->sz = curproc->sz;
  np->parent = curproc;
  *np->tf = *curproc->tf;

  // Clear %eax so that fork returns 0 in the child.
  np->tf->eax = 0;

  for(i = 0; i < NOFILE; i++)
    if(curproc->ofile[i])
      np->ofile[i] = filedup(curproc->ofile[i]);
  np->cwd = idup(curproc->cwd);

  safestrcpy(np->name, curproc->name, sizeof(curproc->name));  

  pid = np->pid;

  acquire(&ptable.lock);

  np->state = RUNNABLE;

  release(&ptable.lock);

  return pid;
}

// Exit the current process.  Does not return.
// An exited process remains in the zombie state
// until its parent calls wait() to find out it exited.
void
exit(void)
{
  struct proc *curproc = myproc();
  struct proc *p;
  int fd;

  if(curproc == initproc)
    panic("init exiting");

  // Close all open files.
  for(fd = 0; fd < NOFILE; fd++){
    if(curproc->ofile[fd]){
      fileclose(curproc->ofile[fd]);
      curproc->ofile[fd] = 0;
    }
  }

  begin_op();
  iput(curproc->cwd);
  end_op();
  curproc->cwd = 0;

  // Remove all mappings from the process's address space
  for (uint va = 0; va < curproc->sz; va += PGSIZE) 
  {
    pte_t *pte = walkpgdir(curproc->pgdir, (void *)va, 0);
    if (pte && (*pte & PTE_P)) 
    {
      uint pa = PTE_ADDR(*pte);
      if (pa != 0) {
        kfree(P2V(pa));
        *pte = 0;
      }
    }
  }

  // Handle wmapinfo mappings
  for (int i = 0; i < curproc->wmapinfo.total_mmaps; i++) 
  {
    uint start_addr = curproc->wmapinfo.addr[i];
    uint length = curproc->wmapinfo.length[i];
    struct file *f = curproc->wmapinfo.files[i];

    for (uint va = start_addr; va < start_addr + length; va += PGSIZE) 
    {
      pte_t *pte = walkpgdir(curproc->pgdir, (void *)va, 0);
      if (pte && (*pte & PTE_P))
       {
        uint pa = PTE_ADDR(*pte);
        if (pa != 0) 
        {
          if (f != 0) 
          {
            // Write back to the file if it's a file-backed mapping
            begin_op();
            writei(f->ip, P2V(pa), va - start_addr, PGSIZE);
            end_op();
          }
          kfree(P2V(pa));
          *pte = 0;
        }
      }
    }
  }

  lcr3(V2P(curproc->pgdir));

  acquire(&ptable.lock);

  // Parent might be sleeping in wait().
  wakeup1(curproc->parent);

  // Pass abandoned children to init.
  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
    if(p->parent == curproc){
      p->parent = initproc;
      if(p->state == ZOMBIE)
        wakeup1(initproc);
    }
  }

  // Jump into the scheduler, never to return.
  curproc->state = ZOMBIE;
  sched();
  panic("zombie exit");
}

// Wait for a child process to exit and return its pid.
// Return -1 if this process has no children.
int
wait(void)
{
  struct proc *p;
  int havekids, pid;
  struct proc *curproc = myproc();
  
  acquire(&ptable.lock);
  for(;;){
    // Scan through table looking for exited children.
    havekids = 0;
    for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
      if(p->parent != curproc)
        continue;
      havekids = 1;
      if(p->state == ZOMBIE){
        // Found one.
        pid = p->pid;
        kfree(p->kstack);
        p->kstack = 0;
        freevm(p->pgdir);
        p->pid = 0;
        p->parent = 0;
        p->name[0] = 0;
        p->killed = 0;
        p->state = UNUSED;
        release(&ptable.lock);
        return pid;
      }
    }

    // No point waiting if we don't have any children.
    if(!havekids || curproc->killed){
      release(&ptable.lock);
      return -1;
    }

    // Wait for children to exit.  (See wakeup1 call in proc_exit.)
    sleep(curproc, &ptable.lock);  //DOC: wait-sleep
  }
}

//PAGEBREAK: 42
// Per-CPU process scheduler.
// Each CPU calls scheduler() after setting itself up.
// Scheduler never returns.  It loops, doing:
//  - choose a process to run
//  - swtch to start running that process
//  - eventually that process transfers control
//      via swtch back to the scheduler.
void
scheduler(void)
{
  struct proc *p;
  struct cpu *c = mycpu();
  c->proc = 0;
  
  for(;;){
    // Enable interrupts on this processor.
    sti();

    // Loop over process table looking for process to run.
    acquire(&ptable.lock);
    for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
      if(p->state != RUNNABLE)
        continue;

      // Switch to chosen process.  It is the process's job
      // to release ptable.lock and then reacquire it
      // before jumping back to us.
      c->proc = p;
      switchuvm(p);
      p->state = RUNNING;

      swtch(&(c->scheduler), p->context);
      switchkvm();

      // Process is done running for now.
      // It should have changed its p->state before coming back.
      c->proc = 0;
    }
    release(&ptable.lock);

  }
}

// Enter scheduler.  Must hold only ptable.lock
// and have changed proc->state. Saves and restores
// intena because intena is a property of this
// kernel thread, not this CPU. It should
// be proc->intena and proc->ncli, but that would
// break in the few places where a lock is held but
// there's no process.
void
sched(void)
{
  int intena;
  struct proc *p = myproc();

  if(!holding(&ptable.lock))
    panic("sched ptable.lock");
  if(mycpu()->ncli != 1)
    panic("sched locks");
  if(p->state == RUNNING)
    panic("sched running");
  if(readeflags()&FL_IF)
    panic("sched interruptible");
  intena = mycpu()->intena;
  swtch(&p->context, mycpu()->scheduler);
  mycpu()->intena = intena;
}

// Give up the CPU for one scheduling round.
void
yield(void)
{
  acquire(&ptable.lock);  //DOC: yieldlock
  myproc()->state = RUNNABLE;
  sched();
  release(&ptable.lock);
}

// A fork child's very first scheduling by scheduler()
// will swtch here.  "Return" to user space.
void
forkret(void)
{
  static int first = 1;
  // Still holding ptable.lock from scheduler.
  release(&ptable.lock);

  if (first) {
    // Some initialization functions must be run in the context
    // of a regular process (e.g., they call sleep), and thus cannot
    // be run from main().
    first = 0;
    iinit(ROOTDEV);
    initlog(ROOTDEV);
  }

  // Return to "caller", actually trapret (see allocproc).
}

// Atomically release lock and sleep on chan.
// Reacquires lock when awakened.
void
sleep(void *chan, struct spinlock *lk)
{
  struct proc *p = myproc();
  
  if(p == 0)
    panic("sleep");

  if(lk == 0)
    panic("sleep without lk");

  // Must acquire ptable.lock in order to
  // change p->state and then call sched.
  // Once we hold ptable.lock, we can be
  // guaranteed that we won't miss any wakeup
  // (wakeup runs with ptable.lock locked),
  // so it's okay to release lk.
  if(lk != &ptable.lock){  //DOC: sleeplock0
    acquire(&ptable.lock);  //DOC: sleeplock1
    release(lk);
  }
  // Go to sleep.
  p->chan = chan;
  p->state = SLEEPING;

  sched();

  // Tidy up.
  p->chan = 0;

  // Reacquire original lock.
  if(lk != &ptable.lock){  //DOC: sleeplock2
    release(&ptable.lock);
    acquire(lk);
  }
}

//PAGEBREAK!
// Wake up all processes sleeping on chan.
// The ptable lock must be held.
static void
wakeup1(void *chan)
{
  struct proc *p;

  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++)
    if(p->state == SLEEPING && p->chan == chan)
      p->state = RUNNABLE;
}

// Wake up all processes sleeping on chan.
void
wakeup(void *chan)
{
  acquire(&ptable.lock);
  wakeup1(chan);
  release(&ptable.lock);
}

// Kill the process with the given pid.
// Process won't exit until it returns
// to user space (see trap in trap.c).
int
kill(int pid)
{
  struct proc *p;

  acquire(&ptable.lock);
  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
    if(p->pid == pid){
      p->killed = 1;
      // Wake process from sleep if necessary.
      if(p->state == SLEEPING)
        p->state = RUNNABLE;
      release(&ptable.lock);
      return 0;
    }
  }
  release(&ptable.lock);
  return -1;
}

//PAGEBREAK: 36
// Print a process listing to console.  For debugging.
// Runs when user types ^P on console.
// No lock to avoid wedging a stuck machine further.
void
procdump(void)
{
  static char *states[] = {
  [UNUSED]    "unused",
  [EMBRYO]    "embryo",
  [SLEEPING]  "sleep ",
  [RUNNABLE]  "runble",
  [RUNNING]   "run   ",
  [ZOMBIE]    "zombie"
  };
  int i;
  struct proc *p;
  char *state;
  uint pc[10];

  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
    if(p->state == UNUSED)
      continue;
    if(p->state >= 0 && p->state < NELEM(states) && states[p->state])
      state = states[p->state];
    else
      state = "???";
    cprintf("%d %s %s", p->pid, state, p->name);
    if(p->state == SLEEPING){
      getcallerpcs((uint*)p->context->ebp+2, pc);
      for(i=0; i<10 && pc[i] != 0; i++)
        cprintf(" %p", pc[i]);
    }
    cprintf("\n");
  }
}

/*
 * wmap has two modes of operation. First is "anonymous" memory allocation which has aspects similar to malloc. The real power of wmap comes through the support of "file-backed" mapping. 
 * Wait - what does file-backed mapping mean? It means you create a memory representation of a file. Reading data from that memory region is the same as reading data from the file. 
 * What happens if we write to memory that is backed by a file? Will it be reflected in the file? Well, that depends on the flags you use for wmap. 
 * When the flag MAP_SHARED is used, you need to write the (perhaps modified) contents of the memory back to the file upon wunmap.
 * 
 * @addr: Depending on the flags (MAP_FIXED, more on that later), it could be a hint for what "virtual" address wmap should use for the mapping, or the "virtual" address that wmap MUST use for the mapping.
 * 
 * @length: The length of the mapping in bytes. It must be greater than 0.
 * 
 * @flags:  The kind of memory mapping you are requesting for. Flags can be ORed together (e.g., MAP_SHARED | MAP_ANONYMOUS). You should define these flags as constants in the wmap.h header file. 
 * Use the snippet provided in the Hints section. If you look at the man page, there are many flags for various purposes. In your implementation, you only need to implement these flags:
 * 
 * @fd: If it's a file-backed mapping, this is the file descriptor for the file to be mapped. You can assume that fd belongs to a file of type FD_INODE. 
 * Also, you can assume that fd was opened in O_RDRW mode. In case of MAP_ANONYMOUS (see flags), you should ignore this argument.
 * 
 * @return: the starting virtual address of the memory on success, and FAILED on failure. That virtual address must be a multiple of page size.
*/
uint do_wmap(uint addr, int length, int flags, int fd)
{
  // Acquire the current process
  struct proc *curproc = myproc();

  // Wmap only deals with fixed & shared mappings
  if (!(flags & MAP_FIXED) || !(flags & MAP_SHARED)) return FAILED;

  // Addr needs to be a multiple of pgsize, and wmap only serves this addr space
  if (addr < 0x60000000 || addr >= 0x80000000 || addr % PGSIZE != 0) return FAILED;

  // Length needs to be >= 0
  if (length <= 0) return FAILED;

  // Check that size of mapping is not greater than addr space
  if ((addr + length) >= 0x80000000) return FAILED;

  // Is there space for mapping?
  if (curproc->wmapinfo.total_mmaps >= MAX_WMMAP_INFO) return FAILED;

  // If so, check for overlapping mappings
  for (int i = 0; i < curproc->wmapinfo.total_mmaps; i++)
  {
    uint start_addr = curproc->wmapinfo.addr[i];
    uint end_addr = start_addr + curproc->wmapinfo.length[i];

    // If there is an overlap in address, FAILED
    if ((addr >= start_addr && addr < end_addr) || (addr + length > start_addr && addr + length <= end_addr)) return FAILED;
  }

  // Otherwise, add the new mapping
  int index = curproc->wmapinfo.total_mmaps;
  curproc->wmapinfo.addr[index] = addr;
  curproc->wmapinfo.length[index] = length;
  curproc->wmapinfo.n_loaded_pages[index] = 0;  // No loaded pages yet
  curproc->wmapinfo.files[index] = (flags & MAP_ANONYMOUS) ? 0 : filedup(curproc->ofile[fd]);  // if MAP_ANONYMOUS, IGNORE FILE
  curproc->wmapinfo.total_mmaps++;

  // Upon successfull mapping, return the address
  return addr;
}

/*
 * wunmap removes the mapping starting at addr from the process virtual address space. If it's a file-backed mapping with MAP_SHARED, it writes the memory data back to the file to ensure the file remains up-to-date. 
 * So, wunmap does not partially unmap any mmap.
 *
 * @addr: The starting address of the mapping to be removed. It must be page aligned and the start address of some existing wmap.
 * 
 * @return: return SUCCESS to indicate success, and FAILED for failure.
 */
int do_wunmap(uint addr)
{
  // Acquire the current process
  struct proc *curproc = myproc();

  // Find any metadata for the mmap starting at addr, and remove from the data structure
  int mapping_found = -1;
  int index = -1;
  for (int i = 0; i < MAX_WMMAP_INFO; i++)
  {
    if (curproc->wmapinfo.addr[i] == addr)
    {
      mapping_found = 0;
      index = i;
      break;
    }
  }

  // Mapping wasn't found in proc list
  if (mapping_found != 0) return FAILED;

  // Get the length from the mapping before removing
  int length = curproc->wmapinfo.length[index];

  // Get the file, to see if we are writing back to file
  struct file *f = curproc->wmapinfo.files[index];

  // For file backed mapping
  if (f != 0) 
  {
    // Walk page directory to find PTE from VA
    for (uint va = addr; va < addr + length; va += PGSIZE)
    {
      pte_t *pte = walkpgdir(curproc->pgdir, (void*)va, 0);

      // If PTE is present
      if (pte && (*pte & PTE_P))
      {
        // Grab the physical address
        uint pa = PTE_ADDR(*pte);

        // Write back to the file
        begin_op(); 
        writei(f->ip, P2V(pa), va - addr, PGSIZE);
        end_op();

        // Free physical memory
        kfree(P2V(pa));
        *pte = 0;
      }
    }

    // Close the duplicated file
    //fileclose(f);
  }

  // For anonymous mapping, free the memory
  else 
  {
    for (uint va = addr; va < addr + length; va += PGSIZE)
    {
      // Walk page directory and find page table entry from virtual address
      pte_t *pte = walkpgdir(curproc->pgdir, (void *)va, 0);

      // Page table entry is present
      if (pte && (*pte & PTE_P))
      {
        // Convert to physical address (we can assume offset is 0)
        uint pa = PTE_ADDR(*pte);

        // Free from memory
        kfree(P2V(pa));

        // Any future reference to va will fail
        *pte = 0;
      }
    }
  }

  // Remove the mapping
  curproc->wmapinfo.addr[index] = 0;
  curproc->wmapinfo.length[index] = 0;
  curproc->wmapinfo.n_loaded_pages[index] = 0;
  curproc->wmapinfo.files[index] = 0;
  curproc->wmapinfo.total_mmaps--;

  return SUCCESS;
}

/*
 * Translate a virtual address according to the page table for the calling process. 
 * (NOT the physical page! also consider the offset)
 * 
 * @va: The virtual address to translate
 *
 * @return:  return the physical address on success, FAILED on failure
 */
uint do_va2pa(uint va)
{
  // Acquire the current process
  struct proc *curproc = myproc();

  // Walk page directory and find page table entry from the VA
  pte_t *pte = walkpgdir(curproc->pgdir, (void*)va, 0);

  // If VA is unaccessible or pte is not present, return FAILED
  if (!pte || !(*pte & PTE_P)) return FAILED;

  // Otherwise, acquire the physical address of the PTE
  uint pa = PTE_ADDR(*pte);

  return pa | (va & 0xFFF); // Add offset within page (first 12 bits of VA)
}

/*
 * Retrieves information about the process address space by populating struct wmapinfo.
 * This system call should calculate the current number of memory maps (mmaps) in the process's address space and store the result in total_mmaps. 
 * It should also populate addr[MAX_WMMAP_INFO] and length[MAX_WMAP_INFO] with the address and length of each wmap. 
 * You can expect that the number of mmaps in the current process will not exceed MAX_WMAP_INFO. 
 * The n_loaded_pages[MAX_WMAP_INFO] should store how many pages have been physically allocated for each wmap (corresponding index of addr and length arrays). 
 * This field should reflect lazy allocation.
 *
 * @wminfo: A pointer to struct wmapinfo that will be filled by the system call.
 * 
 * @return: return SUCCESS to indicate success, and FAILED for failure.
 */
int do_getwmapinfo(struct wmapinfo *wminfo)
{
  // Acquire current process
  struct proc *curproc = myproc();

  // Making edits to proc, so acquire lock
  acquire(&ptable.lock);

  wminfo->total_mmaps = curproc->wmapinfo.total_mmaps;
  for (int i = 0; i < curproc->wmapinfo.total_mmaps; i++)
  {
    wminfo->addr[i] = curproc->wmapinfo.addr[i];
    wminfo->length[i] = curproc->wmapinfo.length[i];
    wminfo->n_loaded_pages[i] = curproc->wmapinfo.n_loaded_pages[i];
    wminfo->files[i] = curproc->wmapinfo.files[i];
  }

  release(&ptable.lock);
  return SUCCESS;
}

