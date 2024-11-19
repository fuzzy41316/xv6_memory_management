#include "types.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "proc.h"
#include "x86.h"
#include "traps.h"
#include "fs.h"
#include "spinlock.h"
#include "sleeplock.h"
#include "file.h"

// Interrupt descriptor table (shared by all CPUs).
struct gatedesc idt[256];
extern uint vectors[];  // in vectors.S: array of 256 entry pointers
struct spinlock tickslock;
uint ticks;

void
tvinit(void)
{
  int i;

  for(i = 0; i < 256; i++)
    SETGATE(idt[i], 0, SEG_KCODE<<3, vectors[i], 0);
  SETGATE(idt[T_SYSCALL], 1, SEG_KCODE<<3, vectors[T_SYSCALL], DPL_USER);

  initlock(&tickslock, "time");
}

void
idtinit(void)
{
  lidt(idt, sizeof(idt));
}

//PAGEBREAK: 41
void
trap(struct trapframe *tf)
{
  if(tf->trapno == T_SYSCALL){
    if(myproc()->killed)
      exit();
    myproc()->tf = tf;
    syscall();
    if(myproc()->killed)
      exit();
    return;
  }

  switch(tf->trapno){
  case T_IRQ0 + IRQ_TIMER:
    if(cpuid() == 0){
      acquire(&tickslock);
      ticks++;
      wakeup(&ticks);
      release(&tickslock);
    }
    lapiceoi();
    break;
  case T_IRQ0 + IRQ_IDE:
    ideintr();
    lapiceoi();
    break;
  case T_IRQ0 + IRQ_IDE+1:
    // Bochs generates spurious IDE1 interrupts.
    break;
  case T_IRQ0 + IRQ_KBD:
    kbdintr();
    lapiceoi();
    break;
  case T_IRQ0 + IRQ_COM1:
    uartintr();
    lapiceoi();
    break;
  case T_IRQ0 + 7:
  case T_IRQ0 + IRQ_SPURIOUS:
    cprintf("cpu%d: spurious interrupt at %x:%x\n",
            cpuid(), tf->cs, tf->eip);
    lapiceoi();
    break;

  case T_PGFLT:
  {
    // Acquire the address at which a page fault occurred
    uint fault_addr = rcr2();

    // Acquire the current process
    struct proc *curproc = myproc();
    
    // Iterate through mappings of the process ( LAZY ALLOCATION )
    for (int i = 0; i < curproc->wmapinfo.total_mmaps; i++)
    {
      // Acquire the start and ending address of the current mapping
      uint start_addr = curproc->wmapinfo.addr[i];
      uint end_addr = start_addr + curproc->wmapinfo.length[i];

      // Check that it's within bounds
      if (fault_addr >= start_addr && fault_addr < end_addr)
      {
        // Then allocate a new page
        char *mem = kalloc();

        // If allocation fails, kill proc and exit
        if (mem == 0)
        {
          cprintf("Page allocation failed\n");
          curproc->killed = 1;
          exit();
        }
        
        // HANDLE COW
        pte_t *pte = walkpgdir(curproc->pgdir, (void*)fault_addr, 0);
        uint pa = PTE_ADDR(*pte);
        uint flags = PTE_FLAGS(*pte);
        if ((flags & PTE_COW) && !(flags & PTE_W))
        {                  
          // Copy contents from old page to new page for COW
          memmove(mem, (char*)P2V(pa), PGSIZE);

          // Update reference counts
          dec_ref_count(pa);
          inc_ref_count(V2P(mem));

          // Update the PTE to point to the new page, set writable, and remove COW flag
          *pte = (V2P(mem) | PTE_W | PTE_U | PTE_P) & ~PTE_COW;

          // Flush the TLB for this page
          lcr3(V2P(curproc->pgdir));
        }

        // HANDLE FILE-BACKED MEMORY
        struct file *f = curproc->wmapinfo.files[i];
        if (f != 0)
        {
          
          begin_op();
          int n = readi(f->ip, mem, fault_addr - start_addr, PGSIZE);
          end_op();
          
          if (n < 0)
          {
            cprintf("Failed to read file\n");
            kfree(mem);
            curproc->killed = 1;
            exit();
          }

          // If < PGSIZE bytes were read, zero out the remaining bytes
          if (n < PGSIZE) memset(mem + n, 0, PGSIZE - n);
          
        }

        // Otherwise, zero-initialize memory for anonymous mapping
        else memset(mem, 0, PGSIZE);

        // Map the allocated memory to the faulting address (making them writable and user-accessible)
        if (mappages(curproc->pgdir, (char*)fault_addr, PGSIZE, V2P(mem), PTE_W|PTE_U) < 0)
        {
          // If mapping fails, free, and kill proc
          cprintf("Page mapping failed\n");
          kfree(mem);
          curproc->killed = 1;
          exit();
        }

        // Increment the count of loaded pages for current mapping
        curproc->wmapinfo.n_loaded_pages[i]++;
        return;
      }
    }
    // If the fault address is not a part of any mapping...
    cprintf("Segmentation Fault\n");
    curproc->killed = 1;
    break;
  }

  //PAGEBREAK: 13
  default:
    if(myproc() == 0 || (tf->cs&3) == 0){
      // In kernel, it must be our mistake.
      cprintf("unexpected trap %d from cpu %d eip %x (cr2=0x%x)\n",
              tf->trapno, cpuid(), tf->eip, rcr2());
      panic("trap");
    }
    // In user space, assume process misbehaved.
    cprintf("pid %d %s: trap %d err %d on cpu %d "
            "eip 0x%x addr 0x%x--kill proc\n",
            myproc()->pid, myproc()->name, tf->trapno,
            tf->err, cpuid(), tf->eip, rcr2());
    myproc()->killed = 1;
  }

  // Force process exit if it has been killed and is in user space.
  // (If it is still executing in the kernel, let it keep running
  // until it gets to the regular system call return.)
  if(myproc() && myproc()->killed && (tf->cs&3) == DPL_USER)
    exit();

  // Force process to give up CPU on clock tick.
  // If interrupts were on while locks held, would need to check nlock.
  if(myproc() && myproc()->state == RUNNING &&
     tf->trapno == T_IRQ0+IRQ_TIMER)
    yield();

  // Check if the process has been killed since we yielded
  if(myproc() && myproc()->killed && (tf->cs&3) == DPL_USER)
    exit();
}
